const std = @import("std");
const boringssl = @import("../crypto/boringssl_crypto.zig");
const Sha1 = boringssl.Sha1;
const base64_encoder = std.base64.standard.Encoder;

/// RFC 6455 WebSocket magic GUID for Sec-WebSocket-Accept computation.
const ws_magic_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
};

pub const FrameHeader = struct {
    fin: bool,
    opcode: Opcode,
    masked: bool,
    payload_len: u64,
    mask_key: [4]u8,
    header_size: usize,
};

pub const WsResult = @import("stream.zig").TransportResult;

pub const Role = enum { server, client };

/// WebSocket transport layer following the TLS Stream transformation pattern.
///
/// Data flow: TCP <-> [TLS] <-> WS <-> Protocol (VMess/Trojan)
///
/// API mirrors TlsStream: feedNetworkData / handshake / readDecrypted /
/// writeEncrypted / getNetworkData.
pub const WsStream = struct {
    role: Role,
    handshake_done: bool = false,

    // Config (stack-allocated, copied from slices)
    path_buf: [128]u8 = undefined,
    path_len: u8 = 0,
    host_buf: [128]u8 = undefined,
    host_len: u8 = 0,

    // Handshake accumulation buffer (HTTP headers can arrive fragmented)
    hs_buf: [4096]u8 = undefined,
    hs_len: usize = 0,

    // Output buffer (handshake response / control frames)
    out_buf: [2048]u8 = undefined,
    out_len: usize = 0,
    out_pos: usize = 0,

    // Client-side: stored key for response validation
    client_key: [24]u8 = undefined,

    // Post-handshake: leftover data after handshake header ends
    leftover_start: usize = 0,

    // Whether client handshake request has been generated
    client_request_sent: bool = false,

    /// Create a server-side WebSocket stream.
    pub fn initServer(path: []const u8, host: []const u8) WsStream {
        var ws = WsStream{ .role = .server };
        ws.path_len = @intCast(@min(path.len, 128));
        @memcpy(ws.path_buf[0..ws.path_len], path[0..ws.path_len]);
        ws.host_len = @intCast(@min(host.len, 128));
        @memcpy(ws.host_buf[0..ws.host_len], host[0..ws.host_len]);
        return ws;
    }

    /// Create a client-side WebSocket stream.
    pub fn initClient(path: []const u8, host: []const u8) WsStream {
        var ws = WsStream{ .role = .client };
        ws.path_len = @intCast(@min(path.len, 128));
        @memcpy(ws.path_buf[0..ws.path_len], path[0..ws.path_len]);
        ws.host_len = @intCast(@min(host.len, 128));
        @memcpy(ws.host_buf[0..ws.host_len], host[0..ws.host_len]);
        return ws;
    }

    /// Feed raw network data into the WebSocket engine.
    /// During handshake: accumulates into hs_buf.
    /// Post-handshake: stores reference for frame parsing.
    pub fn feedNetworkData(self: *WsStream, data: []const u8) !usize {
        if (!self.handshake_done) {
            const space = self.hs_buf.len - self.hs_len;
            if (space == 0) return error.WsHandshakeBufferFull;
            const n = @min(data.len, space);
            @memcpy(self.hs_buf[self.hs_len .. self.hs_len + n], data[0..n]);
            self.hs_len += n;
            return n;
        }
        // Post-handshake: append to hs_buf (reused as frame buffer)
        const space = self.hs_buf.len - self.hs_len;
        if (space == 0) return error.WsFrameBufferFull;
        const n = @min(data.len, space);
        @memcpy(self.hs_buf[self.hs_len .. self.hs_len + n], data[0..n]);
        self.hs_len += n;
        return n;
    }

    /// Drive the WebSocket handshake forward.
    pub fn handshake(self: *WsStream) WsResult {
        return switch (self.role) {
            .server => self.serverHandshake(),
            .client => self.clientHandshake(),
        };
    }

    /// Read decoded application data (unwrap WebSocket frames).
    pub fn readDecrypted(self: *WsStream, buf: []u8) WsResult {
        if (!self.handshake_done) return .want_read;

        // Loop to skip control frames (ping/pong) without recursion
        var control_frames_processed: u8 = 0;
        while (control_frames_processed < 16) {
            const available = self.hs_buf[self.leftover_start..self.hs_len];
            if (available.len == 0) return .want_read;

            const hdr = parseFrameHeader(available) orelse return .want_read;
            const total_frame = hdr.header_size + @as(usize, @intCast(hdr.payload_len));
            if (available.len < total_frame) return .want_read;

            const payload_len: usize = @intCast(hdr.payload_len);

            switch (hdr.opcode) {
                .binary, .text, .continuation => {
                    if (buf.len < payload_len) return .err;
                    @memcpy(buf[0..payload_len], available[hdr.header_size .. hdr.header_size + payload_len]);
                    if (hdr.masked) {
                        applyMask(buf[0..payload_len], hdr.mask_key);
                    }
                    self.consumeInput(total_frame);
                    return .{ .bytes = payload_len };
                },
                .ping => {
                    var ping_payload_buf: [125]u8 = undefined;
                    const ping_len = @min(payload_len, 125);
                    @memcpy(ping_payload_buf[0..ping_len], available[hdr.header_size .. hdr.header_size + ping_len]);
                    if (hdr.masked) {
                        applyMask(ping_payload_buf[0..ping_len], hdr.mask_key);
                    }
                    const pong_size = encodeFrame(
                        self.out_buf[self.out_len..],
                        .pong,
                        ping_payload_buf[0..ping_len],
                        self.role == .client,
                    );
                    if (pong_size) |n| self.out_len += n;
                    self.consumeInput(total_frame);
                    control_frames_processed += 1;
                    continue; // loop to next frame
                },
                .pong => {
                    self.consumeInput(total_frame);
                    control_frames_processed += 1;
                    continue; // loop to next frame
                },
                .close => {
                    const close_size = encodeFrame(
                        self.out_buf[self.out_len..],
                        .close,
                        &[_]u8{},
                        self.role == .client,
                    );
                    if (close_size) |n| self.out_len += n;
                    self.consumeInput(total_frame);
                    return .closed;
                },
            }
        }
        return .want_read; // too many control frames, wait for more data
    }

    /// Encode application data into a WebSocket binary frame.
    /// Output should be retrieved with getNetworkData().
    pub fn writeEncrypted(self: *WsStream, data: []const u8) WsResult {
        const space = self.out_buf.len - self.out_len;
        const need = frameSize(data.len, self.role == .client);
        if (space < need) return .err;

        const n = encodeFrame(
            self.out_buf[self.out_len..],
            .binary,
            data,
            self.role == .client,
        ) orelse return .err;
        self.out_len += n;
        return .{ .bytes = data.len };
    }

    /// Get framed/encoded data that needs to be sent over the network.
    pub fn getNetworkData(self: *WsStream, buf: []u8) usize {
        const pending = self.out_len - self.out_pos;
        if (pending == 0) return 0;
        const n = @min(pending, buf.len);
        @memcpy(buf[0..n], self.out_buf[self.out_pos .. self.out_pos + n]);
        self.out_pos += n;
        // Reset when fully consumed
        if (self.out_pos == self.out_len) {
            self.out_pos = 0;
            self.out_len = 0;
        }
        return n;
    }

    /// Check if there's outgoing data pending to be sent.
    pub fn hasNetworkDataPending(self: *const WsStream) bool {
        return self.out_len > self.out_pos;
    }

    pub fn isHandshakeDone(self: *const WsStream) bool {
        return self.handshake_done;
    }

    // ── Server handshake ──

    fn serverHandshake(self: *WsStream) WsResult {
        // Look for end of HTTP headers
        const end = findEndOfHeaders(self.hs_buf[0..self.hs_len]) orelse return .want_read;
        const header_data = self.hs_buf[0..end];

        // Validate GET request line
        if (!std.mem.startsWith(u8, header_data, "GET ")) return .err;

        // Extract and validate path
        const path_end = std.mem.indexOf(u8, header_data[4..], " ") orelse return .err;
        const req_path = header_data[4 .. 4 + path_end];
        if (!std.mem.eql(u8, req_path, self.path_buf[0..self.path_len])) return .err;

        // Extract Sec-WebSocket-Key
        const ws_key = findHeaderValue(header_data, "Sec-WebSocket-Key") orelse return .err;
        if (ws_key.len == 0 or ws_key.len > 128) return .err;

        // Compute accept key
        const accept = computeAcceptKey(ws_key);

        // Build 101 response
        var pos: usize = 0;
        const response_parts = [_][]const u8{
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: ",
            &accept,
            "\r\n\r\n",
        };
        for (response_parts) |part| {
            if (pos + part.len > self.out_buf.len) return .err;
            @memcpy(self.out_buf[pos .. pos + part.len], part);
            pos += part.len;
        }
        self.out_len = pos;
        self.out_pos = 0;

        // Save leftover data after HTTP headers (may contain first WS frame)
        // end points past the \r\n\r\n
        self.leftover_start = 0;
        if (end < self.hs_len) {
            const leftover = self.hs_len - end;
            std.mem.copyBackwards(u8, self.hs_buf[0..leftover], self.hs_buf[end..self.hs_len]);
            self.hs_len = leftover;
        } else {
            self.hs_len = 0;
        }

        self.handshake_done = true;
        return .{ .bytes = 0 };
    }

    // ── Client handshake ──

    fn clientHandshake(self: *WsStream) WsResult {
        if (!self.client_request_sent) {
            // Generate random 16-byte nonce, base64 encode to 24 chars
            var nonce: [16]u8 = undefined;
            boringssl.random.bytes(&nonce);
            _ = base64_encoder.encode(&self.client_key, &nonce);

            // Build upgrade request
            var pos: usize = 0;
            const parts = [_][]const u8{
                "GET ",
                self.path_buf[0..self.path_len],
                " HTTP/1.1\r\nHost: ",
                self.host_buf[0..self.host_len],
                "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ",
                &self.client_key,
                "\r\nSec-WebSocket-Version: 13\r\n\r\n",
            };
            for (parts) |part| {
                if (pos + part.len > self.out_buf.len) return .err;
                @memcpy(self.out_buf[pos .. pos + part.len], part);
                pos += part.len;
            }
            self.out_len = pos;
            self.out_pos = 0;
            self.client_request_sent = true;
            return .want_write;
        }

        // Waiting for server response
        const end = findEndOfHeaders(self.hs_buf[0..self.hs_len]) orelse return .want_read;
        const header_data = self.hs_buf[0..end];

        // Verify HTTP/1.1 101
        if (!std.mem.startsWith(u8, header_data, "HTTP/1.1 101")) return .err;

        // Verify Sec-WebSocket-Accept
        const accept_value = findHeaderValue(header_data, "Sec-WebSocket-Accept") orelse return .err;
        const expected_accept = computeAcceptKey(&self.client_key);
        if (!std.mem.eql(u8, accept_value, &expected_accept)) return .err;

        // Save leftover data
        self.leftover_start = 0;
        if (end < self.hs_len) {
            const leftover = self.hs_len - end;
            std.mem.copyBackwards(u8, self.hs_buf[0..leftover], self.hs_buf[end..self.hs_len]);
            self.hs_len = leftover;
        } else {
            self.hs_len = 0;
        }

        self.handshake_done = true;
        return .{ .bytes = 0 };
    }

    fn consumeInput(self: *WsStream, n: usize) void {
        const remaining = self.hs_len - self.leftover_start - n;
        if (remaining > 0) {
            std.mem.copyBackwards(
                u8,
                self.hs_buf[self.leftover_start .. self.leftover_start + remaining],
                self.hs_buf[self.leftover_start + n .. self.hs_len],
            );
        }
        self.hs_len = self.leftover_start + remaining;
    }
};

// ── Pure helper functions ──

/// Compute Sec-WebSocket-Accept = Base64(SHA1(client_key ++ ws_magic_guid)).
pub fn computeAcceptKey(client_key: []const u8) [28]u8 {
    var hasher = Sha1.init(.{});
    hasher.update(client_key);
    hasher.update(ws_magic_guid);
    const digest = hasher.finalResult();
    var accept: [28]u8 = undefined;
    _ = base64_encoder.encode(&accept, &digest);
    return accept;
}

/// Parse a WebSocket frame header from the beginning of `data`.
/// Returns null if insufficient data.
pub fn parseFrameHeader(data: []const u8) ?FrameHeader {
    if (data.len < 2) return null;

    const byte0 = data[0];
    const byte1 = data[1];

    const fin = (byte0 & 0x80) != 0;
    const opcode_val: u4 = @intCast(byte0 & 0x0F);
    const opcode: Opcode = std.meta.intToEnum(Opcode, opcode_val) catch return null;
    const masked = (byte1 & 0x80) != 0;
    const len7: u7 = @intCast(byte1 & 0x7F);

    var header_size: usize = 2;
    var payload_len: u64 = 0;

    if (len7 < 126) {
        payload_len = len7;
    } else if (len7 == 126) {
        if (data.len < 4) return null;
        payload_len = std.mem.readInt(u16, data[2..4], .big);
        header_size = 4;
    } else {
        // len7 == 127
        if (data.len < 10) return null;
        payload_len = std.mem.readInt(u64, data[2..10], .big);
        header_size = 10;
    }

    var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) {
        if (data.len < header_size + 4) return null;
        @memcpy(&mask_key, data[header_size .. header_size + 4]);
        header_size += 4;
    }

    return FrameHeader{
        .fin = fin,
        .opcode = opcode,
        .masked = masked,
        .payload_len = payload_len,
        .mask_key = mask_key,
        .header_size = header_size,
    };
}

/// Encode a WebSocket frame into `buf`.
/// Returns number of bytes written, or null if buffer too small.
pub fn encodeFrame(buf: []u8, opcode: Opcode, payload: []const u8, mask: bool) ?usize {
    const need = frameSize(payload.len, mask);
    if (buf.len < need) return null;

    var pos: usize = 0;

    // Byte 0: FIN + opcode
    buf[pos] = 0x80 | @as(u8, @intFromEnum(opcode));
    pos += 1;

    // Byte 1: MASK bit + payload length
    const mask_bit: u8 = if (mask) 0x80 else 0;
    if (payload.len < 126) {
        buf[pos] = mask_bit | @as(u8, @intCast(payload.len));
        pos += 1;
    } else if (payload.len <= 65535) {
        buf[pos] = mask_bit | 126;
        pos += 1;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(payload.len), .big);
        pos += 2;
    } else {
        buf[pos] = mask_bit | 127;
        pos += 1;
        std.mem.writeInt(u64, buf[pos..][0..8], payload.len, .big);
        pos += 8;
    }

    // Masking key (client -> server)
    if (mask) {
        var mask_key: [4]u8 = undefined;
        boringssl.random.bytes(&mask_key);
        @memcpy(buf[pos .. pos + 4], &mask_key);
        pos += 4;
        @memcpy(buf[pos .. pos + payload.len], payload);
        applyMask(buf[pos .. pos + payload.len], mask_key);
    } else {
        @memcpy(buf[pos .. pos + payload.len], payload);
    }
    pos += payload.len;

    return pos;
}

/// Calculate the wire size of a WebSocket frame.
fn frameSize(payload_len: usize, mask: bool) usize {
    var size: usize = 2; // byte0 + byte1
    if (payload_len >= 126 and payload_len <= 65535) {
        size += 2; // 16-bit extended length
    } else if (payload_len > 65535) {
        size += 8; // 64-bit extended length
    }
    if (mask) size += 4; // masking key
    size += payload_len;
    return size;
}

/// Apply (or remove) XOR mask to data in-place. XOR is self-inverse.
pub fn applyMask(data: []u8, mask_key: [4]u8) void {
    applyMaskWithOffset(data, mask_key, 0);
}

/// Apply XOR mask with a starting offset (for streaming WS unwrap across reads).
/// Optimized: processes 8 bytes at a time via word-at-a-time XOR after aligning
/// to the mask-key boundary, then handles the tail byte-by-byte with bitwise AND.
pub fn applyMaskWithOffset(data: []u8, mask_key: [4]u8, offset: u32) void {
    if (data.len == 0) return;
    const off: usize = @intCast(offset);
    var i: usize = 0;

    // Handle unaligned prefix: advance to mask-key-aligned boundary
    const prefix = (4 - (off & 3)) & 3;
    const prefix_len = @min(prefix, data.len);
    for (0..prefix_len) |j| {
        data[j] ^= mask_key[(off + j) & 3];
    }
    i = prefix_len;

    // Word-at-a-time: XOR 8 bytes per iteration using u64
    const mask32: u32 = @bitCast(mask_key);
    const mask64: u64 = @as(u64, mask32) | (@as(u64, mask32) << 32);
    while (i + 8 <= data.len) {
        const ptr: *align(1) u64 = @ptrCast(&data[i]);
        ptr.* ^= mask64;
        i += 8;
    }

    // Handle remaining 0-7 bytes
    while (i < data.len) {
        data[i] ^= mask_key[(off + i) & 3];
        i += 1;
    }
}

/// Find the position right after "\r\n\r\n" in data. Returns null if not found.
fn findEndOfHeaders(data: []const u8) ?usize {
    const needle = "\r\n\r\n";
    const pos = std.mem.indexOf(u8, data, needle) orelse return null;
    return pos + needle.len;
}

/// Extract a header value from HTTP headers. Case-insensitive name match.
/// Returns the trimmed value, or null if not found.
fn findHeaderValue(headers: []const u8, name: []const u8) ?[]const u8 {
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |line| {
        const colon_pos = std.mem.indexOf(u8, line, ": ") orelse continue;
        const hdr_name = line[0..colon_pos];
        if (hdr_name.len != name.len) continue;
        // Case-insensitive compare
        var match = true;
        for (hdr_name, name) |a, b| {
            if (std.ascii.toLower(a) != std.ascii.toLower(b)) {
                match = false;
                break;
            }
        }
        if (match) {
            return std.mem.trim(u8, line[colon_pos + 2 ..], " ");
        }
    }
    return null;
}

// ── Tests ──

const testing = std.testing;

test "computeAcceptKey RFC 6455 known vector" {
    const accept = computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept);
}

test "parseFrameHeader small unmasked binary" {
    // FIN + binary(0x02), len=5, no mask
    const data = [_]u8{ 0x82, 0x05, 'h', 'e', 'l', 'l', 'o' };
    const hdr = parseFrameHeader(&data).?;
    try testing.expect(hdr.fin);
    try testing.expectEqual(Opcode.binary, hdr.opcode);
    try testing.expect(!hdr.masked);
    try testing.expectEqual(@as(u64, 5), hdr.payload_len);
    try testing.expectEqual(@as(usize, 2), hdr.header_size);
}

test "parseFrameHeader masked frame" {
    // FIN + binary(0x02), MASK + len=5, mask_key=0x37FA213D
    const data = [_]u8{ 0x82, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    const hdr = parseFrameHeader(&data).?;
    try testing.expect(hdr.fin);
    try testing.expectEqual(Opcode.binary, hdr.opcode);
    try testing.expect(hdr.masked);
    try testing.expectEqual(@as(u64, 5), hdr.payload_len);
    try testing.expectEqual(@as(usize, 6), hdr.header_size);
    try testing.expectEqual([_]u8{ 0x37, 0xFA, 0x21, 0x3D }, hdr.mask_key);
}

test "parseFrameHeader 16-bit length" {
    // FIN + binary(0x02), len=126 (extended 16-bit), payload_len=256
    var data: [4 + 256]u8 = undefined;
    data[0] = 0x82;
    data[1] = 126;
    std.mem.writeInt(u16, data[2..4], 256, .big);
    @memset(data[4..], 0xAA);

    const hdr = parseFrameHeader(&data).?;
    try testing.expect(hdr.fin);
    try testing.expectEqual(@as(u64, 256), hdr.payload_len);
    try testing.expectEqual(@as(usize, 4), hdr.header_size);
}

test "parseFrameHeader 64-bit length" {
    // FIN + binary(0x02), len=127 (extended 64-bit), payload_len=70000
    var data: [10]u8 = undefined;
    data[0] = 0x82;
    data[1] = 127;
    std.mem.writeInt(u64, data[2..10], 70000, .big);

    const hdr = parseFrameHeader(&data).?;
    try testing.expectEqual(@as(u64, 70000), hdr.payload_len);
    try testing.expectEqual(@as(usize, 10), hdr.header_size);
}

test "parseFrameHeader incomplete" {
    try testing.expect(parseFrameHeader(&[_]u8{0x82}) == null);
    try testing.expect(parseFrameHeader(&[_]u8{}) == null);
}

test "encodeFrame small unmasked binary" {
    var buf: [128]u8 = undefined;
    const n = encodeFrame(&buf, .binary, "hello", false).?;
    try testing.expectEqual(@as(usize, 7), n);
    try testing.expectEqual(@as(u8, 0x82), buf[0]); // FIN + binary
    try testing.expectEqual(@as(u8, 5), buf[1]); // len=5, no mask
    try testing.expectEqualStrings("hello", buf[2..7]);
}

test "encodeFrame medium payload 16-bit length" {
    const payload = [_]u8{0xBB} ** 256;
    var buf: [512]u8 = undefined;
    const n = encodeFrame(&buf, .binary, &payload, false).?;
    try testing.expectEqual(@as(usize, 4 + 256), n);
    try testing.expectEqual(@as(u8, 126), buf[1] & 0x7F);
    try testing.expectEqual(@as(u16, 256), std.mem.readInt(u16, buf[2..4], .big));
}

test "encodeFrame masked binary" {
    var buf: [128]u8 = undefined;
    const n = encodeFrame(&buf, .binary, "hi", true).?;
    // 2 (header) + 4 (mask) + 2 (payload) = 8
    try testing.expectEqual(@as(usize, 8), n);
    try testing.expect(buf[1] & 0x80 != 0); // MASK bit set
}

test "applyMask self-inverse" {
    const original = "Hello, WebSocket!";
    var data: [17]u8 = undefined;
    @memcpy(&data, original);
    const mask = [_]u8{ 0xAB, 0xCD, 0xEF, 0x01 };
    applyMask(&data, mask);
    // Should be different after masking
    try testing.expect(!std.mem.eql(u8, &data, original));
    // Apply again to recover
    applyMask(&data, mask);
    try testing.expectEqualStrings(original, &data);
}

test "server handshake valid request" {
    var ws = WsStream.initServer("/ws", "example.com");
    const request =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";
    _ = try ws.feedNetworkData(request);
    const result = ws.handshake();
    try testing.expect(result == .bytes);
    try testing.expect(ws.isHandshakeDone());

    // Check response contains 101 and correct accept key
    var resp_buf: [512]u8 = undefined;
    const resp_len = ws.getNetworkData(&resp_buf);
    try testing.expect(resp_len > 0);
    const resp = resp_buf[0..resp_len];
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 101"));
    try testing.expect(std.mem.indexOf(u8, resp, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != null);
}

test "server handshake incomplete" {
    var ws = WsStream.initServer("/ws", "");
    _ = try ws.feedNetworkData("GET /ws HTTP/1.1\r\nHost: x\r\n");
    const result = ws.handshake();
    try testing.expect(result == .want_read);
    try testing.expect(!ws.isHandshakeDone());
}

test "server handshake wrong path" {
    var ws = WsStream.initServer("/correct", "");
    const request =
        "GET /wrong HTTP/1.1\r\n" ++
        "Host: x\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";
    _ = try ws.feedNetworkData(request);
    const result = ws.handshake();
    try testing.expect(result == .err);
}

test "server handshake missing key" {
    var ws = WsStream.initServer("/ws", "");
    const request =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: x\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "\r\n";
    _ = try ws.feedNetworkData(request);
    const result = ws.handshake();
    try testing.expect(result == .err);
}

test "client handshake generates request" {
    var ws = WsStream.initClient("/proxy", "example.com");
    const result = ws.handshake();
    try testing.expect(result == .want_write);

    var buf: [512]u8 = undefined;
    const n = ws.getNetworkData(&buf);
    try testing.expect(n > 0);
    const req = buf[0..n];
    try testing.expect(std.mem.startsWith(u8, req, "GET /proxy HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, req, "Host: example.com") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Upgrade: websocket") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Sec-WebSocket-Key: ") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Sec-WebSocket-Version: 13") != null);
}

test "client handshake validates response" {
    var ws = WsStream.initClient("/ws", "example.com");
    _ = ws.handshake(); // Generate request

    // Build matching 101 response
    const accept = computeAcceptKey(&ws.client_key);
    var response_buf: [256]u8 = undefined;
    var pos: usize = 0;
    const parts = [_][]const u8{
        "HTTP/1.1 101 Switching Protocols\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Accept: ",
        &accept,
        "\r\n\r\n",
    };
    for (parts) |part| {
        @memcpy(response_buf[pos .. pos + part.len], part);
        pos += part.len;
    }
    _ = try ws.feedNetworkData(response_buf[0..pos]);
    const result = ws.handshake();
    try testing.expect(result == .bytes);
    try testing.expect(ws.isHandshakeDone());
}

test "client handshake rejects bad accept" {
    var ws = WsStream.initClient("/ws", "example.com");
    _ = ws.handshake();

    const response =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" ++
        "\r\n";
    _ = try ws.feedNetworkData(response);
    const result = ws.handshake();
    try testing.expect(result == .err);
}

test "writeEncrypted and readDecrypted roundtrip server" {
    // Server writes a frame, then reads it back
    var server = WsStream.initServer("/ws", "");
    server.handshake_done = true;

    // Server encodes (unmasked)
    const wr = server.writeEncrypted("test data");
    try testing.expect(wr == .bytes);

    // Get the encoded frame
    var wire: [128]u8 = undefined;
    const wire_len = server.getNetworkData(&wire);
    try testing.expect(wire_len > 0);

    // Another server-side instance reads it (unmasked frame from server)
    var reader = WsStream.initServer("/ws", "");
    reader.handshake_done = true;
    _ = try reader.feedNetworkData(wire[0..wire_len]);
    var out: [128]u8 = undefined;
    const rd = reader.readDecrypted(&out);
    switch (rd) {
        .bytes => |n| try testing.expectEqualStrings("test data", out[0..n]),
        else => return error.UnexpectedResult,
    }
}

test "writeEncrypted and readDecrypted roundtrip client-to-server" {
    // Client writes masked frame, server reads and unmasks
    var client = WsStream.initClient("/ws", "example.com");
    client.handshake_done = true;

    const wr = client.writeEncrypted("masked payload");
    try testing.expect(wr == .bytes);

    var wire: [128]u8 = undefined;
    const wire_len = client.getNetworkData(&wire);

    // Server reads the masked frame
    var server = WsStream.initServer("/ws", "");
    server.handshake_done = true;
    _ = try server.feedNetworkData(wire[0..wire_len]);
    var out: [128]u8 = undefined;
    const rd = server.readDecrypted(&out);
    switch (rd) {
        .bytes => |n| try testing.expectEqualStrings("masked payload", out[0..n]),
        else => return error.UnexpectedResult,
    }
}

test "ping generates pong" {
    var ws = WsStream.initServer("/ws", "");
    ws.handshake_done = true;

    // Build a ping frame with payload "hi"
    var ping_frame: [32]u8 = undefined;
    const ping_len = encodeFrame(&ping_frame, .ping, "hi", false).?;

    _ = try ws.feedNetworkData(ping_frame[0..ping_len]);
    var out: [128]u8 = undefined;
    _ = ws.readDecrypted(&out); // Should auto-generate pong

    // Check pong was generated
    try testing.expect(ws.hasNetworkDataPending());
    var pong_buf: [128]u8 = undefined;
    const pong_len = ws.getNetworkData(&pong_buf);
    try testing.expect(pong_len > 0);
    // Verify it's a pong frame
    const pong_hdr = parseFrameHeader(pong_buf[0..pong_len]).?;
    try testing.expectEqual(Opcode.pong, pong_hdr.opcode);
    try testing.expectEqual(@as(u64, 2), pong_hdr.payload_len);
}

test "close frame handling" {
    var ws = WsStream.initServer("/ws", "");
    ws.handshake_done = true;

    var close_frame: [8]u8 = undefined;
    const close_len = encodeFrame(&close_frame, .close, &[_]u8{}, false).?;
    _ = try ws.feedNetworkData(close_frame[0..close_len]);

    var out: [128]u8 = undefined;
    const result = ws.readDecrypted(&out);
    try testing.expect(result == .closed);
    // Close response should be pending
    try testing.expect(ws.hasNetworkDataPending());
}

test "empty payload frame" {
    var ws = WsStream.initServer("/ws", "");
    ws.handshake_done = true;

    var frame: [8]u8 = undefined;
    const frame_len = encodeFrame(&frame, .binary, &[_]u8{}, false).?;
    try testing.expectEqual(@as(usize, 2), frame_len);

    _ = try ws.feedNetworkData(frame[0..frame_len]);
    var out: [128]u8 = undefined;
    const result = ws.readDecrypted(&out);
    switch (result) {
        .bytes => |n| try testing.expectEqual(@as(usize, 0), n),
        else => return error.UnexpectedResult,
    }
}

test "frameSize calculation" {
    // Small payload, no mask
    try testing.expectEqual(@as(usize, 7), frameSize(5, false));
    // Small payload, with mask
    try testing.expectEqual(@as(usize, 11), frameSize(5, true));
    // Medium payload (126-65535), no mask
    try testing.expectEqual(@as(usize, 4 + 256), frameSize(256, false));
    // Medium payload, with mask
    try testing.expectEqual(@as(usize, 8 + 256), frameSize(256, true));
}

test "applyMask word-at-a-time large buffer" {
    // Verify optimized word-at-a-time path produces correct results
    var data: [1024]u8 = undefined;
    var expected: [1024]u8 = undefined;
    const mask = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    for (&data, &expected, 0..) |*d, *e, i| {
        const v: u8 = @intCast(i & 0xFF);
        d.* = v;
        e.* = v;
    }
    applyMask(&data, mask);
    // Verify against naive byte-by-byte
    for (&expected, 0..) |*e, i| {
        e.* ^= mask[i & 3];
    }
    try testing.expectEqualSlices(u8, &expected, &data);
    // Self-inverse: apply again should recover original
    applyMask(&data, mask);
    for (data, 0..) |byte, i| {
        try testing.expectEqual(@as(u8, @intCast(i & 0xFF)), byte);
    }
}

test "applyMaskWithOffset streaming consistency" {
    // Simulate streaming: split buffer and apply mask in chunks with offset
    const mask = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    var full: [100]u8 = undefined;
    var chunked: [100]u8 = undefined;
    for (&full, &chunked, 0..) |*f, *c, i| {
        const v: u8 = @intCast(i & 0xFF);
        f.* = v;
        c.* = v;
    }
    // Apply to full buffer at once
    applyMask(&full, mask);
    // Apply in 3 chunks: 7 + 50 + 43 bytes with correct offsets
    applyMaskWithOffset(chunked[0..7], mask, 0);
    applyMaskWithOffset(chunked[7..57], mask, 7);
    applyMaskWithOffset(chunked[57..100], mask, 57);
    try testing.expectEqualSlices(u8, &full, &chunked);
}

test "findHeaderValue case insensitive" {
    const headers = "GET / HTTP/1.1\r\nsec-websocket-key: testkey123\r\nHost: x\r\n\r\n";
    const value = findHeaderValue(headers, "Sec-WebSocket-Key");
    try testing.expect(value != null);
    try testing.expectEqualStrings("testkey123", value.?);
}
