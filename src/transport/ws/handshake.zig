const std = @import("std");
const c = @import("../../infra/crypto/bindings.zig").c;

pub const HandshakeError = error{
    InvalidUpgradeRequest,
    InvalidUpgradeResponse,
    PathMismatch,
    InnerStreamError,
    BufferOverflow,
};

const ws_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Perform server-side WebSocket handshake (read HTTP upgrade, send 101).
/// Returns any leftover data after the HTTP header.
pub fn serverHandshake(
    comptime Inner: type,
    inner: *Inner,
    path: []const u8,
    real_ip_header: []const u8,
    real_ip_out: *[46]u8,
    real_ip_len: *u8,
) HandshakeError!struct { pending: []const u8, pending_buf: [4096]u8, pending_len: usize } {
    // Read HTTP request until \r\n\r\n
    var buf: [4096]u8 = undefined;
    var filled: usize = 0;

    while (filled < buf.len) {
        const n = inner.read(buf[filled..]) catch return error.InnerStreamError;
        if (n == 0) return error.InvalidUpgradeRequest;
        filled += n;

        if (findHeaderEnd(buf[0..filled])) |header_end| {
            const header_data = buf[0..header_end];
            const body_start = header_end;

            // Validate HTTP upgrade request
            const ws_key = validateServerRequest(header_data, path) orelse
                return error.InvalidUpgradeRequest;

            // Extract real IP if configured
            if (real_ip_header.len > 0) {
                if (findHeaderValue(header_data, real_ip_header)) |ip_value| {
                    // Handle X-Forwarded-For: ip1, ip2 → take first
                    const ip = if (std.mem.indexOfScalar(u8, ip_value, ',')) |comma|
                        std.mem.trim(u8, ip_value[0..comma], " ")
                    else
                        std.mem.trim(u8, ip_value, " ");

                    const len: u8 = @intCast(@min(ip.len, real_ip_out.len));
                    @memcpy(real_ip_out[0..len], ip[0..len]);
                    real_ip_len.* = len;
                }
            }

            // Compute accept token
            var accept_buf: [64]u8 = undefined;
            const accept = computeAcceptToken(ws_key, &accept_buf);

            // Send 101 response
            var resp_buf: [256]u8 = undefined;
            const resp = std.fmt.bufPrint(&resp_buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{accept}) catch
                return error.BufferOverflow;

            writeAll(Inner, inner, resp) catch return error.InnerStreamError;

            // Return pending data (post-header bytes)
            var pending_buf: [4096]u8 = undefined;
            const pending_len = filled - body_start;
            if (pending_len > 0) {
                @memcpy(pending_buf[0..pending_len], buf[body_start..filled]);
            }
            return .{
                .pending = pending_buf[0..pending_len],
                .pending_buf = pending_buf,
                .pending_len = pending_len,
            };
        }
    }
    return error.BufferOverflow;
}

/// Perform client-side WebSocket handshake (send HTTP upgrade, read 101).
pub fn clientHandshake(
    comptime Inner: type,
    inner: *Inner,
    host: []const u8,
    path: []const u8,
) HandshakeError!struct { pending_buf: [4096]u8, pending_len: usize } {
    // Generate random 16-byte key
    var raw_key: [16]u8 = undefined;
    _ = c.RAND_bytes(&raw_key, 16);
    var key_b64: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&key_b64, &raw_key);

    // Send HTTP upgrade request
    var req_buf: [512]u8 = undefined;
    const req = std.fmt.bufPrint(&req_buf, "GET {s} HTTP/1.1\r\nHost: {s}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: 13\r\n\r\n", .{
        if (path.len > 0) path else "/",
        host,
        key_b64,
    }) catch return error.BufferOverflow;

    writeAll(Inner, inner, req) catch return error.InnerStreamError;

    // Read 101 response
    var buf: [4096]u8 = undefined;
    var filled: usize = 0;

    while (filled < buf.len) {
        const n = inner.read(buf[filled..]) catch return error.InnerStreamError;
        if (n == 0) return error.InvalidUpgradeResponse;
        filled += n;

        if (findHeaderEnd(buf[0..filled])) |header_end| {
            const header_data = buf[0..header_end];

            // Validate 101 response
            if (!std.mem.startsWith(u8, header_data, "HTTP/1.1 101"))
                return error.InvalidUpgradeResponse;

            // Verify Sec-WebSocket-Accept
            const accept_received = findHeaderValue(header_data, "Sec-WebSocket-Accept") orelse
                return error.InvalidUpgradeResponse;

            var expected_buf: [64]u8 = undefined;
            const expected = computeAcceptToken(&key_b64, &expected_buf);

            if (!std.mem.eql(u8, std.mem.trim(u8, accept_received, " "), expected))
                return error.InvalidUpgradeResponse;

            var pending_buf: [4096]u8 = undefined;
            const pending_len = filled - header_end;
            if (pending_len > 0) {
                @memcpy(pending_buf[0..pending_len], buf[header_end..filled]);
            }
            return .{
                .pending_buf = pending_buf,
                .pending_len = pending_len,
            };
        }
    }
    return error.BufferOverflow;
}

// ── Internal helpers ──────────────────────────────────────────────────────

fn validateServerRequest(header: []const u8, expected_path: []const u8) ?[]const u8 {
    // Check first line: GET /path HTTP/1.1
    const first_line_end = std.mem.indexOf(u8, header, "\r\n") orelse return null;
    const first_line = header[0..first_line_end];

    if (!std.mem.startsWith(u8, first_line, "GET ")) return null;

    // Validate path if configured
    if (expected_path.len > 0) {
        const path_start: usize = 4; // "GET "
        const path_end = std.mem.indexOfScalar(u8, first_line[path_start..], ' ') orelse return null;
        const req_path = first_line[path_start .. path_start + path_end];
        if (!std.mem.eql(u8, req_path, expected_path)) return null;
    }

    // Check Upgrade: websocket
    if (!hasHeaderValueCI(header, "Upgrade", "websocket")) return null;

    // Extract Sec-WebSocket-Key
    return findHeaderValue(header, "Sec-WebSocket-Key");
}

fn computeAcceptToken(key: []const u8, out: []u8) []const u8 {
    var sha1_ctx: c.SHA_CTX = undefined;
    _ = c.SHA1_Init(&sha1_ctx);
    _ = c.SHA1_Update(&sha1_ctx, key.ptr, key.len);
    _ = c.SHA1_Update(&sha1_ctx, ws_guid.ptr, ws_guid.len);
    var digest: [20]u8 = undefined;
    _ = c.SHA1_Final(&digest, &sha1_ctx);

    const encoded = std.base64.standard.Encoder.encode(out[0..28], &digest);
    _ = encoded;
    return out[0..28];
}

fn findHeaderEnd(data: []const u8) ?usize {
    if (std.mem.indexOf(u8, data, "\r\n\r\n")) |pos| {
        return pos + 4;
    }
    return null;
}

fn findHeaderValue(header: []const u8, name: []const u8) ?[]const u8 {
    var iter = std.mem.splitSequence(u8, header, "\r\n");
    while (iter.next()) |line| {
        if (line.len <= name.len + 1) continue;
        const colon_pos = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const field_name = line[0..colon_pos];
        if (std.ascii.eqlIgnoreCase(field_name, name)) {
            return std.mem.trim(u8, line[colon_pos + 1 ..], " ");
        }
    }
    return null;
}

fn hasHeaderValueCI(header: []const u8, name: []const u8, expected_value: []const u8) bool {
    const val = findHeaderValue(header, name) orelse return false;
    return std.ascii.eqlIgnoreCase(std.mem.trim(u8, val, " "), expected_value);
}

fn writeAll(comptime Inner: type, inner: *Inner, data: []const u8) !void {
    var sent: usize = 0;
    while (sent < data.len) {
        const n = try inner.write(data[sent..]);
        if (n == 0) return error.InnerStreamError;
        sent += n;
    }
}
