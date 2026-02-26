const std = @import("std");
const ss_crypto = @import("ss_crypto.zig");
const session_mod = @import("../../core/session.zig");

/// Shadowsocks AEAD first-packet format (after salt):
///
/// First encrypted frame payload:
///   [ATYP(1)][Address(variable)][Port(2)][payload...]
///
/// ATYP: 0x01=IPv4, 0x03=Domain, 0x04=IPv6
/// Address: 4 bytes (IPv4), 1+N bytes (Domain), 16 bytes (IPv6)
/// Port: 2 bytes big-endian

/// Parse the SOCKS5-style address from the first decrypted payload.
/// Returns the target address and number of bytes consumed for the address header.
pub fn parseAddress(data: []const u8) ParseResult {
    if (data.len < 1) return .incomplete;
    const atyp = data[0];
    var pos: usize = 1;

    var target = session_mod.TargetAddress{};

    switch (atyp) {
        0x01 => { // IPv4
            if (data.len < pos + 4 + 2) return .incomplete;
            const ip4 = data[pos..][0..4].*;
            pos += 4;
            const port = @as(u16, data[pos]) << 8 | @as(u16, data[pos + 1]);
            pos += 2;
            target.setIpv4(ip4, port);
        },
        0x03 => { // Domain
            if (data.len < pos + 1) return .incomplete;
            const domain_len = data[pos];
            pos += 1;
            if (domain_len == 0 or domain_len > 253) return .protocol_error;
            if (data.len < pos + domain_len + 2) return .incomplete;
            const domain = data[pos .. pos + domain_len];
            pos += domain_len;
            const port = @as(u16, data[pos]) << 8 | @as(u16, data[pos + 1]);
            pos += 2;
            target.setDomain(domain, port);
        },
        0x04 => { // IPv6
            if (data.len < pos + 16 + 2) return .incomplete;
            const ip6 = data[pos..][0..16].*;
            pos += 16;
            const port = @as(u16, data[pos]) << 8 | @as(u16, data[pos + 1]);
            pos += 2;
            target.setIpv6(ip6, port);
        },
        else => return .protocol_error,
    }

    return .{ .success = .{
        .target = target,
        .header_len = pos,
    } };
}

/// Encode a target address in SOCKS5 format (for outbound first payload).
/// Returns bytes written.
pub fn encodeAddress(target: *const session_mod.TargetAddress, buf: []u8) ?usize {
    var pos: usize = 0;

    switch (target.addr_type) {
        .ipv4 => {
            if (buf.len < 1 + 4 + 2) return null;
            buf[pos] = 0x01;
            pos += 1;
            @memcpy(buf[pos .. pos + 4], &target.ip4);
            pos += 4;
        },
        .domain => {
            const domain = target.getDomain();
            if (buf.len < 1 + 1 + domain.len + 2) return null;
            buf[pos] = 0x03;
            pos += 1;
            buf[pos] = @intCast(domain.len);
            pos += 1;
            @memcpy(buf[pos .. pos + domain.len], domain);
            pos += domain.len;
        },
        .ipv6 => {
            if (buf.len < 1 + 16 + 2) return null;
            buf[pos] = 0x04;
            pos += 1;
            @memcpy(buf[pos .. pos + 16], &target.ip6);
            pos += 16;
        },
        .none => return null,
    }

    // Port (big-endian)
    buf[pos] = @intCast(target.port >> 8);
    buf[pos + 1] = @intCast(target.port & 0xFF);
    pos += 2;

    return pos;
}

/// Parse the first Shadowsocks packet (inbound).
/// Input: raw ciphertext including [salt][encrypted frames...]
/// Returns parsed target and any remaining payload data.
pub fn parseFirstPacket(
    data: []const u8,
    method: ss_crypto.Method,
    psk: []const u8,
    decrypt_state_out: *ss_crypto.StreamState,
    plaintext_buf: []u8,
) FirstPacketResult {
    const salt_size = method.saltSize();
    if (data.len < salt_size) return .incomplete;

    const salt = data[0..salt_size];
    const ciphertext = data[salt_size..];

    // Initialize decrypt state from salt
    decrypt_state_out.* = ss_crypto.StreamState.init(method, psk, salt);

    // Try to decrypt first frame
    const result = decrypt_state_out.decryptFrame(ciphertext, plaintext_buf);
    switch (result) {
        .success => |s| {
            // Parse address from decrypted payload
            const addr_result = parseAddress(plaintext_buf[0..s.plaintext_len]);
            switch (addr_result) {
                .success => |a| {
                    return .{ .success = .{
                        .target = a.target,
                        .header_len = salt_size + s.bytes_consumed,
                        .payload = if (s.plaintext_len > a.header_len)
                            plaintext_buf[a.header_len..s.plaintext_len]
                        else
                            &.{},
                    } };
                },
                .incomplete => return .incomplete,
                .protocol_error => return .protocol_error,
            }
        },
        .incomplete => return .incomplete,
        .integrity_error => return .protocol_error,
    }
}

pub const ParseResult = union(enum) {
    success: struct {
        target: session_mod.TargetAddress,
        header_len: usize,
    },
    incomplete,
    protocol_error,
};

pub const FirstPacketResult = union(enum) {
    success: struct {
        target: session_mod.TargetAddress,
        header_len: usize, // total bytes consumed from input (salt + encrypted frame)
        payload: []const u8, // remaining plaintext after address header
    },
    incomplete,
    protocol_error,
};

// ── Tests ──

test "parseAddress IPv4" {
    const data = [_]u8{
        0x01, // ATYP IPv4
        127, 0, 0, 1, // IP
        0x01, 0xBB, // port 443
    };
    const result = parseAddress(&data);
    switch (result) {
        .success => |s| {
            try std.testing.expectEqual(session_mod.TargetAddress.AddressType.ipv4, s.target.addr_type);
            try std.testing.expectEqual(@as(u8, 127), s.target.ip4[0]);
            try std.testing.expectEqual(@as(u16, 443), s.target.port);
            try std.testing.expectEqual(@as(usize, 7), s.header_len);
        },
        else => return error.Unexpected,
    }
}

test "parseAddress domain" {
    var data: [32]u8 = undefined;
    data[0] = 0x03; // ATYP domain
    data[1] = 11; // len
    @memcpy(data[2..13], "example.com");
    data[13] = 0x00; // port high
    data[14] = 0x50; // port 80
    const result = parseAddress(data[0..15]);
    switch (result) {
        .success => |s| {
            try std.testing.expectEqual(session_mod.TargetAddress.AddressType.domain, s.target.addr_type);
            try std.testing.expectEqualStrings("example.com", s.target.getDomain());
            try std.testing.expectEqual(@as(u16, 80), s.target.port);
            try std.testing.expectEqual(@as(usize, 15), s.header_len);
        },
        else => return error.Unexpected,
    }
}

test "parseAddress incomplete" {
    const result = parseAddress(&[_]u8{0x01, 127, 0}); // too short for IPv4
    try std.testing.expect(result == .incomplete);
}

test "parseAddress invalid atyp" {
    const result = parseAddress(&[_]u8{0x05}); // invalid
    try std.testing.expect(result == .protocol_error);
}

test "encodeAddress IPv4" {
    var target = session_mod.TargetAddress{};
    target.setIpv4(.{ 192, 168, 1, 1 }, 8080);

    var buf: [64]u8 = undefined;
    const n = encodeAddress(&target, &buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 7), n);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
    try std.testing.expectEqual(@as(u8, 192), buf[1]);
}

test "encodeAddress domain" {
    var target = session_mod.TargetAddress{};
    target.setDomain("test.com", 443);

    var buf: [64]u8 = undefined;
    const n = encodeAddress(&target, &buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 12), n); // 1 + 1 + 8 + 2
    try std.testing.expectEqual(@as(u8, 0x03), buf[0]);
    try std.testing.expectEqual(@as(u8, 8), buf[1]);
}

test "encodeAddress roundtrip" {
    var target = session_mod.TargetAddress{};
    target.setDomain("google.com", 443);

    var buf: [64]u8 = undefined;
    const n = encodeAddress(&target, &buf) orelse return error.EncodeFailed;

    const result = parseAddress(buf[0..n]);
    switch (result) {
        .success => |s| {
            try std.testing.expectEqualStrings("google.com", s.target.getDomain());
            try std.testing.expectEqual(@as(u16, 443), s.target.port);
        },
        else => return error.ParseFailed,
    }
}

test "parseFirstPacket round-trip" {
    const method = ss_crypto.Method.aes_128_gcm;
    const psk = ss_crypto.evpBytesToKey("test-ss-password", method.keySize());
    const salt = [_]u8{0x42} ** 16;

    // Build first packet: [salt][encrypted(address + payload)]
    var addr_buf: [64]u8 = undefined;
    var target = session_mod.TargetAddress{};
    target.setDomain("example.com", 443);
    const addr_len = encodeAddress(&target, &addr_buf) orelse return error.EncodeFailed;

    // Add some payload after address
    const extra_payload = "GET / HTTP/1.1\r\n";
    const total_plain_len = addr_len + extra_payload.len;
    var plain_buf: [256]u8 = undefined;
    @memcpy(plain_buf[0..addr_len], addr_buf[0..addr_len]);
    @memcpy(plain_buf[addr_len .. addr_len + extra_payload.len], extra_payload);

    // Encrypt
    var enc_state = ss_crypto.StreamState.init(method, psk[0..16], &salt);
    var enc_out: [512]u8 = undefined;
    const frame_len = enc_state.encryptFrame(plain_buf[0..total_plain_len], &enc_out) orelse return error.EncryptFailed;

    // Build full packet: salt + encrypted frame
    var packet: [512]u8 = undefined;
    @memcpy(packet[0..16], &salt);
    @memcpy(packet[16 .. 16 + frame_len], enc_out[0..frame_len]);

    // Parse
    var dec_state: ss_crypto.StreamState = undefined;
    var plaintext: [256]u8 = undefined;
    const result = parseFirstPacket(packet[0 .. 16 + frame_len], method, psk[0..16], &dec_state, &plaintext);
    switch (result) {
        .success => |s| {
            try std.testing.expectEqualStrings("example.com", s.target.getDomain());
            try std.testing.expectEqual(@as(u16, 443), s.target.port);
            try std.testing.expectEqualStrings(extra_payload, s.payload);
        },
        else => return error.ParseFailed,
    }
}
