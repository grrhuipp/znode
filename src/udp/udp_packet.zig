const std = @import("std");
const Session = @import("../core/session.zig");
const TargetAddress = Session.TargetAddress;

/// Parsed UDP packet header with payload location.
pub const UdpPacketHeader = struct {
    target: TargetAddress,
    payload_offset: usize,
    payload_len: usize,
};

/// Result of parsing an address (ATYP + ADDR + PORT).
pub const AddressParseResult = struct {
    target: TargetAddress,
    consumed: usize,
};

// ── Common address parsing (ATYP + ADDR + PORT) ──

/// Parse ATYP(1B) + Address(var) + Port(2B) from data.
/// Returns target address and number of bytes consumed, or null if incomplete.
pub fn parseAddress(data: []const u8) ?AddressParseResult {
    if (data.len < 1) return null;

    const atyp = data[0];
    var pos: usize = 1;

    var target = TargetAddress{};

    switch (atyp) {
        0x01 => { // IPv4
            if (data.len < pos + 4 + 2) return null;
            const ip4 = data[pos..][0..4].*;
            pos += 4;
            const port = @as(u16, data[pos]) << 8 | @as(u16, data[pos + 1]);
            pos += 2;
            target.setIpv4(ip4, port);
        },
        0x03 => { // Domain
            if (data.len < pos + 1) return null;
            const domain_len = data[pos];
            pos += 1;
            if (domain_len == 0 or domain_len > 253) return null;
            if (data.len < pos + domain_len + 2) return null;
            const domain = data[pos .. pos + domain_len];
            pos += domain_len;
            const port = @as(u16, data[pos]) << 8 | @as(u16, data[pos + 1]);
            pos += 2;
            target.setDomain(domain, port);
        },
        0x04 => { // IPv6
            if (data.len < pos + 16 + 2) return null;
            const ip6 = data[pos..][0..16].*;
            pos += 16;
            const port = @as(u16, data[pos]) << 8 | @as(u16, data[pos + 1]);
            pos += 2;
            target.setIpv6(ip6, port);
        },
        else => return null,
    }

    return .{ .target = target, .consumed = pos };
}

/// Encode ATYP(1B) + Address(var) + Port(2B) into buffer.
/// Returns bytes written, or null if buffer too small or address invalid.
pub fn encodeAddress(buf: []u8, target: *const TargetAddress) ?usize {
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
            if (domain.len == 0) return null;
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

// ── Trojan UDP packet format ──
//
// ATYP(1B) + DST.ADDR(var) + DST.PORT(2B) + Length(2B) + CRLF(2B) + Payload(N)

/// Result of parsing a Trojan UDP packet — distinguishes incomplete from protocol error.
pub const TrojanUdpParseResult = union(enum) {
    success: UdpPacketHeader,
    incomplete,
    protocol_error,
};

/// Parse a Trojan-style UDP packet from data.
/// Returns .incomplete if more bytes needed, .protocol_error if data is malformed.
pub fn parseTrojanUdpPacket(data: []const u8) TrojanUdpParseResult {
    if (data.len < 1) return .incomplete;

    // Validate ATYP before calling parseAddress
    const atyp = data[0];
    if (atyp != 0x01 and atyp != 0x03 and atyp != 0x04) return .protocol_error;

    const addr_result = parseAddress(data) orelse {
        // parseAddress returned null — distinguish incomplete vs invalid
        if (atyp == 0x03 and data.len >= 2) {
            const domain_len = data[1];
            if (domain_len == 0 or domain_len > 253) return .protocol_error;
        }
        return .incomplete;
    };
    var pos = addr_result.consumed;

    // Length (2B big-endian)
    if (data.len < pos + 2) return .incomplete;
    const payload_len = @as(usize, data[pos]) << 8 | @as(usize, data[pos + 1]);
    pos += 2;

    // CRLF
    if (data.len < pos + 2) return .incomplete;
    if (data[pos] != '\r' or data[pos + 1] != '\n') return .protocol_error;
    pos += 2;

    // Payload
    if (data.len < pos + payload_len) return .incomplete;

    return .{ .success = .{
        .target = addr_result.target,
        .payload_offset = pos,
        .payload_len = payload_len,
    } };
}

/// Encode a Trojan-style UDP packet into buffer.
/// Returns total bytes written, or null if buffer too small.
pub fn encodeTrojanUdpPacket(buf: []u8, target: *const TargetAddress, payload: []const u8) ?usize {
    var pos = encodeAddress(buf, target) orelse return null;

    // Length (2B)
    if (buf.len < pos + 2 + 2 + payload.len) return null;
    buf[pos] = @intCast(payload.len >> 8);
    buf[pos + 1] = @intCast(payload.len & 0xFF);
    pos += 2;

    // CRLF
    buf[pos] = '\r';
    buf[pos + 1] = '\n';
    pos += 2;

    // Payload
    @memcpy(buf[pos .. pos + payload.len], payload);
    pos += payload.len;

    return pos;
}

// ── VMess UDP packet format ──
//
// ATYP(1B) + DST.ADDR(var) + DST.PORT(2B) + Length(2B) + Payload(N)
// (No CRLF separator)

/// Parse a VMess-style UDP packet from data.
/// Returns null if data is incomplete.
pub fn parseVMessUdpPacket(data: []const u8) ?UdpPacketHeader {
    const addr_result = parseAddress(data) orelse return null;
    var pos = addr_result.consumed;

    // Length (2B big-endian)
    if (data.len < pos + 2) return null;
    const payload_len = @as(usize, data[pos]) << 8 | @as(usize, data[pos + 1]);
    pos += 2;

    // Payload
    if (data.len < pos + payload_len) return null;

    return .{
        .target = addr_result.target,
        .payload_offset = pos,
        .payload_len = payload_len,
    };
}

/// Encode a VMess-style UDP packet into buffer.
/// Returns total bytes written, or null if buffer too small.
pub fn encodeVMessUdpPacket(buf: []u8, target: *const TargetAddress, payload: []const u8) ?usize {
    var pos = encodeAddress(buf, target) orelse return null;

    // Length (2B)
    if (buf.len < pos + 2 + payload.len) return null;
    buf[pos] = @intCast(payload.len >> 8);
    buf[pos + 1] = @intCast(payload.len & 0xFF);
    pos += 2;

    // Payload
    @memcpy(buf[pos .. pos + payload.len], payload);
    pos += payload.len;

    return pos;
}

// ── Tests ──

const testing = std.testing;

test "parseAddress IPv4" {
    const data = [_]u8{ 0x01, 8, 8, 8, 8, 0x00, 0x35 }; // 8.8.8.8:53
    const result = parseAddress(&data).?;
    try testing.expectEqual(TargetAddress.AddressType.ipv4, result.target.addr_type);
    try testing.expectEqual([_]u8{ 8, 8, 8, 8 }, result.target.ip4);
    try testing.expectEqual(@as(u16, 53), result.target.port);
    try testing.expectEqual(@as(usize, 7), result.consumed);
}

test "parseAddress domain" {
    var data: [32]u8 = undefined;
    data[0] = 0x03; // Domain
    data[1] = 11; // "example.com"
    @memcpy(data[2..13], "example.com");
    data[13] = 0x01; // Port 443
    data[14] = 0xBB;
    const result = parseAddress(data[0..15]).?;
    try testing.expectEqual(TargetAddress.AddressType.domain, result.target.addr_type);
    try testing.expectEqualStrings("example.com", result.target.getDomain());
    try testing.expectEqual(@as(u16, 443), result.target.port);
    try testing.expectEqual(@as(usize, 15), result.consumed);
}

test "parseAddress IPv6" {
    var data: [19]u8 = undefined;
    data[0] = 0x04;
    @memset(data[1..16], 0);
    data[16] = 1; // ::1
    data[17] = 0x1F; // Port 8080
    data[18] = 0x90;
    const result = parseAddress(&data).?;
    try testing.expectEqual(TargetAddress.AddressType.ipv6, result.target.addr_type);
    try testing.expectEqual(@as(u16, 8080), result.target.port);
}

test "parseAddress incomplete" {
    try testing.expect(parseAddress(&[_]u8{}) == null);
    try testing.expect(parseAddress(&[_]u8{0x01}) == null); // IPv4 need 7 bytes
    try testing.expect(parseAddress(&[_]u8{ 0x01, 1, 2, 3, 4 }) == null); // missing port
}

test "encodeAddress roundtrip IPv4" {
    var target = TargetAddress{};
    target.setIpv4(.{ 10, 0, 0, 1 }, 8080);
    var buf: [64]u8 = undefined;
    const n = encodeAddress(&buf, &target).?;
    const parsed = parseAddress(buf[0..n]).?;
    try testing.expectEqual(target.addr_type, parsed.target.addr_type);
    try testing.expectEqual(target.ip4, parsed.target.ip4);
    try testing.expectEqual(target.port, parsed.target.port);
}

test "encodeAddress roundtrip domain" {
    var target = TargetAddress{};
    target.setDomain("google.com", 443);
    var buf: [64]u8 = undefined;
    const n = encodeAddress(&buf, &target).?;
    const parsed = parseAddress(buf[0..n]).?;
    try testing.expectEqualStrings("google.com", parsed.target.getDomain());
    try testing.expectEqual(@as(u16, 443), parsed.target.port);
}

test "Trojan UDP packet roundtrip IPv4" {
    var target = TargetAddress{};
    target.setIpv4(.{ 8, 8, 8, 8 }, 53);
    const payload = "DNS query data here";

    var buf: [256]u8 = undefined;
    const n = encodeTrojanUdpPacket(&buf, &target, payload).?;

    const parsed = parseTrojanUdpPacket(buf[0..n]).success;
    try testing.expectEqual(@as(u16, 53), parsed.target.port);
    try testing.expectEqual([_]u8{ 8, 8, 8, 8 }, parsed.target.ip4);
    try testing.expectEqual(payload.len, parsed.payload_len);
    try testing.expectEqualStrings(payload, buf[parsed.payload_offset .. parsed.payload_offset + parsed.payload_len]);
}

test "Trojan UDP packet roundtrip domain" {
    var target = TargetAddress{};
    target.setDomain("dns.google", 443);
    const payload = "encrypted DNS";

    var buf: [256]u8 = undefined;
    const n = encodeTrojanUdpPacket(&buf, &target, payload).?;
    const parsed = parseTrojanUdpPacket(buf[0..n]).success;
    try testing.expectEqualStrings("dns.google", parsed.target.getDomain());
    try testing.expectEqual(@as(u16, 443), parsed.target.port);
    try testing.expectEqualStrings(payload, buf[parsed.payload_offset .. parsed.payload_offset + parsed.payload_len]);
}

test "Trojan UDP packet incomplete" {
    // Too short for address
    try testing.expect(parseTrojanUdpPacket(&[_]u8{ 0x01, 1, 2 }) == .incomplete);
    // Has address but no length
    try testing.expect(parseTrojanUdpPacket(&[_]u8{ 0x01, 1, 2, 3, 4, 0, 80 }) == .incomplete);
    // Has address + length but no CRLF
    try testing.expect(parseTrojanUdpPacket(&[_]u8{ 0x01, 1, 2, 3, 4, 0, 80, 0, 5 }) == .incomplete);
}

test "Trojan UDP packet protocol error" {
    // Bad ATYP
    try testing.expect(parseTrojanUdpPacket(&[_]u8{ 0xFF, 1, 2, 3, 4, 0, 80, 0, 5 }) == .protocol_error);
    // Bad CRLF (has enough bytes but wrong values)
    try testing.expect(parseTrojanUdpPacket(&[_]u8{ 0x01, 1, 2, 3, 4, 0, 80, 0, 1, 0xAA, 0xBB, 0x00 }) == .protocol_error);
    // Zero-length domain
    try testing.expect(parseTrojanUdpPacket(&[_]u8{ 0x03, 0, 0, 80, 0, 1, '\r', '\n', 0x00 }) == .protocol_error);
}

test "VMess UDP packet roundtrip" {
    var target = TargetAddress{};
    target.setIpv4(.{ 1, 1, 1, 1 }, 53);
    const payload = "VMess UDP data";

    var buf: [256]u8 = undefined;
    const n = encodeVMessUdpPacket(&buf, &target, payload).?;
    const parsed = parseVMessUdpPacket(buf[0..n]).?;
    try testing.expectEqual([_]u8{ 1, 1, 1, 1 }, parsed.target.ip4);
    try testing.expectEqual(@as(u16, 53), parsed.target.port);
    try testing.expectEqualStrings(payload, buf[parsed.payload_offset .. parsed.payload_offset + parsed.payload_len]);
}

test "VMess UDP packet empty payload" {
    var target = TargetAddress{};
    target.setIpv4(.{ 127, 0, 0, 1 }, 1234);

    var buf: [64]u8 = undefined;
    const n = encodeVMessUdpPacket(&buf, &target, &[_]u8{}).?;
    const parsed = parseVMessUdpPacket(buf[0..n]).?;
    try testing.expectEqual(@as(usize, 0), parsed.payload_len);
}

test "Trojan vs VMess format difference" {
    var target = TargetAddress{};
    target.setIpv4(.{ 10, 0, 0, 1 }, 80);
    const payload = "test";

    var trojan_buf: [64]u8 = undefined;
    var vmess_buf: [64]u8 = undefined;
    const trojan_len = encodeTrojanUdpPacket(&trojan_buf, &target, payload).?;
    const vmess_len = encodeVMessUdpPacket(&vmess_buf, &target, payload).?;

    // Trojan is 2 bytes longer (CRLF)
    try testing.expectEqual(vmess_len + 2, trojan_len);
}
