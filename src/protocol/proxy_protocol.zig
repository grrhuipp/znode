const std = @import("std");
const mem = std.mem;

/// PROXY Protocol v1/v2 parser.
///
/// Stateless, allocation-free. Detects PP headers at the start of a TCP connection
/// (before TLS handshake) and extracts the real client IP/port sent by load balancers.

pub const ParseResult = struct {
    success: bool = false,
    src_ip4: ?[4]u8 = null,
    src_ip6: ?[16]u8 = null,
    src_port: u16 = 0,
    consumed: usize = 0,
};

/// PP v2 binary signature (12 bytes): \r\n\r\n\0\r\nQUIT\n
const signature_v2 = [12]u8{ 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };

/// Auto-detect and parse PP v1 or v2 header.
/// Returns success=false if the data does not start with a PP header.
pub fn parse(data: []const u8) ParseResult {
    if (data.len >= 12 and mem.eql(u8, data[0..12], &signature_v2))
        return parseV2(data);
    if (data.len >= 6 and mem.eql(u8, data[0..6], "PROXY "))
        return parseV1(data);
    return .{};
}

/// Parse PP v2 binary format.
///
/// Layout:
///   bytes 0-11:  signature (12 bytes)
///   byte 12:     version (high nibble) | command (low nibble)
///   byte 13:     address family (high nibble) | transport (low nibble)
///   bytes 14-15: address data length (big-endian)
///   bytes 16+:   address data
fn parseV2(data: []const u8) ParseResult {
    if (data.len < 16) return .{};

    const ver_cmd = data[12];
    const version = (ver_cmd >> 4) & 0x0F;
    const command = ver_cmd & 0x0F;

    if (version != 2) return .{};

    // LOCAL command: no address data, just consume the fixed header
    if (command == 0) {
        const addr_len = @as(u16, data[14]) << 8 | @as(u16, data[15]);
        const total: usize = 16 + @as(usize, addr_len);
        if (data.len < total) return .{};
        return .{ .success = true, .consumed = total };
    }

    // Only PROXY command (1) carries addresses
    if (command != 1) return .{};

    const fam = (data[13] >> 4) & 0x0F;
    const addr_len = @as(u16, data[14]) << 8 | @as(u16, data[15]);
    const total: usize = 16 + @as(usize, addr_len);

    if (data.len < total) return .{};

    const addr_data = data[16..];

    // AF_INET (IPv4): src_ip[4] + dst_ip[4] + src_port[2] + dst_port[2] = 12
    if (fam == 1) {
        if (addr_len < 12) return .{};
        return .{
            .success = true,
            .src_ip4 = addr_data[0..4].*,
            .src_port = @as(u16, addr_data[8]) << 8 | @as(u16, addr_data[9]),
            .consumed = total,
        };
    }

    // AF_INET6 (IPv6): src_ip[16] + dst_ip[16] + src_port[2] + dst_port[2] = 36
    if (fam == 2) {
        if (addr_len < 36) return .{};
        return .{
            .success = true,
            .src_ip6 = addr_data[0..16].*,
            .src_port = @as(u16, addr_data[32]) << 8 | @as(u16, addr_data[33]),
            .consumed = total,
        };
    }

    // Unknown family — still consume the header
    return .{ .success = true, .consumed = total };
}

/// Parse PP v1 text format: "PROXY TCP4 src_ip dst_ip src_port dst_port\r\n"
fn parseV1(data: []const u8) ParseResult {
    // Find \r\n terminator
    var line_end: ?usize = null;
    for (0..data.len -| 1) |i| {
        if (data[i] == '\r' and data[i + 1] == '\n') {
            line_end = i;
            break;
        }
    }
    const end = line_end orelse return .{}; // no \r\n found
    const consumed = end + 2;

    const line = data[0..end];

    // Skip "PROXY " prefix (6 bytes)
    if (line.len < 6) return .{};
    var rest = line[6..];

    // Parse protocol field
    const proto_end = mem.indexOfScalar(u8, rest, ' ') orelse return .{};
    const proto = rest[0..proto_end];
    rest = rest[proto_end + 1 ..];

    // UNKNOWN: success but no address
    if (mem.eql(u8, proto, "UNKNOWN")) {
        return .{ .success = true, .consumed = consumed };
    }

    if (!mem.eql(u8, proto, "TCP4") and !mem.eql(u8, proto, "TCP6")) return .{};
    const is_v6 = mem.eql(u8, proto, "TCP6");

    // Parse: src_ip dst_ip src_port dst_port
    const src_ip_end = mem.indexOfScalar(u8, rest, ' ') orelse return .{};
    const src_ip_str = rest[0..src_ip_end];
    rest = rest[src_ip_end + 1 ..];

    const dst_ip_end = mem.indexOfScalar(u8, rest, ' ') orelse return .{};
    // skip dst_ip
    rest = rest[dst_ip_end + 1 ..];

    const src_port_end = mem.indexOfScalar(u8, rest, ' ') orelse return .{};
    const src_port_str = rest[0..src_port_end];
    // skip dst_port

    const src_port = std.fmt.parseUnsigned(u16, src_port_str, 10) catch return .{};

    if (is_v6) {
        // Parse IPv6 text address
        const addr6 = parseIp6(src_ip_str) orelse return .{};
        return .{
            .success = true,
            .src_ip6 = addr6,
            .src_port = src_port,
            .consumed = consumed,
        };
    } else {
        // Parse IPv4 text address
        const addr4 = parseIp4(src_ip_str) orelse return .{};
        return .{
            .success = true,
            .src_ip4 = addr4,
            .src_port = src_port,
            .consumed = consumed,
        };
    }
}

/// Convert ParseResult to std.net.Address.
pub fn toNetAddress(result: ParseResult) ?std.net.Address {
    if (result.src_ip4) |ip4| {
        return std.net.Address.initIp4(ip4, result.src_port);
    }
    if (result.src_ip6) |ip6| {
        return std.net.Address.initIp6(ip6, result.src_port, 0, 0);
    }
    return null;
}

/// Format IP from ParseResult for logging.
pub fn fmtIp(result: ParseResult, buf: *[64]u8) []const u8 {
    if (result.src_ip4) |ip4| {
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch "?";
    }
    if (result.src_ip6) |ip6| {
        // Simplified: just format as hex pairs with colons
        var pos: usize = 0;
        for (0..8) |i| {
            if (i > 0) {
                buf[pos] = ':';
                pos += 1;
            }
            const hi = ip6[i * 2];
            const lo = ip6[i * 2 + 1];
            const hex = std.fmt.bufPrint(buf[pos..], "{x:0>2}{x:0>2}", .{ hi, lo }) catch break;
            pos += hex.len;
        }
        return buf[0..pos];
    }
    return "unknown";
}

/// Parse dotted-decimal IPv4 string into 4-byte array.
fn parseIp4(s: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var octet_idx: u8 = 0;
    var start: usize = 0;
    for (s, 0..) |c, i| {
        if (c == '.') {
            if (octet_idx >= 3) return null;
            result[octet_idx] = std.fmt.parseUnsigned(u8, s[start..i], 10) catch return null;
            octet_idx += 1;
            start = i + 1;
        }
    }
    if (octet_idx != 3) return null;
    result[3] = std.fmt.parseUnsigned(u8, s[start..], 10) catch return null;
    return result;
}

/// Parse IPv6 text address (colon-hex) into 16-byte array.
/// Supports :: abbreviation.
fn parseIp6(s: []const u8) ?[16]u8 {
    // Use std.net for robust parsing
    const addr = std.net.Address.parseIp6(s, 0) catch return null;
    return addr.in6.sa.addr;
}

// ══════════════════════════════════════════════════════════════
//  Tests
// ══════════════════════════════════════════════════════════════

test "v2 IPv4 known data" {
    // PP v2 PROXY command, AF_INET, src=192.168.1.100:56324, dst=10.0.0.1:443
    var buf: [28]u8 = undefined;
    @memcpy(buf[0..12], &signature_v2); // signature
    buf[12] = 0x21; // version=2, command=PROXY(1)
    buf[13] = 0x11; // family=AF_INET(1), transport=TCP(1)
    buf[14] = 0x00;
    buf[15] = 0x0C; // addr_len = 12
    // src IP: 192.168.1.100
    buf[16] = 192;
    buf[17] = 168;
    buf[18] = 1;
    buf[19] = 100;
    // dst IP: 10.0.0.1
    buf[20] = 10;
    buf[21] = 0;
    buf[22] = 0;
    buf[23] = 1;
    // src port: 56324 = 0xDC04
    buf[24] = 0xDC;
    buf[25] = 0x04;
    // dst port: 443 = 0x01BB
    buf[26] = 0x01;
    buf[27] = 0xBB;

    const result = parse(&buf);
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, 28), result.consumed);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 100 }, result.src_ip4.?);
    try std.testing.expectEqual(@as(u16, 56324), result.src_port);
    try std.testing.expect(result.src_ip6 == null);
}

test "v2 IPv6 known data" {
    var buf: [52]u8 = undefined;
    @memcpy(buf[0..12], &signature_v2);
    buf[12] = 0x21; // version=2, command=PROXY
    buf[13] = 0x21; // family=AF_INET6(2), transport=TCP
    buf[14] = 0x00;
    buf[15] = 0x24; // addr_len = 36
    // src IP: 2001:db8::1 = 2001:0db8:0000:0000:0000:0000:0000:0001
    const src_ip6 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    @memcpy(buf[16..32], &src_ip6);
    // dst IP: ::1
    @memset(buf[32..46], 0);
    buf[46] = 0;
    buf[47] = 1;
    // src port: 12345 = 0x3039
    buf[48] = 0x30;
    buf[49] = 0x39;
    // dst port: 443
    buf[50] = 0x01;
    buf[51] = 0xBB;

    const result = parse(&buf);
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, 52), result.consumed);
    try std.testing.expectEqual(src_ip6, result.src_ip6.?);
    try std.testing.expectEqual(@as(u16, 12345), result.src_port);
    try std.testing.expect(result.src_ip4 == null);
}

test "v2 LOCAL command" {
    var buf: [16]u8 = undefined;
    @memcpy(buf[0..12], &signature_v2);
    buf[12] = 0x20; // version=2, command=LOCAL(0)
    buf[13] = 0x00;
    buf[14] = 0x00;
    buf[15] = 0x00; // addr_len = 0

    const result = parse(&buf);
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, 16), result.consumed);
    try std.testing.expect(result.src_ip4 == null);
    try std.testing.expect(result.src_ip6 == null);
}

test "v2 LOCAL command with extra TLVs" {
    // LOCAL with addr_len > 0 (TLV extensions)
    var buf: [20]u8 = undefined;
    @memcpy(buf[0..12], &signature_v2);
    buf[12] = 0x20; // LOCAL
    buf[13] = 0x00;
    buf[14] = 0x00;
    buf[15] = 0x04; // addr_len = 4 (some TLV data)
    buf[16] = 0xAA;
    buf[17] = 0xBB;
    buf[18] = 0xCC;
    buf[19] = 0xDD;

    const result = parse(&buf);
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, 20), result.consumed);
}

test "v2 insufficient data" {
    // Only 14 bytes (need 16 minimum)
    var buf: [14]u8 = undefined;
    @memcpy(buf[0..12], &signature_v2);
    buf[12] = 0x21;
    buf[13] = 0x11;

    const result = parse(&buf);
    try std.testing.expect(!result.success);
}

test "v2 insufficient address data" {
    // Header says addr_len=12 but only 8 bytes of address data provided
    var buf: [24]u8 = undefined;
    @memcpy(buf[0..12], &signature_v2);
    buf[12] = 0x21;
    buf[13] = 0x11;
    buf[14] = 0x00;
    buf[15] = 0x0C; // claims 12 bytes
    @memset(buf[16..24], 0);

    const result = parse(buf[0..24]);
    // 24 = 16 + 8, but addr_len says 12, so total needed = 28
    // Actually 24 >= 16 + 12? No: 16 + 12 = 28 > 24
    try std.testing.expect(!result.success);
}

test "v2 wrong version" {
    var buf: [28]u8 = undefined;
    @memcpy(buf[0..12], &signature_v2);
    buf[12] = 0x31; // version=3 (invalid)
    buf[13] = 0x11;
    buf[14] = 0x00;
    buf[15] = 0x0C;
    @memset(buf[16..28], 0);

    const result = parse(&buf);
    try std.testing.expect(!result.success);
}

test "v1 TCP4" {
    const line = "PROXY TCP4 192.168.1.1 10.0.0.1 56324 443\r\n";
    const result = parse(line);
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, line.len), result.consumed);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 1 }, result.src_ip4.?);
    try std.testing.expectEqual(@as(u16, 56324), result.src_port);
}

test "v1 TCP6" {
    const line = "PROXY TCP6 2001:db8::1 ::1 12345 443\r\n";
    const result = parse(line);
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, line.len), result.consumed);
    try std.testing.expectEqual(@as(u16, 12345), result.src_port);
    try std.testing.expect(result.src_ip6 != null);
    // First two bytes: 0x20, 0x01
    try std.testing.expectEqual(@as(u8, 0x20), result.src_ip6.?[0]);
    try std.testing.expectEqual(@as(u8, 0x01), result.src_ip6.?[1]);
}

test "v1 UNKNOWN" {
    const line = "PROXY UNKNOWN\r\n";
    const result = parse(line);
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, line.len), result.consumed);
    try std.testing.expect(result.src_ip4 == null);
    try std.testing.expect(result.src_ip6 == null);
}

test "v1 no CRLF" {
    const line = "PROXY TCP4 192.168.1.1 10.0.0.1 56324 443";
    const result = parse(line);
    try std.testing.expect(!result.success);
}

test "non-PP data: TLS ClientHello" {
    const data = [_]u8{ 0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xFC, 0x03, 0x03 };
    const result = parse(&data);
    try std.testing.expect(!result.success);
}

test "non-PP data: VMess AuthID" {
    const data = [_]u8{ 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const result = parse(&data);
    try std.testing.expect(!result.success);
}

test "v2 with trailing data" {
    // PP v2 header followed by TLS ClientHello
    var buf: [40]u8 = undefined;
    @memcpy(buf[0..12], &signature_v2);
    buf[12] = 0x21; // v2 PROXY
    buf[13] = 0x11; // AF_INET TCP
    buf[14] = 0x00;
    buf[15] = 0x0C; // addr_len = 12
    // src: 1.2.3.4:80
    buf[16] = 1;
    buf[17] = 2;
    buf[18] = 3;
    buf[19] = 4;
    // dst: 5.6.7.8
    buf[20] = 5;
    buf[21] = 6;
    buf[22] = 7;
    buf[23] = 8;
    // src port: 80
    buf[24] = 0x00;
    buf[25] = 0x50;
    // dst port: 443
    buf[26] = 0x01;
    buf[27] = 0xBB;
    // Trailing data (TLS ClientHello start)
    buf[28] = 0x16;
    buf[29] = 0x03;
    buf[30] = 0x01;
    @memset(buf[31..40], 0xFF);

    const result = parse(&buf);
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, 28), result.consumed);
    try std.testing.expectEqual([4]u8{ 1, 2, 3, 4 }, result.src_ip4.?);
    try std.testing.expectEqual(@as(u16, 80), result.src_port);
    // Verify trailing data is untouched
    try std.testing.expectEqual(@as(u8, 0x16), buf[28]);
}

test "v1 with trailing data" {
    const data = "PROXY TCP4 10.0.0.1 172.16.0.1 1234 8080\r\nGET / HTTP/1.1\r\n";
    const result = parse(data);
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, 44), result.consumed); // "PROXY TCP4 10.0.0.1 172.16.0.1 1234 8080\r\n" = 44
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 1 }, result.src_ip4.?);
    try std.testing.expectEqual(@as(u16, 1234), result.src_port);
}

test "toNetAddress IPv4" {
    const result = ParseResult{
        .success = true,
        .src_ip4 = [4]u8{ 192, 168, 1, 1 },
        .src_port = 8080,
    };
    const addr = toNetAddress(result).?;
    try std.testing.expectEqual(@as(u16, 8080), addr.getPort());
}

test "toNetAddress IPv6" {
    const result = ParseResult{
        .success = true,
        .src_ip6 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .src_port = 443,
    };
    const addr = toNetAddress(result).?;
    try std.testing.expectEqual(@as(u16, 443), addr.getPort());
}

test "toNetAddress no IP" {
    const result = ParseResult{ .success = true };
    try std.testing.expect(toNetAddress(result) == null);
}

test "fmtIp IPv4" {
    const result = ParseResult{
        .success = true,
        .src_ip4 = [4]u8{ 10, 20, 30, 40 },
    };
    var buf: [64]u8 = undefined;
    const s = fmtIp(result, &buf);
    try std.testing.expectEqualStrings("10.20.30.40", s);
}

test "empty data" {
    const result = parse("");
    try std.testing.expect(!result.success);
}

test "v2 unknown address family still consumed" {
    var buf: [20]u8 = undefined;
    @memcpy(buf[0..12], &signature_v2);
    buf[12] = 0x21; // v2 PROXY
    buf[13] = 0x31; // family=3 (unknown)
    buf[14] = 0x00;
    buf[15] = 0x04; // addr_len = 4
    buf[16] = 0x01;
    buf[17] = 0x02;
    buf[18] = 0x03;
    buf[19] = 0x04;

    const result = parse(&buf);
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, 20), result.consumed);
    try std.testing.expect(result.src_ip4 == null);
    try std.testing.expect(result.src_ip6 == null);
}
