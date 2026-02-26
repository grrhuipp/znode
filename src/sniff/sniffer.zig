const std = @import("std");
const tls_sniffer = @import("tls_sniffer.zig");
const http_sniffer = @import("http_sniffer.zig");

pub const SniffResult = tls_sniffer.SniffResult;

/// Composite sniffer: tries TLS first, then HTTP.
/// Used to detect protocol and extract hostname from the first packet.
///
/// Evaluation order:
///   1. TLS ClientHello -> extract SNI
///   2. HTTP Request -> extract Host header
///   3. Return null if neither matches
pub fn sniff(data: []const u8) ?SniffResult {
    // Try TLS first (most common for proxy traffic)
    if (tls_sniffer.sniffTls(data)) |result| {
        return result;
    }

    // Try HTTP
    if (http_sniffer.sniffHttp(data)) |result| {
        return result;
    }

    return null;
}

/// Quick check if data looks like TLS.
pub fn isTls(data: []const u8) bool {
    return tls_sniffer.isTlsClientHello(data);
}

/// Quick check if data looks like HTTP.
pub fn isHttp(data: []const u8) bool {
    return http_sniffer.isHttpRequest(data);
}

test "sniff TLS ClientHello" {
    // Build a minimal ClientHello with SNI
    var buf: [256]u8 = undefined;
    var pos: usize = 0;

    buf[0] = 0x16; // Handshake
    buf[1] = 0x03;
    buf[2] = 0x03; // TLS 1.2
    pos = 5;

    buf[5] = 0x01; // ClientHello
    pos = 9;

    // Version
    buf[9] = 0x03;
    buf[10] = 0x03;
    pos = 11;

    // Random
    @memset(buf[pos .. pos + 32], 0);
    pos += 32;

    // Session ID len = 0
    buf[pos] = 0;
    pos += 1;

    // Cipher suites: len=2, one suite
    buf[pos] = 0x00;
    buf[pos + 1] = 0x02;
    buf[pos + 2] = 0x00;
    buf[pos + 3] = 0x2F;
    pos += 4;

    // Compression: len=1, null
    buf[pos] = 0x01;
    buf[pos + 1] = 0x00;
    pos += 2;

    // Extensions
    const ext_start = pos;
    pos += 2;

    // SNI extension for "test.io"
    const domain = "test.io";
    buf[pos] = 0x00;
    buf[pos + 1] = 0x00;
    const sni_ext_len: u16 = @intCast(2 + 1 + 2 + domain.len);
    buf[pos + 2] = @intCast(sni_ext_len >> 8);
    buf[pos + 3] = @intCast(sni_ext_len & 0xFF);
    pos += 4;
    const sni_list_len: u16 = @intCast(1 + 2 + domain.len);
    buf[pos] = @intCast(sni_list_len >> 8);
    buf[pos + 1] = @intCast(sni_list_len & 0xFF);
    pos += 2;
    buf[pos] = 0x00;
    pos += 1;
    buf[pos] = 0x00;
    buf[pos + 1] = @intCast(domain.len);
    pos += 2;
    @memcpy(buf[pos .. pos + domain.len], domain);
    pos += domain.len;

    const ext_total: u16 = @intCast(pos - ext_start - 2);
    buf[ext_start] = @intCast(ext_total >> 8);
    buf[ext_start + 1] = @intCast(ext_total & 0xFF);

    const record_len: u16 = @intCast(pos - 5);
    buf[3] = @intCast(record_len >> 8);
    buf[4] = @intCast(record_len & 0xFF);

    const hs_len = pos - 9;
    buf[6] = @intCast((hs_len >> 16) & 0xFF);
    buf[7] = @intCast((hs_len >> 8) & 0xFF);
    buf[8] = @intCast(hs_len & 0xFF);

    const result = sniff(buf[0..pos]) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("test.io", result.domain);
    try std.testing.expectEqual(SniffResult.Protocol.tls, result.protocol);
}

test "sniff HTTP request" {
    const http = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
    const result = sniff(http) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("www.example.com", result.domain);
    try std.testing.expectEqual(SniffResult.Protocol.http, result.protocol);
}

test "sniff unknown data" {
    const garbage = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13 };
    try std.testing.expectEqual(@as(?SniffResult, null), sniff(&garbage));
}
