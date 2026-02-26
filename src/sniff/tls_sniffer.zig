const std = @import("std");

/// Extract SNI (Server Name Indication) from a TLS ClientHello message.
///
/// TLS Record Layout:
///   [0]     Content Type: 0x16 = Handshake
///   [1..2]  Version (big-endian)
///   [3..4]  Record Length (big-endian)
///   [5]     Handshake Type: 0x01 = ClientHello
///   [6..8]  Handshake Length (3 bytes, big-endian)
///   [9..10] ClientHello Version
///   [11..42] Random (32 bytes)
///   [43]    Session ID Length + Session ID
///   ...     Cipher Suites, Compression Methods, Extensions
///
/// SNI Extension (type 0x0000):
///   [0..1]  SNI List Length
///   [2]     Name Type: 0x00 = host_name
///   [3..4]  Name Length
///   [5..]   Hostname (ASCII, no null terminator)

pub const SniffResult = struct {
    domain: []const u8 = "",
    protocol: Protocol = .unknown,

    pub const Protocol = enum {
        unknown,
        tls,
        http,
    };

    pub fn isValid(self: *const SniffResult) bool {
        return self.domain.len > 0 and self.protocol != .unknown;
    }
};

/// Try to extract SNI from TLS ClientHello.
/// Returns the hostname if found, or null.
/// Data is borrowed (points into the input buffer), not copied.
pub fn sniffTls(data: []const u8) ?SniffResult {
    // Minimum TLS record: 5 (record header) + 1 (handshake type) + 3 (length) + 2 (version) + 32 (random) + 1 (session id len) = 44
    if (data.len < 44) return null;

    // Content type must be Handshake (0x16)
    if (data[0] != 0x16) return null;

    // TLS version check (byte 1): 0x03 for SSL3.0/TLS1.x
    if (data[1] != 0x03) return null;

    // Record length
    const record_len = readU16(data[3..5]);
    if (5 + record_len > data.len) return null; // Truncated, but we may still parse

    // Handshake type: ClientHello (0x01)
    if (data[5] != 0x01) return null;

    // Handshake length (3 bytes big-endian)
    // const hs_len = (@as(u32, data[6]) << 16) | (@as(u32, data[7]) << 8) | data[8];
    // _ = hs_len; // We use positional parsing

    var pos: usize = 9;

    // Skip ClientHello version (2 bytes)
    pos += 2;
    if (pos > data.len) return null;

    // Skip Random (32 bytes)
    pos += 32;
    if (pos >= data.len) return null;

    // Skip Session ID
    const session_id_len = data[pos];
    pos += 1 + session_id_len;
    if (pos + 2 > data.len) return null;

    // Skip Cipher Suites
    const cipher_suites_len = readU16(data[pos .. pos + 2]);
    pos += 2 + cipher_suites_len;
    if (pos + 1 > data.len) return null;

    // Skip Compression Methods
    const compression_len = data[pos];
    pos += 1 + compression_len;
    if (pos + 2 > data.len) return null;

    // Extensions length
    const extensions_len = readU16(data[pos .. pos + 2]);
    pos += 2;

    const extensions_end = @min(pos + extensions_len, data.len);

    // Parse extensions
    while (pos + 4 <= extensions_end) {
        const ext_type = readU16(data[pos .. pos + 2]);
        const ext_len = readU16(data[pos + 2 .. pos + 4]);
        pos += 4;

        if (pos + ext_len > extensions_end) break;

        if (ext_type == 0x0000) {
            // SNI extension
            if (ext_len < 5) {
                pos += ext_len;
                continue;
            }

            const sni_data = data[pos .. pos + ext_len];
            return parseSniExtension(sni_data);
        }

        pos += ext_len;
    }

    return null;
}

fn parseSniExtension(data: []const u8) ?SniffResult {
    if (data.len < 5) return null;

    // SNI list length (2 bytes) - we don't strictly need this
    // const list_len = readU16(data[0..2]);
    var pos: usize = 2;

    // Name type
    if (pos >= data.len) return null;
    const name_type = data[pos];
    pos += 1;

    if (name_type != 0x00) return null; // Only host_name (0) supported

    if (pos + 2 > data.len) return null;
    const name_len = readU16(data[pos .. pos + 2]);
    pos += 2;

    if (pos + name_len > data.len) return null;
    if (name_len == 0) return null;

    const hostname = data[pos .. pos + name_len];

    // Validate: hostname should be ASCII without null bytes
    for (hostname) |c| {
        if (c == 0 or c > 127) return null;
    }

    return SniffResult{
        .domain = hostname,
        .protocol = .tls,
    };
}

fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | bytes[1];
}

/// Check if data looks like it could be a TLS ClientHello.
/// Quick check without full parsing.
pub fn isTlsClientHello(data: []const u8) bool {
    if (data.len < 6) return false;
    return data[0] == 0x16 and data[1] == 0x03 and data[5] == 0x01;
}

// ── Tests ──

test "sniffTls with valid ClientHello" {
    // Minimal synthetic ClientHello with SNI for "example.com"
    var buf: [256]u8 = undefined;
    var pos: usize = 0;

    // TLS Record Header
    buf[0] = 0x16; // Handshake
    buf[1] = 0x03;
    buf[2] = 0x01; // TLS 1.0
    pos = 5; // Will fill length later

    // Handshake header
    buf[5] = 0x01; // ClientHello
    pos = 9; // Will fill length later

    // ClientHello Version
    buf[9] = 0x03;
    buf[10] = 0x03; // TLS 1.2
    pos = 11;

    // Random (32 bytes)
    @memset(buf[pos .. pos + 32], 0xAB);
    pos += 32;

    // Session ID length = 0
    buf[pos] = 0;
    pos += 1;

    // Cipher suites length = 2, one cipher suite
    buf[pos] = 0x00;
    buf[pos + 1] = 0x02;
    buf[pos + 2] = 0x00;
    buf[pos + 3] = 0x2F; // TLS_RSA_WITH_AES_128_CBC_SHA
    pos += 4;

    // Compression methods length = 1, null compression
    buf[pos] = 0x01;
    buf[pos + 1] = 0x00;
    pos += 2;

    // Extensions
    const ext_start = pos;
    pos += 2; // Extensions length placeholder

    // SNI Extension
    const domain = "example.com";
    buf[pos] = 0x00;
    buf[pos + 1] = 0x00; // Extension type: SNI
    const sni_ext_len: u16 = @intCast(2 + 1 + 2 + domain.len);
    buf[pos + 2] = @intCast(sni_ext_len >> 8);
    buf[pos + 3] = @intCast(sni_ext_len & 0xFF);
    pos += 4;

    // SNI list length
    const sni_list_len: u16 = @intCast(1 + 2 + domain.len);
    buf[pos] = @intCast(sni_list_len >> 8);
    buf[pos + 1] = @intCast(sni_list_len & 0xFF);
    pos += 2;

    // Name type: host_name
    buf[pos] = 0x00;
    pos += 1;

    // Name length
    buf[pos] = 0x00;
    buf[pos + 1] = @intCast(domain.len);
    pos += 2;

    // Hostname
    @memcpy(buf[pos .. pos + domain.len], domain);
    pos += domain.len;

    // Fill extensions length
    const ext_total: u16 = @intCast(pos - ext_start - 2);
    buf[ext_start] = @intCast(ext_total >> 8);
    buf[ext_start + 1] = @intCast(ext_total & 0xFF);

    // Fill record length
    const record_len: u16 = @intCast(pos - 5);
    buf[3] = @intCast(record_len >> 8);
    buf[4] = @intCast(record_len & 0xFF);

    // Fill handshake length
    const hs_len = pos - 9;
    buf[6] = @intCast((hs_len >> 16) & 0xFF);
    buf[7] = @intCast((hs_len >> 8) & 0xFF);
    buf[8] = @intCast(hs_len & 0xFF);

    const result = sniffTls(buf[0..pos]) orelse {
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqualStrings("example.com", result.domain);
    try std.testing.expectEqual(SniffResult.Protocol.tls, result.protocol);
}

test "sniffTls returns null for non-TLS" {
    const http_data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    try std.testing.expectEqual(@as(?SniffResult, null), sniffTls(http_data));
}

test "sniffTls returns null for too-short data" {
    const short = [_]u8{ 0x16, 0x03, 0x01 };
    try std.testing.expectEqual(@as(?SniffResult, null), sniffTls(&short));
}

test "isTlsClientHello" {
    const tls = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x10, 0x01 };
    try std.testing.expect(isTlsClientHello(&tls));

    const http = "GET / ";
    try std.testing.expect(!isTlsClientHello(http));
}
