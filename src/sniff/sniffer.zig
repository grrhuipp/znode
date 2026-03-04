/// Protocol sniffer — extract target domain from TLS ClientHello SNI or HTTP Host.
///
/// Used to override routing target when sniffing is enabled.
/// Only inspects the first packet (buffered by caller); never reads from stream.
const std = @import("std");
const types = @import("../common/types.zig");

pub const SniffResult = struct {
    host: [253]u8 = undefined,
    host_len: u8 = 0,
    port: u16 = 0,
    protocol: SniffProtocol,

    pub fn hostname(self: *const SniffResult) []const u8 {
        return self.host[0..self.host_len];
    }

    pub fn toTarget(self: *const SniffResult, fallback_port: u16) types.TargetAddress {
        const port = if (self.port > 0) self.port else fallback_port;
        return types.TargetAddress.init(self.hostname(), port, .domain);
    }
};

pub const SniffProtocol = enum {
    tls,
    http,
    unknown,
};

/// Try to sniff protocol from first packet data.
/// Tries TLS first, then HTTP.
pub fn sniff(data: []const u8) ?SniffResult {
    return sniffTls(data) orelse sniffHttp(data);
}

// ── TLS ClientHello SNI ──────────────────────────────────────────────────

fn sniffTls(data: []const u8) ?SniffResult {
    // Minimum: TLS record header(5) + handshake header(4) + version(2) +
    //          random(32) + session_id_len(1) = 44
    if (data.len < 44) return null;

    // TLS record header
    if (data[0] != 0x16) return null; // Content Type: Handshake
    // Version check: 0x0300-0x0304 (SSL3.0-TLS1.3)
    if (data[1] != 0x03 or data[2] > 0x04) return null;

    const record_len = readU16(data[3..5]);
    if (record_len + 5 > data.len) return null; // incomplete record

    // Handshake header
    const hs = data[5..];
    if (hs[0] != 0x01) return null; // ClientHello

    // Skip: handshake length(3) + version(2) + random(32)
    var pos: usize = 1 + 3 + 2 + 32;
    if (pos >= hs.len) return null;

    // Session ID
    const session_id_len = hs[pos];
    pos += 1 + session_id_len;
    if (pos + 2 > hs.len) return null;

    // Cipher suites
    const cipher_suites_len = readU16(hs[pos..]);
    pos += 2 + cipher_suites_len;
    if (pos >= hs.len) return null;

    // Compression methods
    const comp_len = hs[pos];
    pos += 1 + comp_len;
    if (pos + 2 > hs.len) return null;

    // Extensions
    const ext_total = readU16(hs[pos..]);
    pos += 2;
    const ext_end = pos + ext_total;
    if (ext_end > hs.len) return null;

    while (pos + 4 <= ext_end) {
        const ext_type = readU16(hs[pos..]);
        const ext_len = readU16(hs[pos + 2 ..]);
        pos += 4;
        if (pos + ext_len > ext_end) break;

        if (ext_type == 0x0000) { // SNI extension
            return parseSni(hs[pos .. pos + ext_len]);
        }

        pos += ext_len;
    }

    return null;
}

fn parseSni(ext_data: []const u8) ?SniffResult {
    if (ext_data.len < 5) return null;

    // SNI list length
    const list_len = readU16(ext_data[0..2]);
    _ = list_len;
    var pos: usize = 2;

    while (pos + 3 <= ext_data.len) {
        const name_type = ext_data[pos];
        const name_len = readU16(ext_data[pos + 1 ..]);
        pos += 3;

        if (pos + name_len > ext_data.len) break;

        if (name_type == 0x00) { // host_name
            if (name_len == 0 or name_len > 253) return null;
            var result = SniffResult{
                .protocol = .tls,
                .host_len = @intCast(name_len),
            };
            @memcpy(result.host[0..name_len], ext_data[pos .. pos + name_len]);
            return result;
        }

        pos += name_len;
    }

    return null;
}

// ── HTTP Host Header ─────────────────────────────────────────────────────

const http_methods = [_][]const u8{
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
    "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
};

fn sniffHttp(data: []const u8) ?SniffResult {
    // Check if starts with HTTP method
    var is_http = false;
    for (http_methods) |method| {
        if (data.len >= method.len and std.ascii.eqlIgnoreCase(data[0..method.len], method)) {
            is_http = true;
            break;
        }
    }
    if (!is_http) return null;

    // Find Host header (case-insensitive search)
    const host_header = findHostHeader(data) orelse return null;

    // Parse host[:port]
    return parseHostValue(host_header);
}

fn findHostHeader(data: []const u8) ?[]const u8 {
    // Search for "\nHost:" or "\nhost:" etc. (case-insensitive)
    var i: usize = 0;
    while (i + 6 < data.len) {
        if (data[i] == '\n') {
            const remaining = data[i + 1 ..];
            if (remaining.len >= 5 and
                (remaining[0] == 'H' or remaining[0] == 'h') and
                (remaining[1] == 'O' or remaining[1] == 'o') and
                (remaining[2] == 'S' or remaining[2] == 's') and
                (remaining[3] == 'T' or remaining[3] == 't') and
                remaining[4] == ':')
            {
                var start: usize = 5;
                // Skip whitespace
                while (start < remaining.len and remaining[start] == ' ') start += 1;
                // Find end of line
                var end = start;
                while (end < remaining.len and remaining[end] != '\r' and remaining[end] != '\n') end += 1;
                // Strip trailing whitespace
                while (end > start and remaining[end - 1] == ' ') end -= 1;
                if (end > start) return remaining[start..end];
            }
        }
        i += 1;
    }
    return null;
}

fn parseHostValue(host_val: []const u8) ?SniffResult {
    if (host_val.len == 0 or host_val.len > 253 + 6) return null; // max domain + ":65535"

    var result = SniffResult{
        .protocol = .http,
    };

    // IPv6 bracket notation: [::1]:port or [::1]
    if (host_val[0] == '[') {
        const bracket_end = std.mem.indexOfScalar(u8, host_val, ']') orelse return null;
        const ipv6_host = host_val[1..bracket_end];
        if (ipv6_host.len == 0 or ipv6_host.len > 253) return null;

        result.host_len = @intCast(ipv6_host.len);
        @memcpy(result.host[0..ipv6_host.len], ipv6_host);

        if (bracket_end + 1 < host_val.len and host_val[bracket_end + 1] == ':') {
            result.port = std.fmt.parseInt(u16, host_val[bracket_end + 2 ..], 10) catch 0;
        }
        return result;
    }

    // Regular host or host:port
    if (std.mem.lastIndexOfScalar(u8, host_val, ':')) |colon| {
        const host_part = host_val[0..colon];
        if (host_part.len == 0 or host_part.len > 253) return null;
        result.host_len = @intCast(host_part.len);
        @memcpy(result.host[0..host_part.len], host_part);
        result.port = std.fmt.parseInt(u16, host_val[colon + 1 ..], 10) catch 0;
    } else {
        if (host_val.len > 253) return null;
        result.host_len = @intCast(host_val.len);
        @memcpy(result.host[0..host_val.len], host_val);
    }

    return result;
}

fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}
