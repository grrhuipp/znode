const std = @import("std");
const tls_sniffer = @import("tls_sniffer.zig");

/// Extract Host header from HTTP request.
///
/// Supported methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, CONNECT, TRACE
/// Host header format: "Host: <hostname>[:port]\r\n"

/// Try to extract Host from HTTP request headers.
/// Returns the hostname if found. Data is borrowed, not copied.
pub fn sniffHttp(data: []const u8) ?tls_sniffer.SniffResult {
    if (data.len < 16) return null; // Minimum: "GET / HTTP/1.1\r\n"

    // Check if data starts with an HTTP method
    if (!isHttpRequest(data)) return null;

    // Find "Host:" header (case-insensitive)
    const host_value = findHostHeader(data) orelse return null;
    if (host_value.len == 0) return null;

    // Strip port if present
    const hostname = stripPort(host_value);
    if (hostname.len == 0) return null;

    // Validate hostname
    for (hostname) |c| {
        if (c == 0 or c > 127) return null;
    }

    return tls_sniffer.SniffResult{
        .domain = hostname,
        .protocol = .http,
    };
}

/// Check if data begins with an HTTP method.
pub fn isHttpRequest(data: []const u8) bool {
    // Methods must be followed by a space
    const methods = [_][]const u8{
        "GET ",
        "POST ",
        "PUT ",
        "HEAD ",
        "DELETE ",
        "OPTIONS ",
        "PATCH ",
        "CONNECT ",
        "TRACE ",
    };

    for (methods) |method| {
        if (data.len >= method.len and std.ascii.eqlIgnoreCase(data[0..method.len], method)) {
            return true;
        }
    }
    return false;
}

/// Find the Host header value in HTTP headers.
/// Returns the trimmed value after "Host:", or null.
fn findHostHeader(data: []const u8) ?[]const u8 {
    // Search for "\r\nHost:" or "\nHost:" (case-insensitive)
    const needle_rn = "\r\nHost:";
    const needle_n = "\nHost:";

    var pos: usize = 0;
    while (pos < data.len) {
        // Try \r\nHost:
        if (pos + needle_rn.len <= data.len) {
            if (matchIgnoreCase(data[pos .. pos + needle_rn.len], needle_rn)) {
                pos += needle_rn.len;
                return extractHeaderValue(data, pos);
            }
        }
        // Try \nHost:
        if (pos + needle_n.len <= data.len) {
            if (matchIgnoreCase(data[pos .. pos + needle_n.len], needle_n)) {
                pos += needle_n.len;
                return extractHeaderValue(data, pos);
            }
        }
        pos += 1;
    }
    return null;
}

/// Match two slices ignoring case, but only for the alpha characters in `pattern`.
fn matchIgnoreCase(data: []const u8, pattern: []const u8) bool {
    if (data.len != pattern.len) return false;
    for (data, pattern) |d, p| {
        if (p == '\r' or p == '\n' or p == ':') {
            if (d != p) return false;
        } else {
            if (std.ascii.toLower(d) != std.ascii.toLower(p)) return false;
        }
    }
    return true;
}

/// Extract header value: skip leading spaces, read until \r\n or \n.
fn extractHeaderValue(data: []const u8, start: usize) ?[]const u8 {
    var pos = start;

    // Skip leading spaces
    while (pos < data.len and data[pos] == ' ') : (pos += 1) {}

    const value_start = pos;

    // Read until end of line
    while (pos < data.len) {
        if (data[pos] == '\r' or data[pos] == '\n') break;
        pos += 1;
    }

    if (pos == value_start) return null;

    // Trim trailing spaces
    var end = pos;
    while (end > value_start and data[end - 1] == ' ') : (end -= 1) {}

    return data[value_start..end];
}

/// Strip port from host value.
/// "example.com:8080" -> "example.com"
/// "[::1]:8080" -> "::1"
/// "example.com" -> "example.com"
fn stripPort(host: []const u8) []const u8 {
    if (host.len == 0) return host;

    // IPv6 in brackets: [::1]:port
    if (host[0] == '[') {
        for (host, 0..) |c, i| {
            if (c == ']') {
                return host[1..i]; // Return content between brackets
            }
        }
        return host; // Malformed, return as-is
    }

    // Find last colon - if everything after it is digits, it's a port
    var last_colon: ?usize = null;
    for (host, 0..) |c, i| {
        if (c == ':') last_colon = i;
    }

    if (last_colon) |colon_pos| {
        const after_colon = host[colon_pos + 1 ..];
        if (after_colon.len > 0) {
            var all_digits = true;
            for (after_colon) |c| {
                if (c < '0' or c > '9') {
                    all_digits = false;
                    break;
                }
            }
            if (all_digits) {
                return host[0..colon_pos];
            }
        }
    }

    return host;
}

// ── Tests ──

test "sniffHttp extracts Host header" {
    const request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    const result = sniffHttp(request) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("example.com", result.domain);
    try std.testing.expectEqual(tls_sniffer.SniffResult.Protocol.http, result.protocol);
}

test "sniffHttp with port" {
    const request = "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
    const result = sniffHttp(request) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("example.com", result.domain);
}

test "sniffHttp POST request" {
    const request = "POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n";
    const result = sniffHttp(request) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("api.example.com", result.domain);
}

test "sniffHttp returns null for non-HTTP" {
    const tls = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x10, 0x01 };
    try std.testing.expectEqual(@as(?tls_sniffer.SniffResult, null), sniffHttp(&tls));
}

test "sniffHttp returns null for missing Host" {
    const request = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    try std.testing.expectEqual(@as(?tls_sniffer.SniffResult, null), sniffHttp(request));
}

test "stripPort basic" {
    try std.testing.expectEqualStrings("example.com", stripPort("example.com:8080"));
    try std.testing.expectEqualStrings("example.com", stripPort("example.com"));
    try std.testing.expectEqualStrings("::1", stripPort("[::1]:8080"));
    try std.testing.expectEqualStrings("::1", stripPort("[::1]"));
}

test "isHttpRequest" {
    try std.testing.expect(isHttpRequest("GET / HTTP/1.1"));
    try std.testing.expect(isHttpRequest("POST /api HTTP/1.1"));
    try std.testing.expect(isHttpRequest("put /data HTTP/1.1"));
    try std.testing.expect(!isHttpRequest("INVALID"));
    try std.testing.expect(!isHttpRequest(""));
}
