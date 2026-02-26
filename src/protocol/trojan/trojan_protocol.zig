const std = @import("std");
const Session = @import("../../core/session.zig");
const user_store = @import("../../core/user_store.zig");

/// Trojan protocol implementation.
///
/// Trojan request format:
/// ```
/// +--------------------------+
/// | Password Hash (56 bytes) |  SHA224 hex string
/// +--------------------------+
/// | CRLF (2 bytes)           |  0x0D 0x0A
/// +--------------------------+
/// | CMD (1 byte)             |  0x01=CONNECT, 0x03=UDP
/// +--------------------------+
/// | ATYP (1 byte)            |  0x01=IPv4, 0x03=Domain, 0x04=IPv6
/// +--------------------------+
/// | Address (variable)       |
/// +--------------------------+
/// | Port (2 bytes, BE)       |
/// +--------------------------+
/// | CRLF (2 bytes)           |  0x0D 0x0A
/// +--------------------------+
/// | Payload (optional)       |
/// +--------------------------+
/// ```

pub const HASH_LEN = 56; // SHA224 produces 28 bytes = 56 hex chars

pub const AddressType = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
};

pub const Command = enum(u8) {
    connect = 0x01,
    udp_associate = 0x03,
};

pub const TrojanRequest = struct {
    password_hash: [HASH_LEN]u8,
    command: Command,
    target: Session.TargetAddress,
    /// Total bytes consumed from the input buffer (header only).
    header_len: usize,
};

/// Compute SHA224 hash of a password and return it as a 56-char hex string.
pub fn hashPassword(password: []const u8) [HASH_LEN]u8 {
    var hash: [28]u8 = undefined;
    const boringssl = @import("../../crypto/boringssl_crypto.zig");
    boringssl.Sha224.hash(password, &hash, .{});
    var result: [HASH_LEN]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (hash, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return result;
}

/// Constant-time comparison for password hashes to prevent timing attacks.
fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
}

/// Parse a Trojan request from the given buffer.
///
/// Returns null if the data is incomplete (need more bytes).
/// Returns error on protocol violation.
pub fn parseRequest(data: []const u8) ParseResult {
    // Need at least the hash + first CRLF
    if (data.len < HASH_LEN + 2) return .incomplete;

    // Validate hash is all hex chars
    for (data[0..HASH_LEN]) |ch| {
        if (!isHexChar(ch)) return .protocol_error;
    }

    // Check first CRLF
    if (data[HASH_LEN] != '\r' or data[HASH_LEN + 1] != '\n')
        return .protocol_error;

    var pos: usize = HASH_LEN + 2;

    // CMD
    if (pos >= data.len) return .incomplete;
    const cmd_byte = data[pos];
    const command: Command = switch (cmd_byte) {
        0x01 => .connect,
        0x03 => .udp_associate,
        else => return .protocol_error,
    };
    pos += 1;

    // ATYP
    if (pos >= data.len) return .incomplete;
    const atyp = data[pos];
    pos += 1;

    var target = Session.TargetAddress{};

    switch (atyp) {
        0x01 => { // IPv4
            if (pos + 4 + 2 + 2 > data.len) return .incomplete;
            const ip4 = data[pos..][0..4].*;
            pos += 4;
            const port = @as(u16, data[pos]) << 8 | @as(u16, data[pos + 1]);
            pos += 2;
            target.setIpv4(ip4, port);
        },
        0x03 => { // Domain
            if (pos >= data.len) return .incomplete;
            const domain_len = data[pos];
            pos += 1;
            if (domain_len == 0 or domain_len > 253) return .protocol_error;
            if (pos + domain_len + 2 + 2 > data.len) return .incomplete;
            const domain = data[pos .. pos + domain_len];
            pos += domain_len;
            const port = @as(u16, data[pos]) << 8 | @as(u16, data[pos + 1]);
            pos += 2;
            target.setDomain(domain, port);
        },
        0x04 => { // IPv6
            if (pos + 16 + 2 + 2 > data.len) return .incomplete;
            const ip6 = data[pos..][0..16].*;
            pos += 16;
            const port = @as(u16, data[pos]) << 8 | @as(u16, data[pos + 1]);
            pos += 2;
            target.setIpv6(ip6, port);
        },
        else => return .protocol_error,
    }

    // Second CRLF
    if (pos + 2 > data.len) return .incomplete;
    if (data[pos] != '\r' or data[pos + 1] != '\n')
        return .protocol_error;
    pos += 2;

    return .{ .success = TrojanRequest{
        .password_hash = data[0..HASH_LEN].*,
        .command = command,
        .target = target,
        .header_len = pos,
    } };
}

/// Encode a Trojan request header into a buffer.
/// Returns the number of bytes written, or null if the buffer is too small.
pub fn encodeRequest(
    buf: []u8,
    password_hash: [HASH_LEN]u8,
    command: Command,
    target: *const Session.TargetAddress,
) ?usize {
    var pos: usize = 0;

    // Password hash
    if (pos + HASH_LEN > buf.len) return null;
    @memcpy(buf[pos .. pos + HASH_LEN], &password_hash);
    pos += HASH_LEN;

    // CRLF
    if (pos + 2 > buf.len) return null;
    buf[pos] = '\r';
    buf[pos + 1] = '\n';
    pos += 2;

    // CMD
    if (pos + 1 > buf.len) return null;
    buf[pos] = @intFromEnum(command);
    pos += 1;

    // ATYP + Address
    switch (target.addr_type) {
        .ipv4 => {
            if (pos + 1 + 4 > buf.len) return null;
            buf[pos] = 0x01;
            pos += 1;
            @memcpy(buf[pos .. pos + 4], &target.ip4);
            pos += 4;
        },
        .domain => {
            const domain = target.getDomain();
            if (domain.len == 0) return null;
            if (pos + 1 + 1 + domain.len > buf.len) return null;
            buf[pos] = 0x03;
            pos += 1;
            buf[pos] = @intCast(domain.len);
            pos += 1;
            @memcpy(buf[pos .. pos + domain.len], domain);
            pos += domain.len;
        },
        .ipv6 => {
            if (pos + 1 + 16 > buf.len) return null;
            buf[pos] = 0x04;
            pos += 1;
            @memcpy(buf[pos .. pos + 16], &target.ip6);
            pos += 16;
        },
        .none => return null,
    }

    // Port (big-endian)
    if (pos + 2 > buf.len) return null;
    buf[pos] = @intCast(target.port >> 8);
    buf[pos + 1] = @intCast(target.port & 0xFF);
    pos += 2;

    // CRLF
    if (pos + 2 > buf.len) return null;
    buf[pos] = '\r';
    buf[pos + 1] = '\n';
    pos += 2;

    return pos;
}

/// Authenticate a Trojan request against a user store.
pub fn authenticate(
    request: *const TrojanRequest,
    store: *user_store.UserStore,
) ?*const user_store.UserInfo {
    const users = store.getUsers() orelse return null;
    return users.findByPasswordHash(&request.password_hash);
}

pub const ParseResult = union(enum) {
    success: TrojanRequest,
    incomplete,
    protocol_error,
};

fn isHexChar(ch: u8) bool {
    return (ch >= '0' and ch <= '9') or
        (ch >= 'a' and ch <= 'f') or
        (ch >= 'A' and ch <= 'F');
}

// ── Tests ──

test "hashPassword" {
    const hash = hashPassword("test123");
    try std.testing.expectEqual(@as(usize, 56), hash.len);
    for (hash) |ch| {
        try std.testing.expect(isHexChar(ch));
    }
}

test "hashPassword deterministic" {
    const h1 = hashPassword("secret");
    const h2 = hashPassword("secret");
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "hashPassword different inputs differ" {
    const h1 = hashPassword("password1");
    const h2 = hashPassword("password2");
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "constantTimeEqual" {
    const a = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01";
    const b = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01";
    const c = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef02";
    try std.testing.expect(constantTimeEqual(a, b));
    try std.testing.expect(!constantTimeEqual(a, c));
}

test "parseRequest valid IPv4" {
    var buf: [256]u8 = undefined;
    const hash = hashPassword("test");

    @memcpy(buf[0..HASH_LEN], &hash);
    buf[HASH_LEN] = '\r';
    buf[HASH_LEN + 1] = '\n';
    buf[HASH_LEN + 2] = 0x01; // CMD CONNECT
    buf[HASH_LEN + 3] = 0x01; // ATYP IPv4
    buf[HASH_LEN + 4] = 127; // 127.0.0.1
    buf[HASH_LEN + 5] = 0;
    buf[HASH_LEN + 6] = 0;
    buf[HASH_LEN + 7] = 1;
    buf[HASH_LEN + 8] = 0x00; // Port 80
    buf[HASH_LEN + 9] = 0x50;
    buf[HASH_LEN + 10] = '\r';
    buf[HASH_LEN + 11] = '\n';

    const total_len = HASH_LEN + 12;
    const result = parseRequest(buf[0..total_len]);
    try std.testing.expect(result == .success);

    const req = result.success;
    try std.testing.expectEqualSlices(u8, &hash, &req.password_hash);
    try std.testing.expectEqual(Command.connect, req.command);
    try std.testing.expectEqual(@as(u16, 80), req.target.port);
    try std.testing.expectEqual(Session.TargetAddress.AddressType.ipv4, req.target.addr_type);
    try std.testing.expectEqual(@as(u8, 127), req.target.ip4[0]);
    try std.testing.expectEqual(total_len, req.header_len);
}

test "parseRequest valid domain" {
    var buf: [256]u8 = undefined;
    const hash = hashPassword("user1");
    const domain = "example.com";

    @memcpy(buf[0..HASH_LEN], &hash);
    buf[HASH_LEN] = '\r';
    buf[HASH_LEN + 1] = '\n';
    buf[HASH_LEN + 2] = 0x01; // CONNECT
    buf[HASH_LEN + 3] = 0x03; // Domain
    buf[HASH_LEN + 4] = @intCast(domain.len);
    @memcpy(buf[HASH_LEN + 5 .. HASH_LEN + 5 + domain.len], domain);
    const port_off = HASH_LEN + 5 + domain.len;
    buf[port_off] = 0x01; // Port 443
    buf[port_off + 1] = 0xBB;
    buf[port_off + 2] = '\r';
    buf[port_off + 3] = '\n';

    const total_len = port_off + 4;
    const result = parseRequest(buf[0..total_len]);
    try std.testing.expect(result == .success);

    const req = result.success;
    try std.testing.expectEqual(Session.TargetAddress.AddressType.domain, req.target.addr_type);
    try std.testing.expectEqualStrings("example.com", req.target.getDomain());
    try std.testing.expectEqual(@as(u16, 443), req.target.port);
}

test "parseRequest valid IPv6" {
    var buf: [256]u8 = undefined;
    const hash = hashPassword("v6user");

    @memcpy(buf[0..HASH_LEN], &hash);
    buf[HASH_LEN] = '\r';
    buf[HASH_LEN + 1] = '\n';
    buf[HASH_LEN + 2] = 0x01; // CONNECT
    buf[HASH_LEN + 3] = 0x04; // IPv6
    // ::1
    @memset(buf[HASH_LEN + 4 .. HASH_LEN + 4 + 15], 0);
    buf[HASH_LEN + 4 + 15] = 1;
    buf[HASH_LEN + 20] = 0x1F; // Port 8080
    buf[HASH_LEN + 21] = 0x90;
    buf[HASH_LEN + 22] = '\r';
    buf[HASH_LEN + 23] = '\n';

    const total_len = HASH_LEN + 24;
    const result = parseRequest(buf[0..total_len]);
    try std.testing.expect(result == .success);
    try std.testing.expectEqual(Session.TargetAddress.AddressType.ipv6, result.success.target.addr_type);
}

test "parseRequest UDP associate" {
    var buf: [256]u8 = undefined;
    const hash = hashPassword("udpuser");

    @memcpy(buf[0..HASH_LEN], &hash);
    buf[HASH_LEN] = '\r';
    buf[HASH_LEN + 1] = '\n';
    buf[HASH_LEN + 2] = 0x03; // UDP ASSOCIATE
    buf[HASH_LEN + 3] = 0x01; // IPv4
    buf[HASH_LEN + 4] = 8;
    buf[HASH_LEN + 5] = 8;
    buf[HASH_LEN + 6] = 8;
    buf[HASH_LEN + 7] = 8;
    buf[HASH_LEN + 8] = 0x00;
    buf[HASH_LEN + 9] = 0x35; // Port 53
    buf[HASH_LEN + 10] = '\r';
    buf[HASH_LEN + 11] = '\n';

    const result = parseRequest(buf[0 .. HASH_LEN + 12]);
    try std.testing.expect(result == .success);
    try std.testing.expectEqual(Command.udp_associate, result.success.command);
    try std.testing.expectEqual(@as(u16, 53), result.success.target.port);
}

test "parseRequest incomplete" {
    const short = "abcdef";
    try std.testing.expect(parseRequest(short) == .incomplete);

    var buf: [HASH_LEN]u8 = undefined;
    @memset(&buf, 'a');
    try std.testing.expect(parseRequest(&buf) == .incomplete);
}

test "parseRequest invalid hash" {
    var buf: [70]u8 = undefined;
    @memset(&buf, 'z'); // 'z' is not a valid hex char
    buf[HASH_LEN] = '\r';
    buf[HASH_LEN + 1] = '\n';
    try std.testing.expect(parseRequest(&buf) == .protocol_error);
}

test "parseRequest missing second CRLF" {
    var buf: [256]u8 = undefined;
    const hash = hashPassword("test");
    @memcpy(buf[0..HASH_LEN], &hash);
    buf[HASH_LEN] = '\r';
    buf[HASH_LEN + 1] = '\n';
    buf[HASH_LEN + 2] = 0x01;
    buf[HASH_LEN + 3] = 0x01;
    buf[HASH_LEN + 4] = 1;
    buf[HASH_LEN + 5] = 2;
    buf[HASH_LEN + 6] = 3;
    buf[HASH_LEN + 7] = 4;
    buf[HASH_LEN + 8] = 0;
    buf[HASH_LEN + 9] = 80;
    buf[HASH_LEN + 10] = 'X'; // Not \r
    buf[HASH_LEN + 11] = 'X';
    try std.testing.expect(parseRequest(buf[0 .. HASH_LEN + 12]) == .protocol_error);
}

test "encodeRequest roundtrip" {
    const hash = hashPassword("roundtrip");
    var target = Session.TargetAddress{};
    target.setDomain("www.google.com", 443);

    var buf: [256]u8 = undefined;
    const encoded_len = encodeRequest(&buf, hash, .connect, &target) orelse
        return error.TestUnexpectedResult;

    const result = parseRequest(buf[0..encoded_len]);
    try std.testing.expect(result == .success);
    const req = result.success;
    try std.testing.expectEqualSlices(u8, &hash, &req.password_hash);
    try std.testing.expectEqual(Command.connect, req.command);
    try std.testing.expectEqualStrings("www.google.com", req.target.getDomain());
    try std.testing.expectEqual(@as(u16, 443), req.target.port);
    try std.testing.expectEqual(encoded_len, req.header_len);
}

test "encodeRequest IPv4 roundtrip" {
    const hash = hashPassword("ip4rt");
    var target = Session.TargetAddress{};
    target.setIpv4(.{ 10, 0, 0, 1 }, 8080);

    var buf: [256]u8 = undefined;
    const len = encodeRequest(&buf, hash, .connect, &target).?;
    const result = parseRequest(buf[0..len]);
    try std.testing.expect(result == .success);
    try std.testing.expectEqual(@as(u8, 10), result.success.target.ip4[0]);
    try std.testing.expectEqual(@as(u16, 8080), result.success.target.port);
}
