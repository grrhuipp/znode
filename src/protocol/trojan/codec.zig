const std = @import("std");
const types = @import("../../common/types.zig");
const hash_mod = @import("../../infra/crypto/hash.zig");

pub const hash_len = 56; // SHA224 hex = 28 bytes * 2

pub const Command = enum(u8) {
    connect = 0x01,
    udp_associate = 0x03,
};

pub const User = struct {
    user_id: i64,
    email: []const u8,
    password_hash: []const u8,
    speed_limit_bytes: u64,
};

/// Raw parsed header (without authentication).
pub const ParsedHeader = struct {
    auth_hash: []const u8, // 56-byte slice into input data
    command: Command,
    target: types.TargetAddress,
    consumed: usize,
    initial_payload: []const u8,
};

pub const ParseError = error{
    NeedMoreData,
    InvalidRequest,
    AuthFailed,
    UnsupportedCommand,
    UnsupportedAddressType,
};

/// SHA224(password) → 56-char lowercase hex string (into caller buffer).
pub fn hashPassword(password: []const u8, out: *[hash_len]u8) void {
    hash_mod.sha224Hex(password, out);
}

/// SHA224(password) → allocator-owned 56-byte hex string.
pub fn hashPasswordAlloc(allocator: std.mem.Allocator, password: []const u8) ![]const u8 {
    var buf: [hash_len]u8 = undefined;
    hashPassword(password, &buf);
    return try allocator.dupe(u8, &buf);
}

// ── TCP Request Parsing ───────────────────────────────────────────────────

/// Parse Trojan TCP header without authentication.
/// Caller is responsible for validating auth_hash via UserManager.
pub fn parseHeader(data: []const u8) ParseError!ParsedHeader {
    // Minimum: 56 hash + 2 CRLF + 1 cmd + 1 atype + 1 addr_min + 2 port + 2 CRLF = 65
    if (data.len < hash_len + 2 + 1 + 1 + 1 + 2 + 2) return error.NeedMoreData;

    if (data[hash_len] != '\r' or data[hash_len + 1] != '\n') {
        return error.InvalidRequest;
    }

    const auth_hash = data[0..hash_len];

    var index: usize = hash_len + 2;
    const command: Command = switch (data[index]) {
        0x01 => .connect,
        0x03 => .udp_associate,
        else => return error.UnsupportedCommand,
    };
    index += 1;

    const target = try parseAddress(data, &index);

    if (index + 2 > data.len) return error.NeedMoreData;
    if (data[index] != '\r' or data[index + 1] != '\n') {
        return error.InvalidRequest;
    }
    index += 2;

    return .{
        .auth_hash = auth_hash,
        .command = command,
        .target = target,
        .consumed = index,
        .initial_payload = data[index..],
    };
}

// ── TCP Request Encoding (outbound) ───────────────────────────────────────

pub fn encodeRequest(
    password_hash: []const u8,
    command: Command,
    target: types.TargetAddress,
    buf: []u8,
) ?usize {
    var pos: usize = 0;

    // Password hash (56 bytes)
    if (pos + hash_len > buf.len) return null;
    @memcpy(buf[pos .. pos + hash_len], password_hash[0..hash_len]);
    pos += hash_len;

    // CRLF
    if (pos + 2 > buf.len) return null;
    buf[pos] = '\r';
    buf[pos + 1] = '\n';
    pos += 2;

    // Command
    if (pos + 1 > buf.len) return null;
    buf[pos] = @intFromEnum(command);
    pos += 1;

    // Address
    const addr_len = encodeAddress(target, buf[pos..]) orelse return null;
    pos += addr_len;

    // CRLF
    if (pos + 2 > buf.len) return null;
    buf[pos] = '\r';
    buf[pos + 1] = '\n';
    pos += 2;

    return pos;
}

// ── UDP Packet Parsing ────────────────────────────────────────────────────

pub const UdpPacket = struct {
    target: types.TargetAddress,
    payload: []const u8,
    consumed: usize,
};

pub fn parseUdpPacket(data: []const u8) ParseError!UdpPacket {
    if (data.len < 1) return error.NeedMoreData;

    var index: usize = 0;
    const target = try parseAddress(data, &index);

    // Payload length (2 bytes) + CRLF (2 bytes)
    if (index + 4 > data.len) return error.NeedMoreData;
    const payload_len = readU16BE(data[index..]);
    index += 2;

    if (data[index] != '\r' or data[index + 1] != '\n') return error.InvalidRequest;
    index += 2;

    if (index + payload_len > data.len) return error.NeedMoreData;
    const payload = data[index .. index + payload_len];
    index += payload_len;

    return .{
        .target = target,
        .payload = payload,
        .consumed = index,
    };
}

pub fn encodeUdpPacket(
    target: types.TargetAddress,
    payload: []const u8,
    buf: []u8,
) ?usize {
    var pos: usize = 0;

    const addr_len = encodeAddress(target, buf[pos..]) orelse return null;
    pos += addr_len;

    // Payload length
    if (pos + 4 > buf.len) return null;
    writeU16BE(buf[pos..], @intCast(payload.len));
    pos += 2;

    // CRLF
    buf[pos] = '\r';
    buf[pos + 1] = '\n';
    pos += 2;

    // Payload
    if (pos + payload.len > buf.len) return null;
    @memcpy(buf[pos .. pos + payload.len], payload);
    pos += payload.len;

    return pos;
}

// ── Address Parsing/Encoding (shared by TCP and UDP) ──────────────────────

fn parseAddress(data: []const u8, index: *usize) ParseError!types.TargetAddress {
    if (index.* >= data.len) return error.NeedMoreData;
    const atyp = data[index.*];
    index.* += 1;

    return switch (atyp) {
        0x01 => parseIpv4(data, index),
        0x03 => parseDomain(data, index),
        0x04 => parseIpv6(data, index),
        else => error.UnsupportedAddressType,
    };
}

fn parseIpv4(data: []const u8, index: *usize) ParseError!types.TargetAddress {
    if (index.* + 6 > data.len) return error.NeedMoreData;
    var host_buf: [16]u8 = undefined;
    const host = std.fmt.bufPrint(&host_buf, "{d}.{d}.{d}.{d}", .{
        data[index.*], data[index.* + 1], data[index.* + 2], data[index.* + 3],
    }) catch return error.InvalidRequest;
    index.* += 4;
    const port = readU16BE(data[index.*..]);
    index.* += 2;
    return types.TargetAddress.init(host, port, .ipv4);
}

fn parseDomain(data: []const u8, index: *usize) ParseError!types.TargetAddress {
    if (index.* >= data.len) return error.NeedMoreData;
    const length = data[index.*];
    if (length == 0) return error.InvalidRequest;
    index.* += 1;
    if (index.* + length + 2 > data.len) return error.NeedMoreData;
    const domain = data[index.* .. index.* + length];
    index.* += length;
    const port = readU16BE(data[index.*..]);
    index.* += 2;
    return types.TargetAddress.init(domain, port, .domain);
}

fn parseIpv6(data: []const u8, index: *usize) ParseError!types.TargetAddress {
    if (index.* + 18 > data.len) return error.NeedMoreData;
    var host_buf: [46]u8 = undefined;
    const d = data[index.*..];
    const host = std.fmt.bufPrint(&host_buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
        d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
        d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15],
    }) catch return error.InvalidRequest;
    index.* += 16;
    const port = readU16BE(data[index.*..]);
    index.* += 2;
    return types.TargetAddress.init(host, port, .ipv6);
}

fn encodeAddress(target: types.TargetAddress, buf: []u8) ?usize {
    var pos: usize = 0;
    switch (target.address_type) {
        .ipv4 => {
            if (pos + 1 + 4 + 2 > buf.len) return null;
            buf[pos] = 0x01;
            pos += 1;
            // Parse IP string back to 4 bytes
            var parts: [4]u8 = undefined;
            var iter = std.mem.splitScalar(u8, target.host(), '.');
            var pi: usize = 0;
            while (iter.next()) |part| {
                if (pi >= 4) return null;
                parts[pi] = std.fmt.parseInt(u8, part, 10) catch return null;
                pi += 1;
            }
            if (pi != 4) return null;
            @memcpy(buf[pos .. pos + 4], &parts);
            pos += 4;
            writeU16BE(buf[pos..], target.port);
            pos += 2;
        },
        .domain => {
            const h = target.host();
            if (pos + 1 + 1 + h.len + 2 > buf.len) return null;
            buf[pos] = 0x03;
            pos += 1;
            buf[pos] = @intCast(h.len);
            pos += 1;
            @memcpy(buf[pos .. pos + h.len], h);
            pos += h.len;
            writeU16BE(buf[pos..], target.port);
            pos += 2;
        },
        .ipv6 => {
            if (pos + 1 + 16 + 2 > buf.len) return null;
            buf[pos] = 0x04;
            pos += 1;
            // Parse hex IPv6 back to 16 bytes (simplified: colon-separated pairs)
            var bytes: [16]u8 = undefined;
            var bi: usize = 0;
            var h_iter = std.mem.splitScalar(u8, target.host(), ':');
            while (h_iter.next()) |group| {
                if (bi + 2 > 16) return null;
                if (group.len != 4) return null;
                bytes[bi] = std.fmt.parseInt(u8, group[0..2], 16) catch return null;
                bytes[bi + 1] = std.fmt.parseInt(u8, group[2..4], 16) catch return null;
                bi += 2;
            }
            if (bi != 16) return null;
            @memcpy(buf[pos .. pos + 16], &bytes);
            pos += 16;
            writeU16BE(buf[pos..], target.port);
            pos += 2;
        },
    }
    return pos;
}

/// Constant-time comparison (timing-attack resistant).
fn constantTimeEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |ca, cb| {
        diff |= std.ascii.toLower(ca) ^ std.ascii.toLower(cb);
    }
    return diff == 0;
}

fn readU16BE(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}

fn writeU16BE(buf: []u8, val: u16) void {
    buf[0] = @intCast(val >> 8);
    buf[1] = @intCast(val & 0xFF);
}
