/// Shadowsocks AEAD protocol definitions and key derivation.
///
/// Supported ciphers: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305.
/// Key derivation: EVP_BytesToKey (master key) + HKDF-SHA1 (session subkey).
const std = @import("std");
const aead = @import("../../infra/crypto/aead.zig");
const hkdf = @import("../../infra/crypto/hkdf.zig");
const evp = @import("../../infra/crypto/evp_bytes_to_key.zig");
const rand = @import("../../infra/crypto/rand.zig");
const types = @import("../../common/types.zig");

pub const tag_len = aead.tag_len; // 16
pub const nonce_len = aead.nonce_len; // 12
pub const max_key_len = 32;
pub const max_salt_len = 32;
pub const max_payload_size = 0x3FFF; // 16383 bytes per chunk

pub const CipherInfo = struct {
    cipher_type: aead.CipherType,
    key_len: usize,
    salt_len: usize, // == key_len for all standard ciphers

    pub fn fromString(s: []const u8) ?CipherInfo {
        const ct = aead.CipherType.fromString(s) orelse return null;
        const kl = ct.keyLen();
        return .{
            .cipher_type = ct,
            .key_len = kl,
            .salt_len = kl,
        };
    }
};

/// Derive master key from password using EVP_BytesToKey (MD5).
pub fn deriveMasterKey(password: []const u8, key_len: usize, out: []u8) !void {
    std.debug.assert(out.len >= key_len);
    try evp.deriveKey(password, out[0..key_len]);
}

/// Derive session subkey from master key + salt using HKDF-SHA1("ss-subkey").
pub fn deriveSessionKey(master_key: []const u8, salt: []const u8, out: []u8) !void {
    try hkdf.ssDeriveSubkey(master_key, salt, out);
}

/// Generate a random salt.
pub fn generateSalt(buf: []u8) !void {
    try rand.randomBytes(buf);
}

// ── SOCKS5 Address Parsing (shared with Trojan) ──────────────────────────

pub const AddressParseError = error{
    NeedMoreData,
    InvalidAddress,
};

/// Parse SOCKS5-style address from SS payload.
/// Format: [ATYP(1)] [ADDR...] [PORT(2)]
pub fn parseAddress(data: []const u8, index: *usize) AddressParseError!types.TargetAddress {
    if (index.* >= data.len) return error.NeedMoreData;
    const atyp = data[index.*];
    index.* += 1;

    return switch (atyp) {
        0x01 => parseIpv4(data, index),
        0x03 => parseDomain(data, index),
        0x04 => parseIpv6(data, index),
        else => error.InvalidAddress,
    };
}

fn parseIpv4(data: []const u8, index: *usize) AddressParseError!types.TargetAddress {
    if (index.* + 6 > data.len) return error.NeedMoreData;
    var host_buf: [16]u8 = undefined;
    const host = std.fmt.bufPrint(&host_buf, "{d}.{d}.{d}.{d}", .{
        data[index.*], data[index.* + 1], data[index.* + 2], data[index.* + 3],
    }) catch return error.InvalidAddress;
    index.* += 4;
    const port = readU16BE(data[index.*..]);
    index.* += 2;
    return types.TargetAddress.init(host, port, .ipv4);
}

fn parseDomain(data: []const u8, index: *usize) AddressParseError!types.TargetAddress {
    if (index.* >= data.len) return error.NeedMoreData;
    const length = data[index.*];
    if (length == 0) return error.InvalidAddress;
    index.* += 1;
    if (index.* + length + 2 > data.len) return error.NeedMoreData;
    const domain = data[index.* .. index.* + length];
    index.* += length;
    const port = readU16BE(data[index.*..]);
    index.* += 2;
    return types.TargetAddress.init(domain, port, .domain);
}

fn parseIpv6(data: []const u8, index: *usize) AddressParseError!types.TargetAddress {
    if (index.* + 18 > data.len) return error.NeedMoreData;
    var host_buf: [46]u8 = undefined;
    const d = data[index.*..];
    const host = std.fmt.bufPrint(&host_buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
        d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
        d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15],
    }) catch return error.InvalidAddress;
    index.* += 16;
    const port = readU16BE(data[index.*..]);
    index.* += 2;
    return types.TargetAddress.init(host, port, .ipv6);
}

/// Encode SOCKS5-style address into buffer.
pub fn encodeAddress(target: types.TargetAddress, buf: []u8) ?usize {
    var pos: usize = 0;
    switch (target.address_type) {
        .ipv4 => {
            if (pos + 1 + 4 + 2 > buf.len) return null;
            buf[pos] = 0x01;
            pos += 1;
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

fn readU16BE(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}

fn writeU16BE(buf: []u8, val: u16) void {
    buf[0] = @intCast(val >> 8);
    buf[1] = @intCast(val & 0xFF);
}
