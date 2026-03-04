/// HMAC functions backed by aws-lc.
const c = @import("bindings.zig").c;
const CryptoError = @import("hash.zig").CryptoError;

/// HMAC-SHA256(key, data) → 32 bytes.
pub fn hmacSha256(key: []const u8, data: []const u8) CryptoError![32]u8 {
    var out: [32]u8 = undefined;
    var md_len: c_uint = 32;
    const ret = c.HMAC(
        c.EVP_sha256(),
        key.ptr,
        @intCast(key.len),
        data.ptr,
        data.len,
        &out,
        &md_len,
    );
    if (ret == null) return error.CryptoFailed;
    return out;
}

/// HMAC-MD5(key, data) → 16 bytes.
pub fn hmacMd5(key: []const u8, data: []const u8) CryptoError![16]u8 {
    var out: [16]u8 = undefined;
    var md_len: c_uint = 16;
    const ret = c.HMAC(
        c.EVP_md5(),
        key.ptr,
        @intCast(key.len),
        data.ptr,
        data.len,
        &out,
        &md_len,
    );
    if (ret == null) return error.CryptoFailed;
    return out;
}

/// HMAC-SHA1(key, data) → 20 bytes.
pub fn hmacSha1(key: []const u8, data: []const u8) CryptoError![20]u8 {
    var out: [20]u8 = undefined;
    var md_len: c_uint = 20;
    const ret = c.HMAC(
        c.EVP_sha1(),
        key.ptr,
        @intCast(key.len),
        data.ptr,
        data.len,
        &out,
        &md_len,
    );
    if (ret == null) return error.CryptoFailed;
    return out;
}

/// Incremental HMAC-SHA256 context (for multi-part input).
pub const HmacSha256Ctx = struct {
    ctx: *c.HMAC_CTX,

    pub fn init(key: []const u8) CryptoError!HmacSha256Ctx {
        const ctx = c.HMAC_CTX_new() orelse return error.CryptoFailed;
        if (c.HMAC_Init_ex(ctx, key.ptr, key.len, c.EVP_sha256(), null) != 1) {
            c.HMAC_CTX_free(ctx);
            return error.CryptoFailed;
        }
        return .{ .ctx = ctx };
    }

    pub fn update(self: *HmacSha256Ctx, data: []const u8) CryptoError!void {
        if (data.len == 0) return;
        if (c.HMAC_Update(self.ctx, data.ptr, data.len) != 1)
            return error.CryptoFailed;
    }

    pub fn final(self: *HmacSha256Ctx) [32]u8 {
        var out: [32]u8 = undefined;
        var md_len: c_uint = 32;
        _ = c.HMAC_Final(self.ctx, &out, &md_len);
        return out;
    }

    pub fn deinit(self: *HmacSha256Ctx) void {
        c.HMAC_CTX_free(self.ctx);
    }
};
