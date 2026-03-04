/// EVP_BytesToKey — Shadowsocks MD5-based iterative key derivation.
///
/// Matches OpenSSL EVP_BytesToKey with MD5, no salt, count=1.
/// D_0 = MD5(password)
/// D_i = MD5(D_{i-1} || password)
/// key = D_0 || D_1 || ... truncated to key_size
const c = @import("bindings.zig").c;
const CryptoError = @import("hash.zig").CryptoError;

/// Derive a key of `key_size` bytes from `password` using iterated MD5.
/// `out` must have length >= `key_size`.
pub fn deriveKey(password: []const u8, out: []u8) CryptoError!void {
    var prev: [16]u8 = undefined;
    var pos: usize = 0;

    while (pos < out.len) {
        const ctx = c.EVP_MD_CTX_new() orelse return error.CryptoFailed;
        defer c.EVP_MD_CTX_free(ctx);

        if (c.EVP_DigestInit_ex(ctx, c.EVP_md5(), null) != 1) return error.CryptoFailed;

        // D_i = MD5(D_{i-1} || password)
        if (pos > 0) {
            if (c.EVP_DigestUpdate(ctx, &prev, 16) != 1) return error.CryptoFailed;
        }
        if (password.len > 0) {
            if (c.EVP_DigestUpdate(ctx, password.ptr, password.len) != 1)
                return error.CryptoFailed;
        }

        var md_len: c_uint = 16;
        if (c.EVP_DigestFinal_ex(ctx, &prev, &md_len) != 1) return error.CryptoFailed;

        // Copy to output
        const remaining = out.len - pos;
        const copy_len = @min(remaining, 16);
        @memcpy(out[pos..][0..copy_len], prev[0..copy_len]);
        pos += copy_len;
    }
}
