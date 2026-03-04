/// AEAD encrypt/decrypt backed by aws-lc EVP_CIPHER_CTX.
///
/// Supports: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305.
const std = @import("std");
const c = @import("bindings.zig").c;

pub const tag_len = 16;
pub const nonce_len = 12;

pub const AeadError = error{
    AuthenticationFailed,
    CryptoFailed,
};

/// Supported AEAD cipher types.
pub const CipherType = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,

    pub fn keyLen(self: CipherType) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm => 32,
            .chacha20_poly1305 => 32,
        };
    }

    pub fn fromString(s: []const u8) ?CipherType {
        if (std.ascii.eqlIgnoreCase(s, "aes-128-gcm")) return .aes_128_gcm;
        if (std.ascii.eqlIgnoreCase(s, "aes-256-gcm")) return .aes_256_gcm;
        if (std.ascii.eqlIgnoreCase(s, "chacha20-ietf-poly1305") or
            std.ascii.eqlIgnoreCase(s, "chacha20-poly1305")) return .chacha20_poly1305;
        return null;
    }

    fn evpCipher(self: CipherType) ?*const c.EVP_CIPHER {
        return switch (self) {
            .aes_128_gcm => c.EVP_aes_128_gcm(),
            .aes_256_gcm => c.EVP_aes_256_gcm(),
            .chacha20_poly1305 => c.EVP_chacha20_poly1305(),
        };
    }
};

/// AEAD encrypt: plaintext → ciphertext || tag (16 bytes).
/// `out` must have space for plaintext.len + tag_len bytes.
/// Returns total written length (plaintext.len + 16).
pub fn encrypt(
    cipher: CipherType,
    key: []const u8,
    nonce: *const [nonce_len]u8,
    plaintext: []const u8,
    ad: []const u8,
    out: []u8,
) AeadError!usize {
    const evp = cipher.evpCipher() orelse return error.CryptoFailed;
    const ctx = c.EVP_CIPHER_CTX_new() orelse return error.CryptoFailed;
    defer c.EVP_CIPHER_CTX_free(ctx);

    var out_len: c_int = 0;
    var final_len: c_int = 0;

    // Init cipher + set IV length
    if (c.EVP_EncryptInit_ex(ctx, evp, null, null, null) != 1) return error.CryptoFailed;
    if (c.EVP_CIPHER_CTX_ctrl(ctx, c.EVP_CTRL_AEAD_SET_IVLEN, nonce_len, null) != 1)
        return error.CryptoFailed;
    // Set key + nonce
    if (c.EVP_EncryptInit_ex(ctx, null, null, key.ptr, nonce) != 1) return error.CryptoFailed;

    // AAD (optional)
    if (ad.len > 0) {
        if (c.EVP_EncryptUpdate(ctx, null, &out_len, ad.ptr, @intCast(ad.len)) != 1)
            return error.CryptoFailed;
    }

    // Encrypt plaintext
    if (c.EVP_EncryptUpdate(ctx, out.ptr, &out_len, plaintext.ptr, @intCast(plaintext.len)) != 1)
        return error.CryptoFailed;

    // Finalize
    if (c.EVP_EncryptFinal_ex(ctx, out.ptr + @as(usize, @intCast(out_len)), &final_len) != 1)
        return error.CryptoFailed;

    // Extract tag → append after ciphertext
    const ct_total: usize = @intCast(out_len + final_len);
    if (c.EVP_CIPHER_CTX_ctrl(ctx, c.EVP_CTRL_AEAD_GET_TAG, tag_len, out.ptr + ct_total) != 1)
        return error.CryptoFailed;

    return ct_total + tag_len;
}

/// AEAD decrypt: (ciphertext || tag) → plaintext.
/// Returns plaintext length.
pub fn decrypt(
    cipher: CipherType,
    key: []const u8,
    nonce: *const [nonce_len]u8,
    ciphertext_and_tag: []const u8,
    ad: []const u8,
    out: []u8,
) AeadError!usize {
    if (ciphertext_and_tag.len < tag_len) return error.AuthenticationFailed;
    const ct_len = ciphertext_and_tag.len - tag_len;

    const evp = cipher.evpCipher() orelse return error.CryptoFailed;
    const ctx = c.EVP_CIPHER_CTX_new() orelse return error.CryptoFailed;
    defer c.EVP_CIPHER_CTX_free(ctx);

    var out_len: c_int = 0;
    var final_len: c_int = 0;

    // Init cipher + set IV length
    if (c.EVP_DecryptInit_ex(ctx, evp, null, null, null) != 1) return error.CryptoFailed;
    if (c.EVP_CIPHER_CTX_ctrl(ctx, c.EVP_CTRL_AEAD_SET_IVLEN, nonce_len, null) != 1)
        return error.CryptoFailed;
    // Set key + nonce
    if (c.EVP_DecryptInit_ex(ctx, null, null, key.ptr, nonce) != 1) return error.CryptoFailed;

    // AAD (optional)
    if (ad.len > 0) {
        if (c.EVP_DecryptUpdate(ctx, null, &out_len, ad.ptr, @intCast(ad.len)) != 1)
            return error.CryptoFailed;
    }

    // Decrypt ciphertext
    if (c.EVP_DecryptUpdate(ctx, out.ptr, &out_len, ciphertext_and_tag.ptr, @intCast(ct_len)) != 1)
        return error.CryptoFailed;

    // Set expected tag (from end of ciphertext_and_tag)
    // EVP_CTRL_AEAD_SET_TAG expects a mutable pointer, need @constCast
    if (c.EVP_CIPHER_CTX_ctrl(
        ctx,
        c.EVP_CTRL_AEAD_SET_TAG,
        tag_len,
        @constCast(ciphertext_and_tag.ptr + ct_len),
    ) != 1) return error.CryptoFailed;

    // Finalize — verifies tag
    if (c.EVP_DecryptFinal_ex(ctx, out.ptr + @as(usize, @intCast(out_len)), &final_len) != 1) {
        c.ERR_clear_error();
        return error.AuthenticationFailed;
    }

    return @intCast(out_len + final_len);
}

// ── Nonce builders ────────────────────────────────────────────────────

/// VMess nonce: [count_be16][iv[2..12]].
pub fn vmessNonce(count: u16, iv: []const u8) [nonce_len]u8 {
    var nonce: [nonce_len]u8 = undefined;
    nonce[0] = @intCast(count >> 8);
    nonce[1] = @intCast(count & 0xff);
    @memcpy(nonce[2..12], iv[2..12]);
    return nonce;
}

/// Shadowsocks nonce: [counter_le64][0x00000000].
pub fn ssNonce(counter: u64) [nonce_len]u8 {
    var nonce: [nonce_len]u8 = .{0} ** nonce_len;
    std.mem.writeInt(u64, nonce[0..8], counter, .little);
    return nonce;
}
