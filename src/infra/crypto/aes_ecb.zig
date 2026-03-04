/// AES-128-ECB single block encrypt/decrypt backed by aws-lc.
///
/// Used by VMess AuthID (AES-128-ECB encrypt of [timestamp + random + CRC32]).
const c = @import("bindings.zig").c;
const CryptoError = @import("hash.zig").CryptoError;

/// AES-128-ECB encrypt a single 16-byte block (no padding).
pub fn aes128EcbEncrypt(key: *const [16]u8, plaintext: *const [16]u8, ciphertext: *[16]u8) CryptoError!void {
    const ctx = c.EVP_CIPHER_CTX_new() orelse return error.CryptoFailed;
    defer c.EVP_CIPHER_CTX_free(ctx);

    if (c.EVP_EncryptInit_ex(ctx, c.EVP_aes_128_ecb(), null, key, null) != 1)
        return error.CryptoFailed;
    _ = c.EVP_CIPHER_CTX_set_padding(ctx, 0); // No padding for single block
    var out_len: c_int = 0;
    if (c.EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, 16) != 1)
        return error.CryptoFailed;
}

/// AES-128-ECB decrypt a single 16-byte block (no padding).
pub fn aes128EcbDecrypt(key: *const [16]u8, ciphertext: *const [16]u8, plaintext: *[16]u8) CryptoError!void {
    const ctx = c.EVP_CIPHER_CTX_new() orelse return error.CryptoFailed;
    defer c.EVP_CIPHER_CTX_free(ctx);

    if (c.EVP_DecryptInit_ex(ctx, c.EVP_aes_128_ecb(), null, key, null) != 1)
        return error.CryptoFailed;
    _ = c.EVP_CIPHER_CTX_set_padding(ctx, 0);
    var out_len: c_int = 0;
    if (c.EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, 16) != 1)
        return error.CryptoFailed;
}
