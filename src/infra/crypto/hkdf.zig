/// HKDF backed by aws-lc.
///
/// Uses the BoringSSL-style HKDF() one-shot function from openssl/hkdf.h.
const c = @import("bindings.zig").c;
const CryptoError = @import("hash.zig").CryptoError;

/// Shadowsocks subkey info string.
pub const ss_subkey_info = "ss-subkey";

/// HKDF-SHA1 one-shot (extract + expand).
pub fn hkdfSha1(
    secret: []const u8,
    salt: []const u8,
    info: []const u8,
    out: []u8,
) CryptoError!void {
    if (c.HKDF(
        out.ptr,
        out.len,
        c.EVP_sha1(),
        secret.ptr,
        secret.len,
        salt.ptr,
        salt.len,
        info.ptr,
        info.len,
    ) != 1) return error.CryptoFailed;
}

/// HKDF-SHA256 one-shot (extract + expand).
pub fn hkdfSha256(
    secret: []const u8,
    salt: []const u8,
    info: []const u8,
    out: []u8,
) CryptoError!void {
    if (c.HKDF(
        out.ptr,
        out.len,
        c.EVP_sha256(),
        secret.ptr,
        secret.len,
        salt.ptr,
        salt.len,
        info.ptr,
        info.len,
    ) != 1) return error.CryptoFailed;
}

/// Derive Shadowsocks session subkey using HKDF-SHA1.
///
/// Parameters:
///   master_key: from EVP_BytesToKey
///   salt:       random salt (len = key_size)
///   out:        output subkey buffer (len = key_size)
pub fn ssDeriveSubkey(master_key: []const u8, salt: []const u8, out: []u8) CryptoError!void {
    try hkdfSha1(master_key, salt, ss_subkey_info, out);
}
