/// Hash functions backed by aws-lc (BoringSSL fork).
const c = @import("bindings.zig").c;

pub const CryptoError = error{CryptoFailed};

// ── One-shot hash functions ────────────────────────────────────────────

/// SHA-256: 32-byte digest.
pub fn sha256(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = c.SHA256(data.ptr, data.len, &out);
    return out;
}

/// SHA-224: 28-byte digest.
pub fn sha224(data: []const u8) [28]u8 {
    var out: [28]u8 = undefined;
    _ = c.SHA224(data.ptr, data.len, &out);
    return out;
}

/// SHA-1: 20-byte digest.
pub fn sha1(data: []const u8) [20]u8 {
    var out: [20]u8 = undefined;
    _ = c.SHA1(data.ptr, data.len, &out);
    return out;
}

/// MD5: 16-byte digest.
pub fn md5(data: []const u8) [16]u8 {
    var out: [16]u8 = undefined;
    _ = c.MD5(data.ptr, data.len, &out);
    return out;
}

// ── Incremental / multi-part helpers ───────────────────────────────────

/// MD5(a || b) → 16 bytes. Uses EVP_MD_CTX for multi-part input.
pub fn md5Concat2(a: []const u8, b: []const u8) CryptoError![16]u8 {
    const ctx = c.EVP_MD_CTX_new() orelse return error.CryptoFailed;
    defer c.EVP_MD_CTX_free(ctx);

    if (c.EVP_DigestInit_ex(ctx, c.EVP_md5(), null) != 1) return error.CryptoFailed;
    if (a.len > 0) {
        if (c.EVP_DigestUpdate(ctx, a.ptr, a.len) != 1) return error.CryptoFailed;
    }
    if (b.len > 0) {
        if (c.EVP_DigestUpdate(ctx, b.ptr, b.len) != 1) return error.CryptoFailed;
    }

    var out: [16]u8 = undefined;
    var md_len: c_uint = 16;
    if (c.EVP_DigestFinal_ex(ctx, &out, &md_len) != 1) return error.CryptoFailed;
    return out;
}

/// SHA-224 hex digest (56 hex chars). Used by Trojan password auth.
pub fn sha224Hex(input: []const u8, out: *[56]u8) void {
    const digest = sha224(input);
    const hex_chars = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
}
