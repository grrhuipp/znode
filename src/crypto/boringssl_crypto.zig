// Unified crypto wrappers — drop-in replacements for std.crypto types.
//
// API mirrors Zig stdlib signatures so callers only change the import line.
// BoringSSL: NASM-accelerated AEAD, SHA, HMAC, HKDF, AES-ECB, RNG.
// fast_hash.c: Keccak/SHAKE128, CRC32 (IEEE), FNV-1a 32-bit.

const std = @import("std");
const c = @cImport({
    @cInclude("openssl/aead.h");
    @cInclude("openssl/aes.h");
    @cInclude("openssl/hmac.h");
    @cInclude("openssl/hkdf.h");
    @cInclude("openssl/md5.h");
    @cInclude("openssl/rand.h");
    @cInclude("openssl/sha.h");
    @cInclude("openssl/digest.h");
    @cInclude("fast_hash.h");
});

// ── AEAD (Authenticated Encryption with Associated Data) ──

fn aeadSealScatter(
    aead: *const c.EVP_AEAD,
    ct: [*]u8,
    tag: [*]u8,
    pt: [*]const u8,
    pt_len: usize,
    ad: [*]const u8,
    ad_len: usize,
    nonce: [*]const u8,
    nonce_len: usize,
    key: [*]const u8,
    key_len: usize,
) void {
    var ctx: c.EVP_AEAD_CTX = undefined;
    c.EVP_AEAD_CTX_zero(&ctx);
    defer c.EVP_AEAD_CTX_cleanup(&ctx);
    _ = c.EVP_AEAD_CTX_init(&ctx, aead, key, key_len, 16, null);
    var tag_len: usize = 0;
    _ = c.EVP_AEAD_CTX_seal_scatter(
        &ctx,
        ct,
        tag,
        &tag_len,
        16,
        nonce,
        nonce_len,
        pt,
        pt_len,
        null,
        0,
        if (ad_len > 0) ad else null,
        ad_len,
    );
}

fn aeadOpenGather(
    aead: *const c.EVP_AEAD,
    pt: [*]u8,
    ct: [*]const u8,
    ct_len: usize,
    tag: [*]const u8,
    ad: [*]const u8,
    ad_len: usize,
    nonce: [*]const u8,
    nonce_len: usize,
    key: [*]const u8,
    key_len: usize,
) error{AuthenticationFailed}!void {
    var ctx: c.EVP_AEAD_CTX = undefined;
    c.EVP_AEAD_CTX_zero(&ctx);
    defer c.EVP_AEAD_CTX_cleanup(&ctx);
    _ = c.EVP_AEAD_CTX_init(&ctx, aead, key, key_len, 16, null);
    if (c.EVP_AEAD_CTX_open_gather(
        &ctx,
        pt,
        nonce,
        nonce_len,
        ct,
        ct_len,
        tag,
        16,
        if (ad_len > 0) ad else null,
        ad_len,
    ) != 1) {
        return error.AuthenticationFailed;
    }
}

/// AES-128-GCM — drop-in replacement for std.crypto.aead.aes_gcm.Aes128Gcm.
pub const Aes128Gcm = struct {
    pub const tag_length = 16;
    pub const nonce_length = 12;
    pub const key_length = 16;

    pub fn encrypt(ct: []u8, tag: *[16]u8, pt: []const u8, ad: []const u8, nonce: [12]u8, key: [16]u8) void {
        aeadSealScatter(
            c.EVP_aead_aes_128_gcm().?,
            ct.ptr,
            tag,
            pt.ptr,
            pt.len,
            ad.ptr,
            ad.len,
            &nonce,
            12,
            &key,
            16,
        );
    }

    pub fn decrypt(pt: []u8, ct: []const u8, tag: [16]u8, ad: []const u8, nonce: [12]u8, key: [16]u8) error{AuthenticationFailed}!void {
        return aeadOpenGather(
            c.EVP_aead_aes_128_gcm().?,
            pt.ptr,
            ct.ptr,
            ct.len,
            &tag,
            ad.ptr,
            ad.len,
            &nonce,
            12,
            &key,
            16,
        );
    }
};

/// AES-256-GCM — drop-in replacement for std.crypto.aead.aes_gcm.Aes256Gcm.
pub const Aes256Gcm = struct {
    pub const tag_length = 16;
    pub const nonce_length = 12;
    pub const key_length = 32;

    pub fn encrypt(ct: []u8, tag: *[16]u8, pt: []const u8, ad: []const u8, nonce: [12]u8, key: [32]u8) void {
        aeadSealScatter(
            c.EVP_aead_aes_256_gcm().?,
            ct.ptr,
            tag,
            pt.ptr,
            pt.len,
            ad.ptr,
            ad.len,
            &nonce,
            12,
            &key,
            32,
        );
    }

    pub fn decrypt(pt: []u8, ct: []const u8, tag: [16]u8, ad: []const u8, nonce: [12]u8, key: [32]u8) error{AuthenticationFailed}!void {
        return aeadOpenGather(
            c.EVP_aead_aes_256_gcm().?,
            pt.ptr,
            ct.ptr,
            ct.len,
            &tag,
            ad.ptr,
            ad.len,
            &nonce,
            12,
            &key,
            32,
        );
    }
};

/// ChaCha20-Poly1305 — drop-in replacement for std.crypto.aead.chacha_poly.ChaCha20Poly1305.
pub const ChaCha20Poly1305 = struct {
    pub const tag_length = 16;
    pub const nonce_length = 12;
    pub const key_length = 32;

    pub fn encrypt(ct: []u8, tag: *[16]u8, pt: []const u8, ad: []const u8, nonce: [12]u8, key: [32]u8) void {
        aeadSealScatter(
            c.EVP_aead_chacha20_poly1305().?,
            ct.ptr,
            tag,
            pt.ptr,
            pt.len,
            ad.ptr,
            ad.len,
            &nonce,
            12,
            &key,
            32,
        );
    }

    pub fn decrypt(pt: []u8, ct: []const u8, tag: [16]u8, ad: []const u8, nonce: [12]u8, key: [32]u8) error{AuthenticationFailed}!void {
        return aeadOpenGather(
            c.EVP_aead_chacha20_poly1305().?,
            pt.ptr,
            ct.ptr,
            ct.len,
            &tag,
            ad.ptr,
            ad.len,
            &nonce,
            12,
            &key,
            32,
        );
    }
};

// ── Hash Functions ──

/// MD5 — drop-in replacement for std.crypto.hash.Md5.
pub const Md5 = struct {
    pub const digest_length = 16;

    ctx: c.MD5_CTX,

    pub fn init(_: struct {}) Md5 {
        var self: Md5 = undefined;
        _ = c.MD5_Init(&self.ctx);
        return self;
    }

    pub fn update(self: *Md5, data: []const u8) void {
        _ = c.MD5_Update(&self.ctx, data.ptr, data.len);
    }

    pub fn final(self: *Md5, out: *[16]u8) void {
        _ = c.MD5_Final(out, &self.ctx);
    }

    pub fn hash(data: []const u8, out: *[16]u8, _: struct {}) void {
        _ = c.MD5(data.ptr, data.len, out);
    }
};

/// SHA-1 — drop-in replacement for std.crypto.hash.Sha1.
pub const Sha1 = struct {
    pub const digest_length = 20;

    ctx: c.SHA_CTX,

    pub fn init(_: struct {}) Sha1 {
        var self: Sha1 = undefined;
        _ = c.SHA1_Init(&self.ctx);
        return self;
    }

    pub fn update(self: *Sha1, data: []const u8) void {
        _ = c.SHA1_Update(&self.ctx, data.ptr, data.len);
    }

    pub fn finalResult(self: *Sha1) [20]u8 {
        var out: [20]u8 = undefined;
        _ = c.SHA1_Final(&out, &self.ctx);
        return out;
    }
};

/// SHA-224 — drop-in replacement for std.crypto.hash.sha2.Sha224.
pub const Sha224 = struct {
    pub const digest_length = 28;

    pub fn hash(data: []const u8, out: *[28]u8, _: struct {}) void {
        _ = c.SHA224(data.ptr, data.len, out);
    }
};

/// SHA-256 — drop-in replacement for std.crypto.hash.sha2.Sha256.
pub const Sha256 = struct {
    pub const digest_length = 32;

    pub fn hash(data: []const u8, out: *[32]u8, _: struct {}) void {
        _ = c.SHA256(data.ptr, data.len, out);
    }
};

// ── HMAC ──

/// HMAC-SHA256 — drop-in replacement for std.crypto.auth.hmac.sha2.HmacSha256.
pub const HmacSha256 = struct {
    pub fn create(out: *[32]u8, data: []const u8, key: []const u8) void {
        var out_len: c_uint = 32;
        _ = c.HMAC(c.EVP_sha256(), key.ptr, key.len, data.ptr, data.len, out, &out_len);
    }
};

/// HMAC-SHA1 — for HKDF (drop-in replacement for std.crypto.auth.hmac.HmacSha1).
pub const HmacSha1 = struct {
    pub const mac_length = 20;

    pub fn create(out: *[20]u8, data: []const u8, key: []const u8) void {
        var out_len: c_uint = 20;
        _ = c.HMAC(c.EVP_sha1(), key.ptr, key.len, data.ptr, data.len, out, &out_len);
    }
};

// ── HKDF ──

/// HKDF-SHA1 — drop-in replacement for std.crypto.kdf.hkdf.Hkdf(HmacSha1).
pub const HkdfSha1 = struct {
    pub fn extract(salt: []const u8, ikm: []const u8) [20]u8 {
        var prk: [20]u8 = undefined;
        var prk_len: usize = 0;
        _ = c.HKDF_extract(&prk, &prk_len, c.EVP_sha1(), ikm.ptr, ikm.len, salt.ptr, salt.len);
        return prk;
    }

    pub fn expand(out: []u8, info: []const u8, prk: [20]u8) void {
        _ = c.HKDF_expand(
            out.ptr,
            out.len,
            c.EVP_sha1(),
            &prk,
            20,
            if (info.len > 0) info.ptr else null,
            info.len,
        );
    }
};

// ── AES-ECB (block cipher) ──

/// AES-128 ECB — drop-in replacement for std.crypto.core.aes.Aes128.
pub const Aes128 = struct {
    pub const EncCtx = struct {
        key: c.AES_KEY,

        pub fn encrypt(self: *const EncCtx, out: *[16]u8, in_block: *const [16]u8) void {
            c.AES_encrypt(in_block, out, &self.key);
        }
    };

    pub const DecCtx = struct {
        key: c.AES_KEY,

        pub fn decrypt(self: *const DecCtx, out: *[16]u8, in_block: *const [16]u8) void {
            c.AES_decrypt(in_block, out, &self.key);
        }
    };

    pub fn initEnc(key: [16]u8) EncCtx {
        var ctx: EncCtx = undefined;
        _ = c.AES_set_encrypt_key(&key, 128, &ctx.key);
        return ctx;
    }

    pub fn initDec(key: [16]u8) DecCtx {
        var ctx: DecCtx = undefined;
        _ = c.AES_set_decrypt_key(&key, 128, &ctx.key);
        return ctx;
    }
};

// ── Random ──

pub const random = struct {
    pub fn bytes(buf: []u8) void {
        _ = c.RAND_bytes(buf.ptr, buf.len);
    }

    pub fn int(comptime T: type) T {
        var buf: [@sizeOf(T)]u8 = undefined;
        _ = c.RAND_bytes(&buf, @sizeOf(T));
        return std.mem.readInt(T, &buf, .little);
    }
};

// ── Keccak / SHAKE128 ──

/// SHAKE128 XOF — drop-in replacement for std.crypto.hash.sha3.Shake128.
pub const Shake128 = struct {
    /// Accumulated input (absorb phase). Fixed 16-byte buffer suffices for VMess usage.
    nonce: [16]u8 = undefined,
    nonce_len: usize = 0,

    pub fn init(_: struct {}) Shake128 {
        return .{};
    }

    pub fn update(self: *Shake128, data: []const u8) void {
        @memcpy(self.nonce[self.nonce_len..][0..data.len], data);
        self.nonce_len += data.len;
    }

    pub fn squeeze(self: *Shake128, out: []u8) void {
        c.shake128(self.nonce[0..self.nonce_len].ptr, self.nonce_len, out.ptr, out.len);
    }
};

// ── CRC32 (IEEE 802.3) ──

/// CRC32 — drop-in replacement for std.hash.crc.Crc32.
pub const Crc32 = struct {
    pub fn hash(data: []const u8) u32 {
        return c.crc32_hash(data.ptr, data.len);
    }
};

// ── FNV-1a 32-bit ──

/// FNV-1a 32-bit — drop-in replacement for std.hash.Fnv1a_32.
pub const Fnv1a_32 = struct {
    pub fn hash(data: []const u8) u32 {
        return c.fnv1a32(data.ptr, data.len);
    }
};

// ── Tests ──

const testing = std.testing;

test "Aes128Gcm encrypt/decrypt roundtrip" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x01} ** 12;
    const pt = "Hello, BoringSSL!";
    var ct: [pt.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(&ct, &tag, pt, &[_]u8{}, nonce, key);

    var dec: [pt.len]u8 = undefined;
    try Aes128Gcm.decrypt(&dec, &ct, tag, &[_]u8{}, nonce, key);
    try testing.expectEqualStrings(pt, &dec);
}

test "Aes128Gcm with AD" {
    const key = [_]u8{0x55} ** 16;
    const nonce = [_]u8{0x02} ** 12;
    const pt = "data";
    const ad = "auth-data";
    var ct: [pt.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(&ct, &tag, pt, ad, nonce, key);

    var dec: [pt.len]u8 = undefined;
    try Aes128Gcm.decrypt(&dec, &ct, tag, ad, nonce, key);
    try testing.expectEqualStrings(pt, &dec);

    // Wrong AD should fail
    Aes128Gcm.decrypt(&dec, &ct, tag, "wrong", nonce, key) catch return;
    return error.ShouldHaveFailed;
}

test "Aes256Gcm encrypt/decrypt roundtrip" {
    const key = [_]u8{0xAA} ** 32;
    const nonce = [_]u8{0x03} ** 12;
    const pt = "AES-256-GCM test";
    var ct: [pt.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes256Gcm.encrypt(&ct, &tag, pt, &[_]u8{}, nonce, key);

    var dec: [pt.len]u8 = undefined;
    try Aes256Gcm.decrypt(&dec, &ct, tag, &[_]u8{}, nonce, key);
    try testing.expectEqualStrings(pt, &dec);
}

test "ChaCha20Poly1305 encrypt/decrypt roundtrip" {
    const key = [_]u8{0xBB} ** 32;
    const nonce = [_]u8{0x04} ** 12;
    const pt = "ChaCha20 test";
    var ct: [pt.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(&ct, &tag, pt, &[_]u8{}, nonce, key);

    var dec: [pt.len]u8 = undefined;
    try ChaCha20Poly1305.decrypt(&dec, &ct, tag, &[_]u8{}, nonce, key);
    try testing.expectEqualStrings(pt, &dec);
}

test "Aes128Gcm integrity error on corrupted tag" {
    const key = [_]u8{0x60} ** 16;
    const nonce = [_]u8{0x05} ** 12;
    const pt = "integrity test";
    var ct: [pt.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(&ct, &tag, pt, &[_]u8{}, nonce, key);

    tag[0] ^= 0xFF;
    var dec: [pt.len]u8 = undefined;
    Aes128Gcm.decrypt(&dec, &ct, tag, &[_]u8{}, nonce, key) catch return;
    return error.ShouldHaveFailed;
}

test "Md5 incremental and one-shot" {
    const data = "hello";
    var h1: [16]u8 = undefined;
    Md5.hash(data, &h1, .{});

    var ctx = Md5.init(.{});
    ctx.update("hel");
    ctx.update("lo");
    var h2: [16]u8 = undefined;
    ctx.final(&h2);

    try testing.expectEqual(h1, h2);
}

test "Sha256 one-shot" {
    const data = "test";
    var hash: [32]u8 = undefined;
    Sha256.hash(data, &hash, .{});
    try testing.expect(hash[0] != 0 or hash[1] != 0);

    // Deterministic
    var hash2: [32]u8 = undefined;
    Sha256.hash(data, &hash2, .{});
    try testing.expectEqual(hash, hash2);
}

test "HmacSha256 one-shot" {
    var out1: [32]u8 = undefined;
    HmacSha256.create(&out1, "data", "key");
    var out2: [32]u8 = undefined;
    HmacSha256.create(&out2, "data", "key");
    try testing.expectEqual(out1, out2);

    // Different key = different output
    var out3: [32]u8 = undefined;
    HmacSha256.create(&out3, "data", "other");
    try testing.expect(!std.mem.eql(u8, &out1, &out3));
}

test "Aes128 ECB roundtrip" {
    const key = [_]u8{0x42} ** 16;
    const plain = [_]u8{0xDE} ** 16;
    const enc = Aes128.initEnc(key);
    var ct: [16]u8 = undefined;
    enc.encrypt(&ct, &plain);

    const dec_ctx = Aes128.initDec(key);
    var pt: [16]u8 = undefined;
    dec_ctx.decrypt(&pt, &ct);
    try testing.expectEqual(plain, pt);
}

test "HkdfSha1 extract and expand" {
    const salt = [_]u8{0x01} ** 16;
    const ikm = [_]u8{0x02} ** 16;
    const prk = HkdfSha1.extract(&salt, &ikm);

    var out: [32]u8 = undefined;
    HkdfSha1.expand(&out, "info", prk);
    try testing.expect(out[0] != 0 or out[1] != 0);

    // Deterministic
    var out2: [32]u8 = undefined;
    HkdfSha1.expand(&out2, "info", prk);
    try testing.expectEqual(out, out2);
}

test "random bytes" {
    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;
    random.bytes(&buf1);
    random.bytes(&buf2);
    // Extremely unlikely to be equal
    try testing.expect(!std.mem.eql(u8, &buf1, &buf2));
}

test "Shake128 squeeze deterministic" {
    var s1 = Shake128.init(.{});
    s1.update(&([_]u8{0xAB} ** 16));
    var out1: [64]u8 = undefined;
    s1.squeeze(&out1);

    var s2 = Shake128.init(.{});
    s2.update(&([_]u8{0xAB} ** 16));
    var out2: [64]u8 = undefined;
    s2.squeeze(&out2);

    try testing.expectEqual(out1, out2);
    // Not all zeros
    try testing.expect(out1[0] != 0 or out1[1] != 0);
}

test "Shake128 4KB squeeze" {
    var s = Shake128.init(.{});
    const nonce = [_]u8{0x01} ** 16;
    s.update(&nonce);
    var buf: [4096]u8 = undefined;
    s.squeeze(&buf);
    // Spot check: not all zeros
    var all_zero = true;
    for (buf[0..32]) |b| {
        if (b != 0) { all_zero = false; break; }
    }
    try testing.expect(!all_zero);
}

test "Crc32 known vector" {
    // CRC32 of "123456789" = 0xCBF43926
    const crc = Crc32.hash("123456789");
    try testing.expectEqual(@as(u32, 0xCBF43926), crc);
}

test "Crc32 empty" {
    const crc = Crc32.hash(&[_]u8{});
    try testing.expectEqual(@as(u32, 0x00000000), crc);
}

test "Fnv1a_32 known vector" {
    // FNV-1a 32 of "" = 2166136261 (0x811C9DC5)
    const h_empty = Fnv1a_32.hash(&[_]u8{});
    try testing.expectEqual(@as(u32, 0x811C9DC5), h_empty);

    // FNV-1a 32 of "foobar" = 0xBF9CF968
    const h_foobar = Fnv1a_32.hash("foobar");
    try testing.expectEqual(@as(u32, 0xBF9CF968), h_foobar);
}
