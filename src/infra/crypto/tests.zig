/// Crypto module tests — verifies aws-lc C API bindings.
const std = @import("std");
const hash = @import("hash.zig");
const hmac = @import("hmac.zig");
const aead = @import("aead.zig");
const kdf = @import("kdf.zig");
const hkdf = @import("hkdf.zig");
const evp = @import("evp_bytes_to_key.zig");
const ecb = @import("aes_ecb.zig");
const shake = @import("shake.zig");
const rand_mod = @import("rand.zig");

// ── Hash tests ──────────────────────────────────────────────────────

test "sha256 known answer" {
    const result = hash.sha256("hello");
    // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    try std.testing.expectEqual(@as(u8, 0x2c), result[0]);
    try std.testing.expectEqual(@as(u8, 0xf2), result[1]);
    try std.testing.expectEqual(@as(u8, 0x24), result[31]);
}

test "sha224 known answer" {
    const result = hash.sha224("hello");
    // SHA-224("hello") = ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193
    try std.testing.expectEqual(@as(u8, 0xea), result[0]);
    try std.testing.expectEqual(@as(u8, 0x09), result[1]);
}

test "sha224 hex" {
    var hex: [56]u8 = undefined;
    hash.sha224Hex("hello", &hex);
    try std.testing.expectEqualStrings("ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193", &hex);
}

test "md5 known answer" {
    const result = hash.md5("hello");
    // MD5("hello") = 5d41402abc4b2a76b9719d911017c592
    try std.testing.expectEqual(@as(u8, 0x5d), result[0]);
    try std.testing.expectEqual(@as(u8, 0x41), result[1]);
}

test "md5 concat2" {
    const result = try hash.md5Concat2("hel", "lo");
    const direct = hash.md5("hello");
    try std.testing.expectEqualSlices(u8, &direct, &result);
}

test "sha1 known answer" {
    const result = hash.sha1("hello");
    // SHA-1("hello") = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
    try std.testing.expectEqual(@as(u8, 0xaa), result[0]);
    try std.testing.expectEqual(@as(u8, 0xf4), result[1]);
}

// ── HMAC tests ──────────────────────────────────────────────────────

test "hmac-sha256" {
    const result = try hmac.hmacSha256("key", "hello");
    // Known: HMAC-SHA256("key", "hello") starts with specific bytes
    try std.testing.expect(result.len == 32);
    try std.testing.expect(result[0] != 0 or result[1] != 0); // non-trivial
}

test "hmac-md5" {
    const result = try hmac.hmacMd5("key", "hello");
    try std.testing.expect(result.len == 16);
}

// ── AEAD tests ──────────────────────────────────────────────────────

test "aes-128-gcm round-trip" {
    const key = [_]u8{0} ** 16;
    const nonce = [_]u8{0} ** 12;
    const plaintext = "hello world";
    var ciphertext: [plaintext.len + aead.tag_len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const enc_len = try aead.encrypt(.aes_128_gcm, &key, &nonce, plaintext, "", &ciphertext);
    try std.testing.expectEqual(plaintext.len + aead.tag_len, enc_len);

    const dec_len = try aead.decrypt(.aes_128_gcm, &key, &nonce, ciphertext[0..enc_len], "", &decrypted);
    try std.testing.expectEqual(plaintext.len, dec_len);
    try std.testing.expectEqualStrings(plaintext, &decrypted);
}

test "aes-256-gcm round-trip" {
    const key = [_]u8{1} ** 32;
    const nonce = [_]u8{2} ** 12;
    const plaintext = "test data";
    var ciphertext: [plaintext.len + aead.tag_len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const enc_len = try aead.encrypt(.aes_256_gcm, &key, &nonce, plaintext, "", &ciphertext);
    const dec_len = try aead.decrypt(.aes_256_gcm, &key, &nonce, ciphertext[0..enc_len], "", &decrypted);
    try std.testing.expectEqualStrings(plaintext, decrypted[0..dec_len]);
}

test "chacha20-poly1305 round-trip" {
    const key = [_]u8{3} ** 32;
    const nonce = [_]u8{4} ** 12;
    const plaintext = "chacha test";
    var ciphertext: [plaintext.len + aead.tag_len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const enc_len = try aead.encrypt(.chacha20_poly1305, &key, &nonce, plaintext, "", &ciphertext);
    const dec_len = try aead.decrypt(.chacha20_poly1305, &key, &nonce, ciphertext[0..enc_len], "", &decrypted);
    try std.testing.expectEqualStrings(plaintext, decrypted[0..dec_len]);
}

test "aead authentication failure" {
    const key = [_]u8{0} ** 16;
    const nonce = [_]u8{0} ** 12;
    const plaintext = "test";
    var ciphertext: [plaintext.len + aead.tag_len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    _ = try aead.encrypt(.aes_128_gcm, &key, &nonce, plaintext, "", &ciphertext);

    // Corrupt ciphertext
    ciphertext[0] ^= 0xff;

    try std.testing.expectError(
        error.AuthenticationFailed,
        aead.decrypt(.aes_128_gcm, &key, &nonce, &ciphertext, "", &decrypted),
    );
}

// ── AES-ECB tests ───────────────────────────────────────────────────

test "aes-128-ecb round-trip" {
    const key: [16]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const plaintext: [16]u8 = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    var ciphertext: [16]u8 = undefined;
    var decrypted: [16]u8 = undefined;

    try ecb.aes128EcbEncrypt(&key, &plaintext, &ciphertext);
    try ecb.aes128EcbDecrypt(&key, &ciphertext, &decrypted);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

// ── SHAKE128 tests ──────────────────────────────────────────────────

test "shake128 deterministic output" {
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;
    try shake.shake128("test input", &out1);
    try shake.shake128("test input", &out2);
    try std.testing.expectEqualSlices(u8, &out1, &out2);
}

test "shake mask" {
    const nonce = [_]u8{0} ** 16;
    var mask = shake.ShakeMask.init(&nonce);
    _ = try mask.nextMask();
    _ = try mask.nextMask();
}

// ── EVP_BytesToKey tests ────────────────────────────────────────────

test "evp_bytes_to_key 16 bytes" {
    var key: [16]u8 = undefined;
    try evp.deriveKey("password", &key);
    // MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
    try std.testing.expectEqual(@as(u8, 0x5f), key[0]);
    try std.testing.expectEqual(@as(u8, 0x4d), key[1]);
}

test "evp_bytes_to_key 32 bytes" {
    var key: [32]u8 = undefined;
    try evp.deriveKey("password", &key);
    // First 16 bytes = MD5("password")
    try std.testing.expectEqual(@as(u8, 0x5f), key[0]);
    // Bytes 16..31 = MD5(D_0 || "password")
    try std.testing.expect(key[16] != 0 or key[17] != 0); // non-trivial
}

// ── KDF tests ───────────────────────────────────────────────────────

test "vmess kdf deterministic" {
    const result1 = try kdf.kdf1("test key", "test path");
    const result2 = try kdf.kdf1("test key", "test path");
    try std.testing.expectEqualSlices(u8, &result1, &result2);
}

test "vmess kdf different paths produce different results" {
    const r1 = try kdf.kdf1("key", "path_a");
    const r2 = try kdf.kdf1("key", "path_b");
    try std.testing.expect(!std.mem.eql(u8, &r1, &r2));
}

// ── HKDF tests ──────────────────────────────────────────────────────

test "hkdf-sha1 ss subkey derivation" {
    const master_key = [_]u8{0x01} ** 16;
    const salt = [_]u8{0x02} ** 16;
    var subkey: [16]u8 = undefined;
    try hkdf.ssDeriveSubkey(&master_key, &salt, &subkey);
    try std.testing.expect(subkey[0] != 0 or subkey[1] != 0);
}

// ── Random tests ────────────────────────────────────────────────────

test "random bytes non-zero" {
    var buf: [32]u8 = .{0} ** 32;
    try rand_mod.randomBytes(&buf);
    // Extremely unlikely to be all zeros
    var all_zero = true;
    for (buf) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

// ── Nonce builder tests ─────────────────────────────────────────────

test "vmess nonce format" {
    const iv = [_]u8{0xaa} ** 16;
    const nonce = aead.vmessNonce(0x0102, &iv);
    try std.testing.expectEqual(@as(u8, 0x01), nonce[0]);
    try std.testing.expectEqual(@as(u8, 0x02), nonce[1]);
    try std.testing.expectEqual(@as(u8, 0xaa), nonce[2]);
}

test "ss nonce format" {
    const nonce = aead.ssNonce(1);
    try std.testing.expectEqual(@as(u8, 1), nonce[0]);
    try std.testing.expectEqual(@as(u8, 0), nonce[1]);
    try std.testing.expectEqual(@as(u8, 0), nonce[8]);
}
