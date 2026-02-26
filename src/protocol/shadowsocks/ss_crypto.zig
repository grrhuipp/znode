const std = @import("std");
const boringssl = @import("../../crypto/boringssl_crypto.zig");
const Md5 = boringssl.Md5;
const HmacSha1 = boringssl.HmacSha1;
const Aes128Gcm = boringssl.Aes128Gcm;
const Aes256Gcm = boringssl.Aes256Gcm;
const ChaCha20Poly1305 = boringssl.ChaCha20Poly1305;

/// Shadowsocks AEAD cipher methods.
pub const Method = enum(u8) {
    aes_128_gcm = 0,
    aes_256_gcm = 1,
    chacha20_poly1305 = 2,

    pub fn keySize(self: Method) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm, .chacha20_poly1305 => 32,
        };
    }

    pub fn saltSize(self: Method) usize {
        return self.keySize();
    }

    pub fn nonceSize(_: Method) usize {
        return 12; // All three methods use 12-byte nonces
    }

    pub fn tagSize(_: Method) usize {
        return 16; // All three methods use 16-byte tags
    }

    pub fn fromString(s: []const u8) ?Method {
        if (std.mem.eql(u8, s, "aes-128-gcm")) return .aes_128_gcm;
        if (std.mem.eql(u8, s, "aes-256-gcm")) return .aes_256_gcm;
        if (std.mem.eql(u8, s, "chacha20-ietf-poly1305") or
            std.mem.eql(u8, s, "chacha20-poly1305")) return .chacha20_poly1305;
        return null;
    }
};

pub const max_key_size = 32;
pub const tag_size = 16;
pub const max_payload_size = 0x3FFF; // 16383 bytes

/// HKDF-SHA1: used by Shadowsocks to derive per-session subkeys.
const HkdfSha1 = boringssl.HkdfSha1;

/// Derive a pre-shared key (PSK) from a password using EVP_BytesToKey (MD5-based).
/// This is the standard OpenSSL/Shadowsocks key derivation.
pub fn evpBytesToKey(password: []const u8, key_len: usize) [max_key_size]u8 {
    var key: [max_key_size]u8 = [_]u8{0} ** max_key_size;
    var prev_hash: [Md5.digest_length]u8 = undefined;
    var filled: usize = 0;
    var round: u32 = 0;

    while (filled < key_len) {
        var md5 = Md5.init(.{});
        if (round > 0) {
            md5.update(&prev_hash);
        }
        md5.update(password);
        md5.final(&prev_hash);

        const to_copy = @min(Md5.digest_length, key_len - filled);
        @memcpy(key[filled .. filled + to_copy], prev_hash[0..to_copy]);
        filled += to_copy;
        round += 1;
    }
    return key;
}

/// Derive a per-session subkey from PSK + salt using HKDF-SHA1.
/// info = "ss-subkey" (standard Shadowsocks AEAD info string).
pub fn deriveSubkey(psk: []const u8, salt: []const u8, key_len: usize) [max_key_size]u8 {
    var subkey: [max_key_size]u8 = [_]u8{0} ** max_key_size;
    const prk = HkdfSha1.extract(salt, psk);
    HkdfSha1.expand(subkey[0..key_len], "ss-subkey", prk);
    return subkey;
}

/// Increment a 12-byte little-endian nonce by 1.
fn incrementNonce(nonce: *[12]u8) void {
    var carry: u16 = 1;
    for (nonce) |*b| {
        carry += @as(u16, b.*);
        b.* = @intCast(carry & 0xFF);
        carry >>= 8;
        if (carry == 0) break;
    }
}

/// Shadowsocks AEAD stream state for encrypting or decrypting a session.
/// Each direction (encrypt/decrypt) needs its own instance.
pub const StreamState = struct {
    subkey: [max_key_size]u8,
    nonce: [12]u8 = [_]u8{0} ** 12,
    method: Method,

    pub fn init(method: Method, psk: []const u8, salt: []const u8) StreamState {
        return .{
            .subkey = deriveSubkey(psk, salt, method.keySize()),
            .method = method,
        };
    }

    /// Encrypt a single Shadowsocks AEAD frame:
    ///   [encrypted_length(2)][length_tag(16)][encrypted_payload(N)][payload_tag(16)]
    /// Returns total bytes written to `out`.
    pub fn encryptFrame(self: *StreamState, plaintext: []const u8, out: []u8) ?usize {
        const payload_len = plaintext.len;
        if (payload_len > max_payload_size) return null;
        const frame_size = 2 + tag_size + payload_len + tag_size;
        if (out.len < frame_size) return null;

        const key_len = self.method.keySize();
        const key = self.subkey[0..key_len];

        // 1. Encrypt length (2 bytes, big-endian)
        var len_plain: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_plain, @intCast(payload_len), .big);

        self.encrypt(&len_plain, out[0..2], out[2..18], key);
        incrementNonce(&self.nonce);

        // 2. Encrypt payload
        self.encrypt(plaintext, out[18 .. 18 + payload_len], out[18 + payload_len .. 18 + payload_len + tag_size], key);
        incrementNonce(&self.nonce);

        return frame_size;
    }

    /// Decrypt a Shadowsocks AEAD frame from the buffer.
    /// Returns DecryptResult indicating success (with lengths) or need-more-data.
    pub fn decryptFrame(self: *StreamState, data: []const u8, out: []u8) DecryptResult {
        const key_len = self.method.keySize();
        const key = self.subkey[0..key_len];

        // Need at least length header: 2 + 16 = 18 bytes
        if (data.len < 2 + tag_size) return .incomplete;

        // 1. Decrypt length
        var len_plain: [2]u8 = undefined;
        var len_tag: [16]u8 = undefined;
        @memcpy(&len_tag, data[2..18]);
        if (!self.decrypt(data[0..2], len_tag, &len_plain, key)) {
            return .integrity_error;
        }

        const payload_len = std.mem.readInt(u16, &len_plain, .big);
        if (payload_len > max_payload_size) return .integrity_error;

        // Total frame size: 2 + 16 + payload_len + 16
        const frame_size = 2 + tag_size + payload_len + tag_size;
        if (data.len < frame_size) {
            return .incomplete; // Need more data for the payload
        }

        // 2. Decrypt payload
        const payload_start = 2 + tag_size;
        const payload_end = payload_start + payload_len;
        const payload_tag_start = payload_end;

        // Advance nonce past the length decrypt (already consumed)
        incrementNonce(&self.nonce);

        if (out.len < payload_len) return .integrity_error;

        var payload_tag: [16]u8 = undefined;
        @memcpy(&payload_tag, data[payload_tag_start .. payload_tag_start + tag_size]);
        if (!self.decrypt(
            data[payload_start..payload_end],
            payload_tag,
            out[0..payload_len],
            key,
        )) {
            return .integrity_error;
        }
        incrementNonce(&self.nonce);

        return .{ .success = .{
            .plaintext_len = payload_len,
            .bytes_consumed = frame_size,
        } };
    }

    fn encrypt(self: *const StreamState, plaintext: []const u8, ciphertext: []u8, tag_out: []u8, key: []const u8) void {
        switch (self.method) {
            .aes_128_gcm => {
                Aes128Gcm.encrypt(ciphertext, tag_out[0..16], plaintext, &.{}, self.nonce, key[0..16].*);
            },
            .aes_256_gcm => {
                Aes256Gcm.encrypt(ciphertext, tag_out[0..16], plaintext, &.{}, self.nonce, key[0..32].*);
            },
            .chacha20_poly1305 => {
                ChaCha20Poly1305.encrypt(ciphertext, tag_out[0..16], plaintext, &.{}, self.nonce, key[0..32].*);
            },
        }
    }

    fn decrypt(self: *const StreamState, ciphertext: []const u8, tag_arr: [16]u8, plaintext: []u8, key: []const u8) bool {
        switch (self.method) {
            .aes_128_gcm => {
                Aes128Gcm.decrypt(plaintext, ciphertext, tag_arr, &.{}, self.nonce, key[0..16].*) catch return false;
            },
            .aes_256_gcm => {
                Aes256Gcm.decrypt(plaintext, ciphertext, tag_arr, &.{}, self.nonce, key[0..32].*) catch return false;
            },
            .chacha20_poly1305 => {
                ChaCha20Poly1305.decrypt(plaintext, ciphertext, tag_arr, &.{}, self.nonce, key[0..32].*) catch return false;
            },
        }
        return true;
    }
};

pub const DecryptResult = union(enum) {
    success: struct {
        plaintext_len: usize,
        bytes_consumed: usize,
    },
    incomplete,
    integrity_error,
};

// ── Tests ──

test "EVP_BytesToKey basic derivation" {
    // Known test vector: password "foobar", key_len=16
    const key = evpBytesToKey("foobar", 16);
    // MD5("foobar") = 3858f62230ac3c915f300c664312c63f
    try std.testing.expectEqual(@as(u8, 0x38), key[0]);
    try std.testing.expectEqual(@as(u8, 0x58), key[1]);
    try std.testing.expectEqual(@as(u8, 0xf6), key[2]);
}

test "EVP_BytesToKey 32-byte key" {
    const key = evpBytesToKey("test", 32);
    // First 16 bytes = MD5("test")
    // Next 16 bytes = MD5(prev_hash + "test")
    try std.testing.expect(key[0] != 0 or key[1] != 0); // not all zeros
    try std.testing.expect(key[16] != 0 or key[17] != 0);
}

test "HKDF-SHA1 subkey derivation" {
    const psk = [_]u8{0x01} ** 16;
    const salt = [_]u8{0x02} ** 16;
    const subkey = deriveSubkey(&psk, &salt, 16);
    // Verify non-zero and deterministic
    try std.testing.expect(subkey[0] != 0 or subkey[1] != 0);
    const subkey2 = deriveSubkey(&psk, &salt, 16);
    try std.testing.expectEqualSlices(u8, &subkey, &subkey2);
}

test "HKDF-SHA1 different salt produces different key" {
    const psk = [_]u8{0xAA} ** 32;
    const salt1 = [_]u8{0x01} ** 32;
    const salt2 = [_]u8{0x02} ** 32;
    const key1 = deriveSubkey(&psk, &salt1, 32);
    const key2 = deriveSubkey(&psk, &salt2, 32);
    try std.testing.expect(!std.mem.eql(u8, &key1, &key2));
}

test "incrementNonce" {
    var nonce = [_]u8{0} ** 12;
    incrementNonce(&nonce);
    try std.testing.expectEqual(@as(u8, 1), nonce[0]);
    incrementNonce(&nonce);
    try std.testing.expectEqual(@as(u8, 2), nonce[0]);

    // Test carry
    nonce[0] = 0xFF;
    incrementNonce(&nonce);
    try std.testing.expectEqual(@as(u8, 0), nonce[0]);
    try std.testing.expectEqual(@as(u8, 1), nonce[1]);
}

test "StreamState encrypt/decrypt round-trip AES-128-GCM" {
    const psk = evpBytesToKey("test-password", 16);
    const salt = [_]u8{0x42} ** 16;

    var enc = StreamState.init(.aes_128_gcm, psk[0..16], &salt);
    var dec = StreamState.init(.aes_128_gcm, psk[0..16], &salt);

    const plaintext = "Hello, Shadowsocks!";
    var encrypted: [256]u8 = undefined;
    const enc_len = enc.encryptFrame(plaintext, &encrypted) orelse return error.EncryptFailed;

    var decrypted: [256]u8 = undefined;
    const result = dec.decryptFrame(encrypted[0..enc_len], &decrypted);
    switch (result) {
        .success => |s| {
            try std.testing.expectEqualStrings(plaintext, decrypted[0..s.plaintext_len]);
            try std.testing.expectEqual(enc_len, s.bytes_consumed);
        },
        else => return error.DecryptFailed,
    }
}

test "StreamState encrypt/decrypt round-trip AES-256-GCM" {
    const psk = evpBytesToKey("test-password-256", 32);
    const salt = [_]u8{0x55} ** 32;

    var enc = StreamState.init(.aes_256_gcm, psk[0..32], &salt);
    var dec = StreamState.init(.aes_256_gcm, psk[0..32], &salt);

    const plaintext = "AES-256-GCM test data";
    var encrypted: [256]u8 = undefined;
    const enc_len = enc.encryptFrame(plaintext, &encrypted) orelse return error.EncryptFailed;

    var decrypted: [256]u8 = undefined;
    const result = dec.decryptFrame(encrypted[0..enc_len], &decrypted);
    switch (result) {
        .success => |s| {
            try std.testing.expectEqualStrings(plaintext, decrypted[0..s.plaintext_len]);
        },
        else => return error.DecryptFailed,
    }
}

test "StreamState encrypt/decrypt round-trip ChaCha20-Poly1305" {
    const psk = evpBytesToKey("chacha-password", 32);
    const salt = [_]u8{0x77} ** 32;

    var enc = StreamState.init(.chacha20_poly1305, psk[0..32], &salt);
    var dec = StreamState.init(.chacha20_poly1305, psk[0..32], &salt);

    const plaintext = "ChaCha20-Poly1305 test";
    var encrypted: [256]u8 = undefined;
    const enc_len = enc.encryptFrame(plaintext, &encrypted) orelse return error.EncryptFailed;

    var decrypted: [256]u8 = undefined;
    const result = dec.decryptFrame(encrypted[0..enc_len], &decrypted);
    switch (result) {
        .success => |s| {
            try std.testing.expectEqualStrings(plaintext, decrypted[0..s.plaintext_len]);
        },
        else => return error.DecryptFailed,
    }
}

test "StreamState multiple frames" {
    const psk = evpBytesToKey("multi-frame", 16);
    const salt = [_]u8{0xAA} ** 16;

    var enc = StreamState.init(.aes_128_gcm, psk[0..16], &salt);
    var dec = StreamState.init(.aes_128_gcm, psk[0..16], &salt);

    const messages = [_][]const u8{ "first", "second", "third" };
    for (messages) |msg| {
        var encrypted: [256]u8 = undefined;
        const enc_len = enc.encryptFrame(msg, &encrypted) orelse return error.EncryptFailed;

        var decrypted: [256]u8 = undefined;
        const result = dec.decryptFrame(encrypted[0..enc_len], &decrypted);
        switch (result) {
            .success => |s| {
                try std.testing.expectEqualStrings(msg, decrypted[0..s.plaintext_len]);
            },
            else => return error.DecryptFailed,
        }
    }
}

test "StreamState incomplete data" {
    const psk = evpBytesToKey("incomplete-test", 16);
    const salt = [_]u8{0xBB} ** 16;

    var enc = StreamState.init(.aes_128_gcm, psk[0..16], &salt);
    var dec = StreamState.init(.aes_128_gcm, psk[0..16], &salt);

    const plaintext = "test data here";
    var encrypted: [256]u8 = undefined;
    const enc_len = enc.encryptFrame(plaintext, &encrypted) orelse return error.EncryptFailed;

    // Feed partial data
    var decrypted: [256]u8 = undefined;
    const partial = dec.decryptFrame(encrypted[0..10], &decrypted);
    try std.testing.expect(partial == .incomplete);

    // Feed complete data — but nonce state was consumed for the length decrypt
    // Reset decoder to test again cleanly
    var dec2 = StreamState.init(.aes_128_gcm, psk[0..16], &salt);
    const full = dec2.decryptFrame(encrypted[0..enc_len], &decrypted);
    switch (full) {
        .success => |s| {
            try std.testing.expectEqualStrings(plaintext, decrypted[0..s.plaintext_len]);
        },
        else => return error.DecryptFailed,
    }
}

test "Method properties" {
    try std.testing.expectEqual(@as(usize, 16), Method.aes_128_gcm.keySize());
    try std.testing.expectEqual(@as(usize, 32), Method.aes_256_gcm.keySize());
    try std.testing.expectEqual(@as(usize, 32), Method.chacha20_poly1305.keySize());
    try std.testing.expectEqual(@as(usize, 16), Method.aes_128_gcm.saltSize());
    try std.testing.expectEqual(@as(usize, 32), Method.aes_256_gcm.saltSize());
}

test "Method fromString" {
    try std.testing.expectEqual(Method.aes_128_gcm, Method.fromString("aes-128-gcm").?);
    try std.testing.expectEqual(Method.aes_256_gcm, Method.fromString("aes-256-gcm").?);
    try std.testing.expectEqual(Method.chacha20_poly1305, Method.fromString("chacha20-ietf-poly1305").?);
    try std.testing.expectEqual(Method.chacha20_poly1305, Method.fromString("chacha20-poly1305").?);
    try std.testing.expect(Method.fromString("unknown") == null);
}
