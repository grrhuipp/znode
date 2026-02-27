const std = @import("std");
const boringssl = @import("../../crypto/boringssl_crypto.zig");
const Aes128 = boringssl.Aes128;
const HmacSha256 = boringssl.HmacSha256;
const Md5 = boringssl.Md5;
const Sha256 = boringssl.Sha256;
const Crc32 = boringssl.Crc32;
const Shake128 = boringssl.Shake128;

/// VMess magic bytes used in CmdKey derivation.
pub const vmess_magic = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// KDF base salt (innermost HMAC key).
pub const kdf_salt_vmess_aead_kdf = "VMess AEAD KDF";

// KDF salt constants - must match acppnode exactly (note underscores in length salts).
pub const kdf_salt_auth_id_encryption_key = "AES Auth ID Encryption";
pub const kdf_salt_header_key = "VMess Header AEAD Key";
pub const kdf_salt_header_nonce = "VMess Header AEAD Nonce";
pub const kdf_salt_header_len_key = "VMess Header AEAD Key_Length";
pub const kdf_salt_header_len_nonce = "VMess Header AEAD Nonce_Length";
pub const kdf_salt_resp_header_len_key = "AEAD Resp Header Len Key";
pub const kdf_salt_resp_header_len_nonce = "AEAD Resp Header Len IV";
pub const kdf_salt_resp_header_key = "AEAD Resp Header Key";
pub const kdf_salt_resp_header_nonce = "AEAD Resp Header IV";

pub const CmdKey = [16]u8;
pub const AuthKey = [16]u8;
pub const AuthID = [16]u8;

/// Auth ID timestamp tolerance in seconds (matches Xray: ±120s).
pub const auth_id_window: i64 = 120;

/// Maximum VMess chunk payload size encoded by the 2-byte length field.
/// VMess/Xray does not impose a lower fixed cap than the protocol field width.
pub const max_chunk_size: usize = std.math.maxInt(u16);

/// GCM tag size.
pub const gcm_tag_size: usize = 16;

/// ShakeMask buffer size (4KB, matches acppnode).
pub const shake_mask_buffer_size: usize = 4096;

/// Derive CmdKey = MD5(UUID ++ vmess_magic).
pub fn deriveCmdKey(uuid: [16]u8) CmdKey {
    var ctx = Md5.init(.{});
    ctx.update(&uuid);
    ctx.update(vmess_magic);
    var result: CmdKey = undefined;
    ctx.final(&result);
    return result;
}

/// Derive AuthKey = KDF16(cmd_key, "AES Auth ID Encryption").
/// This is the key used for AuthID AES-128-ECB encryption/decryption.
pub fn deriveAuthKey(cmd_key: CmdKey) AuthKey {
    return kdfKey16(&cmd_key, &.{kdf_salt_auth_id_encryption_key});
}

// ── VMess AEAD KDF ──
//
// The KDF is NOT a simple HMAC chain. It is a recursive construction where
// each path element creates a new HMAC using the previous level as the
// underlying hash function.
//
// kdf(key, [p0, p1, p2]):
//   H0(data) = HMAC-SHA256(key="VMess AEAD KDF", data=data)
//   H1(data) = HMAC(key=p0, hash=H0, data=data)
//   H2(data) = HMAC(key=p1, hash=H1, data=data)
//   H3(data) = HMAC(key=p2, hash=H2, data=data)
//   result   = H3(key)
//
// Where HMAC(key=K, hash=H, data=D) = H(K_opad ++ H(K_ipad ++ D))
// and K_ipad = K ^ 0x36, K_opad = K ^ 0x5c (padded to 64 bytes)

/// VMess AEAD KDF: recursive nested HMAC-SHA256.
pub fn kdf(key: []const u8, paths: []const []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    kdfRecursive(key, paths, paths.len, &result);
    return result;
}

/// KDF returning first 16 bytes (for AES-128 key).
pub fn kdfKey16(key: []const u8, paths: []const []const u8) [16]u8 {
    const full = kdf(key, paths);
    return full[0..16].*;
}

/// KDF returning first 12 bytes (for GCM/ChaCha nonce).
pub fn kdfNonce12(key: []const u8, paths: []const []const u8) [12]u8 {
    const full = kdf(key, paths);
    return full[0..12].*;
}

/// Recursive KDF implementation matching acppnode's vmess_kdf_recursive.
fn kdfRecursive(data: []const u8, paths: []const []const u8, depth: usize, out: *[32]u8) void {
    if (depth == 0) {
        // Base case: HMAC-SHA256(key="VMess AEAD KDF", data=data)
        HmacSha256.create(out, data, kdf_salt_vmess_aead_kdf);
        return;
    }

    const path_key = paths[depth - 1];

    // Prepare HMAC key (pad to 64 bytes)
    var k_padded: [64]u8 = [_]u8{0} ** 64;
    if (path_key.len <= 64) {
        @memcpy(k_padded[0..path_key.len], path_key);
    } else {
        // Key longer than block size: hash it first
        var hashed: [32]u8 = undefined;
        kdfRecursive(path_key, paths, depth - 1, &hashed);
        @memcpy(k_padded[0..32], &hashed);
    }

    // ipad = k_padded XOR 0x36
    var ipad: [64]u8 = undefined;
    for (&ipad, k_padded) |*ip, kp| {
        ip.* = kp ^ 0x36;
    }

    // opad = k_padded XOR 0x5c
    var opad: [64]u8 = undefined;
    for (&opad, k_padded) |*op, kp| {
        op.* = kp ^ 0x5c;
    }

    // inner = H_{depth-1}(ipad || data)
    var inner_input: [576]u8 = undefined; // 64 + max ~512 bytes
    @memcpy(inner_input[0..64], &ipad);
    if (data.len > 512) {
        // Fallback: should not happen in normal VMess usage
        @memcpy(inner_input[64 .. 64 + data.len], data);
    } else {
        @memcpy(inner_input[64 .. 64 + data.len], data);
    }

    var inner_hash: [32]u8 = undefined;
    kdfRecursive(inner_input[0 .. 64 + data.len], paths, depth - 1, &inner_hash);

    // outer = H_{depth-1}(opad || inner_hash)
    var outer_input: [96]u8 = undefined; // 64 + 32
    @memcpy(outer_input[0..64], &opad);
    @memcpy(outer_input[64..96], &inner_hash);
    kdfRecursive(&outer_input, paths, depth - 1, out);
}

/// Generate AuthID from AuthKey (NOT CmdKey!) and timestamp.
/// Input: timestamp(8B BE) + random(4B) + crc32(4B) = 16B, AES-128-ECB encrypted.
pub fn generateAuthId(auth_key: AuthKey, timestamp: i64) AuthID {
    return generateAuthIdWithRandom(auth_key, timestamp, boringssl.random.int(u32));
}

/// Generate AuthID with explicit random value (for testing).
pub fn generateAuthIdWithRandom(auth_key: AuthKey, timestamp: i64, random_val: u32) AuthID {
    var block: [16]u8 = undefined;

    // Timestamp as 8 bytes big-endian
    const ts: u64 = @bitCast(timestamp);
    std.mem.writeInt(u64, block[0..8], ts, .big);

    // 4 random bytes
    std.mem.writeInt(u32, block[8..12], random_val, .big);

    // CRC32 of first 12 bytes
    const crc = Crc32.hash(block[0..12]);
    std.mem.writeInt(u32, block[12..16], crc, .big);

    // AES-128-ECB encrypt with auth_key
    const enc = Aes128.initEnc(auth_key);
    var result: AuthID = undefined;
    enc.encrypt(&result, &block);
    return result;
}

/// Validate AuthID: decrypt with auth_key, check CRC32, check timestamp within ±60s.
/// Returns decoded timestamp on success, null on failure.
pub fn validateAuthId(auth_id: AuthID, auth_key: AuthKey, current_time: i64) ?i64 {
    // AES-128-ECB decrypt with auth_key
    const dec = Aes128.initDec(auth_key);
    var block: [16]u8 = undefined;
    dec.decrypt(&block, &auth_id);

    // Extract timestamp
    const ts_raw = std.mem.readInt(u64, block[0..8], .big);
    const timestamp: i64 = @bitCast(ts_raw);

    // Verify CRC32
    const stored_crc = std.mem.readInt(u32, block[12..16], .big);
    const computed_crc = Crc32.hash(block[0..12]);
    if (stored_crc != computed_crc) return null;

    // Check timestamp window (±60s)
    const diff = if (timestamp > current_time) timestamp - current_time else current_time - timestamp;
    if (diff > auth_id_window) return null;

    return timestamp;
}

/// Derive header payload encryption key.
pub fn deriveHeaderKey(cmd_key: CmdKey, auth_id: AuthID, connection_nonce: [8]u8) [16]u8 {
    return kdfKey16(&cmd_key, &.{ kdf_salt_header_key, &auth_id, &connection_nonce });
}

/// Derive header payload encryption nonce.
pub fn deriveHeaderNonce(cmd_key: CmdKey, auth_id: AuthID, connection_nonce: [8]u8) [12]u8 {
    return kdfNonce12(&cmd_key, &.{ kdf_salt_header_nonce, &auth_id, &connection_nonce });
}

/// Derive header length encryption key.
pub fn deriveHeaderLengthKey(cmd_key: CmdKey, auth_id: AuthID, connection_nonce: [8]u8) [16]u8 {
    return kdfKey16(&cmd_key, &.{ kdf_salt_header_len_key, &auth_id, &connection_nonce });
}

/// Derive header length encryption nonce.
pub fn deriveHeaderLengthNonce(cmd_key: CmdKey, auth_id: AuthID, connection_nonce: [8]u8) [12]u8 {
    return kdfNonce12(&cmd_key, &.{ kdf_salt_header_len_nonce, &auth_id, &connection_nonce });
}

/// Derive response header key from request body key: SHA256(body_key)[0..16].
pub fn deriveResponseKey(request_body_key: [16]u8) [16]u8 {
    var hash: [32]u8 = undefined;
    Sha256.hash(&request_body_key, &hash, .{});
    return hash[0..16].*;
}

/// Derive response header nonce from request body IV: SHA256(body_iv)[0..16].
pub fn deriveResponseIv(request_body_iv: [16]u8) [16]u8 {
    var hash: [32]u8 = undefined;
    Sha256.hash(&request_body_iv, &hash, .{});
    return hash[0..16].*;
}

/// Expand 16-byte key to 32-byte key for AES-256-GCM.
/// key32 = SHA-256(key16)
pub fn expandKeyForAes256(key16: [16]u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(&key16, &result, .{});
    return result;
}

/// Expand 16-byte key to 32-byte key for ChaCha20-Poly1305.
/// key32 = MD5(key16) ++ MD5(MD5(key16))
pub fn expandKeyForChaCha(key16: [16]u8) [32]u8 {
    var result: [32]u8 = undefined;
    Md5.hash(&key16, result[0..16], .{});
    Md5.hash(result[0..16], result[16..32], .{});
    return result;
}

/// Compute FNV1a-32 hash over a byte slice, returned as 4 big-endian bytes.
pub fn fnv1a32(data: []const u8) [4]u8 {
    var result: [4]u8 = undefined;
    std.mem.writeInt(u32, &result, boringssl.Fnv1a_32.hash(data), .big);
    return result;
}

/// ShakeMask: 4KB refill buffer over a continuous SHAKE128 stream.
pub const ShakeMask = struct {
    buffer: [shake_mask_buffer_size]u8 = undefined,
    offset: usize = 0,
    initialized: bool = false,
    shake: Shake128,

    pub fn init(nonce: [16]u8) ShakeMask {
        var shake = Shake128.init(.{});
        shake.update(&nonce);
        return .{ .shake = shake };
    }

    fn refill(self: *ShakeMask) void {
        self.shake.squeeze(&self.buffer);
        self.offset = 0;
        self.initialized = true;
    }

    fn ensureInitialized(self: *ShakeMask) void {
        if (!self.initialized) self.refill();
    }

    /// Get next 2-byte mask value (big-endian).
    pub fn nextMask(self: *ShakeMask) u16 {
        self.ensureInitialized();
        // Refill from the SHAKE stream when the current 4KB block is exhausted.
        if (self.offset + 2 > shake_mask_buffer_size) {
            self.refill();
        }
        const result = (@as(u16, self.buffer[self.offset]) << 8) |
            @as(u16, self.buffer[self.offset + 1]);
        self.offset += 2;
        return result;
    }
};

// ── Tests ──

test "deriveCmdKey deterministic" {
    const uuid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const key1 = deriveCmdKey(uuid);
    const key2 = deriveCmdKey(uuid);
    try std.testing.expectEqual(key1, key2);
}

test "deriveCmdKey different UUIDs differ" {
    const uuid1 = [_]u8{1} ** 16;
    const uuid2 = [_]u8{2} ** 16;
    const key1 = deriveCmdKey(uuid1);
    const key2 = deriveCmdKey(uuid2);
    try std.testing.expect(!std.mem.eql(u8, &key1, &key2));
}

test "deriveAuthKey from CmdKey" {
    const uuid = [_]u8{0x42} ** 16;
    const cmd_key = deriveCmdKey(uuid);
    const auth_key = deriveAuthKey(cmd_key);
    // auth_key should differ from cmd_key
    try std.testing.expect(!std.mem.eql(u8, &auth_key, &cmd_key));
    // Should be deterministic
    const auth_key2 = deriveAuthKey(cmd_key);
    try std.testing.expectEqual(auth_key, auth_key2);
}

test "kdf single path" {
    const result = kdf("test-key", &.{"path0"});
    const result2 = kdf("test-key", &.{"path0"});
    try std.testing.expectEqual(result, result2);
}

test "kdf multi path" {
    const single = kdf("key", &.{"a"});
    const multi = kdf("key", &.{ "a", "b" });
    try std.testing.expect(!std.mem.eql(u8, &single, &multi));
}

test "kdf different keys differ" {
    const r1 = kdf("key1", &.{"path"});
    const r2 = kdf("key2", &.{"path"});
    try std.testing.expect(!std.mem.eql(u8, &r1, &r2));
}

test "generateAuthId and validateAuthId roundtrip" {
    const uuid = [_]u8{ 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78 };
    const cmd_key = deriveCmdKey(uuid);
    const auth_key = deriveAuthKey(cmd_key);
    const now: i64 = 1700000000;
    const auth_id = generateAuthIdWithRandom(auth_key, now, 0x12345678);
    const validated = validateAuthId(auth_id, auth_key, now);
    try std.testing.expect(validated != null);
    try std.testing.expectEqual(now, validated.?);
}

test "validateAuthId accepts within window" {
    const cmd_key = [_]u8{0x42} ** 16;
    const auth_key = deriveAuthKey(cmd_key);
    const ts: i64 = 1700000000;
    const auth_id = generateAuthIdWithRandom(auth_key, ts, 0xAABBCCDD);
    // Should accept at ts+50 (within 60s)
    try std.testing.expect(validateAuthId(auth_id, auth_key, ts + 50) != null);
    // Should accept at ts-50
    try std.testing.expect(validateAuthId(auth_id, auth_key, ts - 50) != null);
}

test "validateAuthId rejects wrong key" {
    const cmd_key = [_]u8{0x01} ** 16;
    const auth_key = deriveAuthKey(cmd_key);
    const wrong_key = [_]u8{0x02} ** 16;
    const auth_id = generateAuthIdWithRandom(auth_key, 1700000000, 0);
    try std.testing.expect(validateAuthId(auth_id, wrong_key, 1700000000) == null);
}

test "validateAuthId rejects expired timestamp" {
    const cmd_key = [_]u8{0x03} ** 16;
    const auth_key = deriveAuthKey(cmd_key);
    const ts: i64 = 1700000000;
    const auth_id = generateAuthIdWithRandom(auth_key, ts, 0);
    // 200 seconds later - outside 120s window
    try std.testing.expect(validateAuthId(auth_id, auth_key, ts + 200) == null);
}

test "validateAuthId rejects corrupted data" {
    const cmd_key = [_]u8{0x04} ** 16;
    const auth_key = deriveAuthKey(cmd_key);
    var auth_id = generateAuthIdWithRandom(auth_key, 1700000000, 0);
    auth_id[5] ^= 0x01;
    try std.testing.expect(validateAuthId(auth_id, auth_key, 1700000000) == null);
}

test "deriveHeaderKey deterministic" {
    const cmd_key = [_]u8{0x10} ** 16;
    const auth_id = [_]u8{0x20} ** 16;
    const nonce = [_]u8{0x30} ** 8;
    const k1 = deriveHeaderKey(cmd_key, auth_id, nonce);
    const k2 = deriveHeaderKey(cmd_key, auth_id, nonce);
    try std.testing.expectEqual(k1, k2);
}

test "deriveHeaderKey and Nonce differ" {
    const cmd_key = [_]u8{0x10} ** 16;
    const auth_id = [_]u8{0x20} ** 16;
    const nonce = [_]u8{0x30} ** 8;
    const key = deriveHeaderKey(cmd_key, auth_id, nonce);
    const n = deriveHeaderNonce(cmd_key, auth_id, nonce);
    try std.testing.expect(!std.mem.eql(u8, key[0..12], &n));
}

test "deriveResponseKey from SHA256" {
    const body_key = [_]u8{0x55} ** 16;
    const resp_key = deriveResponseKey(body_key);
    var hash: [32]u8 = undefined;
    Sha256.hash(&body_key, &hash, .{});
    try std.testing.expectEqual(hash[0..16].*, resp_key);
}

test "expandKeyForAes256 produces 32 bytes from SHA-256" {
    const key16 = [_]u8{0xBB} ** 16;
    const key32 = expandKeyForAes256(key16);
    var expected: [32]u8 = undefined;
    Sha256.hash(&key16, &expected, .{});
    try std.testing.expectEqual(expected, key32);
}

test "expandKeyForChaCha produces 32 bytes" {
    const key16 = [_]u8{0xAA} ** 16;
    const key32 = expandKeyForChaCha(key16);
    var expected_first: [16]u8 = undefined;
    Md5.hash(&key16, &expected_first, .{});
    try std.testing.expectEqual(expected_first, key32[0..16].*);
    var expected_second: [16]u8 = undefined;
    Md5.hash(&expected_first, &expected_second, .{});
    try std.testing.expectEqual(expected_second, key32[16..32].*);
}

test "fnv1a32 known value" {
    const empty = fnv1a32(&[_]u8{});
    const offset_basis: u32 = 0x811c9dc5;
    const expected = std.mem.toBytes(std.mem.nativeTo(u32, offset_basis, .big));
    try std.testing.expectEqual(expected, empty);
}

test "fnv1a32 deterministic" {
    const data = "hello world";
    const h1 = fnv1a32(data);
    const h2 = fnv1a32(data);
    try std.testing.expectEqual(h1, h2);
}

test "ShakeMask deterministic" {
    const nonce = [_]u8{0x42} ** 16;
    var mask1 = ShakeMask.init(nonce);
    var mask2 = ShakeMask.init(nonce);

    // Same nonce should produce same masks
    const m1 = mask1.nextMask();
    const m2 = mask2.nextMask();
    try std.testing.expectEqual(m1, m2);
}

test "ShakeMask sequential values differ" {
    const nonce = [_]u8{0x55} ** 16;
    var mask = ShakeMask.init(nonce);

    const m1 = mask.nextMask();
    const m2 = mask.nextMask();
    // Very unlikely to be the same (2^-16 probability)
    try std.testing.expect(m1 != m2);
}

// ── Cross-Implementation Verification Tests ──
//
// These tests verify that znode produces identical results to acppnode/V2Ray
// for each cryptographic primitive. Test vectors use fixed inputs so results
// can be compared across implementations.

test "CRC32 matches zlib (standard CRC-32/ISO-HDLC)" {
    // Standard test vector: CRC32("123456789") = 0xCBF43926
    const crc1 = Crc32.hash("123456789");
    try std.testing.expectEqual(@as(u32, 0xCBF43926), crc1);

    // Empty input: CRC32("") = 0x00000000
    const crc_empty = Crc32.hash(&[_]u8{});
    try std.testing.expectEqual(@as(u32, 0x00000000), crc_empty);

    // Single byte: CRC32("\x00") - known value
    const crc_zero = Crc32.hash(&[_]u8{0x00});
    try std.testing.expectEqual(@as(u32, 0xD202EF8D), crc_zero);
}

test "FNV1a32 matches reference implementation" {
    // FNV-1a specification test vectors (big-endian output)
    // FNV1a32("") = 0x811c9dc5 (offset basis)
    const empty = fnv1a32(&[_]u8{});
    try std.testing.expectEqual([_]u8{ 0x81, 0x1c, 0x9d, 0xc5 }, empty);

    // FNV1a32("a") = 0xe40c292c
    const a = fnv1a32("a");
    try std.testing.expectEqual([_]u8{ 0xe4, 0x0c, 0x29, 0x2c }, a);

    // FNV1a32("foobar") = 0xbf9cf968
    const foobar = fnv1a32("foobar");
    try std.testing.expectEqual([_]u8{ 0xbf, 0x9c, 0xf9, 0x68 }, foobar);
}

test "CmdKey derivation: MD5(UUID || magic) matches acppnode VMessUser::FromUUID" {
    // Test UUID: b831381d-6324-4d53-ad4f-8cda48b30811 (common test UUID)
    const uuid = [_]u8{ 0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11 };

    const cmd_key = deriveCmdKey(uuid);

    // Manually compute: MD5(uuid ++ "c48619fe-8f02-49e0-b9e9-edf763e17e21")
    var ctx = Md5.init(.{});
    ctx.update(&uuid);
    ctx.update(vmess_magic);
    var expected: [16]u8 = undefined;
    ctx.final(&expected);

    try std.testing.expectEqual(expected, cmd_key);

    // Verify magic string is exactly 36 bytes (UUID format without braces)
    try std.testing.expectEqual(@as(usize, 36), vmess_magic.len);
}

test "AuthKey derivation: KDF16(CmdKey, 'AES Auth ID Encryption')" {
    const uuid = [_]u8{ 0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11 };
    const cmd_key = deriveCmdKey(uuid);
    const auth_key = deriveAuthKey(cmd_key);

    // Must equal KDF16(cmd_key, ["AES Auth ID Encryption"])
    const expected = kdfKey16(&cmd_key, &.{kdf_salt_auth_id_encryption_key});
    try std.testing.expectEqual(expected, auth_key);

    // AuthKey must differ from CmdKey (KDF transforms it)
    try std.testing.expect(!std.mem.eql(u8, &auth_key, &cmd_key));
}

test "KDF recursive: single path matches HMAC(key=path, hash=HMAC(VMess AEAD KDF, .))" {
    // For KDF(data, [path]):
    //   H0(x) = HMAC-SHA256(key="VMess AEAD KDF", x)
    //   H1(x) = Manual-HMAC(key=path, hash=H0, x)
    //   result = H1(data)
    //
    // H1(data) = H0(opad || H0(ipad || data))
    // where ipad = path ^ 0x36 (padded to 64), opad = path ^ 0x5c (padded to 64)

    const data = "test-input";
    const path = "test-path";

    const result = kdf(data, &.{path});

    // Verify by manual computation:
    // 1. Prepare k_padded = "test-path" zero-padded to 64 bytes
    var k_padded: [64]u8 = [_]u8{0} ** 64;
    @memcpy(k_padded[0..path.len], path);

    // 2. ipad = k_padded XOR 0x36
    var ipad: [64]u8 = undefined;
    for (&ipad, k_padded) |*ip, kp| ip.* = kp ^ 0x36;

    // 3. opad = k_padded XOR 0x5c
    var opad: [64]u8 = undefined;
    for (&opad, k_padded) |*op, kp| op.* = kp ^ 0x5c;

    // 4. inner = H0(ipad || data) = HMAC-SHA256(key="VMess AEAD KDF", ipad || data)
    var inner_input: [64 + data.len]u8 = undefined;
    @memcpy(inner_input[0..64], &ipad);
    @memcpy(inner_input[64..], data);
    var inner: [32]u8 = undefined;
    HmacSha256.create(&inner, &inner_input, kdf_salt_vmess_aead_kdf);

    // 5. result = H0(opad || inner)
    var outer_input: [96]u8 = undefined;
    @memcpy(outer_input[0..64], &opad);
    @memcpy(outer_input[64..96], &inner);
    var expected: [32]u8 = undefined;
    HmacSha256.create(&expected, &outer_input, kdf_salt_vmess_aead_kdf);

    try std.testing.expectEqual(expected, result);
}

test "AuthID generation: AES-128-ECB(auth_key, [ts_be64 || random_be32 || crc32_be32])" {
    const auth_key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const timestamp: i64 = 1700000000;
    const random_val: u32 = 0xDEADBEEF;

    const auth_id = generateAuthIdWithRandom(auth_key, timestamp, random_val);

    // Manually construct plaintext
    var plaintext: [16]u8 = undefined;
    const ts: u64 = @bitCast(timestamp);
    std.mem.writeInt(u64, plaintext[0..8], ts, .big);
    std.mem.writeInt(u32, plaintext[8..12], random_val, .big);
    const crc = Crc32.hash(plaintext[0..12]);
    std.mem.writeInt(u32, plaintext[12..16], crc, .big);

    // AES-128-ECB encrypt
    const enc = Aes128.initEnc(auth_key);
    var expected: [16]u8 = undefined;
    enc.encrypt(&expected, &plaintext);

    try std.testing.expectEqual(expected, auth_id);

    // Verify roundtrip
    const validated = validateAuthId(auth_id, auth_key, timestamp);
    try std.testing.expect(validated != null);
    try std.testing.expectEqual(timestamp, validated.?);
}

test "AuthID plaintext layout: big-endian timestamp + random + CRC32" {
    // Verify the exact byte layout of AuthID plaintext
    const timestamp: i64 = 0x0000000065729F80; // 1702035328 in decimal
    const random_val: u32 = 0xAABBCCDD;

    var plaintext: [16]u8 = undefined;
    const ts: u64 = @bitCast(timestamp);
    std.mem.writeInt(u64, plaintext[0..8], ts, .big);
    std.mem.writeInt(u32, plaintext[8..12], random_val, .big);

    // Verify big-endian timestamp bytes
    try std.testing.expectEqual(@as(u8, 0x00), plaintext[0]);
    try std.testing.expectEqual(@as(u8, 0x00), plaintext[1]);
    try std.testing.expectEqual(@as(u8, 0x00), plaintext[2]);
    try std.testing.expectEqual(@as(u8, 0x00), plaintext[3]);
    try std.testing.expectEqual(@as(u8, 0x65), plaintext[4]);
    try std.testing.expectEqual(@as(u8, 0x72), plaintext[5]);
    try std.testing.expectEqual(@as(u8, 0x9F), plaintext[6]);
    try std.testing.expectEqual(@as(u8, 0x80), plaintext[7]);

    // Verify big-endian random bytes
    try std.testing.expectEqual(@as(u8, 0xAA), plaintext[8]);
    try std.testing.expectEqual(@as(u8, 0xBB), plaintext[9]);
    try std.testing.expectEqual(@as(u8, 0xCC), plaintext[10]);
    try std.testing.expectEqual(@as(u8, 0xDD), plaintext[11]);

    // CRC32 of first 12 bytes, stored big-endian
    const crc = Crc32.hash(plaintext[0..12]);
    std.mem.writeInt(u32, plaintext[12..16], crc, .big);
    const stored_crc = std.mem.readInt(u32, plaintext[12..16], .big);
    try std.testing.expectEqual(crc, stored_crc);
}

test "header key derivation: KDF paths = [salt_str, auth_id_raw, nonce_raw]" {
    // Verify that deriveHeaderKey/Nonce use raw bytes for auth_id and nonce (not hex strings)
    const cmd_key = [_]u8{ 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90 };
    const auth_id = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
    const nonce = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };

    // Header length key uses "VMess Header AEAD Key_Length" salt (note underscore!)
    const len_key = deriveHeaderLengthKey(cmd_key, auth_id, nonce);
    const expected_len_key = kdfKey16(&cmd_key, &.{ kdf_salt_header_len_key, &auth_id, &nonce });
    try std.testing.expectEqual(expected_len_key, len_key);

    // Header payload key uses "VMess Header AEAD Key" salt (no underscore)
    const hdr_key = deriveHeaderKey(cmd_key, auth_id, nonce);
    const expected_hdr_key = kdfKey16(&cmd_key, &.{ kdf_salt_header_key, &auth_id, &nonce });
    try std.testing.expectEqual(expected_hdr_key, hdr_key);

    // Length key and header key must differ (different salt strings)
    try std.testing.expect(!std.mem.eql(u8, &len_key, &hdr_key));

    // Nonce derivation uses first 12 bytes of full KDF output
    const len_nonce = deriveHeaderLengthNonce(cmd_key, auth_id, nonce);
    const expected_len_nonce = kdfNonce12(&cmd_key, &.{ kdf_salt_header_len_nonce, &auth_id, &nonce });
    try std.testing.expectEqual(expected_len_nonce, len_nonce);
}

test "response key derivation: SHA256 truncated to 16 bytes" {
    const body_key = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00 };
    const body_iv = [_]u8{ 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };

    const resp_key = deriveResponseKey(body_key);
    const resp_iv = deriveResponseIv(body_iv);

    // resp_key = SHA256(body_key)[0..16]
    var key_hash: [32]u8 = undefined;
    Sha256.hash(&body_key, &key_hash, .{});
    try std.testing.expectEqual(key_hash[0..16].*, resp_key);

    // resp_iv = SHA256(body_iv)[0..16]
    var iv_hash: [32]u8 = undefined;
    Sha256.hash(&body_iv, &iv_hash, .{});
    try std.testing.expectEqual(iv_hash[0..16].*, resp_iv);

    // resp_key != body_key (SHA256 transforms it)
    try std.testing.expect(!std.mem.eql(u8, &resp_key, &body_key));
    // resp_iv != body_iv
    try std.testing.expect(!std.mem.eql(u8, &resp_iv, &body_iv));
}

test "ChaCha20 key expansion: MD5(key) || MD5(MD5(key)) matches acppnode" {
    // acppnode: key32[0:16] = MD5(key16), key32[16:32] = MD5(key32[0:16])
    const key16 = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const key32 = expandKeyForChaCha(key16);

    // First half: MD5(key16)
    var first_half: [16]u8 = undefined;
    Md5.hash(&key16, &first_half, .{});
    try std.testing.expectEqual(first_half, key32[0..16].*);

    // Second half: MD5(first_half) = MD5(MD5(key16))
    var second_half: [16]u8 = undefined;
    Md5.hash(&first_half, &second_half, .{});
    try std.testing.expectEqual(second_half, key32[16..32].*);
}

test "full key derivation chain: UUID -> CmdKey -> AuthKey -> AuthID -> header keys" {
    // End-to-end test with a realistic UUID
    const uuid = [_]u8{ 0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11 };
    const timestamp: i64 = 1700000000;
    const random_val: u32 = 0x42424242;
    const connection_nonce = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    // Step 1: CmdKey = MD5(UUID || magic)
    const cmd_key = deriveCmdKey(uuid);

    // Step 2: AuthKey = KDF16(CmdKey, ["AES Auth ID Encryption"])
    const auth_key = deriveAuthKey(cmd_key);

    // Step 3: AuthID = AES-ECB(auth_key, [ts || random || crc32])
    const auth_id = generateAuthIdWithRandom(auth_key, timestamp, random_val);

    // Step 4: Validate AuthID roundtrip
    const ts = validateAuthId(auth_id, auth_key, timestamp).?;
    try std.testing.expectEqual(timestamp, ts);

    // Step 5: Header length key/nonce = KDF(cmd_key, [salt, auth_id, nonce])
    const len_key = deriveHeaderLengthKey(cmd_key, auth_id, connection_nonce);
    const len_nonce = deriveHeaderLengthNonce(cmd_key, auth_id, connection_nonce);

    // Step 6: Header payload key/nonce = KDF(cmd_key, [salt, auth_id, nonce])
    const hdr_key = deriveHeaderKey(cmd_key, auth_id, connection_nonce);
    const hdr_nonce = deriveHeaderNonce(cmd_key, auth_id, connection_nonce);

    // All derived keys must be different from each other
    try std.testing.expect(!std.mem.eql(u8, &len_key, &hdr_key));
    try std.testing.expect(!std.mem.eql(u8, &len_nonce, &hdr_nonce));
    try std.testing.expect(!std.mem.eql(u8, &len_key, &cmd_key));
    try std.testing.expect(!std.mem.eql(u8, &hdr_key, &cmd_key));

    // Step 7: Response keys
    const body_key = [_]u8{0x42} ** 16;
    const body_iv = [_]u8{0x43} ** 16;
    const resp_key = deriveResponseKey(body_key);
    const resp_iv = deriveResponseIv(body_iv);

    // Response header length key/nonce use resp_key/resp_iv
    const resp_len_key = kdfKey16(&resp_key, &.{kdf_salt_resp_header_len_key});
    const resp_len_nonce = kdfNonce12(&resp_iv, &.{kdf_salt_resp_header_len_nonce});
    const resp_hdr_key = kdfKey16(&resp_key, &.{kdf_salt_resp_header_key});
    const resp_hdr_nonce = kdfNonce12(&resp_iv, &.{kdf_salt_resp_header_nonce});

    // All response keys must differ
    try std.testing.expect(!std.mem.eql(u8, &resp_len_key, &resp_hdr_key));
    try std.testing.expect(!std.mem.eql(u8, &resp_len_nonce, &resp_hdr_nonce));
}

test "cross-implementation: KDF matches Xray-core Go reference" {
    // Reference values computed by Xray-core Go implementation (go.dev/play)
    // UUID: bf417eb3-d283-5487-b6ad-9a9be278be8a
    const uuid = [_]u8{ 0xbf, 0x41, 0x7e, 0xb3, 0xd2, 0x83, 0x54, 0x87, 0xb6, 0xad, 0x9a, 0x9b, 0xe2, 0x78, 0xbe, 0x8a };
    const timestamp: i64 = 1700000000;
    const random_val: u32 = 0xDEADBEEF;
    const connection_nonce = [_]u8{0x42} ** 8;

    // Step 1: CmdKey = MD5(UUID || vmess_magic)
    const cmd_key = deriveCmdKey(uuid);
    // Go: 51cdabe371fe6dd7f8f67e16beaa5adc
    try std.testing.expectEqual([_]u8{ 0x51, 0xcd, 0xab, 0xe3, 0x71, 0xfe, 0x6d, 0xd7, 0xf8, 0xf6, 0x7e, 0x16, 0xbe, 0xaa, 0x5a, 0xdc }, cmd_key);

    // Step 2: AuthKey = KDF16(CmdKey, "AES Auth ID Encryption")
    const auth_key = deriveAuthKey(cmd_key);
    // Go: 3051e6c95c3533be40abd85a61e285ab
    try std.testing.expectEqual([_]u8{ 0x30, 0x51, 0xe6, 0xc9, 0x5c, 0x35, 0x33, 0xbe, 0x40, 0xab, 0xd8, 0x5a, 0x61, 0xe2, 0x85, 0xab }, auth_key);

    // Step 3: AuthID plaintext = [ts_be64 || random_be32 || crc32_be32]
    // Go: 000000006553f100deadbeef72f52d60
    const auth_id = generateAuthIdWithRandom(auth_key, timestamp, random_val);
    // Go encrypted: aecdf507eff0267642c5d072917f7aae
    try std.testing.expectEqual([_]u8{ 0xae, 0xcd, 0xf5, 0x07, 0xef, 0xf0, 0x26, 0x76, 0x42, 0xc5, 0xd0, 0x72, 0x91, 0x7f, 0x7a, 0xae }, auth_id);

    // Step 4: Header length key (3-path KDF)
    const len_key = deriveHeaderLengthKey(cmd_key, auth_id, connection_nonce);
    // Go: 333248d6a9148fb98cf65fda3140878a
    try std.testing.expectEqual([_]u8{ 0x33, 0x32, 0x48, 0xd6, 0xa9, 0x14, 0x8f, 0xb9, 0x8c, 0xf6, 0x5f, 0xda, 0x31, 0x40, 0x87, 0x8a }, len_key);

    // Step 5: Header length nonce (3-path KDF, 12 bytes)
    const len_nonce = deriveHeaderLengthNonce(cmd_key, auth_id, connection_nonce);
    // Go: 12714d30dc463ab4241ca3b6
    try std.testing.expectEqual([_]u8{ 0x12, 0x71, 0x4d, 0x30, 0xdc, 0x46, 0x3a, 0xb4, 0x24, 0x1c, 0xa3, 0xb6 }, len_nonce);

    // Step 6: Header payload key (3-path KDF)
    const hdr_key = deriveHeaderKey(cmd_key, auth_id, connection_nonce);
    // Go: ce8cdd1cd82e20cb22381a4eab909457
    try std.testing.expectEqual([_]u8{ 0xce, 0x8c, 0xdd, 0x1c, 0xd8, 0x2e, 0x20, 0xcb, 0x22, 0x38, 0x1a, 0x4e, 0xab, 0x90, 0x94, 0x57 }, hdr_key);

    // Step 7: Header payload nonce (3-path KDF, 12 bytes)
    const hdr_nonce = deriveHeaderNonce(cmd_key, auth_id, connection_nonce);
    // Go: 096a2af11b2f2986d97279f9
    try std.testing.expectEqual([_]u8{ 0x09, 0x6a, 0x2a, 0xf1, 0x1b, 0x2f, 0x29, 0x86, 0xd9, 0x72, 0x79, 0xf9 }, hdr_nonce);
}

test "ShakeMask buffer is SHAKE128 of 16-byte nonce" {
    // Verify ShakeMask generates SHAKE128 output correctly
    const nonce = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
    var mask = ShakeMask.init(nonce);

    // Force initialization
    const m1 = mask.nextMask();

    // Manually compute SHAKE128
    var expected_buf: [shake_mask_buffer_size]u8 = undefined;
    var shake = Shake128.init(.{});
    shake.update(&nonce);
    shake.squeeze(&expected_buf);

    // First mask value should be big-endian read of first 2 bytes
    const expected_m1 = (@as(u16, expected_buf[0]) << 8) | @as(u16, expected_buf[1]);
    try std.testing.expectEqual(expected_m1, m1);

    // Second mask value
    const m2 = mask.nextMask();
    const expected_m2 = (@as(u16, expected_buf[2]) << 8) | @as(u16, expected_buf[3]);
    try std.testing.expectEqual(expected_m2, m2);
}

test "ShakeMask refill at 4096 boundary continues stream" {
    const nonce = [_]u8{0x42} ** 16;
    var mask = ShakeMask.init(nonce);

    // Consume all 2048 mask values (4096 bytes / 2 bytes per mask)
    for (0..2048) |_| {
        _ = mask.nextMask();
    }

    // After consuming all values, offset = 4096. Next call refills the next block.
    try std.testing.expectEqual(@as(usize, 4096), mask.offset);
    const after_refill = mask.nextMask();

    // Expected value = bytes[4096..4098] from the SHAKE stream.
    var shake = Shake128.init(.{});
    shake.update(&nonce);
    var stream_bytes: [4098]u8 = undefined;
    shake.squeeze(&stream_bytes);
    const expected = (@as(u16, stream_bytes[4096]) << 8) | @as(u16, stream_bytes[4097]);
    try std.testing.expectEqual(expected, after_refill);

    // Offset should now be 2 (read 2 bytes from start)
    try std.testing.expectEqual(@as(usize, 2), mask.offset);
}
