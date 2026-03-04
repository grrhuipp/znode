/// VMess AEAD cryptographic operations.
///
/// AuthID generation/validation, AEAD header encryption/decryption,
/// request/response header parsing, and key derivation.
const std = @import("std");
const hash_mod = @import("../../infra/crypto/hash.zig");
const aead_mod = @import("../../infra/crypto/aead.zig");
const ecb = @import("../../infra/crypto/aes_ecb.zig");
const kdf = @import("../../infra/crypto/kdf.zig");
const rand_mod = @import("../../infra/crypto/rand.zig");
const types = @import("../../common/types.zig");

const CryptoError = hash_mod.CryptoError;

pub const vmess_magic = "c48619fe-8f02-49e0-b9e9-edf763e17e21";
pub const timestamp_tolerance: i64 = 60;

// ── Protocol Constants ───────────────────────────────────────────────────

pub const Security = enum(u8) {
    auto = 0,
    aes_128_gcm = 3,
    chacha20_poly1305 = 4,
    none = 5,
    zero = 6,

    pub fn toAeadCipher(self: Security) ?aead_mod.CipherType {
        return switch (self) {
            .aes_128_gcm => .aes_128_gcm,
            .chacha20_poly1305 => .chacha20_poly1305,
            else => null,
        };
    }
};

pub const Command = enum(u8) {
    tcp = 1,
    udp = 2,
    mux = 3,
};

pub const Option = struct {
    pub const chunk_stream: u8 = 0x01;
    pub const connection_reuse: u8 = 0x02;
    pub const chunk_masking: u8 = 0x04;
    pub const global_padding: u8 = 0x08;
    pub const authenticated_length: u8 = 0x10;
};

pub const max_chunk_size: usize = 16384;

// ── UUID Parsing ─────────────────────────────────────────────────────────

/// Parse UUID string (with or without hyphens) to 16 bytes.
pub fn parseUuid(uuid_str: []const u8) ?[16]u8 {
    var hex_buf: [32]u8 = undefined;
    var hex_len: usize = 0;

    for (uuid_str) |ch| {
        if (ch == '-') continue;
        if (hex_len >= 32) return null;
        hex_buf[hex_len] = ch;
        hex_len += 1;
    }
    if (hex_len != 32) return null;

    var result: [16]u8 = undefined;
    for (0..16) |i| {
        result[i] = std.fmt.parseInt(u8, hex_buf[i * 2 ..][0..2], 16) catch return null;
    }
    return result;
}

// ── Key Derivation from UUID ─────────────────────────────────────────────

/// Derive cmd_key = MD5(uuid_bytes || vmess_magic).
pub fn deriveCmdKey(uuid_bytes: *const [16]u8) CryptoError![16]u8 {
    return hash_mod.md5Concat2(uuid_bytes, vmess_magic);
}

/// Derive auth_key = KDF16(cmd_key, ["AES Auth ID Encryption"]).
pub fn deriveAuthKey(cmd_key: *const [16]u8) CryptoError![16]u8 {
    return kdf.kdf16(cmd_key, kdf.salts.auth_id_encryption_key);
}

// ── AuthID ───────────────────────────────────────────────────────────────

/// AuthID plaintext: [timestamp_be64(8)] [random(4)] [crc32(4)]
pub fn generateAuthId(auth_key: *const [16]u8, timestamp: i64) CryptoError![16]u8 {
    var plain: [16]u8 = undefined;

    // Timestamp (big-endian i64)
    std.mem.writeInt(i64, plain[0..8], timestamp, .big);

    // Random 4 bytes
    try rand_mod.randomBytes(plain[8..12]);

    // CRC32 of first 12 bytes
    const crc = std.hash.crc.Crc32IsoHdlc.hash(plain[0..12]);
    std.mem.writeInt(u32, plain[12..16], crc, .big);

    // AES-128-ECB encrypt
    var auth_id: [16]u8 = undefined;
    try ecb.aes128EcbEncrypt(auth_key, &plain, &auth_id);
    return auth_id;
}

/// Validate a decrypted AuthID plaintext: check timestamp and CRC32.
pub fn validateAuthIdPlain(plain: *const [16]u8, now: i64) bool {
    const timestamp = std.mem.readInt(i64, plain[0..8], .big);
    if (@abs(now - timestamp) > timestamp_tolerance) return false;

    const expected_crc = std.hash.crc.Crc32IsoHdlc.hash(plain[0..12]);
    const actual_crc = std.mem.readInt(u32, plain[12..16], .big);
    return expected_crc == actual_crc;
}

/// Try to decrypt an AuthID with a given auth_key. Returns timestamp if valid.
pub fn tryDecryptAuthId(auth_key: *const [16]u8, auth_id: *const [16]u8, now: i64) ?i64 {
    var plain: [16]u8 = undefined;
    ecb.aes128EcbDecrypt(auth_key, auth_id, &plain) catch return null;
    if (!validateAuthIdPlain(&plain, now)) return null;
    return std.mem.readInt(i64, plain[0..8], .big);
}

// ── AEAD Header Decryption ───────────────────────────────────────────────

/// Derive header AEAD keys/nonces from cmd_key + auth_id + connection_nonce.
pub const HeaderKeys = struct {
    len_key: [16]u8,
    len_iv: [12]u8,
    payload_key: [16]u8,
    payload_iv: [12]u8,
};

pub fn deriveHeaderKeys(
    cmd_key: *const [16]u8,
    auth_id: *const [16]u8,
    nonce: *const [8]u8,
) CryptoError!HeaderKeys {
    // Convert auth_id and nonce to strings for KDF path
    // Actually they're passed as raw bytes in the KDF path
    const auth_id_slice: []const u8 = auth_id;
    const nonce_slice: []const u8 = nonce;

    var result: HeaderKeys = undefined;

    // Length key: KDF(cmd_key, [VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, auth_id, nonce])[0:16]
    const lk = try kdf.kdfN(cmd_key, &.{
        kdf.salts.header_payload_length_aead_key,
        auth_id_slice,
        nonce_slice,
    });
    result.len_key = lk[0..16].*;

    // Length IV: KDF(cmd_key, [VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, auth_id, nonce])[0:12]
    const li = try kdf.kdfN(cmd_key, &.{
        kdf.salts.header_payload_length_aead_iv,
        auth_id_slice,
        nonce_slice,
    });
    result.len_iv = li[0..12].*;

    // Payload key: KDF(cmd_key, [VMESS_HEADER_PAYLOAD_AEAD_KEY, auth_id, nonce])[0:16]
    const pk = try kdf.kdfN(cmd_key, &.{
        kdf.salts.header_payload_aead_key,
        auth_id_slice,
        nonce_slice,
    });
    result.payload_key = pk[0..16].*;

    // Payload IV: KDF(cmd_key, [VMESS_HEADER_PAYLOAD_AEAD_IV, auth_id, nonce])[0:12]
    const pi = try kdf.kdfN(cmd_key, &.{
        kdf.salts.header_payload_aead_iv,
        auth_id_slice,
        nonce_slice,
    });
    result.payload_iv = pi[0..12].*;

    return result;
}

/// Decrypt AEAD header: length (18 bytes) → payload.
/// Returns decrypted header payload.
pub fn decryptHeader(
    keys: *const HeaderKeys,
    auth_id: *const [16]u8,
    len_chunk: *const [18]u8, // 2 + 16 tag
    payload_chunk: []const u8, // N + 16 tag
    out: []u8,
) !DecryptedHeader {
    // Decrypt length
    var len_plain: [2]u8 = undefined;
    _ = aead_mod.decrypt(
        .aes_128_gcm,
        &keys.len_key,
        &keys.len_iv,
        len_chunk,
        auth_id, // AAD = auth_id
        &len_plain,
    ) catch return error.AuthenticationFailed;

    const header_len = (@as(usize, len_plain[0]) << 8) | @as(usize, len_plain[1]);
    if (header_len + 16 > payload_chunk.len) return error.NeedMoreData;

    // Decrypt payload
    const dec_len = aead_mod.decrypt(
        .aes_128_gcm,
        &keys.payload_key,
        &keys.payload_iv,
        payload_chunk[0 .. header_len + 16],
        auth_id, // AAD = auth_id
        out,
    ) catch return error.AuthenticationFailed;

    return .{
        .data = out[0..dec_len],
        .header_len = header_len,
        .total_consumed = header_len + 16,
    };
}

pub const DecryptedHeader = struct {
    data: []const u8,
    header_len: usize,
    total_consumed: usize,
};

// ── Request Header Parsing ───────────────────────────────────────────────

pub const VMessRequest = struct {
    body_iv: [16]u8,
    body_key: [16]u8,
    response_header: u8,
    options: u8,
    security: Security,
    padding_len: u8,
    command: Command,
    target: types.TargetAddress,
    // Derived response keys
    response_key: [16]u8,
    response_iv: [16]u8,
};

pub const ParseError = error{
    InvalidVersion,
    InvalidCommand,
    InvalidAddress,
    InvalidChecksum,
    NeedMoreData,
    AuthenticationFailed,
};

/// Parse a decrypted VMess request header payload.
pub fn parseRequestPayload(data: []const u8) ParseError!VMessRequest {
    // Minimum: 1(ver) + 16(iv) + 16(key) + 1(resp) + 1(opt) + 1(sec_pad) +
    //          1(rsv) + 1(cmd) + 2(port) + 1(atyp) + 1(addr_min) + 4(fnv) = 46
    if (data.len < 46) return error.NeedMoreData;

    var pos: usize = 0;

    // Version
    if (data[pos] != 0x01) return error.InvalidVersion;
    pos += 1;

    // Body IV (16 bytes)
    var body_iv: [16]u8 = undefined;
    @memcpy(&body_iv, data[pos..][0..16]);
    pos += 16;

    // Body Key (16 bytes)
    var body_key: [16]u8 = undefined;
    @memcpy(&body_key, data[pos..][0..16]);
    pos += 16;

    // Response header byte
    const response_header = data[pos];
    pos += 1;

    // Options
    const options = data[pos];
    pos += 1;

    // Security (low nibble) + padding_len (high nibble)
    const sec_pad = data[pos];
    pos += 1;
    const padding_len: u8 = sec_pad >> 4;
    const security: Security = @enumFromInt(sec_pad & 0x0F);

    // Reserved
    pos += 1;

    // Command
    const command: Command = switch (data[pos]) {
        1 => .tcp,
        2 => .udp,
        3 => .mux,
        else => return error.InvalidCommand,
    };
    pos += 1;

    // Port (big-endian)
    if (pos + 2 > data.len) return error.NeedMoreData;
    const port = (@as(u16, data[pos]) << 8) | @as(u16, data[pos + 1]);
    pos += 2;

    // Address
    if (pos >= data.len) return error.NeedMoreData;
    const target = try parseAddress(data, &pos, port);

    // Skip padding
    if (pos + padding_len > data.len) return error.NeedMoreData;
    pos += padding_len;

    // FNV-1a checksum (4 bytes)
    if (pos + 4 > data.len) return error.NeedMoreData;
    const expected_fnv = std.mem.readInt(u32, data[pos..][0..4], .big);
    const actual_fnv = fnv1a32(data[0..pos]);
    if (expected_fnv != actual_fnv) return error.InvalidChecksum;

    // Derive response keys
    const response_key = hash_mod.sha256(&body_key)[0..16].*;
    const response_iv = hash_mod.sha256(&body_iv)[0..16].*;

    return .{
        .body_iv = body_iv,
        .body_key = body_key,
        .response_header = response_header,
        .options = options,
        .security = security,
        .padding_len = padding_len,
        .command = command,
        .target = target,
        .response_key = response_key,
        .response_iv = response_iv,
    };
}

fn parseAddress(data: []const u8, pos: *usize, port: u16) ParseError!types.TargetAddress {
    const atyp = data[pos.*];
    pos.* += 1;

    return switch (atyp) {
        1 => { // IPv4
            if (pos.* + 4 > data.len) return error.NeedMoreData;
            var buf: [16]u8 = undefined;
            const host = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{
                data[pos.*], data[pos.* + 1], data[pos.* + 2], data[pos.* + 3],
            }) catch return error.InvalidAddress;
            pos.* += 4;
            return types.TargetAddress.init(host, port, .ipv4);
        },
        2 => { // Domain
            if (pos.* >= data.len) return error.NeedMoreData;
            const dlen = data[pos.*];
            pos.* += 1;
            if (pos.* + dlen > data.len) return error.NeedMoreData;
            const domain = data[pos.* .. pos.* + dlen];
            pos.* += dlen;
            return types.TargetAddress.init(domain, port, .domain);
        },
        3 => { // IPv6
            if (pos.* + 16 > data.len) return error.NeedMoreData;
            var buf: [46]u8 = undefined;
            const d = data[pos.*..];
            const host = std.fmt.bufPrint(&buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
                d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15],
            }) catch return error.InvalidAddress;
            pos.* += 16;
            return types.TargetAddress.init(host, port, .ipv6);
        },
        else => error.InvalidAddress,
    };
}

// ── Response Header Encoding ─────────────────────────────────────────────

/// Encode AEAD response header (server → client).
/// Returns total bytes written to `out`.
pub fn encodeResponseHeader(
    response_key: *const [16]u8,
    response_iv: *const [16]u8,
    response_header_byte: u8,
    options: u8,
    out: []u8,
) !usize {
    // Response payload: [response_header, options, 0x00, 0x00]
    const payload = [4]u8{ response_header_byte, options, 0x00, 0x00 };

    // Derive keys for response header
    const resp_len_key = try kdf.kdf16(response_key, kdf.salts.resp_header_len_key);
    const resp_len_iv = try kdf.kdf12(response_iv, kdf.salts.resp_header_len_iv);
    const resp_payload_key = try kdf.kdf16(response_key, kdf.salts.resp_header_payload_key);
    const resp_payload_iv = try kdf.kdf12(response_iv, kdf.salts.resp_header_payload_iv);

    var pos: usize = 0;

    // Encrypt length (payload is 4 bytes)
    const len_bytes = [2]u8{ 0x00, 0x04 };
    const len_enc = aead_mod.encrypt(
        .aes_128_gcm,
        &resp_len_key,
        &resp_len_iv,
        &len_bytes,
        &.{},
        out[pos..],
    ) catch return error.CryptoFailed;
    pos += len_enc;

    // Encrypt payload
    const payload_enc = aead_mod.encrypt(
        .aes_128_gcm,
        &resp_payload_key,
        &resp_payload_iv,
        &payload,
        &.{},
        out[pos..],
    ) catch return error.CryptoFailed;
    pos += payload_enc;

    return pos;
}

/// Decrypt AEAD response header (client reads from server).
pub fn decryptResponseHeader(
    response_key: *const [16]u8,
    response_iv: *const [16]u8,
    data: []const u8,
) !ResponseHeader {
    // Need at least 18 (len chunk) + 4+16 (min payload chunk) = 38 bytes
    if (data.len < 38) return error.NeedMoreData;

    const resp_len_key = try kdf.kdf16(response_key, kdf.salts.resp_header_len_key);
    const resp_len_iv = try kdf.kdf12(response_iv, kdf.salts.resp_header_len_iv);
    const resp_payload_key = try kdf.kdf16(response_key, kdf.salts.resp_header_payload_key);
    const resp_payload_iv = try kdf.kdf12(response_iv, kdf.salts.resp_header_payload_iv);

    // Decrypt length
    var len_plain: [2]u8 = undefined;
    _ = aead_mod.decrypt(
        .aes_128_gcm,
        &resp_len_key,
        &resp_len_iv,
        data[0..18],
        &.{},
        &len_plain,
    ) catch return error.AuthenticationFailed;

    const header_len = (@as(usize, len_plain[0]) << 8) | @as(usize, len_plain[1]);
    if (18 + header_len + 16 > data.len) return error.NeedMoreData;

    // Decrypt payload
    var payload: [256]u8 = undefined;
    const dec_len = aead_mod.decrypt(
        .aes_128_gcm,
        &resp_payload_key,
        &resp_payload_iv,
        data[18 .. 18 + header_len + 16],
        &.{},
        &payload,
    ) catch return error.AuthenticationFailed;

    if (dec_len < 4) return error.InvalidVersion;

    return .{
        .response_header = payload[0],
        .options = payload[1],
        .consumed = 18 + header_len + 16,
    };
}

pub const ResponseHeader = struct {
    response_header: u8,
    options: u8,
    consumed: usize,
};

// ── FNV-1a ───────────────────────────────────────────────────────────────

fn fnv1a32(data: []const u8) u32 {
    var hash: u32 = 0x811c9dc5;
    for (data) |byte| {
        hash ^= byte;
        hash *%= 0x01000193;
    }
    return hash;
}
