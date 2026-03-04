/// VMess AEAD KDF — nested HMAC-SHA256 with recursive hash construction.
///
/// Matches C++ vmess_kdf_recursive() exactly:
///   depth 0: HMAC-SHA256("VMess AEAD KDF", data)
///   depth N: HMAC(path[N-1] as key, using depth N-1 as hash function)
///
/// The "hash function" at each depth is NOT a standard hash — it's
/// the recursive HMAC from the previous depth, with manual ipad/opad.
const c = @import("bindings.zig").c;
const CryptoError = @import("hash.zig").CryptoError;

const kdf_key = "VMess AEAD KDF";

/// Recursive KDF core. Matches C++ vmess_kdf_recursive().
///
/// At depth 0: H(data) = HMAC-SHA256("VMess AEAD KDF", data).
/// At depth N: HMAC(key=path[N-1], data) using H_{N-1} as the hash function.
///
/// The HMAC at depth N manually constructs ipad/opad and uses the depth N-1
/// recursive hash to compute the inner and outer hashes.
fn kdfRecursive(
    data: []const u8,
    paths: []const []const u8,
    depth: usize,
    out: *[32]u8,
) CryptoError!void {
    if (depth == 0) {
        // Base case: HMAC-SHA256 with fixed key
        var md_len: c_uint = 32;
        const ret = c.HMAC(
            c.EVP_sha256(),
            kdf_key.ptr,
            @intCast(kdf_key.len),
            data.ptr,
            data.len,
            out,
            &md_len,
        );
        if (ret == null) return error.CryptoFailed;
        return;
    }

    // Recursive case: HMAC(key=path[depth-1], data) with depth-1 hash
    const key = paths[depth - 1];

    // Pad key to 64 bytes (HMAC block size for SHA-256)
    var k_padded: [64]u8 = .{0} ** 64;
    if (key.len <= 64) {
        @memcpy(k_padded[0..key.len], key);
    } else {
        // Key longer than block size: hash it first using depth-1 hash
        try kdfRecursive(key, paths, depth - 1, k_padded[0..32]);
        // Remaining bytes already zero
    }

    // ipad = k_padded XOR 0x36, opad = k_padded XOR 0x5c
    var ipad: [64]u8 = undefined;
    var opad: [64]u8 = undefined;
    for (0..64) |i| {
        ipad[i] = k_padded[i] ^ 0x36;
        opad[i] = k_padded[i] ^ 0x5c;
    }

    // inner = H_{depth-1}(ipad || data)
    var inner_input: [576]u8 = undefined; // 64 + max ~512 bytes of data
    @memcpy(inner_input[0..64], &ipad);
    if (data.len > inner_input.len - 64) return error.CryptoFailed;
    @memcpy(inner_input[64..][0..data.len], data);

    var inner_hash: [32]u8 = undefined;
    try kdfRecursive(inner_input[0 .. 64 + data.len], paths, depth - 1, &inner_hash);

    // outer = H_{depth-1}(opad || inner_hash)
    var outer_input: [96]u8 = undefined; // 64 + 32
    @memcpy(outer_input[0..64], &opad);
    @memcpy(outer_input[64..96], &inner_hash);

    try kdfRecursive(&outer_input, paths, depth - 1, out);
}

/// Compute VMess KDF with arbitrary path elements. Output: 32 bytes.
pub fn kdfN(key: []const u8, paths: []const []const u8) CryptoError![32]u8 {
    var out: [32]u8 = undefined;
    try kdfRecursive(key, paths, paths.len, &out);
    return out;
}

/// Compute VMess KDF with a single path element. Output: 32 bytes.
pub fn kdf1(key: []const u8, path0: []const u8) CryptoError![32]u8 {
    return kdfN(key, &.{path0});
}

/// KDF truncated to 16 bytes (for AES-128 keys).
pub fn kdf16(key: []const u8, path0: []const u8) CryptoError![16]u8 {
    const full = try kdf1(key, path0);
    return full[0..16].*;
}

/// KDF truncated to 12 bytes (for nonces/IVs).
pub fn kdf12(key: []const u8, path0: []const u8) CryptoError![12]u8 {
    const full = try kdf1(key, path0);
    return full[0..12].*;
}

/// VMess KDF salt constants.
pub const salts = struct {
    pub const auth_id_encryption_key = "AES Auth ID Encryption";
    pub const resp_header_len_key = "AEAD Resp Header Len Key";
    pub const resp_header_len_iv = "AEAD Resp Header Len IV";
    pub const resp_header_payload_key = "AEAD Resp Header Key";
    pub const resp_header_payload_iv = "AEAD Resp Header IV";
    pub const header_payload_aead_key = "VMess Header AEAD Key";
    pub const header_payload_aead_iv = "VMess Header AEAD Nonce";
    pub const header_payload_length_aead_key = "VMess Header AEAD Key_Length";
    pub const header_payload_length_aead_iv = "VMess Header AEAD Nonce_Length";
};
