/// Cryptographic random number generation backed by aws-lc.
const c = @import("bindings.zig").c;
const CryptoError = @import("hash.zig").CryptoError;

/// Fill buffer with cryptographically secure random bytes.
pub fn randomBytes(buf: []u8) CryptoError!void {
    if (buf.len == 0) return;
    if (c.RAND_bytes(buf.ptr, buf.len) != 1) return error.CryptoFailed;
}
