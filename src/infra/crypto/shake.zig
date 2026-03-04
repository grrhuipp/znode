/// SHAKE128 extendable output function backed by aws-lc.
///
/// Used by VMess chunk length masking (4KB buffer, 2 bytes per mask).
const c = @import("bindings.zig").c;
const CryptoError = @import("hash.zig").CryptoError;

/// SHAKE128: hash `input` into `output` of arbitrary length.
pub fn shake128(input: []const u8, output: []u8) CryptoError!void {
    const ctx = c.EVP_MD_CTX_new() orelse return error.CryptoFailed;
    defer c.EVP_MD_CTX_free(ctx);

    const md = c.EVP_shake128() orelse return error.CryptoFailed;

    if (c.EVP_DigestInit_ex(ctx, md, null) != 1) return error.CryptoFailed;
    if (input.len > 0) {
        if (c.EVP_DigestUpdate(ctx, input.ptr, input.len) != 1)
            return error.CryptoFailed;
    }
    if (c.EVP_DigestFinalXOF(ctx, output.ptr, output.len) != 1)
        return error.CryptoFailed;
}

/// ShakeMask — chunk length mask generator (VMess).
///
/// Pre-generates 4KB of SHAKE128 output from a 16-byte nonce.
/// Each NextMask() consumes 2 bytes → 2048 masks before wrap-around.
pub const ShakeMask = struct {
    const buffer_size = 4096;

    buffer: [buffer_size]u8 = undefined,
    offset: usize = 0,
    initialized: bool = false,
    nonce: [16]u8,

    pub fn init(nonce: *const [16]u8) ShakeMask {
        return .{ .nonce = nonce.* };
    }

    /// Get the next 16-bit mask value. Lazily initializes on first call.
    pub fn nextMask(self: *ShakeMask) CryptoError!u16 {
        if (!self.initialized) {
            try shake128(&self.nonce, &self.buffer);
            self.initialized = true;
        }

        const hi = self.buffer[self.offset];
        const lo = self.buffer[self.offset + 1];
        self.offset = (self.offset + 2) % buffer_size;

        return (@as(u16, hi) << 8) | @as(u16, lo);
    }
};
