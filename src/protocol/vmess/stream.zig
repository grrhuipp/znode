/// VMess AEAD stream — chunk-based encrypt/decrypt with SHAKE128 masking.
///
/// Chunk wire format:
///   [2 bytes length (possibly XOR masked)] [encrypted_payload + tag(16)]
///
/// With GLOBAL_PADDING, random padding bytes are appended to each chunk.
/// With CHUNK_MASKING, chunk lengths are XOR'd with SHAKE128 mask stream.
const std = @import("std");
const aead_mod = @import("../../infra/crypto/aead.zig");
const shake_mod = @import("../../infra/crypto/shake.zig");
const rand_mod = @import("../../infra/crypto/rand.zig");
const crypto = @import("crypto.zig");

const tag_len = aead_mod.tag_len; // 16

pub const VMessStreamError = error{
    AuthenticationFailed,
    CryptoFailed,
    InvalidLength,
    InnerStreamError,
    BufferOverflow,
};

/// VMess AEAD stream wrapper.
pub fn VMessStream(comptime Inner: type) type {
    return struct {
        inner: Inner,

        // Read state
        read_key: [16]u8,
        read_iv: [16]u8,
        read_nonce_count: u16 = 0,
        read_cipher: aead_mod.CipherType,
        read_mask: ?shake_mod.ShakeMask,
        read_global_padding: bool,

        // Read buffers
        dec_buf: [crypto.max_chunk_size]u8 = undefined,
        dec_start: usize = 0,
        dec_end: usize = 0,

        raw_buf: [2 + crypto.max_chunk_size + tag_len + 64]u8 = undefined,
        raw_filled: usize = 0,
        read_state: ReadState = .read_length,
        pending_chunk_len: usize = 0,
        pending_padding_len: usize = 0,

        // Write state
        write_key: [16]u8,
        write_iv: [16]u8,
        write_nonce_count: u16 = 0,
        write_cipher: aead_mod.CipherType,
        write_mask: ?shake_mod.ShakeMask,
        write_global_padding: bool,

        const Self = @This();

        const ReadState = enum {
            read_length,
            read_payload,
        };

        pub fn init(
            inner: Inner,
            cipher: aead_mod.CipherType,
            read_key: [16]u8,
            read_iv: [16]u8,
            write_key: [16]u8,
            write_iv: [16]u8,
            options: u8,
        ) Self {
            const chunk_masking = (options & crypto.Option.chunk_masking) != 0;
            const global_padding = (options & crypto.Option.global_padding) != 0;

            return .{
                .inner = inner,
                .read_key = read_key,
                .read_iv = read_iv,
                .read_cipher = cipher,
                .read_mask = if (chunk_masking) shake_mod.ShakeMask.init(&read_iv) else null,
                .read_global_padding = global_padding,
                .write_key = write_key,
                .write_iv = write_iv,
                .write_cipher = cipher,
                .write_mask = if (chunk_masking) shake_mod.ShakeMask.init(&write_iv) else null,
                .write_global_padding = global_padding,
            };
        }

        /// Read decrypted data. Returns 0 on EOF.
        pub fn read(self: *Self, buf: []u8) VMessStreamError!usize {
            // Drain buffered data first
            if (self.dec_start < self.dec_end) {
                return self.drainDecBuf(buf);
            }

            while (true) {
                switch (self.read_state) {
                    .read_length => {
                        try self.fillRaw(2);

                        var raw_len = (@as(u16, self.raw_buf[0]) << 8) | @as(u16, self.raw_buf[1]);

                        // v2ray order: get padding mask first, then size mask
                        var padding_len: usize = 0;
                        if (self.read_global_padding) {
                            if (self.read_mask) |*mask| {
                                const padding_mask = mask.nextMask() catch return error.CryptoFailed;
                                padding_len = padding_mask % 64;
                            }
                        }

                        // Apply size mask
                        if (self.read_mask) |*mask| {
                            const size_mask = mask.nextMask() catch return error.CryptoFailed;
                            raw_len ^= size_mask;
                        }

                        const chunk_len = @as(usize, raw_len);
                        if (chunk_len == 0) {
                            // Zero-length chunk = EOF signal
                            self.consumeRaw(2);
                            return 0;
                        }

                        // Wire: [len(2)] [AEAD(payload + tag)] [padding]
                        // chunk_len includes tag but NOT padding
                        if (chunk_len + padding_len > crypto.max_chunk_size + tag_len + 64) {
                            return error.InvalidLength;
                        }

                        self.pending_chunk_len = chunk_len;
                        self.pending_padding_len = padding_len;
                        self.consumeRaw(2);
                        self.read_state = .read_payload;
                    },
                    .read_payload => {
                        const total_read = self.pending_chunk_len + self.pending_padding_len;
                        try self.fillRaw(total_read);

                        if (self.pending_chunk_len < tag_len) return error.InvalidLength;

                        // Decrypt AEAD chunk (padding is outside AEAD envelope)
                        const nonce = aead_mod.vmessNonce(self.read_nonce_count, &self.read_iv);
                        const dec_len = aead_mod.decrypt(
                            self.read_cipher,
                            &self.read_key,
                            &nonce,
                            self.raw_buf[0..self.pending_chunk_len],
                            &.{},
                            &self.dec_buf,
                        ) catch return error.AuthenticationFailed;
                        self.read_nonce_count +%= 1;

                        self.dec_start = 0;
                        self.dec_end = dec_len;
                        self.consumeRaw(total_read); // consume AEAD + padding
                        self.read_state = .read_length;

                        return self.drainDecBuf(buf);
                    },
                }
            }
        }

        /// Write encrypted data as VMess chunks.
        pub fn write(self: *Self, data: []const u8) VMessStreamError!usize {
            if (data.len == 0) return 0;

            var total: usize = 0;
            var remaining = data;

            while (remaining.len > 0) {
                const chunk_payload = @min(remaining.len, crypto.max_chunk_size);

                // Generate padding
                var padding_len: usize = 0;
                var padding_buf: [64]u8 = undefined;
                if (self.write_global_padding) {
                    if (self.write_mask) |*mask| {
                        const padding_mask = mask.nextMask() catch return error.CryptoFailed;
                        padding_len = padding_mask % 64;
                        rand_mod.randomBytes(padding_buf[0..padding_len]) catch
                            return error.CryptoFailed;
                    }
                }

                // Encrypt payload
                var enc_buf: [crypto.max_chunk_size + tag_len]u8 = undefined;
                const nonce = aead_mod.vmessNonce(self.write_nonce_count, &self.write_iv);
                const enc_len = aead_mod.encrypt(
                    self.write_cipher,
                    &self.write_key,
                    &nonce,
                    remaining[0..chunk_payload],
                    &.{},
                    &enc_buf,
                ) catch return error.CryptoFailed;
                self.write_nonce_count +%= 1;

                // Compute masked length
                var raw_len: u16 = @intCast(enc_len);
                if (self.write_mask) |*mask| {
                    const size_mask = mask.nextMask() catch return error.CryptoFailed;
                    raw_len ^= size_mask;
                }

                // Write: [length(2)] [encrypted_data] [padding]
                var len_bytes = [2]u8{
                    @intCast(raw_len >> 8),
                    @intCast(raw_len & 0xFF),
                };
                self.inner.writeAll(&len_bytes) catch return error.InnerStreamError;
                self.inner.writeAll(enc_buf[0..enc_len]) catch return error.InnerStreamError;
                if (padding_len > 0) {
                    self.inner.writeAll(padding_buf[0..padding_len]) catch
                        return error.InnerStreamError;
                }

                total += chunk_payload;
                remaining = remaining[chunk_payload..];
            }

            return total;
        }

        /// Write all data as encrypted VMess chunks.
        pub fn writeAll(self: *Self, data: []const u8) VMessStreamError!void {
            if (data.len == 0) return;
            _ = try self.write(data);
        }

        pub fn close(self: *Self) void {
            self.inner.close();
        }

        // ── Internal ──────────────────────────────────────────────────────

        fn drainDecBuf(self: *Self, buf: []u8) usize {
            const avail = self.dec_end - self.dec_start;
            const n = @min(avail, buf.len);
            @memcpy(buf[0..n], self.dec_buf[self.dec_start..][0..n]);
            self.dec_start += n;
            return n;
        }

        fn fillRaw(self: *Self, needed: usize) VMessStreamError!void {
            while (self.raw_filled < needed) {
                const space = self.raw_buf[self.raw_filled..];
                if (space.len == 0) return error.BufferOverflow;
                const n = self.inner.read(space) catch return error.InnerStreamError;
                if (n == 0) return error.InnerStreamError;
                self.raw_filled += n;
            }
        }

        fn consumeRaw(self: *Self, n: usize) void {
            const remaining = self.raw_filled - n;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.raw_buf[0..remaining], self.raw_buf[n..self.raw_filled]);
            }
            self.raw_filled = remaining;
        }
    };
}
