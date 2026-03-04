/// Shadowsocks AEAD stream — chunk-based encrypt/decrypt.
///
/// Wire format (each direction independently):
///   [salt (key_len bytes)]
///   [encrypted_length(2) + tag(16)] [encrypted_payload + tag(16)]
///   [encrypted_length(2) + tag(16)] [encrypted_payload + tag(16)]
///   ...
///
/// Length is big-endian u16, max 0x3FFF (16383).
/// Nonce is a 96-bit little-endian counter, incremented per AEAD operation.
const std = @import("std");
const aead_mod = @import("../../infra/crypto/aead.zig");
const protocol = @import("protocol.zig");

const tag_len = protocol.tag_len;
const nonce_len = protocol.nonce_len;
const max_payload = protocol.max_payload_size;

/// Length chunk overhead: encrypted_length(2) + tag(16) = 18 bytes.
const len_chunk_size = 2 + tag_len;
/// Maximum data chunk overhead: payload + tag(16).
const max_data_chunk = max_payload + tag_len;

pub const SsStreamError = error{
    AuthenticationFailed,
    CryptoFailed,
    InvalidLength,
    InnerStreamError,
    BufferOverflow,
};

/// Shadowsocks AEAD stream wrapper.
///
/// Handles chunk-based AEAD encryption/decryption transparently.
/// The salt exchange and subkey derivation must be done before init.
pub fn SsStream(comptime Inner: type) type {
    return struct {
        inner: Inner,

        // Decrypt state (read direction)
        read_key: [protocol.max_key_len]u8,
        read_key_len: usize,
        read_nonce_counter: u64 = 0,
        cipher_type: aead_mod.CipherType,

        // Buffered decrypted data (from partial chunk reads)
        dec_buf: [max_payload]u8 = undefined,
        dec_start: usize = 0,
        dec_end: usize = 0,

        // Raw read buffer for accumulating encrypted chunks
        raw_buf: [len_chunk_size + max_data_chunk]u8 = undefined,
        raw_filled: usize = 0,
        read_state: ReadState = .read_length,

        // Pending payload length for current chunk
        pending_payload_len: u16 = 0,

        // Encrypt state (write direction)
        write_key: [protocol.max_key_len]u8,
        write_key_len: usize,
        write_nonce_counter: u64 = 0,
        write_salt_sent: bool,

        // Salt for write direction
        write_salt: [protocol.max_salt_len]u8 = undefined,
        write_salt_len: usize = 0,

        const Self = @This();

        const ReadState = enum {
            read_length,
            read_payload,
        };

        pub fn init(
            inner: Inner,
            cipher_type: aead_mod.CipherType,
            read_subkey: []const u8,
            write_subkey: []const u8,
            write_salt: ?[]const u8,
        ) Self {
            var self = Self{
                .inner = inner,
                .read_key = undefined,
                .read_key_len = read_subkey.len,
                .cipher_type = cipher_type,
                .write_key = undefined,
                .write_key_len = write_subkey.len,
                .write_salt_sent = write_salt == null,
            };
            @memcpy(self.read_key[0..read_subkey.len], read_subkey);
            @memcpy(self.write_key[0..write_subkey.len], write_subkey);
            if (write_salt) |s| {
                @memcpy(self.write_salt[0..s.len], s);
                self.write_salt_len = s.len;
            }
            return self;
        }

        /// Read decrypted data. Returns 0 on EOF.
        pub fn read(self: *Self, buf: []u8) SsStreamError!usize {
            // Return buffered decrypted data first
            if (self.dec_start < self.dec_end) {
                return self.drainDecBuf(buf);
            }

            // Need to decrypt a new chunk
            while (true) {
                switch (self.read_state) {
                    .read_length => {
                        // Need len_chunk_size bytes for encrypted length
                        try self.fillRaw(len_chunk_size);

                        // Decrypt length
                        var len_plain: [2]u8 = undefined;
                        const nonce = aead_mod.ssNonce(self.read_nonce_counter);
                        _ = aead_mod.decrypt(
                            self.cipher_type,
                            self.read_key[0..self.read_key_len],
                            &nonce,
                            self.raw_buf[0..len_chunk_size],
                            &.{},
                            &len_plain,
                        ) catch return error.AuthenticationFailed;
                        self.read_nonce_counter += 1;

                        const payload_len = (@as(u16, len_plain[0]) << 8) | @as(u16, len_plain[1]);
                        if (payload_len == 0 or payload_len > max_payload) {
                            return error.InvalidLength;
                        }
                        self.pending_payload_len = payload_len;
                        // Consume length chunk from raw_buf
                        self.consumeRaw(len_chunk_size);
                        self.read_state = .read_payload;
                    },
                    .read_payload => {
                        const data_chunk_size = @as(usize, self.pending_payload_len) + tag_len;
                        try self.fillRaw(data_chunk_size);

                        // Decrypt payload
                        const nonce = aead_mod.ssNonce(self.read_nonce_counter);
                        const dec_len = aead_mod.decrypt(
                            self.cipher_type,
                            self.read_key[0..self.read_key_len],
                            &nonce,
                            self.raw_buf[0..data_chunk_size],
                            &.{},
                            &self.dec_buf,
                        ) catch return error.AuthenticationFailed;
                        self.read_nonce_counter += 1;

                        self.dec_start = 0;
                        self.dec_end = dec_len;
                        self.consumeRaw(data_chunk_size);
                        self.read_state = .read_length;

                        return self.drainDecBuf(buf);
                    },
                }
            }
        }

        /// Write data as encrypted chunks.
        pub fn write(self: *Self, data: []const u8) SsStreamError!usize {
            if (data.len == 0) return 0;

            // Send salt first if not yet sent
            if (!self.write_salt_sent) {
                self.inner.writeAll(self.write_salt[0..self.write_salt_len]) catch
                    return error.InnerStreamError;
                self.write_salt_sent = true;
            }

            var total_sent: usize = 0;
            var remaining = data;

            while (remaining.len > 0) {
                const chunk_len = @min(remaining.len, max_payload);
                var out_buf: [len_chunk_size + max_data_chunk]u8 = undefined;
                var out_pos: usize = 0;

                // Encrypt length (2 bytes → 2 + 16)
                const len_bytes = [2]u8{
                    @intCast(chunk_len >> 8),
                    @intCast(chunk_len & 0xFF),
                };
                const nonce_len_enc = aead_mod.ssNonce(self.write_nonce_counter);
                const enc_len = aead_mod.encrypt(
                    self.cipher_type,
                    self.write_key[0..self.write_key_len],
                    &nonce_len_enc,
                    &len_bytes,
                    &.{},
                    out_buf[out_pos..],
                ) catch return error.CryptoFailed;
                out_pos += enc_len;
                self.write_nonce_counter += 1;

                // Encrypt payload
                const nonce_data_enc = aead_mod.ssNonce(self.write_nonce_counter);
                const enc_data = aead_mod.encrypt(
                    self.cipher_type,
                    self.write_key[0..self.write_key_len],
                    &nonce_data_enc,
                    remaining[0..chunk_len],
                    &.{},
                    out_buf[out_pos..],
                ) catch return error.CryptoFailed;
                out_pos += enc_data;
                self.write_nonce_counter += 1;

                self.inner.writeAll(out_buf[0..out_pos]) catch return error.InnerStreamError;
                total_sent += chunk_len;
                remaining = remaining[chunk_len..];
            }

            return total_sent;
        }

        /// Write all data as encrypted SS chunks.
        pub fn writeAll(self: *Self, data: []const u8) SsStreamError!void {
            if (data.len == 0) return;
            _ = try self.write(data);
        }

        pub fn close(self: *Self) void {
            self.inner.close();
        }

        // ── Internal helpers ──────────────────────────────────────────────

        fn drainDecBuf(self: *Self, buf: []u8) usize {
            const avail = self.dec_end - self.dec_start;
            const n = @min(avail, buf.len);
            @memcpy(buf[0..n], self.dec_buf[self.dec_start..][0..n]);
            self.dec_start += n;
            return n;
        }

        /// Fill raw_buf until we have at least `needed` bytes.
        fn fillRaw(self: *Self, needed: usize) SsStreamError!void {
            while (self.raw_filled < needed) {
                const space = self.raw_buf[self.raw_filled..];
                if (space.len == 0) return error.BufferOverflow;
                const n = self.inner.read(space) catch return error.InnerStreamError;
                if (n == 0) return error.InnerStreamError; // EOF mid-chunk
                self.raw_filled += n;
            }
        }

        /// Consume `n` bytes from the front of raw_buf.
        fn consumeRaw(self: *Self, n: usize) void {
            const remaining = self.raw_filled - n;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.raw_buf[0..remaining], self.raw_buf[n..self.raw_filled]);
            }
            self.raw_filled = remaining;
        }
    };
}
