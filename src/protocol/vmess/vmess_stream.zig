const std = @import("std");
const boringssl = @import("../../crypto/boringssl_crypto.zig");
const Aes128Gcm = boringssl.Aes128Gcm;
const Aes256Gcm = boringssl.Aes256Gcm;
const ChaCha20Poly1305 = boringssl.ChaCha20Poly1305;
const Md5 = boringssl.Md5;
const vmess_protocol = @import("vmess_protocol.zig");
const vmess_crypto = @import("vmess_crypto.zig");

pub const SecurityMethod = vmess_protocol.SecurityMethod;
pub const OptionFlags = vmess_protocol.OptionFlags;

const gcm_tag_len = Aes128Gcm.tag_length; // 16
const chacha_tag_len = ChaCha20Poly1305.tag_length; // 16

pub const DecryptErrorKind = enum(u8) {
    auth_length_size_aead_fail,
    chunk_too_large,
    payload_smaller_than_padding,
    encrypted_too_short_for_tag,
    output_buffer_too_small,
    data_aead_fail,
};

pub const DecryptDebugInfo = struct {
    kind: DecryptErrorKind,
    data_len: usize,
    size_field_len: usize,
    total_payload: usize,
    padding_len: usize,
    enc_len: usize,
    tag_len: usize,
    wire_len: usize,
    nonce_counter: u16,
    auth_length_nonce_counter: u16,
    security: SecurityMethod,
    auth_length: bool,
    chunk_masking: bool,
    global_padding: bool,
};

/// Per-direction stream cipher state for VMess chunk stream.
pub const StreamState = struct {
    /// AES-128-GCM key (16B) or ChaCha20-Poly1305 expanded key (32B)
    key: [32]u8,
    key_len: u8,
    /// Base IV for nonce construction
    base_iv: [16]u8,
    /// Chunk counter (incremented per chunk, used in nonce)
    nonce_counter: u16 = 0,
    /// Security method
    security: SecurityMethod,
    /// Options
    options: OptionFlags,
    /// ShakeMask for length masking (4KB one-shot buffer)
    shake_mask: vmess_crypto.ShakeMask,
    has_shake: bool,
    /// Pending decoded chunk length (saved when .incomplete to avoid re-consuming masks)
    pending_decode: ?PendingDecode = null,
    /// Authenticated length: AEAD-encrypted size field (18 bytes on wire)
    /// Key = KDF16(body_key, "auth_len"), separate nonce counter
    auth_length_key: [16]u8 = undefined,
    auth_length_nonce_counter: u16 = 0,
    /// Last decrypt integrity_error details (for diagnostics in upper layers).
    last_decrypt_error: ?DecryptDebugInfo = null,

    const PendingDecode = struct {
        total_payload: u16,
        padding_len: u16,
    };

    pub fn init(
        body_key: [16]u8,
        body_iv: [16]u8,
        security: SecurityMethod,
        options: OptionFlags,
    ) StreamState {
        var state = StreamState{
            .key = undefined,
            .key_len = 0,
            .base_iv = body_iv,
            .security = security,
            .options = options,
            .shake_mask = vmess_crypto.ShakeMask.init(body_iv),
            .has_shake = false,
        };

        switch (security) {
            .aes_128_gcm => {
                @memcpy(state.key[0..16], &body_key);
                state.key_len = 16;
            },
            .aes_256_gcm => {
                const expanded = vmess_crypto.expandKeyForAes256(body_key);
                state.key = expanded;
                state.key_len = 32;
            },
            .chacha20_poly1305 => {
                const expanded = vmess_crypto.expandKeyForChaCha(body_key);
                state.key = expanded;
                state.key_len = 32;
            },
            .none => {
                state.key_len = 0;
            },
        }

        // ShakeMask for length masking (only when auth_length is NOT set)
        if (options.chunk_masking and !options.auth_length) {
            state.has_shake = true;
        }

        // Authenticated length: derive separate AES-128-GCM key for size field
        if (options.auth_length) {
            state.auth_length_key = vmess_crypto.kdfKey16(&body_key, &.{"auth_len"});
        }

        return state;
    }

    /// Build 12-byte nonce for the current chunk (data AEAD).
    fn buildNonce(self: *const StreamState) [12]u8 {
        var nonce: [12]u8 = undefined;
        std.mem.writeInt(u16, nonce[0..2], self.nonce_counter, .big);
        @memcpy(nonce[2..12], self.base_iv[2..12]);
        return nonce;
    }

    /// Build 12-byte nonce for size field AEAD (separate counter).
    fn buildSizeNonce(self: *const StreamState) [12]u8 {
        var nonce: [12]u8 = undefined;
        std.mem.writeInt(u16, nonce[0..2], self.auth_length_nonce_counter, .big);
        @memcpy(nonce[2..12], self.base_iv[2..12]);
        return nonce;
    }

    /// Get next 2-byte ShakeMask for length masking.
    fn nextLengthMask(self: *StreamState) u16 {
        return self.shake_mask.nextMask();
    }

    fn clearDecryptError(self: *StreamState) void {
        self.last_decrypt_error = null;
    }

    fn failDecrypt(
        self: *StreamState,
        kind: DecryptErrorKind,
        data_len: usize,
        size_field_len: usize,
        total_payload: usize,
        padding_len: usize,
        enc_len: usize,
        tag_len: usize,
        wire_len: usize,
    ) DecryptResult {
        self.last_decrypt_error = .{
            .kind = kind,
            .data_len = data_len,
            .size_field_len = size_field_len,
            .total_payload = total_payload,
            .padding_len = padding_len,
            .enc_len = enc_len,
            .tag_len = tag_len,
            .wire_len = wire_len,
            .nonce_counter = self.nonce_counter,
            .auth_length_nonce_counter = self.auth_length_nonce_counter,
            .security = self.security,
            .auth_length = self.options.auth_length,
            .chunk_masking = self.options.chunk_masking,
            .global_padding = self.options.global_padding,
        };
        return .integrity_error;
    }

    pub fn lastDecryptError(self: *const StreamState) ?DecryptDebugInfo {
        return self.last_decrypt_error;
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

/// Tag length for the current security method.
pub fn tagLength(security: SecurityMethod) usize {
    return switch (security) {
        .aes_128_gcm, .aes_256_gcm => gcm_tag_len,
        .chacha20_poly1305 => chacha_tag_len,
        .none => 0,
    };
}

/// Encrypt a data chunk for writing.
///
/// Output format (legacy):     Length(2B) + Ciphertext(N) + Tag(T) + Padding(P)
/// Output format (auth_length): SizeAEAD(18B) + Ciphertext(N) + Tag(T)
///
/// Legacy: Length = N + T + P, optionally XORed with ShakeMask.
/// auth_length: 2B size AEAD-encrypted (AES-128-GCM) → 18B on wire; no padding, no ShakeMask.
///
/// Returns the number of bytes written, or null if buffer too small.
pub fn encryptChunk(state: *StreamState, plaintext: []const u8, out_buf: []u8) ?usize {
    const tag_len = tagLength(state.security);
    const enc_len = plaintext.len + tag_len;

    var padding_len: usize = 0;
    var size_field_len: usize = 2;

    if (state.options.auth_length) {
        // auth_length: 18-byte AEAD size field, no padding, no ShakeMask
        size_field_len = 2 + gcm_tag_len; // 18
    } else {
        // Global padding: generate padding length BEFORE length mask (acppnode order)
        if (state.options.global_padding and state.has_shake) {
            const padding_mask = state.nextLengthMask();
            padding_len = padding_mask % 64;
        }
    }

    const total_payload: usize = enc_len + padding_len;
    const wire_len = size_field_len + total_payload;
    if (out_buf.len < wire_len) return null;

    // Write size field
    if (state.options.auth_length) {
        // AEAD-encrypt 2-byte size value (always AES-128-GCM, separate key/nonce)
        var size_plaintext: [2]u8 = undefined;
        std.mem.writeInt(u16, &size_plaintext, @intCast(total_payload), .big);
        const size_nonce = state.buildSizeNonce();
        var size_ct: [2]u8 = undefined;
        var size_tag: [gcm_tag_len]u8 = undefined;
        Aes128Gcm.encrypt(&size_ct, &size_tag, &size_plaintext, &[_]u8{}, size_nonce, state.auth_length_key);
        @memcpy(out_buf[0..2], &size_ct);
        @memcpy(out_buf[2..size_field_len], &size_tag);
        state.auth_length_nonce_counter +%= 1;
    } else {
        // Write length (optionally masked — this is the second mask call)
        var length_val: u16 = @intCast(total_payload);
        if (state.has_shake) {
            length_val ^= state.nextLengthMask();
        }
        std.mem.writeInt(u16, out_buf[0..2], length_val, .big);
    }

    // Encrypt payload at offset size_field_len
    const ct_end = size_field_len + plaintext.len;
    const tag_end = size_field_len + enc_len;
    switch (state.security) {
        .aes_128_gcm => {
            const nonce = state.buildNonce();
            var tag: [gcm_tag_len]u8 = undefined;
            Aes128Gcm.encrypt(
                out_buf[size_field_len..ct_end],
                &tag,
                plaintext,
                &[_]u8{},
                nonce,
                state.key[0..16].*,
            );
            @memcpy(out_buf[ct_end..tag_end], &tag);
        },
        .aes_256_gcm => {
            const nonce = state.buildNonce();
            var tag: [gcm_tag_len]u8 = undefined;
            Aes256Gcm.encrypt(
                out_buf[size_field_len..ct_end],
                &tag,
                plaintext,
                &[_]u8{},
                nonce,
                state.key,
            );
            @memcpy(out_buf[ct_end..tag_end], &tag);
        },
        .chacha20_poly1305 => {
            const nonce = state.buildNonce();
            var tag: [chacha_tag_len]u8 = undefined;
            ChaCha20Poly1305.encrypt(
                out_buf[size_field_len..ct_end],
                &tag,
                plaintext,
                &[_]u8{},
                nonce,
                state.key,
            );
            @memcpy(out_buf[ct_end..tag_end], &tag);
        },
        .none => {
            @memcpy(out_buf[size_field_len..ct_end], plaintext);
        },
    }

    // Append random padding bytes after ciphertext+tag (only in legacy mode)
    if (padding_len > 0) {
        boringssl.random.bytes(out_buf[tag_end..wire_len]);
    }

    state.nonce_counter +%= 1;
    return wire_len;
}

/// Decrypt a data chunk from reading.
///
/// Input (legacy):      Length(2B) + Ciphertext(N) + Tag(T) + Padding(P)
/// Input (auth_length): SizeAEAD(18B) + Ciphertext(N) + Tag(T)
///
/// Legacy: mask call order (matching acppnode): padding mask first, then length mask.
/// auth_length: AEAD-decrypt 18B → 2B size; no padding, no ShakeMask.
pub fn decryptChunk(state: *StreamState, data: []const u8, out_buf: []u8) DecryptResult {
    state.clearDecryptError();

    var padding_len: usize = undefined;
    var total_payload: usize = undefined;
    const size_field_len: usize = if (state.options.auth_length) 2 + gcm_tag_len else 2; // 18 or 2

    if (state.pending_decode) |pending| {
        // Reuse previously decoded length (masks/nonce already consumed)
        total_payload = pending.total_payload;
        padding_len = pending.padding_len;
    } else if (state.options.auth_length) {
        // auth_length: 18-byte AEAD-encrypted size field
        if (data.len < size_field_len) return .incomplete;

        // AEAD-decrypt size (always AES-128-GCM, separate key/nonce)
        const size_nonce = state.buildSizeNonce();
        var size_plaintext: [2]u8 = undefined;
        Aes128Gcm.decrypt(
            &size_plaintext,
            data[0..2],
            data[2..size_field_len][0..gcm_tag_len].*,
            &[_]u8{},
            size_nonce,
            state.auth_length_key,
        ) catch return state.failDecrypt(
            .auth_length_size_aead_fail,
            data.len,
            size_field_len,
            0,
            0,
            0,
            gcm_tag_len,
            0,
        );

        state.auth_length_nonce_counter +%= 1;
        total_payload = std.mem.readInt(u16, &size_plaintext, .big);
        padding_len = 0;
    } else {
        // Legacy: 2-byte size with optional masking
        if (data.len < 2) return .incomplete;

        padding_len = 0;
        if (state.options.global_padding and state.has_shake) {
            const padding_mask = state.nextLengthMask();
            padding_len = padding_mask % 64;
        }

        var length_val = std.mem.readInt(u16, data[0..2], .big);
        if (state.has_shake) {
            length_val ^= state.nextLengthMask();
        }
        total_payload = length_val;
    }

    const tag_len = tagLength(state.security);

    // Chunk size limit: bounded by VMess 2-byte size field width.
    if (total_payload > vmess_crypto.max_chunk_size) {
        state.pending_decode = null;
        return state.failDecrypt(
            .chunk_too_large,
            data.len,
            size_field_len,
            total_payload,
            padding_len,
            0,
            tag_len,
            0,
        );
    }

    // Check we have enough data — save decoded state for next call
    const wire_len = size_field_len + total_payload;
    if (data.len < wire_len) {
        state.pending_decode = .{
            .total_payload = @intCast(total_payload),
            .padding_len = @intCast(padding_len),
        };
        return .incomplete;
    }

    // Have full chunk — clear pending state
    state.pending_decode = null;

    // Subtract padding to get encrypted data length
    if (total_payload < padding_len) {
        return state.failDecrypt(
            .payload_smaller_than_padding,
            data.len,
            size_field_len,
            total_payload,
            padding_len,
            0,
            tag_len,
            wire_len,
        );
    }
    const enc_len = total_payload - padding_len;

    if (enc_len < tag_len) {
        return state.failDecrypt(
            .encrypted_too_short_for_tag,
            data.len,
            size_field_len,
            total_payload,
            padding_len,
            enc_len,
            tag_len,
            wire_len,
        );
    }
    const plaintext_len = enc_len - tag_len;

    if (out_buf.len < plaintext_len) {
        return state.failDecrypt(
            .output_buffer_too_small,
            data.len,
            size_field_len,
            total_payload,
            padding_len,
            enc_len,
            tag_len,
            wire_len,
        );
    }

    // Decrypt (only the enc_len portion, skip trailing padding)
    const ct_end = size_field_len + plaintext_len;
    const tag_end = size_field_len + enc_len;
    switch (state.security) {
        .aes_128_gcm => {
            const nonce = state.buildNonce();
            Aes128Gcm.decrypt(
                out_buf[0..plaintext_len],
                data[size_field_len..ct_end],
                data[ct_end..tag_end][0..gcm_tag_len].*,
                &[_]u8{},
                nonce,
                state.key[0..16].*,
            ) catch return state.failDecrypt(
                .data_aead_fail,
                data.len,
                size_field_len,
                total_payload,
                padding_len,
                enc_len,
                tag_len,
                wire_len,
            );
        },
        .aes_256_gcm => {
            const nonce = state.buildNonce();
            Aes256Gcm.decrypt(
                out_buf[0..plaintext_len],
                data[size_field_len..ct_end],
                data[ct_end..tag_end][0..gcm_tag_len].*,
                &[_]u8{},
                nonce,
                state.key,
            ) catch return state.failDecrypt(
                .data_aead_fail,
                data.len,
                size_field_len,
                total_payload,
                padding_len,
                enc_len,
                tag_len,
                wire_len,
            );
        },
        .chacha20_poly1305 => {
            const nonce = state.buildNonce();
            ChaCha20Poly1305.decrypt(
                out_buf[0..plaintext_len],
                data[size_field_len..ct_end],
                data[ct_end..tag_end][0..chacha_tag_len].*,
                &[_]u8{},
                nonce,
                state.key,
            ) catch return state.failDecrypt(
                .data_aead_fail,
                data.len,
                size_field_len,
                total_payload,
                padding_len,
                enc_len,
                tag_len,
                wire_len,
            );
        },
        .none => {
            @memcpy(out_buf[0..plaintext_len], data[size_field_len..ct_end]);
        },
    }

    state.nonce_counter +%= 1;
    return .{ .success = .{
        .plaintext_len = plaintext_len,
        .bytes_consumed = wire_len,
    } };
}

// ── Tests ──

const testing = std.testing;

fn roundtripTest(security: SecurityMethod, mask: bool) !void {
    try roundtripTestWithPadding(security, mask, false);
}

fn roundtripTestWithPadding(security: SecurityMethod, mask: bool, padding: bool) !void {
    const body_key = [_]u8{0x42} ** 16;
    const body_iv = [_]u8{0x43} ** 16;
    const opts = OptionFlags{ .chunk_stream = true, .chunk_masking = mask, .global_padding = padding };

    var enc_state = StreamState.init(body_key, body_iv, security, opts);
    var dec_state = StreamState.init(body_key, body_iv, security, opts);

    const plaintext = "Hello, VMess chunk stream!";
    var wire_buf: [512]u8 = undefined;
    var dec_buf: [256]u8 = undefined;

    const n = encryptChunk(&enc_state, plaintext, &wire_buf) orelse return error.EncryptFailed;
    const result = decryptChunk(&dec_state, wire_buf[0..n], &dec_buf);

    switch (result) {
        .success => |s| {
            try testing.expectEqual(plaintext.len, s.plaintext_len);
            try testing.expectEqual(n, s.bytes_consumed);
            try testing.expectEqualStrings(plaintext, dec_buf[0..s.plaintext_len]);
        },
        else => return error.DecryptFailed,
    }
}

test "encryptChunk and decryptChunk roundtrip AES-128-GCM" {
    try roundtripTest(.aes_128_gcm, false);
}

test "encryptChunk and decryptChunk roundtrip AES-128-GCM with masking" {
    try roundtripTest(.aes_128_gcm, true);
}

test "encryptChunk and decryptChunk roundtrip ChaCha20-Poly1305" {
    try roundtripTest(.chacha20_poly1305, false);
}

test "encryptChunk and decryptChunk roundtrip ChaCha20-Poly1305 with masking" {
    try roundtripTest(.chacha20_poly1305, true);
}

test "encryptChunk and decryptChunk roundtrip no encryption" {
    try roundtripTest(.none, false);
}

test "decryptChunk incomplete data" {
    const body_key = [_]u8{0} ** 16;
    const body_iv = [_]u8{0} ** 16;
    var state = StreamState.init(body_key, body_iv, .aes_128_gcm, .{});
    var out: [256]u8 = undefined;
    const result = decryptChunk(&state, &[_]u8{0}, &out);
    try testing.expect(result == .incomplete);
}

test "decryptChunk integrity failure" {
    const body_key = [_]u8{0x50} ** 16;
    const body_iv = [_]u8{0x51} ** 16;
    var enc_state = StreamState.init(body_key, body_iv, .aes_128_gcm, .{});

    var wire_buf: [256]u8 = undefined;
    const n = encryptChunk(&enc_state, "test data", &wire_buf) orelse return error.EncryptFailed;

    // Corrupt a byte in the ciphertext
    wire_buf[5] ^= 0xFF;

    var dec_state = StreamState.init(body_key, body_iv, .aes_128_gcm, .{});
    var out: [256]u8 = undefined;
    const result = decryptChunk(&dec_state, wire_buf[0..n], &out);
    try testing.expect(result == .integrity_error);
}

test "nonce counter increment" {
    const body_key = [_]u8{0x60} ** 16;
    const body_iv = [_]u8{0x61} ** 16;
    var enc_state = StreamState.init(body_key, body_iv, .aes_128_gcm, .{});
    var dec_state = StreamState.init(body_key, body_iv, .aes_128_gcm, .{});

    var wire_buf: [256]u8 = undefined;
    var dec_buf: [256]u8 = undefined;

    const n1 = encryptChunk(&enc_state, "chunk1", &wire_buf) orelse return error.EncryptFailed;
    const r1 = decryptChunk(&dec_state, wire_buf[0..n1], &dec_buf);
    try testing.expect(r1 == .success);

    const n2 = encryptChunk(&enc_state, "chunk2", &wire_buf) orelse return error.EncryptFailed;
    const r2 = decryptChunk(&dec_state, wire_buf[0..n2], &dec_buf);
    switch (r2) {
        .success => |s| try testing.expectEqualStrings("chunk2", dec_buf[0..s.plaintext_len]),
        else => return error.DecryptFailed,
    }

    try testing.expectEqual(@as(u16, 2), enc_state.nonce_counter);
    try testing.expectEqual(@as(u16, 2), dec_state.nonce_counter);
}

test "multiple chunks sequential" {
    const body_key = [_]u8{0x70} ** 16;
    const body_iv = [_]u8{0x71} ** 16;
    var enc_state = StreamState.init(body_key, body_iv, .chacha20_poly1305, .{ .chunk_stream = true, .chunk_masking = true });
    var dec_state = StreamState.init(body_key, body_iv, .chacha20_poly1305, .{ .chunk_stream = true, .chunk_masking = true });

    const messages = [_][]const u8{ "first", "second", "third", "fourth", "fifth" };

    var wire_buf: [256]u8 = undefined;
    var dec_buf: [256]u8 = undefined;

    for (messages) |msg| {
        const n = encryptChunk(&enc_state, msg, &wire_buf) orelse return error.EncryptFailed;
        const result = decryptChunk(&dec_state, wire_buf[0..n], &dec_buf);
        switch (result) {
            .success => |s| try testing.expectEqualStrings(msg, dec_buf[0..s.plaintext_len]),
            else => return error.DecryptFailed,
        }
    }
}

test "empty chunk" {
    const body_key = [_]u8{0x80} ** 16;
    const body_iv = [_]u8{0x81} ** 16;
    var enc_state = StreamState.init(body_key, body_iv, .aes_128_gcm, .{});
    var dec_state = StreamState.init(body_key, body_iv, .aes_128_gcm, .{});

    var wire_buf: [256]u8 = undefined;
    var dec_buf: [256]u8 = undefined;

    const n = encryptChunk(&enc_state, &[_]u8{}, &wire_buf) orelse return error.EncryptFailed;
    const result = decryptChunk(&dec_state, wire_buf[0..n], &dec_buf);
    switch (result) {
        .success => |s| try testing.expectEqual(@as(usize, 0), s.plaintext_len),
        else => return error.DecryptFailed,
    }
}

test "encryptChunk buffer too small" {
    var state = StreamState.init([_]u8{0} ** 16, [_]u8{0} ** 16, .aes_128_gcm, .{});
    var small_buf: [4]u8 = undefined;
    const result = encryptChunk(&state, "this is a longer message", &small_buf);
    try testing.expect(result == null);
}

test "StreamState init AES-128-GCM" {
    const state = StreamState.init([_]u8{0xAA} ** 16, [_]u8{0xBB} ** 16, .aes_128_gcm, .{});
    try testing.expectEqual(@as(u8, 16), state.key_len);
    try testing.expectEqual(@as(u16, 0), state.nonce_counter);
}

test "StreamState init ChaCha20-Poly1305" {
    const state = StreamState.init([_]u8{0xCC} ** 16, [_]u8{0xDD} ** 16, .chacha20_poly1305, .{});
    try testing.expectEqual(@as(u8, 32), state.key_len);
}

test "encryptChunk and decryptChunk roundtrip AES-256-GCM" {
    try roundtripTest(.aes_256_gcm, false);
}

test "encryptChunk and decryptChunk roundtrip AES-256-GCM with masking" {
    try roundtripTest(.aes_256_gcm, true);
}

test "StreamState init AES-256-GCM" {
    const state = StreamState.init([_]u8{0xEE} ** 16, [_]u8{0xFF} ** 16, .aes_256_gcm, .{});
    try testing.expectEqual(@as(u8, 32), state.key_len);
}

test "global_padding roundtrip AES-128-GCM" {
    // global_padding requires chunk_masking=true (ShakeMask provides padding length)
    try roundtripTestWithPadding(.aes_128_gcm, true, true);
}

test "global_padding roundtrip AES-256-GCM" {
    try roundtripTestWithPadding(.aes_256_gcm, true, true);
}

test "global_padding roundtrip ChaCha20-Poly1305" {
    try roundtripTestWithPadding(.chacha20_poly1305, true, true);
}

test "global_padding multiple chunks sequential" {
    const body_key = [_]u8{0x90} ** 16;
    const body_iv = [_]u8{0x91} ** 16;
    const opts = OptionFlags{ .chunk_stream = true, .chunk_masking = true, .global_padding = true };

    var enc_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);
    var dec_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);

    const messages = [_][]const u8{ "first", "second message", "third", "four", "five-five-five" };

    var wire_buf: [512]u8 = undefined;
    var dec_buf: [256]u8 = undefined;

    for (messages) |msg| {
        const n = encryptChunk(&enc_state, msg, &wire_buf) orelse return error.EncryptFailed;
        // With padding, wire_len >= 2 + msg.len + tag + padding
        try testing.expect(n >= 2 + msg.len + gcm_tag_len);
        const result = decryptChunk(&dec_state, wire_buf[0..n], &dec_buf);
        switch (result) {
            .success => |s| try testing.expectEqualStrings(msg, dec_buf[0..s.plaintext_len]),
            else => return error.DecryptFailed,
        }
    }

    // Verify nonce counters are in sync
    try testing.expectEqual(@as(u16, 5), enc_state.nonce_counter);
    try testing.expectEqual(@as(u16, 5), dec_state.nonce_counter);
}

test "global_padding empty chunk (EOF marker)" {
    const body_key = [_]u8{0xA0} ** 16;
    const body_iv = [_]u8{0xA1} ** 16;
    const opts = OptionFlags{ .chunk_stream = true, .chunk_masking = true, .global_padding = true };

    var enc_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);
    var dec_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);

    var wire_buf: [512]u8 = undefined;
    var dec_buf: [256]u8 = undefined;

    // Encrypt empty chunk (EOF marker)
    const n = encryptChunk(&enc_state, &[_]u8{}, &wire_buf) orelse return error.EncryptFailed;
    const result = decryptChunk(&dec_state, wire_buf[0..n], &dec_buf);
    switch (result) {
        .success => |s| try testing.expectEqual(@as(usize, 0), s.plaintext_len),
        else => return error.DecryptFailed,
    }
}

test "global_padding without masking has no effect" {
    // global_padding=true but chunk_masking=false → padding_len stays 0
    const body_key = [_]u8{0xB0} ** 16;
    const body_iv = [_]u8{0xB1} ** 16;
    const opts_no_mask = OptionFlags{ .chunk_stream = true, .chunk_masking = false, .global_padding = true };
    const opts_plain = OptionFlags{ .chunk_stream = true, .chunk_masking = false, .global_padding = false };

    var enc1 = StreamState.init(body_key, body_iv, .aes_128_gcm, opts_no_mask);
    var enc2 = StreamState.init(body_key, body_iv, .aes_128_gcm, opts_plain);

    var buf1: [256]u8 = undefined;
    var buf2: [256]u8 = undefined;

    const n1 = encryptChunk(&enc1, "test", &buf1) orelse return error.EncryptFailed;
    const n2 = encryptChunk(&enc2, "test", &buf2) orelse return error.EncryptFailed;

    // Without masking, both should produce identical output (same size, same content)
    try testing.expectEqual(n1, n2);
    try testing.expectEqualSlices(u8, buf1[0..n1], buf2[0..n2]);
}

// ── auth_length tests ──

fn authLengthRoundtripTest(security: SecurityMethod) !void {
    const body_key = [_]u8{0xD0} ** 16;
    const body_iv = [_]u8{0xD1} ** 16;
    const opts = OptionFlags{ .chunk_stream = true, .chunk_masking = true, .auth_length = true };

    var enc_state = StreamState.init(body_key, body_iv, security, opts);
    var dec_state = StreamState.init(body_key, body_iv, security, opts);

    // auth_length should disable ShakeMask
    try testing.expect(!enc_state.has_shake);
    try testing.expect(!dec_state.has_shake);

    const plaintext = "Hello, auth_length VMess!";
    var wire_buf: [512]u8 = undefined;
    var dec_buf: [256]u8 = undefined;

    const n = encryptChunk(&enc_state, plaintext, &wire_buf) orelse return error.EncryptFailed;

    // Wire format: 18B AEAD size + plaintext_len + tag_len (no padding)
    const tag_len = tagLength(security);
    try testing.expectEqual(@as(usize, 18 + plaintext.len + tag_len), n);

    const result = decryptChunk(&dec_state, wire_buf[0..n], &dec_buf);
    switch (result) {
        .success => |s| {
            try testing.expectEqual(plaintext.len, s.plaintext_len);
            try testing.expectEqual(n, s.bytes_consumed);
            try testing.expectEqualStrings(plaintext, dec_buf[0..s.plaintext_len]);
        },
        else => return error.DecryptFailed,
    }
}

test "auth_length roundtrip AES-128-GCM" {
    try authLengthRoundtripTest(.aes_128_gcm);
}

test "auth_length roundtrip AES-256-GCM" {
    try authLengthRoundtripTest(.aes_256_gcm);
}

test "auth_length roundtrip ChaCha20-Poly1305" {
    try authLengthRoundtripTest(.chacha20_poly1305);
}

test "auth_length multiple chunks sequential" {
    const body_key = [_]u8{0xD2} ** 16;
    const body_iv = [_]u8{0xD3} ** 16;
    const opts = OptionFlags{ .chunk_stream = true, .chunk_masking = true, .auth_length = true };

    var enc_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);
    var dec_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);

    const messages = [_][]const u8{ "first", "second message", "third", "four", "five-five-five" };

    var wire_buf: [512]u8 = undefined;
    var dec_buf: [256]u8 = undefined;

    for (messages) |msg| {
        const n = encryptChunk(&enc_state, msg, &wire_buf) orelse return error.EncryptFailed;
        const result = decryptChunk(&dec_state, wire_buf[0..n], &dec_buf);
        switch (result) {
            .success => |s| try testing.expectEqualStrings(msg, dec_buf[0..s.plaintext_len]),
            else => return error.DecryptFailed,
        }
    }

    // Verify both nonce counters are in sync
    try testing.expectEqual(@as(u16, 5), enc_state.nonce_counter);
    try testing.expectEqual(@as(u16, 5), dec_state.nonce_counter);
    try testing.expectEqual(@as(u16, 5), enc_state.auth_length_nonce_counter);
    try testing.expectEqual(@as(u16, 5), dec_state.auth_length_nonce_counter);
}

test "auth_length empty chunk (EOF marker)" {
    const body_key = [_]u8{0xD4} ** 16;
    const body_iv = [_]u8{0xD5} ** 16;
    const opts = OptionFlags{ .chunk_stream = true, .chunk_masking = true, .auth_length = true };

    var enc_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);
    var dec_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);

    var wire_buf: [512]u8 = undefined;
    var dec_buf: [256]u8 = undefined;

    const n = encryptChunk(&enc_state, &[_]u8{}, &wire_buf) orelse return error.EncryptFailed;
    // Empty chunk: 18B AEAD size + 0 plaintext + 16B tag = 34
    try testing.expectEqual(@as(usize, 18 + gcm_tag_len), n);

    const result = decryptChunk(&dec_state, wire_buf[0..n], &dec_buf);
    switch (result) {
        .success => |s| try testing.expectEqual(@as(usize, 0), s.plaintext_len),
        else => return error.DecryptFailed,
    }
}

test "auth_length integrity error on corrupted size AEAD" {
    const body_key = [_]u8{0xD6} ** 16;
    const body_iv = [_]u8{0xD7} ** 16;
    const opts = OptionFlags{ .chunk_stream = true, .chunk_masking = true, .auth_length = true };

    var enc_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);
    var wire_buf: [512]u8 = undefined;

    const n = encryptChunk(&enc_state, "test data", &wire_buf) orelse return error.EncryptFailed;

    // Corrupt a byte in the AEAD size tag (bytes 2..18)
    wire_buf[10] ^= 0xFF;

    var dec_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);
    var out: [256]u8 = undefined;
    const result = decryptChunk(&dec_state, wire_buf[0..n], &out);
    try testing.expect(result == .integrity_error);
}

test "auth_length integrity error on corrupted data" {
    const body_key = [_]u8{0xD8} ** 16;
    const body_iv = [_]u8{0xD9} ** 16;
    const opts = OptionFlags{ .chunk_stream = true, .chunk_masking = true, .auth_length = true };

    var enc_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);
    var wire_buf: [512]u8 = undefined;

    const n = encryptChunk(&enc_state, "test data", &wire_buf) orelse return error.EncryptFailed;

    // Corrupt a byte in the data ciphertext (after 18-byte size field)
    wire_buf[20] ^= 0xFF;

    var dec_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);
    var out: [256]u8 = undefined;
    const result = decryptChunk(&dec_state, wire_buf[0..n], &out);
    try testing.expect(result == .integrity_error);
}

test "auth_length incomplete at size field" {
    const body_key = [_]u8{0xDA} ** 16;
    const body_iv = [_]u8{0xDB} ** 16;
    const opts = OptionFlags{ .chunk_stream = true, .chunk_masking = true, .auth_length = true };

    var state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);
    var out: [256]u8 = undefined;

    // Only 10 bytes — less than 18-byte size field
    const result = decryptChunk(&state, &([_]u8{0} ** 10), &out);
    try testing.expect(result == .incomplete);
    // auth_length_nonce_counter should NOT have been incremented
    try testing.expectEqual(@as(u16, 0), state.auth_length_nonce_counter);
}

test "auth_length incomplete at data portion with pending_decode" {
    const body_key = [_]u8{0xDC} ** 16;
    const body_iv = [_]u8{0xDD} ** 16;
    const opts = OptionFlags{ .chunk_stream = true, .chunk_masking = true, .auth_length = true };

    var enc_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);
    var dec_state = StreamState.init(body_key, body_iv, .aes_128_gcm, opts);

    var wire_buf: [512]u8 = undefined;
    var dec_buf: [256]u8 = undefined;

    const plaintext = "partial delivery test";
    const n = encryptChunk(&enc_state, plaintext, &wire_buf) orelse return error.EncryptFailed;

    // First attempt: give only 20 bytes (size field OK but not enough data)
    const r1 = decryptChunk(&dec_state, wire_buf[0..20], &dec_buf);
    try testing.expect(r1 == .incomplete);
    // auth_length_nonce_counter should have been incremented (size was decoded OK)
    try testing.expectEqual(@as(u16, 1), dec_state.auth_length_nonce_counter);
    // pending_decode should be set
    try testing.expect(dec_state.pending_decode != null);

    // Second attempt: give full data — pending_decode reused, no double nonce increment
    const r2 = decryptChunk(&dec_state, wire_buf[0..n], &dec_buf);
    switch (r2) {
        .success => |s| {
            try testing.expectEqualStrings(plaintext, dec_buf[0..s.plaintext_len]);
        },
        else => return error.DecryptFailed,
    }
    // auth_length_nonce_counter still 1 (not incremented again)
    try testing.expectEqual(@as(u16, 1), dec_state.auth_length_nonce_counter);
    // data nonce_counter incremented
    try testing.expectEqual(@as(u16, 1), dec_state.nonce_counter);
}
