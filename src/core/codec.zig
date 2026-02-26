// ══════════════════════════════════════════════════════════════
//  Codec — Unified encrypt/decrypt vtable interface
//
//  Wraps VMess/SS stream crypto behind a common interface.
//  Passthrough codec (trojan/direct) uses is_noop flag for
//  zero-copy fast path in relay loop.
// ══════════════════════════════════════════════════════════════

const vmess_stream = @import("../protocol/vmess/vmess_stream.zig");
const ss_crypto = @import("../protocol/shadowsocks/ss_crypto.zig");

/// Result of a decrypt operation — common to VMess and SS.
pub const DecryptResult = union(enum) {
    success: struct {
        plaintext_len: usize,
        bytes_consumed: usize,
    },
    incomplete,
    integrity_error,
};

/// Unified codec interface — protocol layer uses only this.
pub const Codec = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    is_noop: bool, // passthrough fast path flag

    pub const VTable = struct {
        encryptFn: *const fn (ptr: *anyopaque, plaintext: []const u8, out: []u8) ?usize,
        decryptFn: *const fn (ptr: *anyopaque, data: []const u8, out: []u8) DecryptResult,
    };

    pub inline fn encrypt(self: Codec, plaintext: []const u8, out: []u8) ?usize {
        return self.vtable.encryptFn(self.ptr, plaintext, out);
    }

    pub inline fn decrypt(self: Codec, data: []const u8, out: []u8) DecryptResult {
        return self.vtable.decryptFn(self.ptr, data, out);
    }

    /// Passthrough codec — no encryption/decryption.
    pub const passthrough: Codec = .{
        .ptr = undefined,
        .vtable = &noop_vtable,
        .is_noop = true,
    };

    const noop_vtable = VTable{
        .encryptFn = noopEncrypt,
        .decryptFn = noopDecrypt,
    };

    fn noopEncrypt(_: *anyopaque, plaintext: []const u8, _: []u8) ?usize {
        return plaintext.len;
    }

    fn noopDecrypt(_: *anyopaque, data: []const u8, _: []u8) DecryptResult {
        return .{ .success = .{ .plaintext_len = data.len, .bytes_consumed = data.len } };
    }
};

/// Codec pair — one per direction (inbound: decode uplink + encode downlink).
pub const CodecPair = struct {
    decoder: Codec, // decrypt direction
    encoder: Codec, // encrypt direction

    pub const passthrough: CodecPair = .{
        .decoder = Codec.passthrough,
        .encoder = Codec.passthrough,
    };
};

// ── VMess Codec Adapter ──

pub const VMessCodec = struct {
    state: *vmess_stream.StreamState,

    const vmess_vtable = Codec.VTable{
        .encryptFn = vmessEncrypt,
        .decryptFn = vmessDecrypt,
    };

    pub fn codec(self: *VMessCodec) Codec {
        return .{ .ptr = @ptrCast(self), .vtable = &vmess_vtable, .is_noop = false };
    }

    fn vmessEncrypt(ptr: *anyopaque, plaintext: []const u8, out: []u8) ?usize {
        const self: *VMessCodec = @ptrCast(@alignCast(ptr));
        return vmess_stream.encryptChunk(self.state, plaintext, out);
    }

    fn vmessDecrypt(ptr: *anyopaque, data: []const u8, out: []u8) DecryptResult {
        const self: *VMessCodec = @ptrCast(@alignCast(ptr));
        const result = vmess_stream.decryptChunk(self.state, data, out);
        return switch (result) {
            .success => |s| .{ .success = .{ .plaintext_len = s.plaintext_len, .bytes_consumed = s.bytes_consumed } },
            .incomplete => .incomplete,
            .integrity_error => .integrity_error,
        };
    }
};

// ── Shadowsocks Codec Adapter ──

pub const SsCodec = struct {
    state: *ss_crypto.StreamState,

    const ss_vtable = Codec.VTable{
        .encryptFn = ssEncrypt,
        .decryptFn = ssDecrypt,
    };

    pub fn codec(self: *SsCodec) Codec {
        return .{ .ptr = @ptrCast(self), .vtable = &ss_vtable, .is_noop = false };
    }

    fn ssEncrypt(ptr: *anyopaque, plaintext: []const u8, out: []u8) ?usize {
        const self: *SsCodec = @ptrCast(@alignCast(ptr));
        return self.state.encryptFrame(plaintext, out);
    }

    fn ssDecrypt(ptr: *anyopaque, data: []const u8, out: []u8) DecryptResult {
        const self: *SsCodec = @ptrCast(@alignCast(ptr));
        const result = self.state.decryptFrame(data, out);
        return switch (result) {
            .success => |s| .{ .success = .{ .plaintext_len = s.plaintext_len, .bytes_consumed = s.bytes_consumed } },
            .incomplete => .incomplete,
            .integrity_error => .integrity_error,
        };
    }
};
