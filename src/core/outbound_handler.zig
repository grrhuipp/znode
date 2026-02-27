// ══════════════════════════════════════════════════════════════
//  OutboundHandler — Outbound protocol vtable interface
//
//  Aligned with Xray's proxy.Outbound: each protocol implements
//  the same interface; session_handler has zero protocol knowledge.
//
//  Each implementation struct holds its own dependencies
//  (password_hash, uuid, PSK, crypto state, etc.).
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const zio = @import("zio");
const codec_mod = @import("codec.zig");
const transport_mod = @import("transport.zig");
const session_mod = @import("session.zig");
const trojan_outbound = @import("../protocol/trojan/trojan_outbound.zig");
const trojan_protocol = @import("../protocol/trojan/trojan_protocol.zig");
const vmess_outbound = @import("../protocol/vmess/vmess_outbound.zig");
const vmess_protocol = @import("../protocol/vmess/vmess_protocol.zig");
const vmess_stream = @import("../protocol/vmess/vmess_stream.zig");
const ss_outbound = @import("../protocol/shadowsocks/ss_outbound.zig");
const ss_crypto = @import("../protocol/shadowsocks/ss_crypto.zig");

const Codec = codec_mod.Codec;
const CodecPair = codec_mod.CodecPair;
const VMessCodec = codec_mod.VMessCodec;
const SsCodec = codec_mod.SsCodec;
const DecryptResult = codec_mod.DecryptResult;
const Transport = transport_mod.Transport;
const TargetAddress = session_mod.TargetAddress;

/// Outbound protocol handler — unified interface.
pub const OutboundHandler = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Encode protocol header + send via Transport; read response if needed (VMess).
        handshakeFn: *const fn (
            ptr: *anyopaque,
            t: Transport,
            target: *const TargetAddress,
            initial_payload: ?[]const u8,
            send_buf: []u8,
            recv_buf: []u8,
            timeout: zio.Timeout,
        ) anyerror!void,

        /// Extract CodecPair for relay encryption/decryption (uplink encrypt + downlink decrypt).
        codecsFn: *const fn (ptr: *anyopaque) CodecPair,
    };

    pub inline fn handshake(
        self: OutboundHandler,
        t: Transport,
        target: *const TargetAddress,
        initial_payload: ?[]const u8,
        send_buf: []u8,
        recv_buf: []u8,
        timeout: zio.Timeout,
    ) anyerror!void {
        return self.vtable.handshakeFn(self.ptr, t, target, initial_payload, send_buf, recv_buf, timeout);
    }

    pub inline fn codecs(self: OutboundHandler) CodecPair {
        return self.vtable.codecsFn(self.ptr);
    }
};

// ── Direct Outbound ──

pub const DirectOutbound = struct {
    const vtable = OutboundHandler.VTable{
        .handshakeFn = directHandshake,
        .codecsFn = directCodecs,
    };

    pub fn handler(self: *DirectOutbound) OutboundHandler {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn directHandshake(
        _: *anyopaque,
        t: Transport,
        _: *const TargetAddress,
        initial_payload: ?[]const u8,
        _: []u8,
        _: []u8,
        timeout: zio.Timeout,
    ) anyerror!void {
        if (initial_payload) |payload| {
            if (payload.len > 0) try t.write(payload, timeout);
        }
    }

    fn directCodecs(_: *anyopaque) CodecPair {
        return CodecPair.passthrough;
    }
};

// ── Trojan Outbound ──

pub const TrojanOutbound = struct {
    password_hash: *const [trojan_protocol.HASH_LEN]u8,

    const vtable = OutboundHandler.VTable{
        .handshakeFn = trojanHandshake,
        .codecsFn = trojanCodecs,
    };

    pub fn handler(self: *TrojanOutbound) OutboundHandler {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn trojanHandshake(
        ptr: *anyopaque,
        t: Transport,
        target: *const TargetAddress,
        initial_payload: ?[]const u8,
        send_buf: []u8,
        _: []u8,
        timeout: zio.Timeout,
    ) anyerror!void {
        const self: *TrojanOutbound = @ptrCast(@alignCast(ptr));
        const header_len = trojan_outbound.encodeHeader(
            send_buf,
            self.password_hash.*,
            .connect,
            target,
        ) orelse return error.HeaderEncodeFailed;

        // Append initial payload after header
        var total = header_len;
        if (initial_payload) |payload| {
            if (total + payload.len <= send_buf.len) {
                @memcpy(send_buf[total .. total + payload.len], payload);
                total += payload.len;
            }
        }
        try t.write(send_buf[0..total], timeout);
    }

    fn trojanCodecs(_: *anyopaque) CodecPair {
        return CodecPair.passthrough;
    }
};

// ── VMess Outbound ──

pub const VMessOutbound = struct {
    uuid: *const [16]u8,
    security: vmess_protocol.SecurityMethod,

    // Crypto state produced during handshake
    request_state: vmess_stream.StreamState = undefined,
    response_state: vmess_stream.StreamState = undefined,
    body_key: [16]u8 = undefined,
    body_iv: [16]u8 = undefined,
    resp_header: u8 = 0,
    has_request: bool = false,
    has_response: bool = false,

    // Codec adapters — lifetime tied to this VMessOutbound instance
    enc_adapter: VMessCodec = undefined,
    dec_adapter: VMessCodec = undefined,

    const vtable = OutboundHandler.VTable{
        .handshakeFn = vmessHandshake,
        .codecsFn = vmessCodecs,
    };

    pub fn handler(self: *VMessOutbound) OutboundHandler {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn vmessHandshake(
        ptr: *anyopaque,
        t: Transport,
        target: *const TargetAddress,
        initial_payload: ?[]const u8,
        send_buf: []u8,
        recv_buf: []u8,
        timeout: zio.Timeout,
    ) anyerror!void {
        const self: *VMessOutbound = @ptrCast(@alignCast(ptr));

        // 1. Encode VMess request header
        const result = vmess_outbound.encodeHeader(
            send_buf,
            self.uuid.*,
            target,
            .tcp,
            self.security,
        ) orelse return error.VMessHeaderEncodeFailed;

        // Install crypto state
        self.request_state = result.request_state;
        self.body_key = result.body_key;
        self.body_iv = result.body_iv;
        self.resp_header = result.resp_header;
        self.has_request = true;

        // 2. Optionally append initial payload as first VMess chunk (encrypted)
        //    by writing header + encrypted chunk in a single send_buf write,
        //    so the server sees them in one TCP segment (avoids two RTTs).
        var total_write: usize = result.wire_len;
        if (initial_payload) |payload| {
            if (payload.len > 0) {
                // Encrypt into the space after the header (must not overlap)
                const remaining_buf = send_buf[total_write..];
                const enc_n = vmess_stream.encryptChunk(
                    &self.request_state,
                    payload,
                    remaining_buf,
                ) orelse return error.VMessEncryptFailed;
                total_write += enc_n;
            }
        }
        try t.write(send_buf[0..total_write], timeout);

        // 4. Read VMess response header (exactly 38 bytes)
        //    CRITICAL: limit read buffer to response_wire_size to avoid consuming
        //    data beyond the response header. Excess bytes stay in TLS/WS internal
        //    buffers and will be read by the relay.
        const resp_size = vmess_protocol.response_wire_size;
        var accumulated: usize = 0;
        while (accumulated < resp_size) {
            const n = try t.read(recv_buf[accumulated..resp_size], timeout);
            if (n == 0) return error.TargetDisconnected;
            accumulated += n;

            const resp = vmess_outbound.parseResponse(
                recv_buf[0..accumulated],
                self.body_key,
                self.body_iv,
                self.resp_header,
                self.security,
            );
            switch (resp) {
                .success => |s| {
                    self.response_state = s.response_state;
                    self.has_response = true;
                    return;
                },
                .need_more => continue,
                .protocol_error, .validation_failed => return error.VMessResponseInvalid,
            }
        }
        return error.VMessResponseTooLarge;
    }

    fn vmessCodecs(ptr: *anyopaque) CodecPair {
        const self: *VMessOutbound = @ptrCast(@alignCast(ptr));
        if (self.has_request and self.has_response) {
            self.enc_adapter = .{ .state = &self.request_state };
            self.dec_adapter = .{ .state = &self.response_state };
            return .{
                .encoder = self.enc_adapter.codec(),
                .decoder = self.dec_adapter.codec(),
            };
        }
        return CodecPair.passthrough;
    }
};

// ── Shadowsocks Outbound ──

pub const SsOutbound = struct {
    method: ss_crypto.Method,
    psk: []const u8,

    // Crypto state produced during handshake
    encrypt_state: ss_crypto.StreamState = undefined,
    has_encrypt: bool = false,

    // Lazy-init decrypt state (initialized on first server response)
    out_decoder: SsOutboundDecoder = undefined,

    // Codec adapters
    enc_adapter: SsCodec = undefined,

    const vtable = OutboundHandler.VTable{
        .handshakeFn = ssHandshake,
        .codecsFn = ssCodecs,
    };

    pub fn handler(self: *SsOutbound) OutboundHandler {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn ssHandshake(
        ptr: *anyopaque,
        t: Transport,
        target: *const TargetAddress,
        initial_payload: ?[]const u8,
        send_buf: []u8,
        _: []u8,
        timeout: zio.Timeout,
    ) anyerror!void {
        const self: *SsOutbound = @ptrCast(@alignCast(ptr));
        const payload = initial_payload orelse &[_]u8{};

        const result = ss_outbound.encodeFirstPacket(
            send_buf,
            self.method,
            self.psk,
            target,
            payload,
        ) orelse return error.SsEncodeFailed;

        // Install encrypt state (decrypt initialized lazily on first response)
        self.encrypt_state = result.encrypt_state;
        self.has_encrypt = true;

        try t.write(send_buf[0..result.total_len], timeout);
    }

    fn ssCodecs(ptr: *anyopaque) CodecPair {
        const self: *SsOutbound = @ptrCast(@alignCast(ptr));
        if (self.has_encrypt) {
            self.enc_adapter = .{ .state = &self.encrypt_state };

            // Decoder: lazy-init from server's salt on first response
            self.out_decoder = .{
                .method = self.method,
                .psk = self.psk,
            };

            return .{
                .encoder = self.enc_adapter.codec(),
                .decoder = self.out_decoder.codec(),
            };
        }
        return CodecPair.passthrough;
    }
};

/// Convert ss_crypto.DecryptResult → codec.DecryptResult (structurally identical, different types).
fn convertDecryptResult(result: ss_crypto.DecryptResult, extra_consumed: usize) DecryptResult {
    return switch (result) {
        .success => |s| .{ .success = .{
            .plaintext_len = s.plaintext_len,
            .bytes_consumed = extra_consumed + s.bytes_consumed,
        } },
        .incomplete => if (extra_consumed > 0)
            .{ .success = .{ .plaintext_len = 0, .bytes_consumed = extra_consumed } }
        else
            .incomplete,
        .integrity_error => .integrity_error,
    };
}

/// SS outbound decrypt codec — handles salt extraction on first server response.
///
/// SS AEAD response format: [salt][encrypted frames...]
/// The salt arrives with the first response data. This codec transparently
/// extracts the salt, initializes the decrypt StreamState, then delegates
/// to normal frame decryption.
const SsOutboundDecoder = struct {
    method: ss_crypto.Method = .aes_128_gcm,
    psk: []const u8 = &.{},
    decrypt_state: ss_crypto.StreamState = undefined,
    initialized: bool = false,

    const decoder_vtable = Codec.VTable{
        .encryptFn = noopEncrypt,
        .decryptFn = lazyDecrypt,
        .decryptDebugFn = noDecryptDebug,
    };

    fn codec(self: *SsOutboundDecoder) Codec {
        return .{ .ptr = @ptrCast(self), .vtable = &decoder_vtable, .is_noop = false };
    }

    fn noopEncrypt(_: *anyopaque, plaintext: []const u8, _: []u8) ?usize {
        return plaintext.len;
    }

    fn lazyDecrypt(ptr: *anyopaque, data: []const u8, out: []u8) DecryptResult {
        const self: *SsOutboundDecoder = @ptrCast(@alignCast(ptr));

        if (!self.initialized) {
            // First response: extract salt to derive decrypt subkey
            const salt_size = self.method.saltSize();
            if (data.len < salt_size) return .incomplete;

            // Initialize decrypt state from server's salt + PSK
            self.decrypt_state = ss_crypto.StreamState.init(
                self.method,
                self.psk,
                data[0..salt_size],
            );
            self.initialized = true;

            // Process remaining data after salt
            const remaining = data[salt_size..];
            if (remaining.len == 0) {
                // Salt consumed but no frame data yet
                return .{ .success = .{ .plaintext_len = 0, .bytes_consumed = salt_size } };
            }

            // Try to decrypt first frame
            return convertDecryptResult(self.decrypt_state.decryptFrame(remaining, out), salt_size);
        }

        // After initialization: normal frame decrypt
        return convertDecryptResult(self.decrypt_state.decryptFrame(data, out), 0);
    }

    fn noDecryptDebug(_: *anyopaque) ?codec_mod.DecryptDebugInfo {
        return null;
    }
};

// ── Handler Storage ──

/// Holds concrete outbound handler instances — one active at a time per session.
pub const OutboundHandlerStorage = struct {
    direct: DirectOutbound = .{},
    trojan: TrojanOutbound = undefined,
    vmess: VMessOutbound = undefined,
    ss: SsOutbound = undefined,
};
