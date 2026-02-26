// ══════════════════════════════════════════════════════════════
//  InboundHandler — Inbound protocol vtable interface (streaming)
//
//  Aligned with Xray's proxy.Inbound: each protocol implements
//  the same interface; session_handler has zero protocol knowledge.
//
//  parseStreamingFn reads exactly the bytes it needs from the
//  Transport — no accumulate-and-retry loop in the caller.
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const zio = @import("zio");
const codec_mod = @import("codec.zig");
const conn_types = @import("conn_types.zig");
const inbound_result_mod = @import("inbound_result.zig");
const InboundResult = inbound_result_mod.InboundResult;
const ConnectAction = inbound_result_mod.ConnectAction;
const ParsedAction = inbound_result_mod.ParsedAction;
const transport_mod = @import("transport.zig");
const Transport = transport_mod.Transport;
const user_store_mod = @import("user_store.zig");
const trojan_inbound = @import("../protocol/trojan/trojan_inbound.zig");
const vmess_inbound = @import("../protocol/vmess/vmess_inbound.zig");
const vmess_protocol = @import("../protocol/vmess/vmess_protocol.zig");
const vmess_hot_cache = @import("../protocol/vmess/vmess_hot_cache.zig");
const vmess_stream = @import("../protocol/vmess/vmess_stream.zig");
const vmess_crypto = @import("../protocol/vmess/vmess_crypto.zig");
const ss_inbound = @import("../protocol/shadowsocks/ss_inbound.zig");
const ss_crypto = @import("../protocol/shadowsocks/ss_crypto.zig");
const ss_protocol = @import("../protocol/shadowsocks/ss_protocol.zig");
const boringssl = @import("../crypto/boringssl_crypto.zig");

const Codec = codec_mod.Codec;
const CodecPair = codec_mod.CodecPair;
const VMessCodec = codec_mod.VMessCodec;
const SsCodec = codec_mod.SsCodec;
const InboundProtocol = conn_types.InboundProtocol;

/// Inbound protocol handler — unified streaming interface.
pub const InboundHandler = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Stream-read protocol header from Transport → ParsedAction.
        /// Reads exactly the bytes needed; no accumulate-and-retry loop.
        /// work_buf (20KB): ciphertext / accumulation workspace.
        /// plain_buf (20KB): plaintext output (SS first frame decryption).
        /// payload_buf (8KB): initial application payload output.
        parseStreamingFn: *const fn (
            ptr: *anyopaque,
            t: Transport,
            work_buf: []u8,
            plain_buf: []u8,
            payload_buf: []u8,
            timeout: zio.Timeout,
        ) anyerror!ParsedAction,

        /// Extract CodecPair from parsed protocol state (decrypt uplink + encrypt downlink).
        codecsFn: *const fn (ptr: *anyopaque, state: *InboundProtocol) CodecPair,

        /// Get inbound response bytes (VMess response header / SS salt; trojan = null).
        responseFn: *const fn (ptr: *anyopaque, action: *const ConnectAction) ?[]const u8,
    };

    pub inline fn parseStreaming(
        self: InboundHandler,
        t: Transport,
        work_buf: []u8,
        plain_buf: []u8,
        payload_buf: []u8,
        timeout: zio.Timeout,
    ) anyerror!ParsedAction {
        return self.vtable.parseStreamingFn(self.ptr, t, work_buf, plain_buf, payload_buf, timeout);
    }

    pub inline fn codecs(self: InboundHandler, state: *InboundProtocol) CodecPair {
        return self.vtable.codecsFn(self.ptr, state);
    }

    pub inline fn response(self: InboundHandler, action: *const ConnectAction) ?[]const u8 {
        return self.vtable.responseFn(self.ptr, action);
    }
};

// ── Trojan Inbound ──

pub const TrojanInbound = struct {
    user_store: ?*user_store_mod.UserStore,

    const vtable = InboundHandler.VTable{
        .parseStreamingFn = trojanParseStreaming,
        .codecsFn = trojanCodecs,
        .responseFn = trojanResponse,
    };

    pub fn handler(self: *TrojanInbound) InboundHandler {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    /// Accumulate bytes into work_buf until the Trojan header is fully parsed.
    /// Header max size ≈ 320B (SHA224_HEX + CRLF + CMD + ATYP + addr + port + CRLF).
    /// work_buf is 20KB — more than enough for header + generous initial payload.
    fn trojanParseStreaming(
        ptr: *anyopaque,
        t: Transport,
        work_buf: []u8,
        _: []u8,
        payload_buf: []u8,
        timeout: zio.Timeout,
    ) anyerror!ParsedAction {
        const self: *TrojanInbound = @ptrCast(@alignCast(ptr));
        var accumulated: usize = 0;

        while (accumulated < work_buf.len) {
            const n = try t.read(work_buf[accumulated..], timeout);
            if (n == 0) return error.ClientDisconnected;
            accumulated += n;

            switch (trojan_inbound.parseInbound(work_buf[0..accumulated], self.user_store, payload_buf)) {
                .connect => |act| return .{ .action = act, .is_udp = false },
                .udp_associate => |act| return .{ .action = act, .is_udp = true },
                .need_more => continue,
                .close => |_| return error.ProtocolRejected,
                .fallback => return error.Fallback,
            }
        }
        return error.ProtocolBufferFull;
    }

    fn trojanCodecs(_: *anyopaque, _: *InboundProtocol) CodecPair {
        return CodecPair.passthrough;
    }

    fn trojanResponse(_: *anyopaque, _: *const ConnectAction) ?[]const u8 {
        return null;
    }
};

// ── VMess Inbound ──

pub const VMessInbound = struct {
    user_store: ?*user_store_mod.UserStore,
    replay_filter: *vmess_protocol.ReplayFilter,
    replay_mutex: *std.Thread.Mutex,
    hot_cache: ?*vmess_hot_cache.HotCache,
    allocator: std.mem.Allocator,

    // Codec adapter storage — lifetime tied to this VMessInbound instance
    dec_adapter: VMessCodec = undefined,
    enc_adapter: VMessCodec = undefined,

    const vtable = InboundHandler.VTable{
        .parseStreamingFn = vmessParseStreaming,
        .codecsFn = vmessCodecs,
        .responseFn = vmessResponse,
    };

    pub fn handler(self: *VMessInbound) InboundHandler {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    /// Streaming VMess parse:
    ///   1. readExact 42B preamble
    ///   2. scan users → identify cmd_key + header_len  (replay_mutex locked)
    ///   3. readExact header_len+16 bytes
    ///   4. decrypt header + replay check               (replay_mutex locked)
    ///   5. init StreamStates, encode 38B response header
    fn vmessParseStreaming(
        ptr: *anyopaque,
        t: Transport,
        work_buf: []u8,
        _: []u8,
        _: []u8,
        timeout: zio.Timeout,
    ) anyerror!ParsedAction {
        const self: *VMessInbound = @ptrCast(@alignCast(ptr));
        const user_map_opt = if (self.user_store) |us| us.getUsers() else null;
        const users = user_map_opt orelse return error.NoUsersConfigured;

        // 1. Read 42-byte preamble: AuthID(16) + EncLen(18) + Nonce(8)
        try t.readExact(work_buf[0..42], timeout);

        const now = std.time.timestamp();

        // 2. Identify user + decode header length (does NOT check replay)
        const step1: vmess_protocol.StreamStep1Result = blk: {
            self.replay_mutex.lock();
            defer self.replay_mutex.unlock();
            break :blk vmess_protocol.streamStep1(
                work_buf[0..42],
                users,
                self.hot_cache,
                self.allocator,
                now,
            ) orelse return error.VMessAuthFailed;
        };

        // 3. Read remaining header: EncHeader(header_len) + GCM-tag(16)
        const header_body_len: usize = @as(usize, step1.header_len) + 16;
        if (42 + header_body_len > work_buf.len) return error.VMessHeaderTooLarge;
        try t.readExact(work_buf[42 .. 42 + header_body_len], timeout);

        // 4. Decrypt header + replay check
        const req: vmess_protocol.VMessRequest = blk: {
            self.replay_mutex.lock();
            defer self.replay_mutex.unlock();
            const result = vmess_protocol.streamStep2(
                work_buf[0 .. 42 + header_body_len],
                step1,
                self.replay_filter,
                now,
            );
            switch (result) {
                .success => |r| break :blk r,
                .incomplete => return error.VMessIncomplete,
                .auth_failed => return error.VMessAuthFailed,
                .replay_detected => return error.VMessReplay,
                .protocol_error => return error.VMessProtocolError,
            }
        };

        // 5. Build ConnectAction
        const user_id: i64 = if (req.matched_user) |u| u.id else -1;
        const resp_key = vmess_crypto.deriveResponseKey(req.request_body_key);
        const resp_iv = vmess_crypto.deriveResponseIv(req.request_body_iv);

        var action = ConnectAction{
            .target = req.target,
            .user_id = user_id,
            .protocol_state = .{ .vmess = .{
                .request_state = vmess_stream.StreamState.init(
                    req.request_body_key,
                    req.request_body_iv,
                    req.security,
                    req.options,
                ),
                .response_state = vmess_stream.StreamState.init(
                    resp_key,
                    resp_iv,
                    req.security,
                    req.options,
                ),
            } },
        };

        const label = std.fmt.bufPrint(&action.proto_label_buf, "vmess|{s}", .{@tagName(req.security)}) catch "vmess";
        action.proto_label_len = @intCast(label.len);

        // Encode 38-byte VMess response header for later send
        if (vmess_protocol.encodeResponse(&action.response_buf, &req)) |resp_len| {
            action.response_len = @intCast(resp_len);
        }

        // No initial payload: relay loop decrypts the first VMess chunk naturally
        return .{ .action = action, .is_udp = req.command == .udp };
    }

    fn vmessCodecs(ptr: *anyopaque, state: *InboundProtocol) CodecPair {
        const self: *VMessInbound = @ptrCast(@alignCast(ptr));
        switch (state.*) {
            .vmess => |*vs| {
                self.dec_adapter = .{ .state = &vs.request_state };
                self.enc_adapter = .{ .state = &vs.response_state };
                return .{
                    .decoder = self.dec_adapter.codec(),
                    .encoder = self.enc_adapter.codec(),
                };
            },
            else => return CodecPair.passthrough,
        }
    }

    fn vmessResponse(_: *anyopaque, action: *const ConnectAction) ?[]const u8 {
        if (action.response_len > 0) {
            return action.response_buf[0..action.response_len];
        }
        return null;
    }
};

// ── Shadowsocks Inbound ──

pub const SsInbound = struct {
    method: ss_crypto.Method,
    psk: []const u8,

    // Codec adapter storage
    dec_adapter: SsCodec = undefined,
    enc_adapter: SsCodec = undefined,

    const vtable = InboundHandler.VTable{
        .parseStreamingFn = ssParseStreaming,
        .codecsFn = ssCodecs,
        .responseFn = ssResponse,
    };

    pub fn handler(self: *SsInbound) InboundHandler {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    /// Streaming SS parse — fixes the 4KB first-frame limit:
    ///   1. readExact salt (16 or 32B)
    ///   2. init decrypt_state from salt + PSK
    ///   3. readExact 18B encrypted length block
    ///   4. peekPayloadLen (no nonce advance)
    ///   5. readExact payload_len + 16B (payload ciphertext + AEAD tag)
    ///   6. decryptFrame the full first frame into plain_buf (20KB)
    ///   7. parseAddress from plaintext
    ///   8. copy initial app payload to payload_buf; set payload_is_decrypted = true
    fn ssParseStreaming(
        ptr: *anyopaque,
        t: Transport,
        work_buf: []u8,
        plain_buf: []u8,
        payload_buf: []u8,
        timeout: zio.Timeout,
    ) anyerror!ParsedAction {
        const self: *SsInbound = @ptrCast(@alignCast(ptr));
        const salt_size = self.method.saltSize();

        // 1. Read salt
        try t.readExact(work_buf[0..salt_size], timeout);

        // 2. Init decrypt state
        var decrypt_state = ss_crypto.StreamState.init(self.method, self.psk, work_buf[0..salt_size]);

        // 3. Read 18-byte encrypted length block (after the salt in work_buf)
        try t.readExact(work_buf[salt_size .. salt_size + 18], timeout);

        // 4. Peek payload length without advancing nonce
        const payload_len = decrypt_state.peekPayloadLen(work_buf[salt_size .. salt_size + 18][0..18]) orelse
            return error.SsDecryptFailed;

        // 5. Read encrypted payload + 16-byte AEAD tag
        const payload_wire_len: usize = payload_len + 16;
        const frame_end = salt_size + 18 + payload_wire_len;
        if (frame_end > work_buf.len) return error.SsFrameTooLarge;
        try t.readExact(work_buf[salt_size + 18 .. frame_end], timeout);

        // 6. Decrypt the full first frame (18B length + payload_len+16B payload)
        //    plain_buf is 20KB — handles SS max frame (16383B plaintext)
        const dec_result = decrypt_state.decryptFrame(work_buf[salt_size..frame_end], plain_buf);
        const plaintext_len = switch (dec_result) {
            .success => |s| s.plaintext_len,
            .incomplete => return error.SsDecryptFailed,
            .integrity_error => return error.SsDecryptFailed,
        };

        // 7. Parse SOCKS5 address from decrypted plaintext
        const addr_result = ss_protocol.parseAddress(plain_buf[0..plaintext_len]);
        const parsed_addr = switch (addr_result) {
            .success => |a| a,
            .incomplete => return error.SsIncomplete,
            .protocol_error => return error.SsProtocolError,
        };

        // 8. Copy initial application payload (after address header) to payload_buf
        const addr_header_len = parsed_addr.header_len;
        const ip_payload_len = plaintext_len - addr_header_len;
        const copy_len = @min(ip_payload_len, payload_buf.len);
        if (copy_len > 0) {
            @memcpy(payload_buf[0..copy_len], plain_buf[addr_header_len .. addr_header_len + copy_len]);
        }

        // 9. Generate random salt for response encryption
        var resp_salt: [ss_crypto.max_key_size]u8 = undefined;
        boringssl.random.bytes(resp_salt[0..salt_size]);

        var action = ConnectAction{
            .target = parsed_addr.target,
            .protocol_state = .{ .shadowsocks = .{
                .decrypt_state = decrypt_state,
                .encrypt_state = ss_crypto.StreamState.init(self.method, self.psk, resp_salt[0..salt_size]),
            } },
            .payload_len = @intCast(copy_len),
            // payload_buf contains already-decrypted plaintext — skip re-decryption
            .payload_is_decrypted = true,
        };

        @memcpy(action.salt_buf[0..salt_size], resp_salt[0..salt_size]);
        action.salt_len = @intCast(salt_size);
        action.setProtoLabel("shadowsocks");

        return .{ .action = action, .is_udp = false };
    }

    fn ssCodecs(ptr: *anyopaque, state: *InboundProtocol) CodecPair {
        const self: *SsInbound = @ptrCast(@alignCast(ptr));
        switch (state.*) {
            .shadowsocks => |*ss| {
                self.dec_adapter = .{ .state = &ss.decrypt_state };
                self.enc_adapter = .{ .state = &ss.encrypt_state };
                return .{
                    .decoder = self.dec_adapter.codec(),
                    .encoder = self.enc_adapter.codec(),
                };
            },
            else => return CodecPair.passthrough,
        }
    }

    fn ssResponse(_: *anyopaque, action: *const ConnectAction) ?[]const u8 {
        if (action.salt_len > 0) {
            return action.salt_buf[0..action.salt_len];
        }
        return null;
    }
};

// ── Handler Storage ──

/// Holds concrete inbound handler instances — one active at a time per session.
pub const InboundHandlerStorage = struct {
    trojan: TrojanInbound = undefined,
    vmess: VMessInbound = undefined,
    ss: SsInbound = undefined,
};
