/// VMess AEAD inbound handler.
///
/// Flow:
/// 1. Read AuthID (16 bytes) → brute-force user authentication
/// 2. Read AEAD header: length chunk (18) + connection nonce (8) + header payload
/// 3. Decrypt double-layer AEAD header → extract VMessRequest
/// 4. Send AEAD response header
/// 5. Wrap stream with VMessStream for chunk AEAD
const std = @import("std");
const types = @import("../../common/types.zig");
const session = @import("../../app/session.zig");
const crypto = @import("crypto.zig");
const user_manager_mod = @import("user_manager.zig");
const aead_mod = @import("../../infra/crypto/aead.zig");

pub const ParsedAction = struct {
    target: types.TargetAddress,
    network: types.Network,
    request: crypto.VMessRequest,
};

pub const InboundError = error{
    AuthFailed,
    InvalidProtocol,
    NeedMoreData,
    BufferOverflow,
    InnerStreamError,
    CryptoFailed,
};

pub const VMessInboundHandler = struct {
    user_manager: *const user_manager_mod.UserManager,

    pub fn init(um: *const user_manager_mod.UserManager) VMessInboundHandler {
        return .{ .user_manager = um };
    }

    /// Read VMess AEAD request from transport stream.
    pub fn parseStream(
        self: *const VMessInboundHandler,
        comptime Transport: type,
        transport: *Transport,
        ctx: *session.SessionContext,
    ) InboundError!ParsedAction {
        // 1. Read AuthID (16 bytes)
        var auth_id: [16]u8 = undefined;
        try readExact(Transport, transport, &auth_id);

        // 2. Authenticate
        const auth = self.user_manager.authenticate(&auth_id) orelse
            return error.AuthFailed;

        ctx.user_id = auth.user.user_id;
        ctx.setUserEmail(auth.user.email);
        ctx.speed_limit = auth.user.speed_limit_bytes;
        ctx.inbound_protocol = .vmess;

        // 3. Read length chunk (18 bytes = 2 + 16 tag)
        var len_chunk: [18]u8 = undefined;
        try readExact(Transport, transport, &len_chunk);

        // 4. Read connection nonce (8 bytes)
        var conn_nonce: [8]u8 = undefined;
        try readExact(Transport, transport, &conn_nonce);

        // 5. Derive header keys
        const header_keys = crypto.deriveHeaderKeys(
            &auth.user.cmd_key,
            &auth_id,
            &conn_nonce,
        ) catch return error.CryptoFailed;

        // 6. Decrypt length to know header payload size
        var len_plain: [2]u8 = undefined;
        _ = aead_mod.decrypt(
            .aes_128_gcm,
            &header_keys.len_key,
            &header_keys.len_iv,
            &len_chunk,
            &auth_id, // AAD
            &len_plain,
        ) catch return error.AuthFailed;

        const header_len = (@as(usize, len_plain[0]) << 8) | @as(usize, len_plain[1]);
        if (header_len > 512) return error.InvalidProtocol;

        // 7. Read header payload + tag
        var payload_buf: [512 + 16]u8 = undefined;
        const payload_total = header_len + 16;
        try readExactSlice(Transport, transport, payload_buf[0..payload_total]);

        // 8. Decrypt header payload
        var header_plain: [512]u8 = undefined;
        const dec_len = aead_mod.decrypt(
            .aes_128_gcm,
            &header_keys.payload_key,
            &header_keys.payload_iv,
            payload_buf[0..payload_total],
            &auth_id, // AAD
            &header_plain,
        ) catch return error.AuthFailed;

        // 9. Parse request
        const request = crypto.parseRequestPayload(header_plain[0..dec_len]) catch
            return error.InvalidProtocol;

        // Set target port (VMess has port before address in wire format)
        var target = request.target;
        target.port = request.target.port;

        ctx.target = target;
        const network: types.Network = switch (request.command) {
            .tcp => .tcp,
            .udp => .udp,
            .mux => .mux,
        };
        ctx.network = network;

        return .{
            .target = target,
            .network = network,
            .request = request,
        };
    }

    /// Send AEAD response header after successful parsing.
    pub fn sendResponse(
        comptime Transport: type,
        transport: *Transport,
        request: *const crypto.VMessRequest,
    ) InboundError!void {
        var resp_buf: [256]u8 = undefined;
        const resp_len = crypto.encodeResponseHeader(
            &request.response_key,
            &request.response_iv,
            request.response_header,
            request.options,
            &resp_buf,
        ) catch return error.CryptoFailed;

        transport.writeAll(resp_buf[0..resp_len]) catch return error.InnerStreamError;
    }
};

fn readExact(comptime T: type, transport: *T, buf: []u8) InboundError!void {
    var filled: usize = 0;
    while (filled < buf.len) {
        const n = transport.read(buf[filled..]) catch return error.InnerStreamError;
        if (n == 0) return error.InvalidProtocol;
        filled += n;
    }
}

fn readExactSlice(comptime T: type, transport: *T, buf: []u8) InboundError!void {
    var filled: usize = 0;
    while (filled < buf.len) {
        const n = transport.read(buf[filled..]) catch return error.InnerStreamError;
        if (n == 0) return error.InvalidProtocol;
        filled += n;
    }
}
