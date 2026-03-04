const std = @import("std");
const types = @import("../../common/types.zig");
const codec = @import("codec.zig");
const UserManager = @import("user_manager.zig").UserManager;
const session = @import("../../app/session.zig");

pub const ParsedAction = struct {
    target: types.TargetAddress,
    network: types.Network,
    initial_payload: []const u8,
};

pub const InboundError = error{
    AuthFailed,
    InvalidProtocol,
    NeedMoreData,
    BufferOverflow,
    InnerStreamError,
};

/// Trojan inbound handler.
///
/// Trojan has NO stream encryption (relies on TLS).
/// parseStream reads the Trojan header and authenticates via UserManager.
/// wrapStream is a no-op — returns the transport stream as-is.
pub const TrojanInboundHandler = struct {
    user_manager: *const UserManager,

    pub fn init(user_manager: *const UserManager) TrojanInboundHandler {
        return .{ .user_manager = user_manager };
    }

    /// Read Trojan header from transport stream, authenticate, extract target.
    pub fn parseStream(
        self: *const TrojanInboundHandler,
        comptime Transport: type,
        transport: *Transport,
        ctx: *session.SessionContext,
    ) InboundError!ParsedAction {
        var buf: [4096]u8 = undefined;
        var filled: usize = 0;

        while (filled < buf.len) {
            const n = transport.read(buf[filled..]) catch return error.InnerStreamError;
            if (n == 0) return error.InvalidProtocol;
            filled += n;

            const header = codec.parseHeader(buf[0..filled]) catch |err| switch (err) {
                error.NeedMoreData => {
                    if (filled > 1024) return error.InvalidProtocol;
                    continue;
                },
                error.UnsupportedCommand, error.UnsupportedAddressType => return error.InvalidProtocol,
                error.InvalidRequest, error.AuthFailed => return error.InvalidProtocol,
            };

            // Authenticate via UserManager
            const user_info = self.user_manager.validate(header.auth_hash) orelse
                return error.AuthFailed;

            // Fill session context
            ctx.user_id = user_info.user_id;
            ctx.setUserEmail(user_info.email);
            ctx.target = header.target;
            ctx.speed_limit = user_info.speed_limit_bytes;
            ctx.inbound_protocol = .trojan;

            const network: types.Network = switch (header.command) {
                .connect => .tcp,
                .udp_associate => .udp,
            };
            ctx.network = network;

            if (header.initial_payload.len > 0) {
                ctx.setFirstPacket(header.initial_payload);
            }

            return .{
                .target = header.target,
                .network = network,
                .initial_payload = header.initial_payload,
            };
        }

        return error.BufferOverflow;
    }
};
