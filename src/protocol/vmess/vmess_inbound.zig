// ══════════════════════════════════════════════════════════════
//  VMess Inbound Handler
//
//  Pure protocol parser: authenticate, init stream states,
//  encode response header.
//  Returns InboundResult — no Session dependency.
//
//  Single responsibility: inbound VMess protocol only.
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const vmess_protocol = @import("vmess_protocol.zig");
const vmess_stream = @import("vmess_stream.zig");
const vmess_crypto = @import("vmess_crypto.zig");
const config_mod = @import("../../core/config.zig");
const conn_types = @import("../../core/conn_types.zig");
const user_store_mod = @import("../../core/user_store.zig");
const inbound_result = @import("../../core/inbound_result.zig");
const InboundResult = inbound_result.InboundResult;
const ConnectAction = inbound_result.ConnectAction;

pub const protocol_tag: config_mod.Protocol = .vmess;

/// Parse VMess AEAD request from accumulated protocol buffer.
/// Writes initial payload (encrypted data after header) to payload_out.
/// Does NOT touch Session — returns action description.
pub fn parseInbound(
    buf: []const u8,
    user_map: ?*const user_store_mod.UserStore.UserMap,
    replay_filter: *vmess_protocol.ReplayFilter,
    allocator: std.mem.Allocator,
    payload_out: []u8,
) InboundResult {
    if (user_map == null) return .{ .close = .proto_err };

    switch (vmess_protocol.parseRequest(buf, user_map.?, replay_filter, allocator)) {
        .success => |req| {
            const user_id: i64 = if (req.matched_user) |u| u.id else -1;

            // Initialize inbound protocol state (request decrypt + response encrypt)
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

            // Proto label: "vmess|<security>"
            const label = std.fmt.bufPrint(&action.proto_label_buf, "vmess|{s}", .{@tagName(req.security)}) catch "vmess";
            action.proto_label_len = @intCast(label.len);

            // Copy initial payload (data after VMess header) to payload_out
            if (req.header_len < buf.len) {
                const payload_len = buf.len - req.header_len;
                if (payload_len <= payload_out.len) {
                    @memcpy(payload_out[0..payload_len], buf[req.header_len..buf.len]);
                    action.payload_len = @intCast(payload_len);
                }
            }

            // Encode VMess response header
            if (vmess_protocol.encodeResponse(&action.response_buf, &req)) |resp_len| {
                action.response_len = @intCast(resp_len);
            }

            return .{ .connect = action };
        },
        .incomplete => return .need_more,
        .auth_failed => return .{ .close = .auth_fail },
        .replay_detected => return .{ .close = .auth_fail },
        .protocol_error => return .{ .close = .proto_err },
    }
}
