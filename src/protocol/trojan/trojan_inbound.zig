// ══════════════════════════════════════════════════════════════
//  Trojan Inbound Handler
//
//  Pure protocol parser: authenticate + extract target.
//  Returns InboundResult — no Session dependency.
//
//  Single responsibility: inbound Trojan protocol only.
// ══════════════════════════════════════════════════════════════

const trojan = @import("trojan_protocol.zig");
const config_mod = @import("../../core/config.zig");
const inbound_result = @import("../../core/inbound_result.zig");
const InboundResult = inbound_result.InboundResult;
const ConnectAction = inbound_result.ConnectAction;
const user_store_mod = @import("../../core/user_store.zig");

pub const protocol_tag: config_mod.Protocol = .trojan;

/// Parse Trojan request from accumulated protocol buffer.
/// Writes initial payload (data after header) to payload_out.
/// Does NOT touch Session — returns action description.
pub fn parseInbound(
    buf: []const u8,
    user_store: ?*user_store_mod.UserStore,
    payload_out: []u8,
) InboundResult {
    switch (trojan.parseRequest(buf)) {
        .success => |req| {
            // Authenticate
            var user_id: i64 = -1;
            if (user_store) |store| {
                if (store.getUsers()) |users| {
                    if (users.findByPasswordHash(&req.password_hash)) |user| {
                        user_id = user.id;
                    } else {
                        return .fallback;
                    }
                } else {
                    return .fallback;
                }
            }

            // Build action
            var action = ConnectAction{
                .target = req.target,
                .user_id = user_id,
            };

            // Copy initial payload (data after header) to payload_out
            if (req.header_len < buf.len) {
                const payload_len = buf.len - req.header_len;
                if (payload_len <= payload_out.len) {
                    @memcpy(payload_out[0..payload_len], buf[req.header_len..buf.len]);
                    action.payload_len = @intCast(payload_len);
                }
            }

            // Set proto label based on command
            if (req.command == .udp_associate) {
                action.setProtoLabel("trojan-udp");
                return .{ .udp_associate = action };
            }

            action.setProtoLabel("trojan");
            return .{ .connect = action };
        },
        .incomplete => return .need_more,
        .protocol_error => return .fallback,
    }
}
