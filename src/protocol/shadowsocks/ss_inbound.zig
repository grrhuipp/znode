// ══════════════════════════════════════════════════════════════
//  Shadowsocks Inbound Handler
//
//  Pure protocol parser: extract salt, decrypt first chunk,
//  parse target address, init stream states.
//  Returns InboundResult — no Session dependency.
//
//  Single responsibility: inbound Shadowsocks protocol only.
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const ss_crypto = @import("ss_crypto.zig");
const ss_protocol = @import("ss_protocol.zig");
const config_mod = @import("../../core/config.zig");
const conn_types = @import("../../core/conn_types.zig");
const inbound_result = @import("../../core/inbound_result.zig");
const InboundResult = inbound_result.InboundResult;
const ConnectAction = inbound_result.ConnectAction;

pub const protocol_tag: config_mod.Protocol = .shadowsocks;

/// Parse Shadowsocks first packet from accumulated protocol buffer.
/// Writes initial payload (decrypted data after address) to payload_out.
/// Does NOT touch Session — returns action description.
pub fn parseInbound(
    buf: []const u8,
    method: ss_crypto.Method,
    psk: []const u8,
    payload_out: []u8,
) InboundResult {
    var dec_state: ss_crypto.StreamState = undefined;
    var plaintext_buf: [4096]u8 = undefined;
    const result = ss_protocol.parseFirstPacket(
        buf,
        method,
        psk,
        &dec_state,
        &plaintext_buf,
    );

    switch (result) {
        .success => |s| {
            // Generate random salt for response encrypt state
            var salt: [32]u8 = undefined;
            const salt_size = method.saltSize();
            const boringssl = @import("../../crypto/boringssl_crypto.zig");
            boringssl.random.bytes(salt[0..salt_size]);

            // Build action
            var action = ConnectAction{
                .target = s.target,
                .user_id = -1,
                .protocol_state = .{ .shadowsocks = .{
                    .decrypt_state = dec_state,
                    .encrypt_state = ss_crypto.StreamState.init(
                        method,
                        psk,
                        salt[0..salt_size],
                    ),
                } },
            };
            action.setProtoLabel("shadowsocks");

            // Save salt for response
            @memcpy(action.salt_buf[0..salt_size], salt[0..salt_size]);
            action.salt_len = @intCast(salt_size);

            // Copy initial payload (decrypted data after address) to payload_out
            if (s.payload.len > 0 and s.payload.len <= payload_out.len) {
                @memcpy(payload_out[0..s.payload.len], s.payload);
                action.payload_len = @intCast(s.payload.len);
            }

            return .{ .connect = action };
        },
        .incomplete => return .need_more,
        .protocol_error => return .{ .close = .proto_err },
    }
}
