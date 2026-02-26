// ══════════════════════════════════════════════════════════════
//  Shadowsocks Outbound — Pure Encoding
//
//  Pure functions only. No Session dependency, no I/O.
//  The dispatcher (outbound_dispatch.zig) calls these functions,
//  reads/writes Session fields, and performs I/O.
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const ss_crypto = @import("ss_crypto.zig");
const ss_protocol = @import("ss_protocol.zig");
const config_mod = @import("../../core/config.zig");
const session_mod = @import("../../core/session.zig");

pub const protocol_tag: config_mod.Protocol = .shadowsocks;

pub const FirstPacketResult = struct {
    /// Total bytes written to send_buf: [salt][encrypted frame]
    total_len: usize,
    /// Initialized encrypt state (counter advanced past first frame).
    encrypt_state: ss_crypto.StreamState,
};

/// Encode the first Shadowsocks outbound packet into send_buf.
/// Format: [random salt][AEAD-encrypted(address + optional payload)]
/// Returns null if address encoding fails or encryption fails.
pub fn encodeFirstPacket(
    send_buf: []u8,
    method: ss_crypto.Method,
    psk: []const u8,
    target: *const session_mod.TargetAddress,
    initial_payload: ?[]const u8,
) ?FirstPacketResult {
    const salt_size = method.saltSize();

    // Generate random salt
    var salt: [32]u8 = undefined;
    const boringssl = @import("../../crypto/boringssl_crypto.zig");
    boringssl.random.bytes(salt[0..salt_size]);

    // Initialize outbound encrypt state
    var enc_state = ss_crypto.StreamState.init(method, psk, salt[0..salt_size]);

    // Build plaintext: [address][initial payload]
    var plain_buf: [4096]u8 = undefined;
    const addr_len = ss_protocol.encodeAddress(target, &plain_buf) orelse return null;

    var plain_total = addr_len;
    if (initial_payload) |payload| {
        if (payload.len > 0 and plain_total + payload.len <= plain_buf.len) {
            @memcpy(plain_buf[plain_total .. plain_total + payload.len], payload);
            plain_total += payload.len;
        }
    }

    // Encrypt into send_buf: [salt][encrypted frame]
    @memcpy(send_buf[0..salt_size], salt[0..salt_size]);
    const frame_len = enc_state.encryptFrame(plain_buf[0..plain_total], send_buf[salt_size..]) orelse
        return null;

    return .{
        .total_len = salt_size + frame_len,
        .encrypt_state = enc_state,
    };
}
