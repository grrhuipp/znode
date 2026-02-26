// ══════════════════════════════════════════════════════════════
//  Trojan Outbound — Pure Encoding
//
//  Pure functions only. No Session dependency, no I/O.
//  The dispatcher (outbound_dispatch.zig) calls these functions,
//  reads/writes Session fields, and performs I/O.
// ══════════════════════════════════════════════════════════════

const trojan = @import("trojan_protocol.zig");
const config_mod = @import("../../core/config.zig");
const session_mod = @import("../../core/session.zig");

pub const protocol_tag: config_mod.Protocol = .trojan;

/// Encode Trojan outbound request header into buf.
/// Returns bytes written (header only), or null if buf too small / encode failed.
/// The dispatcher appends initial_payload after the header.
pub fn encodeHeader(
    buf: []u8,
    password_hash: [trojan.HASH_LEN]u8,
    command: trojan.Command,
    target: *const session_mod.TargetAddress,
) ?usize {
    return trojan.encodeRequest(buf, password_hash, command, target);
}
