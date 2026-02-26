// ══════════════════════════════════════════════════════════════
//  Protocol Interface — Comptime Duck-Typing Verification
//
//  Defines explicit interface contracts for protocols.
//  Uses @hasDecl to verify at compile time that protocol modules
//  satisfy the required method signatures.
//
//  This enables a "comptime generic + inline for" dispatch pattern
//  where adding a new protocol only requires:
//    1. Implement the interface methods
//    2. Add one line to protocol_registry.zig
// ══════════════════════════════════════════════════════════════

const xev = @import("xev");
const config_mod = @import("config.zig");
const Session = @import("proxy_connection.zig").Session;

/// Verify that T satisfies the Inbound Protocol interface.
///
/// Required declarations:
///   - `pub const protocol_tag: config_mod.Protocol`
///   - `pub fn parseInbound(...)` — returns InboundResult
///     (exact signature varies per protocol; verified by @hasDecl only)
pub fn InboundProtocol(comptime T: type) void {
    comptime {
        if (!@hasDecl(T, "protocol_tag")) {
            @compileError(@typeName(T) ++ ": InboundProtocol requires `pub const protocol_tag: Protocol`");
        }
        if (!@hasDecl(T, "parseInbound")) {
            @compileError(@typeName(T) ++ ": InboundProtocol requires `pub fn parseInbound(...)` returning InboundResult");
        }
    }
}

/// Verify that T satisfies the Outbound Protocol interface.
///
/// Required declarations:
///   - `pub const protocol_tag: config_mod.Protocol`
///   - One of:
///     - `pub fn encodeHeader(...)` — pure encoding function (Trojan, VMess)
///     - `pub fn encodeFirstPacket(...)` — pure encoding function (Shadowsocks)
///
/// Exact signatures differ per protocol; verified by @hasDecl only
/// (same rationale as InboundProtocol — per-protocol arg lists).
pub fn OutboundProtocol(comptime T: type) void {
    comptime {
        if (!@hasDecl(T, "protocol_tag")) {
            @compileError(@typeName(T) ++ ": OutboundProtocol requires `pub const protocol_tag: Protocol`");
        }
        const has_header = @hasDecl(T, "encodeHeader");
        const has_first_packet = @hasDecl(T, "encodeFirstPacket");
        if (!has_header and !has_first_packet) {
            @compileError(@typeName(T) ++ ": OutboundProtocol requires `encodeHeader` or `encodeFirstPacket` (pure encoding function)");
        }
    }
}
