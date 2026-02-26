// ══════════════════════════════════════════════════════════════
//  Protocol Registry — Comptime Dispatch Generation
//
//  Central registry of all protocol implementations.
//  Uses `inline for` over comptime tuples to auto-generate
//  dispatch code equivalent to hand-written switch statements.
//
//  Adding a new protocol requires only:
//    1. Implement the interface (protocol_iface.zig)
//    2. Add one entry to the appropriate tuple below
//
//  `inline for` unrolls at compile time → direct function calls,
//  zero runtime overhead (no vtable, no function pointer indirection).
//
//  Note: Inbound dispatch is handled by inbound_dispatch.zig because
//  each protocol's parseInbound() has a different signature (different
//  dependencies). The registry verifies interfaces but dispatch is
//  protocol-aware in the dispatcher.
// ══════════════════════════════════════════════════════════════

const config_mod = @import("config.zig");
const protocol_iface = @import("protocol_iface.zig");
const OutboundKind = @import("conn_types.zig").OutboundKind;

// ── Protocol handler modules ──
const trojan_inbound = @import("../protocol/trojan/trojan_inbound.zig");
const trojan_outbound = @import("../protocol/trojan/trojan_outbound.zig");
const vmess_inbound = @import("../protocol/vmess/vmess_inbound.zig");
const vmess_outbound = @import("../protocol/vmess/vmess_outbound.zig");
const ss_inbound = @import("../protocol/shadowsocks/ss_inbound.zig");
const ss_outbound = @import("../protocol/shadowsocks/ss_outbound.zig");

// ══════════════════════════════════════════════════════════════
//  Inbound Protocol Registry
// ══════════════════════════════════════════════════════════════

/// Registered inbound protocols: (config.Protocol tag, handler module).
/// Each module must satisfy protocol_iface.InboundProtocol.
const inbound_protocols = .{
    .{ config_mod.Protocol.trojan, trojan_inbound },
    .{ config_mod.Protocol.vmess, vmess_inbound },
    .{ config_mod.Protocol.shadowsocks, ss_inbound },
};

// Compile-time interface verification for all registered inbound protocols
comptime {
    for (inbound_protocols) |entry| {
        protocol_iface.InboundProtocol(entry[1]);
    }
}

// ══════════════════════════════════════════════════════════════
//  Outbound Protocol Registry
// ══════════════════════════════════════════════════════════════

/// Registered outbound protocols: (OutboundKind tag, handler module).
/// Each module must satisfy protocol_iface.OutboundProtocol.
const outbound_protocols = .{
    .{ OutboundKind.trojan, trojan_outbound },
    .{ OutboundKind.vmess, vmess_outbound },
    .{ OutboundKind.shadowsocks, ss_outbound },
};

// Compile-time interface verification for all registered outbound protocols
comptime {
    for (outbound_protocols) |entry| {
        protocol_iface.OutboundProtocol(entry[1]);
    }
}

// Outbound dispatch is handled by outbound_dispatch.zig (sendProtocolHeader).
// The registry retains comptime interface verification only.
