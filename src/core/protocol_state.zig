// ══════════════════════════════════════════════════════════════
//  Protocol State — Sub-struct for Session
//
//  Inbound/outbound protocol type and state, XUDP, inbound WS.
//  All protocol-specific runtime state lives here.
// ══════════════════════════════════════════════════════════════

const config_mod = @import("config.zig");
const session_mod = @import("session.zig");
const conn_types = @import("conn_types.zig");

// Re-export shared types for convenience
pub const InboundProtocol = conn_types.InboundProtocol;
pub const OutboundKind = conn_types.OutboundKind;
pub const InboundWsState = conn_types.InboundWsState;

// OutboundState stays in proxy_connection.zig (has transport methods)
const proxy_conn = @import("proxy_connection.zig");
pub const OutboundState = proxy_conn.OutboundState;

/// Protocol runtime state: inbound/outbound type, XUDP, WS.
/// Embedded in Session as `proto` field.
pub const ProtocolState = struct {
    // ── Per-connection protocol (from listener config) ──
    node_type: config_mod.Protocol = .vmess,

    // ── Inbound protocol state (VMess/SS — mutually exclusive) ──
    inbound_protocol: InboundProtocol = .none,

    // ── Outbound protocol ──
    outbound_kind: OutboundKind = .direct,
    outbound_config: ?*const config_mod.OutConfig = null,
    outbound_state: ?*OutboundState = null, // heap-allocated on-demand
    real_target: ?session_mod.TargetAddress = null, // saved target for outbound header

    // ── Protocol parsing ──
    target_addr: ?session_mod.TargetAddress = null, // saved for deferred connect (VMess)
    initial_payload: ?[]const u8 = null, // data after protocol header
    initial_payload_len: usize = 0,
    dns_target_port: u16 = 0, // saved across async DNS

    // ── XUDP (UDP over VMess TCP) ──
    xudp_mode: bool = false,
    xudp_session_started: bool = false,
    xudp_down_pending: ?[]u8 = null, // pool-borrowed for XUDP downlink half-frame accumulation
    xudp_down_pending_len: usize = 0,

    // ── Inbound WebSocket (server-side: client→server masked frames) ──
    inbound_ws: bool = false, // WS transport active for this connection
    inbound_ws_done: bool = false, // WS handshake completed
    inbound_ws_state: InboundWsState = .{},
};
