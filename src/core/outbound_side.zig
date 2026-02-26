// ══════════════════════════════════════════════════════════════
//  Outbound Side — Sub-struct for Session (Session)
//
//  Owns all outbound I/O state: target TCP, outbound TLS,
//  outbound WebSocket, protocol kind/state, completions.
// ══════════════════════════════════════════════════════════════

const xev = @import("xev");
const config_mod = @import("config.zig");
const session_mod = @import("session.zig");
const tls_mod = @import("../transport/tls_stream.zig");
const ws_mod = @import("../transport/ws_stream.zig");
const conn_types = @import("conn_types.zig");

pub const OutboundSide = struct {
    // ── Target TCP ──
    tcp: ?xev.TCP = null,

    // ── Outbound TLS (client-side) ──
    tls: ?tls_mod.TlsStream = null,

    // ── Outbound WebSocket ──
    ws: ?*ws_mod.WsStream = null, // heap-allocated, freed after handshake
    ws_active: bool = false, // WS transport active (persists after WsStream freed)

    // ── Outbound protocol ──
    kind: conn_types.OutboundKind = .direct,
    config: ?*const config_mod.OutConfig = null, // points into config.routes
    // Note: OutboundState pointer kept on Session directly (circular import)

    // ── XUDP Mux (UDP over VMess TCP) ──
    xudp_mode: bool = false,
    xudp_session_started: bool = false,
    xudp_down_pending: ?[]u8 = null, // pool-borrowed buffer for half-frame accumulation
    xudp_down_pending_len: usize = 0,

    // ── xev Completions ──
    read_comp: xev.Completion = .{},
    write_comp: xev.Completion = .{},
    connect_comp: xev.Completion = .{},
    close_comp: xev.Completion = .{},

    // ── State flags ──
    early_detect_active: bool = false, // early disconnect detection read
    pending_downlink_flush: bool = false, // VMess outbound: pending data needs flush
    vmess_response_pending: bool = false, // VMess outbound: response read deferred

    // ── Target address ──
    real_target: ?session_mod.TargetAddress = null, // saved for outbound header
    target_addr: ?session_mod.TargetAddress = null, // saved for deferred connect

    // ── Buffers ──
    target_buf: ?[]u8 = null, // target TCP recv — downlink (8KB)
};
