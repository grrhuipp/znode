// ══════════════════════════════════════════════════════════════
//  Inbound Side — Sub-struct for Session (Session)
//
//  Owns all inbound I/O state: client TCP, inbound TLS,
//  inbound WebSocket, protocol state, completions, and buffers.
// ══════════════════════════════════════════════════════════════

const xev = @import("xev");
const config_mod = @import("config.zig");
const tls_mod = @import("../transport/tls_stream.zig");
const conn_types = @import("conn_types.zig");

pub const InboundSide = struct {
    // ── Client TCP ──
    tcp: xev.TCP,

    // ── Inbound TLS (server-side) ──
    tls: ?tls_mod.TlsStream = null,

    // ── Inbound WebSocket (server-side: client→server frames are masked) ──
    ws_active: bool = false, // WS transport active for this connection
    ws_done: bool = false, // WS handshake completed
    ws_state: conn_types.InboundWsState = .{},

    // ── Inbound protocol runtime state (VMess/SS, used in relay phase) ──
    protocol: conn_types.InboundProtocol = .none,
    node_type: config_mod.Protocol = .vmess,

    // ── xev Completions ──
    read_comp: xev.Completion = .{},
    write_comp: xev.Completion = .{},
    close_comp: xev.Completion = .{},

    // ── State flags ──
    read_pending: bool = false, // client read I/O submission tracking

    // ── Buffers (pool-borrowed, null when not in use) ──
    recv_buf: ?[]u8 = null, // client TCP recv + WS outbound framing (8KB)
    decrypt_buf: ?[]u8 = null, // TLS decrypted / protocol plaintext (20KB)
    send_buf: ?[]u8 = null, // encrypt output → client TCP write (20KB)
    protocol_buf: ?[]u8 = null, // protocol header accumulation (8KB, released after handshake)
    protocol_buf_len: usize = 0,

    // ── Inbound chunk accumulation (VMess/SS, chunks may span TCP segments) ──
    pending: ?[]u8 = null, // pool-borrowed on-demand (large=32KB)
    pending_head: usize = 0,
    pending_tail: usize = 0,
};
