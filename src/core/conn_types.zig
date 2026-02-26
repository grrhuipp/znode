// ══════════════════════════════════════════════════════════════
//  Shared Connection Types
//
//  Standalone type definitions used by both proxy_connection.zig
//  and sub-struct files. Placed here to break circular imports.
// ══════════════════════════════════════════════════════════════

const vmess_stream = @import("../protocol/vmess/vmess_stream.zig");
const ss_crypto = @import("../protocol/shadowsocks/ss_crypto.zig");
const ws_mod = @import("../transport/ws_stream.zig");

/// Inbound protocol state — exactly one is active per connection.
pub const InboundProtocol = union(enum) {
    none: void,
    vmess: struct {
        request_state: vmess_stream.StreamState, // client → server decrypt
        response_state: vmess_stream.StreamState, // server → client encrypt
        response_sent: bool = false,
    },
    shadowsocks: struct {
        decrypt_state: ss_crypto.StreamState, // client → server decrypt
        encrypt_state: ss_crypto.StreamState, // server → client encrypt
    },
};

/// Outbound protocol kind — mutually exclusive.
pub const OutboundKind = enum { direct, vmess, trojan, shadowsocks };

/// Reason a connection was closed — logged in the close summary.
pub const CloseReason = enum(u8) {
    none = 0, // still open or unknown
    done = 1, // normal completion (EOF)
    idle = 2, // idle timeout
    hs_timeout = 3, // handshake timeout
    conn_err = 4, // target connect failed
    auth_fail = 5, // trojan/vmess auth failed
    proto_err = 6, // protocol error
    tls_err = 7, // TLS error
    dns_err = 8, // DNS resolution failed
    blocked = 9, // route blackhole
    err = 10, // generic error

    pub fn tag(self: CloseReason) []const u8 {
        return switch (self) {
            .none => "-",
            .done => "done",
            .idle => "idle",
            .hs_timeout => "hs_timeout",
            .conn_err => "conn_err",
            .auth_fail => "auth_fail",
            .proto_err => "proto_err",
            .tls_err => "tls_err",
            .dns_err => "dns_err",
            .blocked => "blocked",
            .err => "err",
        };
    }
};

/// Inbound WebSocket frame parsing state for relay phase.
/// Tracks partial frames across TCP reads (client→server: masked per RFC 6455).
pub const InboundWsState = struct {
    frame_remaining: u32 = 0, // payload bytes remaining in current WS frame
    mask_key: [4]u8 = .{ 0, 0, 0, 0 }, // current frame mask
    mask_offset: u32 = 0, // mask position within frame (for partial reads)
    header_buf: [14]u8 = undefined, // partial frame header accumulation (max: 2+8+4=14)
    header_len: u8 = 0,
    ctrl_skip: u32 = 0, // control frame payload bytes to skip
    pong_buf: [140]u8 = undefined, // pending pong frame (6 header + 125 payload max, unmasked)
    pong_len: u8 = 0,
    accum_len: usize = 0, // WS accumulation buffer length (protocol_parse: target_buf)
    // Streaming relay state
    ctrl_is_ping: bool = false, // currently skipping a ping frame's payload
    ping_payload: [125]u8 = undefined, // ping payload accumulation (for pong response)
    ping_len: u8 = 0,
    close_received: bool = false, // WS close frame received
};
