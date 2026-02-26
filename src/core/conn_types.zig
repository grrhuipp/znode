// ══════════════════════════════════════════════════════════════
//  Shared Connection Types
//
//  Type definitions shared between protocol parsers and
//  session handler vtable interfaces.
// ══════════════════════════════════════════════════════════════

const vmess_stream = @import("../protocol/vmess/vmess_stream.zig");
const ss_crypto = @import("../protocol/shadowsocks/ss_crypto.zig");

/// Inbound protocol state — exactly one is active per connection.
/// Used by InboundHandler.codecs() to extract codec pairs.
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
