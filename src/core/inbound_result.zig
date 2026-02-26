// ══════════════════════════════════════════════════════════════
//  InboundResult — Action description from protocol handlers
//
//  Protocol handlers (trojan/vmess/ss) return InboundResult
//  instead of directly operating on Session.
//  The dispatcher (inbound_dispatch) interprets the result.
// ══════════════════════════════════════════════════════════════

const session_mod = @import("session.zig");
const conn_types = @import("conn_types.zig");

/// Result of inbound protocol parsing — describes what the dispatcher should do.
pub const InboundResult = union(enum) {
    /// TCP connect to target
    connect: ConnectAction,
    /// Client requested UDP associate (dispatcher decides XUDP vs regular UDP)
    udp_associate: ConnectAction,
    /// Need more data (header incomplete)
    need_more: void,
    /// Auth/protocol error → try fallback
    fallback: void,
    /// Fatal error → close connection
    close: conn_types.CloseReason,
};

/// Action metadata returned by protocol handlers.
pub const ConnectAction = struct {
    target: session_mod.TargetAddress,
    user_id: i64 = -1,

    // Protocol label for access log (e.g. "trojan", "vmess|aes-128-gcm", "shadowsocks")
    proto_label_buf: [64]u8 = .{0} ** 64,
    proto_label_len: u8 = 0,

    // Inbound protocol state (VMess/SS crypto, set on inbound.protocol)
    protocol_state: conn_types.InboundProtocol = .none,

    // Initial payload length — data written to payload_out buffer by handler
    payload_len: u16 = 0,

    // Set true when initial payload is already plaintext (e.g. SS streaming parse
    // decrypts the first AEAD frame itself; session_handler must skip re-decryption).
    payload_is_decrypted: bool = false,

    // VMess: response header to send before connecting (triggers deferred connect)
    response_buf: [64]u8 = undefined,
    response_len: u8 = 0,

    // SS: salt bytes for response (dispatcher saves in protocol_buf)
    salt_buf: [32]u8 = undefined,
    salt_len: u8 = 0,

    pub fn protoLabel(self: *const ConnectAction) []const u8 {
        return self.proto_label_buf[0..self.proto_label_len];
    }

    pub fn setProtoLabel(self: *ConnectAction, label: []const u8) void {
        const n: u8 = @intCast(@min(label.len, self.proto_label_buf.len));
        @memcpy(self.proto_label_buf[0..n], label[0..n]);
        self.proto_label_len = n;
    }
};

/// Result of streaming protocol parse — action + whether client requested UDP.
pub const ParsedAction = struct {
    action: ConnectAction,
    is_udp: bool,
};
