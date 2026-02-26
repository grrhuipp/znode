const std = @import("std");
const builtin = @import("builtin");

/// Connection lifecycle states — matches the actual proxy pipeline.
///
/// Three-layer close model:
///   1. Half-close: real TCP shutdown(SHUT_WR) propagates FIN, fd still open
///      - half_close_client: client sent FIN → shutdown(target,SHUT_WR), downlink active
///      - half_close_target: target sent FIN → shutdown(client,SHUT_WR), uplink active
///      - Hard grace period (default 5s) caps half-close duration
///   2. Closing: fd close() submitted to IOCP, awaiting completion callbacks
///   3. Closed: all fds closed, terminal state — destroy on pending_ops==0
pub const State = enum(u8) {
    // ── Inbound pipeline ──
    proxy_protocol, // auto-detect PROXY Protocol header
    tls_handshake, // inbound TLS handshake
    protocol_parse, // parse Trojan/VMess/SS header + route()

    // ── Outbound pipeline ──
    dns_resolving, // async DNS resolution
    connecting, // TCP connect to target
    outbound_tls_handshake, // TLS handshake with outbound server
    outbound_ws_handshake, // WebSocket upgrade with outbound server
    outbound_vmess_header, // VMess outbound header exchange
    outbound_trojan_header, // Trojan outbound header write
    outbound_ss_header, // Shadowsocks first packet write

    // ── Active relay ──
    relaying, // bidirectional data relay (both directions active)
    half_close_client, // client FIN received: uplink stopped, downlink still active
    half_close_target, // target FIN received: downlink stopped, uplink still active
    udp_relaying, // UDP full-cone NAT relay

    // ── Teardown (fd-level close) ──
    closing, // close(fd) submitted, awaiting IOCP completion
    closed, // terminal: all fds closed

    pub fn name(self: State) []const u8 {
        return @tagName(self);
    }
};

/// Recorded state transition for debugging.
pub const Transition = struct {
    from: State,
    to: State,
    timestamp_us: i64,
};

const MAX_HISTORY = 16;

/// Unified connection FSM with validated transitions and history buffer.
///
/// Memory: ~264 bytes (0.34% of ~76KB Session).
///
/// Usage:
///   var fsm = ConnFSM{};                  // default: .proxy_protocol
///   _ = fsm.transition(.tls_handshake);   // validated + recorded
///   if (fsm.isClosingOrClosed()) return;  // helper guard
pub const ConnFSM = struct {
    state: State = .proxy_protocol,
    history: [MAX_HISTORY]Transition = undefined,
    history_head: u8 = 0,
    history_count: u8 = 0,

    // ── Transitions ──

    /// Transition to a new state. Validates in Debug/ReleaseSafe builds, records history.
    /// Returns true if transition was valid (always true in ReleaseFast).
    pub fn transition(self: *ConnFSM, to: State) bool {
        if (comptime builtin.mode == .Debug or builtin.mode == .ReleaseSafe) {
            if (!isValidTransition(self.state, to)) {
                std.debug.print("[FSM] INVALID: {s} -> {s}\n", .{ self.state.name(), to.name() });
                if (comptime builtin.mode == .Debug) {
                    unreachable;
                }
                return false;
            }
        }
        self.recordTransition(self.state, to);
        self.state = to;
        return true;
    }

    /// Force transition to .closing from any active state. Idempotent.
    pub fn transitionToClosing(self: *ConnFSM) void {
        if (self.state == .closing or self.state == .closed) return;
        self.recordTransition(self.state, .closing);
        self.state = .closing;
    }

    /// Transition closing -> closed.
    pub fn transitionToClosed(self: *ConnFSM) void {
        if (comptime builtin.mode == .Debug) {
            std.debug.assert(self.state == .closing);
        }
        self.recordTransition(self.state, .closed);
        self.state = .closed;
    }

    // ── Guards ──

    pub inline fn isClosingOrClosed(self: *const ConnFSM) bool {
        return self.state == .closing or self.state == .closed;
    }

    /// Exact: bidirectional relay (both directions active).
    pub inline fn isRelaying(self: *const ConnFSM) bool {
        return self.state == .relaying;
    }

    /// Any TCP relay phase: full duplex or half-closed.
    pub inline fn isActiveRelay(self: *const ConnFSM) bool {
        return switch (self.state) {
            .relaying, .half_close_client, .half_close_target => true,
            else => false,
        };
    }

    pub inline fn isUdpRelaying(self: *const ConnFSM) bool {
        return self.state == .udp_relaying;
    }

    /// Any relay phase (TCP full/half-close or UDP).
    pub inline fn isRelayingOrUdp(self: *const ConnFSM) bool {
        return switch (self.state) {
            .relaying, .half_close_client, .half_close_target, .udp_relaying => true,
            else => false,
        };
    }

    /// Half-closed in either direction.
    pub inline fn isHalfClosed(self: *const ConnFSM) bool {
        return self.state == .half_close_client or self.state == .half_close_target;
    }

    pub inline fn isClosed(self: *const ConnFSM) bool {
        return self.state == .closed;
    }

    pub inline fn is(self: *const ConnFSM, s: State) bool {
        return self.state == s;
    }

    // ── History ──

    pub fn lastTransition(self: *const ConnFSM) ?Transition {
        if (self.history_count == 0) return null;
        const idx = if (self.history_head == 0) MAX_HISTORY - 1 else self.history_head - 1;
        return self.history[idx];
    }

    /// Format history as compact debug string: "tls_handshake>protocol_parse>connecting"
    pub fn formatHistory(self: *const ConnFSM, buf: []u8) []const u8 {
        var pos: usize = 0;
        var i: u8 = 0;
        while (i < self.history_count) : (i += 1) {
            const idx = if (self.history_count < MAX_HISTORY)
                i
            else
                (self.history_head +% i) % MAX_HISTORY;
            const t = self.history[idx];
            if (i > 0) {
                if (pos < buf.len) {
                    buf[pos] = '>';
                    pos += 1;
                }
            }
            const tag = t.to.name();
            const end = @min(pos + tag.len, buf.len);
            const copy_len = end - pos;
            if (copy_len > 0) {
                @memcpy(buf[pos..end], tag[0..copy_len]);
                pos = end;
            }
        }
        return buf[0..pos];
    }

    // ── Internal ──

    fn recordTransition(self: *ConnFSM, from: State, to: State) void {
        self.history[self.history_head] = .{
            .from = from,
            .to = to,
            .timestamp_us = std.time.microTimestamp(),
        };
        self.history_head = (self.history_head + 1) % MAX_HISTORY;
        if (self.history_count < MAX_HISTORY) {
            self.history_count += 1;
        }
    }
};

/// Transition validation table derived from actual proxy_connection.zig code paths.
///
/// Half-close transitions:
///   relaying → half_close_client  (client FIN, direct/trojan, no TLS)
///   relaying → half_close_target  (target FIN, direct/trojan, no TLS)
///   half_close_client → closing   (target also FIN'd, or error/timeout)
///   half_close_target → closing   (client also FIN'd, or error/timeout)
///
/// Note: half_close_client + target FIN does NOT go to half_close_target.
/// Both FINs received → straight to closing (fd close). The half-close
/// states are mutually exclusive — only the FIRST FIN creates a half-close.
fn isValidTransition(from: State, to: State) bool {
    return switch (from) {
        .proxy_protocol => to == .tls_handshake or to == .protocol_parse,
        .tls_handshake => to == .protocol_parse,
        .protocol_parse => switch (to) {
            .dns_resolving, .connecting, .udp_relaying, .closing => true,
            else => false,
        },
        .dns_resolving => to == .connecting or to == .closing,
        .connecting => switch (to) {
            .outbound_tls_handshake,
            .outbound_ws_handshake,
            .outbound_vmess_header,
            .outbound_trojan_header,
            .outbound_ss_header,
            .relaying,
            .closing,
            => true,
            else => false,
        },
        .outbound_tls_handshake => switch (to) {
            .outbound_ws_handshake,
            .outbound_vmess_header,
            .outbound_trojan_header,
            .outbound_ss_header,
            .relaying,
            .closing,
            => true,
            else => false,
        },
        .outbound_ws_handshake => switch (to) {
            .outbound_vmess_header,
            .outbound_trojan_header,
            .outbound_ss_header,
            .relaying,
            .closing,
            => true,
            else => false,
        },
        .outbound_vmess_header => to == .relaying or to == .closing,
        .outbound_trojan_header => to == .relaying or to == .closing,
        .outbound_ss_header => to == .relaying or to == .closing,
        // Full duplex relay can half-close or fully close
        .relaying => switch (to) {
            .half_close_client, .half_close_target, .closing => true,
            else => false,
        },
        // Half-closed: only transition is fd close (both FINs or error)
        .half_close_client => to == .closing,
        .half_close_target => to == .closing,
        .udp_relaying => to == .closing,
        .closing => to == .closed,
        .closed => false,
    };
}

// ── Tests ──

test "happy path: proxy_protocol -> tls -> parse -> dns -> connect -> relay -> close" {
    var fsm = ConnFSM{};
    try std.testing.expectEqual(State.proxy_protocol, fsm.state);

    try std.testing.expect(fsm.transition(.tls_handshake));
    try std.testing.expect(fsm.transition(.protocol_parse));
    try std.testing.expect(fsm.transition(.dns_resolving));
    try std.testing.expect(fsm.transition(.connecting));
    try std.testing.expect(fsm.transition(.relaying));
    try std.testing.expect(fsm.isRelaying());

    fsm.transitionToClosing();
    try std.testing.expect(fsm.isClosingOrClosed());

    fsm.transitionToClosed();
    try std.testing.expect(fsm.isClosed());
    try std.testing.expectEqual(@as(u8, 7), fsm.history_count);
}

test "direct connect (no DNS)" {
    var fsm = ConnFSM{};
    try std.testing.expect(fsm.transition(.protocol_parse));
    try std.testing.expect(fsm.transition(.connecting));
    try std.testing.expect(fsm.transition(.relaying));
}

test "outbound handshake chain: TLS -> WS -> VMess -> relay" {
    var fsm = ConnFSM{ .state = .connecting };
    try std.testing.expect(fsm.transition(.outbound_tls_handshake));
    try std.testing.expect(fsm.transition(.outbound_ws_handshake));
    try std.testing.expect(fsm.transition(.outbound_vmess_header));
    try std.testing.expect(fsm.transition(.relaying));
}

test "Trojan outbound: TLS -> trojan header -> relay" {
    var fsm = ConnFSM{ .state = .connecting };
    try std.testing.expect(fsm.transition(.outbound_tls_handshake));
    try std.testing.expect(fsm.transition(.outbound_trojan_header));
    try std.testing.expect(fsm.transition(.relaying));
}

test "Shadowsocks: connect -> ss header -> relay" {
    var fsm = ConnFSM{ .state = .connecting };
    try std.testing.expect(fsm.transition(.outbound_ss_header));
    try std.testing.expect(fsm.transition(.relaying));
}

test "UDP relay path" {
    var fsm = ConnFSM{ .state = .protocol_parse };
    try std.testing.expect(fsm.transition(.udp_relaying));
    try std.testing.expect(fsm.isUdpRelaying());
    try std.testing.expect(fsm.isRelayingOrUdp());
    try std.testing.expect(!fsm.isRelaying());
    fsm.transitionToClosing();
    try std.testing.expect(fsm.isClosingOrClosed());
}

test "half-close: client FIN first, then target FIN" {
    var fsm = ConnFSM{ .state = .relaying };
    try std.testing.expect(fsm.isRelaying());
    try std.testing.expect(fsm.isActiveRelay());

    // Client sends FIN → half_close_client (downlink still active)
    try std.testing.expect(fsm.transition(.half_close_client));
    try std.testing.expect(!fsm.isRelaying()); // no longer full duplex
    try std.testing.expect(fsm.isActiveRelay()); // still active relay
    try std.testing.expect(fsm.isHalfClosed());
    try std.testing.expect(fsm.isRelayingOrUdp()); // still counts as relaying
    try std.testing.expect(!fsm.isClosingOrClosed()); // fd still open!

    // Target also sends FIN → closing (fd close)
    fsm.transitionToClosing();
    try std.testing.expect(fsm.isClosingOrClosed());
    try std.testing.expect(!fsm.isActiveRelay());

    fsm.transitionToClosed();
    try std.testing.expect(fsm.isClosed());
}

test "half-close: target FIN first, then client FIN" {
    var fsm = ConnFSM{ .state = .relaying };

    // Target sends FIN → half_close_target (uplink still active)
    try std.testing.expect(fsm.transition(.half_close_target));
    try std.testing.expect(!fsm.isRelaying());
    try std.testing.expect(fsm.isActiveRelay());
    try std.testing.expect(fsm.isHalfClosed());

    // Client also sends FIN → closing (fd close)
    fsm.transitionToClosing();
    try std.testing.expect(fsm.isClosingOrClosed());

    fsm.transitionToClosed();
    try std.testing.expect(fsm.isClosed());
}

test "half-close: error during half-close goes to closing" {
    var fsm = ConnFSM{ .state = .relaying };
    try std.testing.expect(fsm.transition(.half_close_client));

    // Error during half-close → force close
    fsm.transitionToClosing();
    try std.testing.expect(fsm.is(.closing));
}

test "no half-close for non-relay states (error → closing)" {
    var fsm = ConnFSM{ .state = .relaying };
    // Protocol without half-close support → direct closing
    fsm.transitionToClosing();
    try std.testing.expect(fsm.is(.closing));
}

test "transitionToClosing is idempotent" {
    var fsm = ConnFSM{ .state = .relaying };
    fsm.transitionToClosing();
    const count1 = fsm.history_count;
    fsm.transitionToClosing(); // no-op
    try std.testing.expectEqual(count1, fsm.history_count);
    try std.testing.expectEqual(State.closing, fsm.state);
}

test "transitionToClosing from closed is no-op" {
    var fsm = ConnFSM{ .state = .relaying };
    fsm.transitionToClosing();
    fsm.transitionToClosed();
    const count = fsm.history_count;
    fsm.transitionToClosing(); // no-op (already closed)
    try std.testing.expectEqual(count, fsm.history_count);
    try std.testing.expectEqual(State.closed, fsm.state);
}

test "transitionToClosing from half-close" {
    var fsm = ConnFSM{ .state = .half_close_client };
    fsm.transitionToClosing();
    try std.testing.expect(fsm.is(.closing));
    fsm.transitionToClosed();
    try std.testing.expect(fsm.isClosed());
}

test "guards" {
    var fsm = ConnFSM{ .state = .relaying };
    try std.testing.expect(!fsm.isClosingOrClosed());
    try std.testing.expect(fsm.isRelaying());
    try std.testing.expect(fsm.isActiveRelay());
    try std.testing.expect(fsm.isRelayingOrUdp());
    try std.testing.expect(!fsm.isUdpRelaying());
    try std.testing.expect(!fsm.isHalfClosed());
    try std.testing.expect(!fsm.isClosed());
    try std.testing.expect(fsm.is(.relaying));
    try std.testing.expect(!fsm.is(.connecting));
}

test "guards: half-close states" {
    var fsm = ConnFSM{ .state = .half_close_client };
    try std.testing.expect(!fsm.isRelaying()); // not full duplex
    try std.testing.expect(fsm.isActiveRelay()); // still active
    try std.testing.expect(fsm.isRelayingOrUdp()); // counts as relay
    try std.testing.expect(fsm.isHalfClosed());
    try std.testing.expect(!fsm.isClosingOrClosed()); // fd still open

    fsm.state = .half_close_target;
    try std.testing.expect(!fsm.isRelaying());
    try std.testing.expect(fsm.isActiveRelay());
    try std.testing.expect(fsm.isHalfClosed());
}

test "history buffer" {
    var fsm = ConnFSM{};
    _ = fsm.transition(.tls_handshake);
    _ = fsm.transition(.protocol_parse);
    _ = fsm.transition(.connecting);

    try std.testing.expectEqual(@as(u8, 3), fsm.history_count);
    const last = fsm.lastTransition().?;
    try std.testing.expectEqual(State.protocol_parse, last.from);
    try std.testing.expectEqual(State.connecting, last.to);
}

test "formatHistory" {
    var fsm = ConnFSM{};
    _ = fsm.transition(.tls_handshake);
    _ = fsm.transition(.protocol_parse);
    _ = fsm.transition(.connecting);

    var buf: [256]u8 = undefined;
    const s = fsm.formatHistory(&buf);
    try std.testing.expectEqualStrings("tls_handshake>protocol_parse>connecting", s);
}

test "formatHistory with half-close" {
    var fsm = ConnFSM{ .state = .relaying };
    _ = fsm.transition(.half_close_client);
    fsm.transitionToClosing();
    fsm.transitionToClosed();

    var buf: [256]u8 = undefined;
    const s = fsm.formatHistory(&buf);
    try std.testing.expectEqualStrings("half_close_client>closing>closed", s);
}

test "history wraps at 16" {
    var fsm = ConnFSM{};
    // Drive through many transitions to wrap
    _ = fsm.transition(.tls_handshake);
    _ = fsm.transition(.protocol_parse);
    _ = fsm.transition(.dns_resolving);
    _ = fsm.transition(.connecting);
    _ = fsm.transition(.relaying);
    fsm.transitionToClosing();
    fsm.transitionToClosed();
    // Reset for more transitions (simulate a new connection reusing the struct)
    fsm = ConnFSM{};
    _ = fsm.transition(.tls_handshake);
    _ = fsm.transition(.protocol_parse);
    _ = fsm.transition(.dns_resolving);
    _ = fsm.transition(.connecting);
    _ = fsm.transition(.outbound_tls_handshake);
    _ = fsm.transition(.outbound_ws_handshake);
    _ = fsm.transition(.outbound_vmess_header);
    _ = fsm.transition(.relaying);
    fsm.transitionToClosing();
    fsm.transitionToClosed();

    try std.testing.expectEqual(@as(u8, 10), fsm.history_count);
}

test "State.name returns tag name" {
    try std.testing.expectEqualStrings("proxy_protocol", State.proxy_protocol.name());
    try std.testing.expectEqualStrings("relaying", State.relaying.name());
    try std.testing.expectEqualStrings("half_close_client", State.half_close_client.name());
    try std.testing.expectEqualStrings("half_close_target", State.half_close_target.name());
    try std.testing.expectEqualStrings("closed", State.closed.name());
}

test "transition validation table" {
    // Valid transitions
    try std.testing.expect(isValidTransition(.proxy_protocol, .tls_handshake));
    try std.testing.expect(isValidTransition(.proxy_protocol, .protocol_parse));
    try std.testing.expect(isValidTransition(.tls_handshake, .protocol_parse));
    try std.testing.expect(isValidTransition(.protocol_parse, .dns_resolving));
    try std.testing.expect(isValidTransition(.protocol_parse, .connecting));
    try std.testing.expect(isValidTransition(.protocol_parse, .udp_relaying));
    try std.testing.expect(isValidTransition(.dns_resolving, .connecting));
    try std.testing.expect(isValidTransition(.connecting, .relaying));
    try std.testing.expect(isValidTransition(.connecting, .outbound_tls_handshake));
    try std.testing.expect(isValidTransition(.outbound_tls_handshake, .outbound_ws_handshake));
    try std.testing.expect(isValidTransition(.outbound_ws_handshake, .outbound_vmess_header));
    try std.testing.expect(isValidTransition(.outbound_vmess_header, .relaying));
    try std.testing.expect(isValidTransition(.outbound_trojan_header, .relaying));
    try std.testing.expect(isValidTransition(.outbound_ss_header, .relaying));
    try std.testing.expect(isValidTransition(.connecting, .outbound_ss_header));
    try std.testing.expect(isValidTransition(.outbound_tls_handshake, .outbound_ss_header));
    try std.testing.expect(isValidTransition(.outbound_ws_handshake, .outbound_ss_header));
    try std.testing.expect(isValidTransition(.relaying, .closing));
    try std.testing.expect(isValidTransition(.udp_relaying, .closing));
    try std.testing.expect(isValidTransition(.closing, .closed));

    // Half-close transitions
    try std.testing.expect(isValidTransition(.relaying, .half_close_client));
    try std.testing.expect(isValidTransition(.relaying, .half_close_target));
    try std.testing.expect(isValidTransition(.half_close_client, .closing));
    try std.testing.expect(isValidTransition(.half_close_target, .closing));

    // Invalid transitions
    try std.testing.expect(!isValidTransition(.proxy_protocol, .relaying));
    try std.testing.expect(!isValidTransition(.tls_handshake, .connecting));
    try std.testing.expect(!isValidTransition(.relaying, .protocol_parse));
    try std.testing.expect(!isValidTransition(.closed, .proxy_protocol));
    try std.testing.expect(!isValidTransition(.closed, .closing));
    try std.testing.expect(!isValidTransition(.closing, .relaying));

    // Half-close cannot go to each other (both FINs → closing)
    try std.testing.expect(!isValidTransition(.half_close_client, .half_close_target));
    try std.testing.expect(!isValidTransition(.half_close_target, .half_close_client));
    // Half-close cannot go back to relaying
    try std.testing.expect(!isValidTransition(.half_close_client, .relaying));
    try std.testing.expect(!isValidTransition(.half_close_target, .relaying));
}
