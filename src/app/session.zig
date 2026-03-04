const std = @import("std");
const types = @import("../common/types.zig");

/// Monotonically increasing connection ID generator.
var next_conn_id: std.atomic.Value(u64) = std.atomic.Value(u64).init(1);

fn generateConnId() u64 {
    return next_conn_id.fetchAdd(1, .monotonic);
}

fn nowMicros() i64 {
    return @intCast(std.time.microTimestamp());
}

/// Session context — the data bus that all pipeline stages read/write.
///
/// Each stage only touches its own fields. Zero cross-layer coupling.
///
/// Lifetime: created at accept, destroyed at close. Lives on the fiber stack.
pub const SessionContext = struct {
    // ── Connection identity (set at accept) ──────────────────────────────
    conn_id: u64,
    worker_id: u32 = 0,

    // ── Source info (set by transport layer) ──────────────────────────────
    client_ip_buf: [46]u8 = undefined, // INET6_ADDRSTRLEN
    client_ip_len: u8 = 0,
    client_port: u16 = 0,
    inbound_tag_buf: [128]u8 = undefined,
    inbound_tag_len: u8 = 0,

    // ── Panel user info (set by protocol layer auth) ─────────────────────
    panel_name_buf: [64]u8 = undefined,
    panel_name_len: u8 = 0,
    node_id: i32 = 0,
    user_id: i64 = 0,
    user_email_buf: [128]u8 = undefined,
    user_email_len: u8 = 0,

    // ── Target info (set by protocol layer) ──────────────────────────────
    target: types.TargetAddress = .{},
    network: types.Network = .tcp,
    inbound_protocol: types.Protocol = .unknown,

    // ── Sniff result (set by sniff layer) ────────────────────────────────
    sniffed_target: types.TargetAddress = .{},
    final_target: types.TargetAddress = .{},

    // ── Routing result (set by router) ───────────────────────────────────
    outbound_tag_buf: [64]u8 = undefined,
    outbound_tag_len: u8 = 0,

    // ── State ────────────────────────────────────────────────────────────
    state: types.ConnState = .accepted,
    error_code: types.ErrorCode = .ok,

    // ── Timestamps (microseconds, monotonic) ─────────────────────────────
    accept_time_us: i64,
    handshake_done_us: i64 = 0,
    sniff_done_us: i64 = 0,
    dial_done_us: i64 = 0,
    close_time_us: i64 = 0,

    // ── Traffic stats ────────────────────────────────────────────────────
    bytes_up: u64 = 0,
    bytes_down: u64 = 0,

    // ── Rate limit (bytes/s, 0 = unlimited) ──────────────────────────────
    speed_limit: u64 = 0,

    // ── First packet buffer (for sniff replay) ───────────────────────────
    first_packet_buf: [4096]u8 = undefined,
    first_packet_len: u16 = 0,

    pub fn init() SessionContext {
        return .{
            .conn_id = generateConnId(),
            .accept_time_us = nowMicros(),
        };
    }

    // ── Field accessors (slice views into fixed buffers) ─────────────────

    pub fn clientIp(self: *const SessionContext) []const u8 {
        return self.client_ip_buf[0..self.client_ip_len];
    }

    pub fn setClientIp(self: *SessionContext, ip: []const u8) void {
        const len: u8 = @intCast(@min(ip.len, self.client_ip_buf.len));
        @memcpy(self.client_ip_buf[0..len], ip[0..len]);
        self.client_ip_len = len;
    }

    pub fn inboundTag(self: *const SessionContext) []const u8 {
        return self.inbound_tag_buf[0..self.inbound_tag_len];
    }

    pub fn setInboundTag(self: *SessionContext, tag: []const u8) void {
        const len: u8 = @intCast(@min(tag.len, self.inbound_tag_buf.len));
        @memcpy(self.inbound_tag_buf[0..len], tag[0..len]);
        self.inbound_tag_len = len;
    }

    pub fn userEmail(self: *const SessionContext) []const u8 {
        return self.user_email_buf[0..self.user_email_len];
    }

    pub fn setUserEmail(self: *SessionContext, email: []const u8) void {
        const len: u8 = @intCast(@min(email.len, self.user_email_buf.len));
        @memcpy(self.user_email_buf[0..len], email[0..len]);
        self.user_email_len = len;
    }

    pub fn outboundTag(self: *const SessionContext) []const u8 {
        return self.outbound_tag_buf[0..self.outbound_tag_len];
    }

    pub fn setOutboundTag(self: *SessionContext, tag: []const u8) void {
        const len: u8 = @intCast(@min(tag.len, self.outbound_tag_buf.len));
        @memcpy(self.outbound_tag_buf[0..len], tag[0..len]);
        self.outbound_tag_len = len;
    }

    pub fn firstPacket(self: *const SessionContext) []const u8 {
        return self.first_packet_buf[0..self.first_packet_len];
    }

    pub fn setFirstPacket(self: *SessionContext, data: []const u8) void {
        const len: u16 = @intCast(@min(data.len, self.first_packet_buf.len));
        @memcpy(self.first_packet_buf[0..len], data[0..len]);
        self.first_packet_len = len;
    }

    // ── State transitions ────────────────────────────────────────────────

    pub fn transitionTo(self: *SessionContext, new_state: types.ConnState) void {
        self.state = new_state;
        const now = nowMicros();
        switch (new_state) {
            .sniffing => self.handshake_done_us = now,
            .routing => self.sniff_done_us = now,
            .relaying => self.dial_done_us = now,
            .closed => self.close_time_us = now,
            else => {},
        }
    }

    pub fn setError(self: *SessionContext, code: types.ErrorCode) void {
        self.error_code = code;
    }

    /// Effective target: final_target if set, else sniffed, else original.
    pub fn effectiveTarget(self: *const SessionContext) types.TargetAddress {
        if (!self.final_target.isEmpty()) return self.final_target;
        if (!self.sniffed_target.isEmpty()) return self.sniffed_target;
        return self.target;
    }

    /// Duration in milliseconds since accept.
    pub fn durationMs(self: *const SessionContext) i64 {
        const end = if (self.close_time_us > 0) self.close_time_us else nowMicros();
        return @divTrunc(end - self.accept_time_us, 1000);
    }
};
