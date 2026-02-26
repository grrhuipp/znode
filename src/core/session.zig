const std = @import("std");
const config = @import("config.zig");

/// Per-connection session context.
/// Tracks the full lifecycle of a proxied connection.
pub const SessionContext = struct {
    // Connection identity
    conn_id: u64 = 0,
    worker_id: u16 = 0,

    // Source info
    src_addr: ?std.net.Address = null,
    src_port: u16 = 0,
    client_ip: [64]u8 = [_]u8{0} ** 64,
    client_ip_len: u8 = 0,

    // Inbound info
    inbound_tag: [64]u8 = [_]u8{0} ** 64,
    inbound_tag_len: u8 = 0,
    protocol: config.Protocol = .freedom,
    transport: config.Transport = .tcp,

    // Target info (from protocol handshake)
    target: TargetAddress = .{},

    // Resolved target: reused across pipeline stages.
    // During sniffing/routing: holds TLS SNI / HTTP Host override.
    // After DNS resolution: holds the final address to connect to.
    resolved_target: TargetAddress = .{},

    // Outbound info
    outbound_tag: [64]u8 = [_]u8{0} ** 64,
    outbound_tag_len: u8 = 0,

    // User info (from authentication)
    user_id: i64 = -1,
    user_email: [128]u8 = [_]u8{0} ** 128,
    user_email_len: u8 = 0,

    // Panel info
    panel_name: [64]u8 = [_]u8{0} ** 64,
    panel_name_len: u8 = 0,
    node_id: u32 = 0,

    // Traffic statistics
    bytes_up: u64 = 0,
    bytes_down: u64 = 0,
    speed_limit: u64 = 0, // 0 = unlimited

    // Lifecycle timestamps (microseconds)
    accept_time_us: i64 = 0,
    handshake_done_us: i64 = 0,
    sniff_done_us: i64 = 0,
    dial_done_us: i64 = 0,
    close_time_us: i64 = 0,

    /// Get client IP as a string slice.
    pub fn getClientIp(self: *const SessionContext) []const u8 {
        return self.client_ip[0..self.client_ip_len];
    }

    /// Set client IP from string.
    pub fn setClientIp(self: *SessionContext, ip: []const u8) void {
        const len = @min(ip.len, self.client_ip.len);
        @memcpy(self.client_ip[0..len], ip[0..len]);
        self.client_ip_len = @intCast(len);
    }

    /// Get inbound tag as string slice.
    pub fn getInboundTag(self: *const SessionContext) []const u8 {
        return self.inbound_tag[0..self.inbound_tag_len];
    }

    /// Set inbound tag.
    pub fn setInboundTag(self: *SessionContext, tag: []const u8) void {
        const len = @min(tag.len, self.inbound_tag.len);
        @memcpy(self.inbound_tag[0..len], tag[0..len]);
        self.inbound_tag_len = @intCast(len);
    }

    /// Get outbound tag as string slice.
    pub fn getOutboundTag(self: *const SessionContext) []const u8 {
        return self.outbound_tag[0..self.outbound_tag_len];
    }

    /// Set outbound tag.
    pub fn setOutboundTag(self: *SessionContext, tag: []const u8) void {
        const len = @min(tag.len, self.outbound_tag.len);
        @memcpy(self.outbound_tag[0..len], tag[0..len]);
        self.outbound_tag_len = @intCast(len);
    }

    /// Record current time as microsecond timestamp.
    pub fn nowUs() i64 {
        return std.time.microTimestamp();
    }

    /// Calculate connection duration in milliseconds.
    pub fn durationMs(self: *const SessionContext) i64 {
        const end = if (self.close_time_us > 0) self.close_time_us else nowUs();
        return @divFloor(end - self.accept_time_us, 1000);
    }
};

/// Target address, supporting domain name, IPv4, and IPv6.
pub const TargetAddress = struct {
    addr_type: AddressType = .none,
    port: u16 = 0,

    // Domain name storage (inline, no heap allocation)
    domain: [256]u8 = [_]u8{0} ** 256,
    domain_len: u8 = 0,

    // IP address storage
    ip4: [4]u8 = [_]u8{0} ** 4,
    ip6: [16]u8 = [_]u8{0} ** 16,

    pub const AddressType = enum(u8) {
        none = 0,
        ipv4 = 1,
        domain = 3,
        ipv6 = 4,
    };

    pub fn setDomain(self: *TargetAddress, domain: []const u8, port: u16) void {
        const len = @min(domain.len, self.domain.len);
        @memcpy(self.domain[0..len], domain[0..len]);
        self.domain_len = @intCast(len);
        self.port = port;
        self.addr_type = .domain;
    }

    pub fn setIpv4(self: *TargetAddress, ip: [4]u8, port: u16) void {
        self.ip4 = ip;
        self.port = port;
        self.addr_type = .ipv4;
    }

    pub fn setIpv6(self: *TargetAddress, ip: [16]u8, port: u16) void {
        self.ip6 = ip;
        self.port = port;
        self.addr_type = .ipv6;
    }

    pub fn getDomain(self: *const TargetAddress) []const u8 {
        return self.domain[0..self.domain_len];
    }

    pub fn isValid(self: *const TargetAddress) bool {
        return self.addr_type != .none and self.port > 0;
    }

    /// Convert to std.net.Address (only for IP types).
    pub fn toNetAddress(self: *const TargetAddress) ?std.net.Address {
        return switch (self.addr_type) {
            .ipv4 => std.net.Address.initIp4(self.ip4, self.port),
            .ipv6 => std.net.Address.initIp6(self.ip6, self.port, 0, 0),
            else => null,
        };
    }
};

/// Global atomic connection ID counter.
var next_conn_id: std.atomic.Value(u64) = std.atomic.Value(u64).init(1);

pub fn nextConnId() u64 {
    return next_conn_id.fetchAdd(1, .monotonic);
}

test "SessionContext basic usage" {
    var ctx = SessionContext{};
    ctx.conn_id = nextConnId();
    ctx.worker_id = 0;
    ctx.accept_time_us = SessionContext.nowUs();
    ctx.setClientIp("192.168.1.100");

    try std.testing.expectEqualStrings("192.168.1.100", ctx.getClientIp());
    try std.testing.expect(ctx.conn_id > 0);
}

test "TargetAddress domain" {
    var addr = TargetAddress{};
    addr.setDomain("example.com", 443);

    try std.testing.expectEqualStrings("example.com", addr.getDomain());
    try std.testing.expectEqual(@as(u16, 443), addr.port);
    try std.testing.expect(addr.isValid());
}
