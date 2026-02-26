// ══════════════════════════════════════════════════════════════
//  Connection Metrics — Sub-struct for Session
//
//  Tracks connection identity, byte counters, sniff results,
//  and access log metadata. Pure data container.
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const sniffer = @import("../sniff/sniffer.zig");
const session_mod = @import("session.zig");
const config_mod = @import("config.zig");
const log = @import("log.zig");

/// Connection metrics, identity, and access log metadata.
/// Embedded in Session as `metrics` field.
pub const ConnMetrics = struct {
    // ── Connection identity ──
    conn_id: u64 = 0, // global unique connection ID for log tracing
    conn_start_ms: u64 = 0,

    // ── Byte counters ──
    conn_bytes_up: u64 = 0, // uplink: client → target
    conn_bytes_dn: u64 = 0, // downlink: target → client

    // ── Sniff results ──
    sniff_enabled: bool = true,
    sniff_redirect: bool = true,
    sniff_domain_buf: [256]u8 = [_]u8{0} ** 256,
    sniff_domain_len: u8 = 0,
    sniff_proto: sniffer.SniffResult.Protocol = .unknown,

    // ── Source address (real client IP from Proxy Protocol or socket) ──
    src_addr: ?std.net.Address = null,
    src_ip_buf: [32]u8 = undefined,

    // ── Access log metadata ──
    acc_user_id: i64 = -1,
    acc_proto: [64]u8 = undefined,
    acc_proto_len: u8 = 0,
    acc_target: [280]u8 = undefined,
    acc_target_len: u16 = 0,
    acc_dns: enum { direct, cache, resolve } = .direct,
    acc_route: [64]u8 = undefined,
    acc_route_len: u8 = 0,

    /// Save access log metadata (user ID, target, protocol tag).
    pub fn saveAccessMeta(self: *ConnMetrics, user_id: i64, target: session_mod.TargetAddress, proto_tag: []const u8) void {
        self.acc_user_id = user_id;
        const plen: u8 = @intCast(@min(proto_tag.len, self.acc_proto.len));
        @memcpy(self.acc_proto[0..plen], proto_tag[0..plen]);
        self.acc_proto_len = plen;
        const ts = switch (target.addr_type) {
            .domain => std.fmt.bufPrint(&self.acc_target, "{s}:{d}", .{ target.getDomain(), target.port }),
            .ipv4 => std.fmt.bufPrint(&self.acc_target, "{d}.{d}.{d}.{d}:{d}", .{
                target.ip4[0], target.ip4[1], target.ip4[2], target.ip4[3], target.port,
            }),
            .ipv6 => std.fmt.bufPrint(&self.acc_target, "[ipv6]:{d}", .{target.port}),
            .none => std.fmt.bufPrint(&self.acc_target, "?:0", .{}),
        };
        self.acc_target_len = if (ts) |v| @intCast(v.len) else |_| 0;
    }

    /// Format source address as "ip:port" string for logging.
    pub fn fmtSrcAddr(self: *ConnMetrics) []const u8 {
        const a = self.src_addr orelse return "-";
        const ip_bytes: [4]u8 = @bitCast(a.in.sa.addr);
        const port = a.getPort();
        return std.fmt.bufPrint(&self.src_ip_buf, "{d}.{d}.{d}.{d}:{d}", .{
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], port,
        }) catch "-";
    }

    /// Log routing decision immediately after route is resolved.
    pub fn logRouteDecision(
        self: *ConnMetrics,
        logger: *log.ScopedLogger,
        node_type: config_mod.Protocol,
        inbound_tag_buf: []const u8,
        inbound_tag_len: u8,
    ) void {
        if (!logger.enabled(.info)) return;

        const src = self.fmtSrcAddr();
        const proto = if (self.acc_proto_len > 0) self.acc_proto[0..self.acc_proto_len] else @tagName(node_type);
        const target = if (self.acc_target_len > 0) self.acc_target[0..self.acc_target_len] else "-";
        const inbound = if (inbound_tag_len > 0) inbound_tag_buf[0..inbound_tag_len] else @tagName(node_type);
        const route_tag: []const u8 = if (self.acc_route_len > 0) self.acc_route[0..self.acc_route_len] else "-";
        const sniff_tag: []const u8 = if (!self.sniff_enabled) "off" else switch (self.sniff_proto) {
            .tls => "tls",
            .http => "http",
            .unknown => "-",
        };
        var uid_buf: [24]u8 = undefined;
        const uid_str = if (self.acc_user_id >= 0)
            std.fmt.bufPrint(&uid_buf, "{d}", .{self.acc_user_id}) catch "-"
        else
            @as([]const u8, "-");

        logger.accessInfo("#{d} {s} {s} {s} sniff:{s} [{s}>{s}] uid:{s}", .{
            self.conn_id, src, proto, target, sniff_tag, inbound, route_tag, uid_str,
        });
    }
};
