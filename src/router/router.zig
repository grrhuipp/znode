const std = @import("std");
const config_mod = @import("../core/config.zig");
const session_mod = @import("../core/session.zig");
const geoip_mod = @import("../geo/geoip.zig");
const geosite_mod = @import("../geo/geosite.zig");
const regex_lite = @import("regex_lite.zig");

/// Routing engine: matches connections to outbound configs (Xray-compatible).
///
/// Route evaluation order:
///   1. Iterate routes in config order (first match wins)
///   2. For each route, check ALL rules (OR logic — any rule match → route matches)
///   3. If route matches, pick one of its outbound endpoints (round-robin if multiple)
///   4. If no route matches, return null → caller uses default_outbound or closes
pub const Router = struct {
    routes: []const config_mod.RouteEntry,
    geoip: ?*const geoip_mod.GeoIP,
    geosite: ?*const geosite_mod.GeoSite,
    /// Round-robin counter for multi-outbound load balancing (atomic for thread safety).
    rr_counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn init(
        routes: []const config_mod.RouteEntry,
        geoip: ?*const geoip_mod.GeoIP,
        geosite: ?*const geosite_mod.GeoSite,
    ) Router {
        return .{
            .routes = routes,
            .geoip = geoip,
            .geosite = geosite,
        };
    }

    /// Route a connection based on session context.
    /// Returns pointer to matched OutConfig, or null (no match).
    pub const RouteResult = struct {
        out: *const config_mod.OutConfig,
        /// First matching rule string (e.g. "geosite:netflix", "ip:10.0.0.0/8")
        matched_rule: []const u8 = "",
    };

    pub fn route(self: *const Router, ctx: *const session_mod.SessionContext) ?RouteResult {
        // Determine effective target (prefer sniffed, fallback to protocol target)
        const target = if (ctx.resolved_target.isValid())
            &ctx.resolved_target
        else
            &ctx.target;

        for (self.routes) |*entry| {
            if (self.matchAnyRule(entry.rules, ctx, target)) {
                if (entry.outs.len == 0) return null;
                const out = if (entry.outs.len == 1)
                    &entry.outs[0]
                else blk: {
                    const counter = @constCast(&self.rr_counter).fetchAdd(1, .monotonic);
                    break :blk &entry.outs[counter % entry.outs.len];
                };
                return .{
                    .out = out,
                    .matched_rule = if (entry.rules.len > 0) entry.rules[0] else "",
                };
            }
        }

        return null; // No route matched
    }

    /// Check if any rule in the list matches (OR logic).
    fn matchAnyRule(
        self: *const Router,
        rules: []const []const u8,
        ctx: *const session_mod.SessionContext,
        target: *const session_mod.TargetAddress,
    ) bool {
        for (rules) |rule| {
            if (rule.len == 1 and rule[0] == '*') return true;
            if (self.matchRuleStr(rule, ctx, target)) return true;
        }
        return false;
    }

    /// Parse and match a single rule string like "geosite:netflix" or "domain:google.com".
    fn matchRuleStr(
        self: *const Router,
        rule: []const u8,
        ctx: *const session_mod.SessionContext,
        target: *const session_mod.TargetAddress,
    ) bool {
        // Find ':' separator
        const colon = std.mem.indexOfScalar(u8, rule, ':') orelse return false;
        const prefix = rule[0..colon];
        const value = rule[colon + 1 ..];

        if (std.mem.eql(u8, prefix, "geosite")) return self.matchGeoSite(target, value);
        if (std.mem.eql(u8, prefix, "geoip")) return self.matchGeoIP(target, value);
        if (std.mem.eql(u8, prefix, "domain")) return matchDomainSuffix(target, value);
        if (std.mem.eql(u8, prefix, "domain_full")) return matchDomainFull(target, value);
        if (std.mem.eql(u8, prefix, "domain_keyword")) return matchDomainKeyword(target, value);
        if (std.mem.eql(u8, prefix, "domain_regex")) return matchDomainRegex(target, value);
        if (std.mem.eql(u8, prefix, "ip")) return matchIpCidr(target, value);
        if (std.mem.eql(u8, prefix, "port")) return matchPort(target, value);
        if (std.mem.eql(u8, prefix, "source")) return matchSourceIp(ctx, value);
        if (std.mem.eql(u8, prefix, "sourcePort")) return matchSourcePort(ctx, value);
        if (std.mem.eql(u8, prefix, "network")) return matchNetwork(ctx, value);
        if (std.mem.eql(u8, prefix, "protocol")) return matchProtocol(ctx, value);
        if (std.mem.eql(u8, prefix, "inbound")) return matchInboundTag(ctx, value);
        if (std.mem.eql(u8, prefix, "user")) return matchUserId(ctx, value);
        if (std.mem.eql(u8, prefix, "user_email")) return matchUserEmail(ctx, value);

        return false;
    }

    // ── Domain match functions ──

    fn matchDomainFull(target: *const session_mod.TargetAddress, domain: []const u8) bool {
        if (target.addr_type != .domain) return false;
        return std.ascii.eqlIgnoreCase(target.getDomain(), domain);
    }

    fn matchDomainSuffix(target: *const session_mod.TargetAddress, suffix: []const u8) bool {
        if (target.addr_type != .domain) return false;
        const domain = target.getDomain();
        if (domain.len == suffix.len) {
            return std.ascii.eqlIgnoreCase(domain, suffix);
        }
        if (domain.len > suffix.len) {
            const offset = domain.len - suffix.len;
            if (domain[offset - 1] != '.') return false;
            return std.ascii.eqlIgnoreCase(domain[offset..], suffix);
        }
        return false;
    }

    fn matchDomainKeyword(target: *const session_mod.TargetAddress, keyword: []const u8) bool {
        if (target.addr_type != .domain) return false;
        const domain = target.getDomain();
        if (keyword.len > domain.len) return false;
        if (keyword.len == 0) return true;
        const end = domain.len - keyword.len + 1;
        for (0..end) |i| {
            if (std.ascii.eqlIgnoreCase(domain[i .. i + keyword.len], keyword)) {
                return true;
            }
        }
        return false;
    }

    fn matchGeoSite(self: *const Router, target: *const session_mod.TargetAddress, tag: []const u8) bool {
        if (target.addr_type != .domain) return false;
        const gs = self.geosite orelse return false;
        return gs.matchDomain(target.getDomain(), tag);
    }

    fn matchGeoIP(self: *const Router, target: *const session_mod.TargetAddress, country: []const u8) bool {
        if (target.addr_type != .ipv4) return false;
        const gi = self.geoip orelse return false;
        return gi.matchCountryIp4(target.ip4, country);
    }

    fn matchDomainRegex(target: *const session_mod.TargetAddress, pattern: []const u8) bool {
        if (target.addr_type != .domain) return false;
        return regex_lite.match(pattern, target.getDomain());
    }

    // ── IP match (IPv4 + IPv6 CIDR) ──

    fn matchIpCidr(target: *const session_mod.TargetAddress, cidr_str: []const u8) bool {
        if (target.addr_type == .ipv4) {
            if (parseCidr4(cidr_str)) |cidr| {
                return matchesCidr4(target.ip4, cidr);
            }
            return false;
        }
        if (target.addr_type == .ipv6) {
            if (parseCidr6(cidr_str)) |cidr| {
                return matchesCidr6(target.ip6, cidr);
            }
            return false;
        }
        return false;
    }

    // ── Port match (supports comma-separated lists: "80,443,8000-9000") ──

    fn matchPort(target: *const session_mod.TargetAddress, port_str: []const u8) bool {
        return matchPortValue(target.port, port_str);
    }

    fn matchPortValue(port: u16, port_str: []const u8) bool {
        // Split by commas and check each segment
        var rest: []const u8 = port_str;
        while (rest.len > 0) {
            // Find next comma
            const comma = std.mem.indexOfScalar(u8, rest, ',');
            const segment = if (comma) |pos| rest[0..pos] else rest;
            rest = if (comma) |pos| rest[pos + 1 ..] else &[_]u8{};

            if (segment.len == 0) continue;

            // Check for range (e.g. "1000-2000")
            if (std.mem.indexOfScalar(u8, segment, '-')) |dash| {
                const min_port = std.fmt.parseInt(u16, segment[0..dash], 10) catch continue;
                const max_port = std.fmt.parseInt(u16, segment[dash + 1 ..], 10) catch continue;
                if (port >= min_port and port <= max_port) return true;
            } else {
                const p = std.fmt.parseInt(u16, segment, 10) catch continue;
                if (port == p) return true;
            }
        }
        return false;
    }

    // ── Source IP/Port match ──

    fn matchSourceIp(ctx: *const session_mod.SessionContext, value: []const u8) bool {
        const src = ctx.src_addr orelse return false;
        if (src.any.family == 2) { // AF_INET
            const ip4 = @as(*const [4]u8, @ptrCast(&src.in.sa.addr)).*;
            if (parseCidr4(value)) |cidr| {
                return matchesCidr4(ip4, cidr);
            }
            return false;
        }
        // TODO: IPv6 source matching
        return false;
    }

    fn matchSourcePort(ctx: *const session_mod.SessionContext, value: []const u8) bool {
        return matchPortValue(ctx.src_port, value);
    }

    // ── Network match (tcp, udp, tcp,udp) ──

    fn matchNetwork(ctx: *const session_mod.SessionContext, value: []const u8) bool {
        const transport_name = @tagName(ctx.transport);
        var rest: []const u8 = value;
        while (rest.len > 0) {
            const comma = std.mem.indexOfScalar(u8, rest, ',');
            const segment = if (comma) |pos| rest[0..pos] else rest;
            rest = if (comma) |pos| rest[pos + 1 ..] else &[_]u8{};
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, segment, " "), transport_name)) return true;
        }
        return false;
    }

    // ── Protocol match (trojan, vmess, shadowsocks) ──

    fn matchProtocol(ctx: *const session_mod.SessionContext, value: []const u8) bool {
        const proto_name = @tagName(ctx.protocol);
        var rest: []const u8 = value;
        while (rest.len > 0) {
            const comma = std.mem.indexOfScalar(u8, rest, ',');
            const segment = if (comma) |pos| rest[0..pos] else rest;
            rest = if (comma) |pos| rest[pos + 1 ..] else &[_]u8{};
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, segment, " "), proto_name)) return true;
        }
        return false;
    }

    // ── Identity match ──

    fn matchInboundTag(ctx: *const session_mod.SessionContext, tag: []const u8) bool {
        return std.mem.eql(u8, ctx.getInboundTag(), tag);
    }

    fn matchUserId(ctx: *const session_mod.SessionContext, uid_str: []const u8) bool {
        const uid = std.fmt.parseInt(i64, uid_str, 10) catch return false;
        return ctx.user_id == uid;
    }

    fn matchUserEmail(ctx: *const session_mod.SessionContext, email: []const u8) bool {
        const user_email = ctx.user_email[0..ctx.user_email_len];
        return std.ascii.eqlIgnoreCase(user_email, email);
    }

    // ══════════════════════════════════════════════════════════════
    //  IPv4 CIDR
    // ══════════════════════════════════════════════════════════════

    pub const CidrInfo4 = struct {
        ip: [4]u8,
        prefix: u8,
    };

    pub fn parseCidr4(cidr: []const u8) ?CidrInfo4 {
        var slash_pos: ?usize = null;
        for (cidr, 0..) |ch, i| {
            if (ch == '/') {
                slash_pos = i;
                break;
            }
        }

        const ip_str = if (slash_pos) |pos| cidr[0..pos] else cidr;
        const prefix = if (slash_pos) |pos| blk: {
            break :blk std.fmt.parseInt(u8, cidr[pos + 1 ..], 10) catch return null;
        } else 32;

        const addr = std.net.Address.parseIp4(ip_str, 0) catch return null;
        const ip_bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr)).*;

        return CidrInfo4{
            .ip = ip_bytes,
            .prefix = prefix,
        };
    }

    pub fn matchesCidr4(ip: [4]u8, cidr: CidrInfo4) bool {
        const ip_val = (@as(u32, ip[0]) << 24) | (@as(u32, ip[1]) << 16) |
            (@as(u32, ip[2]) << 8) | ip[3];
        const cidr_val = (@as(u32, cidr.ip[0]) << 24) | (@as(u32, cidr.ip[1]) << 16) |
            (@as(u32, cidr.ip[2]) << 8) | cidr.ip[3];
        const mask: u32 = if (cidr.prefix >= 32) 0xFFFFFFFF else ~(@as(u32, 0xFFFFFFFF) >> @intCast(cidr.prefix));
        return (ip_val & mask) == (cidr_val & mask);
    }

    // Backward compat aliases
    pub const CidrInfo = CidrInfo4;
    pub const parseCidr = parseCidr4;
    pub const matchesCidr = matchesCidr4;

    // ══════════════════════════════════════════════════════════════
    //  IPv6 CIDR
    // ══════════════════════════════════════════════════════════════

    pub const CidrInfo6 = struct {
        ip: [16]u8,
        prefix: u8,
    };

    pub fn parseCidr6(cidr: []const u8) ?CidrInfo6 {
        // Find '/' for prefix length
        var slash_pos: ?usize = null;
        for (cidr, 0..) |ch, i| {
            if (ch == '/') {
                slash_pos = i;
                break;
            }
        }

        const ip_str = if (slash_pos) |pos| cidr[0..pos] else cidr;
        const prefix = if (slash_pos) |pos| blk: {
            break :blk std.fmt.parseInt(u8, cidr[pos + 1 ..], 10) catch return null;
        } else 128;

        if (prefix > 128) return null;

        const addr = std.net.Address.parseIp6(ip_str, 0) catch return null;
        const ip_bytes = @as(*const [16]u8, @ptrCast(&addr.in6.sa.addr)).*;

        return CidrInfo6{
            .ip = ip_bytes,
            .prefix = prefix,
        };
    }

    pub fn matchesCidr6(ip: [16]u8, cidr: CidrInfo6) bool {
        // Compare full bytes
        const full_bytes = cidr.prefix / 8;
        const remaining_bits = cidr.prefix % 8;

        if (full_bytes > 0) {
            if (!std.mem.eql(u8, ip[0..full_bytes], cidr.ip[0..full_bytes])) return false;
        }

        // Compare remaining bits in partial byte
        if (remaining_bits > 0 and full_bytes < 16) {
            const mask: u8 = @as(u8, 0xFF) << @intCast(8 - remaining_bits);
            if ((ip[full_bytes] & mask) != (cidr.ip[full_bytes] & mask)) return false;
        }

        return true;
    }
};

// ── Tests ──

test "Router empty routes returns null" {
    const router = Router.init(&.{}, null, null);
    var ctx = session_mod.SessionContext{};
    ctx.target.setDomain("example.com", 443);

    try std.testing.expect(router.route(&ctx) == null);
}

test "Router catch-all route" {
    const direct_out = config_mod.OutConfig{ .protocol = .freedom };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{"*"}, .outs = &.{direct_out} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.setDomain("example.com", 443);
    const out = router.route(&ctx) orelse unreachable;
    try std.testing.expectEqual(config_mod.Protocol.freedom, out.out.protocol);
}

test "Router domain suffix match" {
    const proxy_out = config_mod.OutConfig{ .protocol = .vmess };
    const direct_out = config_mod.OutConfig{ .protocol = .freedom };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{"domain:google.com"}, .outs = &.{proxy_out} },
        .{ .rules = &.{"*"}, .outs = &.{direct_out} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.setDomain("www.google.com", 443);
    const out1 = router.route(&ctx) orelse unreachable;
    try std.testing.expectEqual(config_mod.Protocol.vmess, out1.out.protocol);

    ctx.target.setDomain("other.com", 443);
    const out2 = router.route(&ctx) orelse unreachable;
    try std.testing.expectEqual(config_mod.Protocol.freedom, out2.out.protocol);
}

test "Router domain full match" {
    const block_out = config_mod.OutConfig{ .protocol = .blackhole };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{"domain_full:blocked.com"}, .outs = &.{block_out} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.setDomain("blocked.com", 80);
    try std.testing.expect(router.route(&ctx) != null);

    ctx.target.setDomain("www.blocked.com", 80);
    try std.testing.expect(router.route(&ctx) == null); // no catch-all
}

test "Router port match" {
    const proxy_out = config_mod.OutConfig{ .protocol = .vmess };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{"port:443"}, .outs = &.{proxy_out} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.setDomain("example.com", 443);
    try std.testing.expect(router.route(&ctx) != null);

    ctx.target.setDomain("example.com", 80);
    try std.testing.expect(router.route(&ctx) == null);
}

test "Router port range match" {
    const proxy_out = config_mod.OutConfig{ .protocol = .vmess };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{"port:1000-2000"}, .outs = &.{proxy_out} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.setDomain("example.com", 1500);
    try std.testing.expect(router.route(&ctx) != null);

    ctx.target.setDomain("example.com", 999);
    try std.testing.expect(router.route(&ctx) == null);
}

test "Router multi-port match (comma-separated)" {
    const proxy_out = config_mod.OutConfig{ .protocol = .vmess };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{"port:80,443,8000-9000"}, .outs = &.{proxy_out} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.setDomain("example.com", 80);
    try std.testing.expect(router.route(&ctx) != null);

    ctx.target.setDomain("example.com", 443);
    try std.testing.expect(router.route(&ctx) != null);

    ctx.target.setDomain("example.com", 8500);
    try std.testing.expect(router.route(&ctx) != null);

    ctx.target.setDomain("example.com", 7999);
    try std.testing.expect(router.route(&ctx) == null);
}

test "Router OR rules (any match)" {
    const proxy_out = config_mod.OutConfig{ .protocol = .vmess };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{ "domain:google.com", "domain:youtube.com" }, .outs = &.{proxy_out} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.setDomain("www.google.com", 443);
    try std.testing.expect(router.route(&ctx) != null);

    ctx.target.setDomain("www.youtube.com", 443);
    try std.testing.expect(router.route(&ctx) != null);

    ctx.target.setDomain("www.facebook.com", 443);
    try std.testing.expect(router.route(&ctx) == null);
}

test "Router first match wins" {
    const out1 = config_mod.OutConfig{ .protocol = .vmess };
    const out2 = config_mod.OutConfig{ .protocol = .trojan };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{"domain_full:example.com"}, .outs = &.{out1} },
        .{ .rules = &.{"domain:example.com"}, .outs = &.{out2} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.setDomain("example.com", 80);
    const out = router.route(&ctx) orelse unreachable;
    try std.testing.expectEqual(config_mod.Protocol.vmess, out.out.protocol);
}

test "Router domain regex match" {
    const block_out = config_mod.OutConfig{ .protocol = .blackhole };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{"domain_regex:^ads?\\."}, .outs = &.{block_out} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.setDomain("ad.example.com", 80);
    try std.testing.expect(router.route(&ctx) != null);

    ctx.target.setDomain("ads.example.com", 80);
    try std.testing.expect(router.route(&ctx) != null);

    ctx.target.setDomain("admin.example.com", 80);
    try std.testing.expect(router.route(&ctx) == null);
}

test "Router user match" {
    const premium_out = config_mod.OutConfig{ .protocol = .vmess };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{"user:42"}, .outs = &.{premium_out} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.setDomain("example.com", 80);
    ctx.user_id = 42;
    try std.testing.expect(router.route(&ctx) != null);

    ctx.user_id = 99;
    try std.testing.expect(router.route(&ctx) == null);
}

test "Router CIDR matching (IPv4)" {
    const cidr = Router.parseCidr4("192.168.1.0/24") orelse unreachable;
    try std.testing.expect(Router.matchesCidr4(.{ 192, 168, 1, 100 }, cidr));
    try std.testing.expect(Router.matchesCidr4(.{ 192, 168, 1, 0 }, cidr));
    try std.testing.expect(!Router.matchesCidr4(.{ 192, 168, 2, 1 }, cidr));
    try std.testing.expect(!Router.matchesCidr4(.{ 10, 0, 0, 1 }, cidr));
}

test "Router CIDR matching (IPv6)" {
    const cidr = Router.parseCidr6("2001:db8::/32") orelse unreachable;
    // Match: same /32 prefix
    try std.testing.expect(Router.matchesCidr6(
        .{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
        cidr,
    ));
    // No match: different prefix
    try std.testing.expect(!Router.matchesCidr6(
        .{ 0x20, 0x02, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
        cidr,
    ));
}

test "Router IP CIDR rule (IPv4)" {
    const proxy_out = config_mod.OutConfig{ .protocol = .vmess };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{"ip:10.0.0.0/8"}, .outs = &.{proxy_out} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.addr_type = .ipv4;
    ctx.target.ip4 = .{ 10, 1, 2, 3 };
    ctx.target.port = 80;
    try std.testing.expect(router.route(&ctx) != null);

    ctx.target.ip4 = .{ 192, 168, 1, 1 };
    try std.testing.expect(router.route(&ctx) == null);
}

test "Router IP CIDR rule (IPv6)" {
    const proxy_out = config_mod.OutConfig{ .protocol = .vmess };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{"ip:fd00::/8"}, .outs = &.{proxy_out} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.addr_type = .ipv6;
    ctx.target.ip6 = .{ 0xfd, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    ctx.target.port = 80;
    try std.testing.expect(router.route(&ctx) != null);

    ctx.target.ip6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    try std.testing.expect(router.route(&ctx) == null);
}

test "Router source port match" {
    const proxy_out = config_mod.OutConfig{ .protocol = .vmess };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{"sourcePort:8080,9090"}, .outs = &.{proxy_out} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.setDomain("example.com", 443);
    ctx.src_port = 8080;
    try std.testing.expect(router.route(&ctx) != null);

    ctx.src_port = 9090;
    try std.testing.expect(router.route(&ctx) != null);

    ctx.src_port = 1234;
    try std.testing.expect(router.route(&ctx) == null);
}

test "Router network match" {
    const proxy_out = config_mod.OutConfig{ .protocol = .vmess };
    const routes = [_]config_mod.RouteEntry{
        .{ .rules = &.{"network:udp"}, .outs = &.{proxy_out} },
    };
    const router = Router.init(&routes, null, null);

    var ctx = session_mod.SessionContext{};
    ctx.target.setDomain("example.com", 443);
    ctx.transport = .udp;
    try std.testing.expect(router.route(&ctx) != null);

    ctx.transport = .tcp;
    try std.testing.expect(router.route(&ctx) == null);
}
