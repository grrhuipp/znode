const std = @import("std");
const config = @import("../infra/config.zig");
const types = @import("../common/types.zig");

pub const Cidr = struct {
    network: u32,
    mask: u32,
};

pub const CompiledRule = struct {
    domain_suffix: []const []const u8,
    ip_cidrs: []const Cidr,
    outbound_tag: []const u8,
};

pub const Router = struct {
    rules: []const CompiledRule,
    default_outbound: []const u8,

    pub fn init(allocator: std.mem.Allocator, routing: config.RoutingConfig) !Router {
        var rules = std.array_list.Managed(CompiledRule).init(allocator);

        for (routing.rules) |rule| {
            var cidrs = std.array_list.Managed(Cidr).init(allocator);
            for (rule.ip_cidrs) |ip_cidr| {
                if (parseCidr(ip_cidr)) |parsed| {
                    try cidrs.append(parsed);
                } else {
                    std.log.warn("忽略无效 CIDR 规则: {s}", .{ip_cidr});
                }
            }

            try rules.append(.{
                .domain_suffix = rule.domain_suffix,
                .ip_cidrs = try cidrs.toOwnedSlice(),
                .outbound_tag = rule.outbound_tag,
            });
        }

        return .{
            .rules = try rules.toOwnedSlice(),
            .default_outbound = routing.default_outbound,
        };
    }

    pub fn route(self: *const Router, target: types.TargetAddress) []const u8 {
        for (self.rules) |rule| {
            if (matchRule(rule, target)) {
                return rule.outbound_tag;
            }
        }
        return self.default_outbound;
    }
};

fn matchRule(rule: CompiledRule, target: types.TargetAddress) bool {
    var has_condition = false;

    if (rule.domain_suffix.len > 0) {
        has_condition = true;
        if (target.address_type != .domain) return false;
        if (!matchDomainSuffix(rule.domain_suffix, target.host())) return false;
    }

    if (rule.ip_cidrs.len > 0) {
        has_condition = true;
        if (target.address_type != .ipv4) return false;
        const ip = parseIpv4(target.host()) orelse return false;
        if (!matchIpCidr(rule.ip_cidrs, ip)) return false;
    }

    return has_condition;
}

fn matchDomainSuffix(suffixes: []const []const u8, domain: []const u8) bool {
    for (suffixes) |raw_suffix| {
        const suffix = if (raw_suffix.len > 0 and raw_suffix[0] == '.') raw_suffix[1..] else raw_suffix;
        if (std.ascii.eqlIgnoreCase(domain, suffix)) return true;
        if (domain.len > suffix.len and std.ascii.endsWithIgnoreCase(domain, suffix)) {
            const dot_index = domain.len - suffix.len - 1;
            if (domain[dot_index] == '.') return true;
        }
    }
    return false;
}

fn matchIpCidr(cidrs: []const Cidr, ip: u32) bool {
    for (cidrs) |cidr| {
        if ((ip & cidr.mask) == cidr.network) return true;
    }
    return false;
}

fn parseCidr(text: []const u8) ?Cidr {
    const slash_index = std.mem.indexOfScalar(u8, text, '/');
    if (slash_index == null) {
        const ip = parseIpv4(text) orelse return null;
        return .{
            .network = ip,
            .mask = 0xffffffff,
        };
    }

    const ip_text = text[0..slash_index.?];
    const prefix_text = text[slash_index.? + 1 ..];
    const prefix = std.fmt.parseInt(u8, prefix_text, 10) catch return null;
    if (prefix > 32) return null;

    const ip = parseIpv4(ip_text) orelse return null;
    const mask: u32 = if (prefix == 0) 0 else @as(u32, 0xffffffff) << @as(u5, @intCast(32 - prefix));
    return .{
        .network = ip & mask,
        .mask = mask,
    };
}

fn parseIpv4(text: []const u8) ?u32 {
    var iter = std.mem.splitScalar(u8, text, '.');
    var parts: [4]u8 = undefined;
    var index: usize = 0;

    while (iter.next()) |part| {
        if (index >= 4) return null;
        const value = std.fmt.parseInt(u8, part, 10) catch return null;
        parts[index] = value;
        index += 1;
    }

    if (index != 4) return null;

    return (@as(u32, parts[0]) << 24) |
        (@as(u32, parts[1]) << 16) |
        (@as(u32, parts[2]) << 8) |
        @as(u32, parts[3]);
}
