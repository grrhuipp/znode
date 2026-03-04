/// GeoIP/GeoSite loader — hand-rolled protobuf parser for V2Ray .dat files.
///
/// Two-phase strategy:
///   Phase 1 (LoadIndex): scan file, build tag→offset index
///   Phase 2 (LoadTag): on-demand parse CIDRs/domains for a specific tag
const std = @import("std");

// ── Protobuf primitives ─────────────────────────────────────────────────

fn readVarint(data: []const u8, pos: *usize) ?u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    while (pos.* < data.len) {
        const b = data[pos.*];
        pos.* += 1;
        result |= @as(u64, b & 0x7F) << shift;
        if (b & 0x80 == 0) return result;
        shift +%= 7;
        if (shift >= 64) return null;
    }
    return null;
}

fn readLengthDelimited(data: []const u8, pos: *usize) ?[]const u8 {
    const len = readVarint(data, pos) orelse return null;
    const end = pos.* + @as(usize, @intCast(len));
    if (end > data.len) return null;
    const result = data[pos.*..end];
    pos.* = end;
    return result;
}

fn skipField(data: []const u8, pos: *usize, wire_type: u3) bool {
    switch (wire_type) {
        0 => { // varint
            _ = readVarint(data, pos) orelse return false;
        },
        1 => { // 64-bit
            if (pos.* + 8 > data.len) return false;
            pos.* += 8;
        },
        2 => { // length-delimited
            const len = readVarint(data, pos) orelse return false;
            const skip = @as(usize, @intCast(len));
            if (pos.* + skip > data.len) return false;
            pos.* += skip;
        },
        5 => { // 32-bit
            if (pos.* + 4 > data.len) return false;
            pos.* += 4;
        },
        else => return false,
    }
    return true;
}

// ── CIDR ────────────────────────────────────────────────────────────────

pub const CIDR = struct {
    addr: [16]u8 = .{0} ** 16,
    prefix: u8,
    is_v6: bool,
};

/// Match an IP address against a CIDR prefix.
pub fn matchPrefix(ip: []const u8, cidr: []const u8, prefix: u8) bool {
    const full_bytes = prefix / 8;
    if (full_bytes > ip.len or full_bytes > cidr.len) return false;

    if (!std.mem.eql(u8, ip[0..full_bytes], cidr[0..full_bytes])) return false;

    const remaining = @as(u3, @intCast(prefix % 8));
    if (remaining > 0 and full_bytes < ip.len and full_bytes < cidr.len) {
        const m: u8 = @as(u8, 0xFF) << @intCast(8 - remaining);
        if ((ip[full_bytes] & m) != (cidr[full_bytes] & m)) return false;
    }
    return true;
}

// ── GeoIP data ──────────────────────────────────────────────────────────

pub const GeoIPData = struct {
    cidrs_v4: []const CIDR,
    cidrs_v6: []const CIDR,

    pub fn match(self: *const GeoIPData, ip_str: []const u8) bool {
        // Try IPv4
        if (parseIPv4(ip_str)) |addr| {
            for (self.cidrs_v4) |cidr| {
                if (matchPrefix(&addr, cidr.addr[0..4], cidr.prefix)) return true;
            }
        }
        // Try IPv6
        if (parseIPv6(ip_str)) |addr| {
            for (self.cidrs_v6) |cidr| {
                if (matchPrefix(&addr, &cidr.addr, cidr.prefix)) return true;
            }
        }
        return false;
    }
};

// ── GeoSite data ────────────────────────────────────────────────────────

pub const DomainType = enum(u8) {
    plain = 0,
    regexp = 1,
    domain_suffix = 2,
    full = 3,
};

pub const GeoSiteData = struct {
    full_domains: std.StringHashMap(void),
    suffix_domains: std.StringHashMap(void),
    plain_keywords: []const []const u8,

    pub fn match(self: *const GeoSiteData, domain: []const u8) bool {
        // Lowercase domain for matching
        var lower_buf: [256]u8 = undefined;
        const lower = toLower(domain, &lower_buf) orelse return false;

        // Full match
        if (self.full_domains.contains(lower)) return true;

        // Suffix match
        if (self.suffix_domains.contains(lower)) return true;
        // Check parent domains
        var rest = lower;
        while (std.mem.indexOfScalar(u8, rest, '.')) |dot| {
            rest = rest[dot + 1 ..];
            if (self.suffix_domains.contains(rest)) return true;
        }

        // Keyword (substring) match
        for (self.plain_keywords) |kw| {
            if (std.mem.indexOf(u8, lower, kw) != null) return true;
        }

        return false;
    }
};

// ── Index entry ─────────────────────────────────────────────────────────

const IndexEntry = struct {
    offset: usize,
    size: usize,
};

// ── GeoData loader ──────────────────────────────────────────────────────

pub const GeoData = struct {
    allocator: std.mem.Allocator,
    ip_data: std.StringHashMap(GeoIPData),
    site_data: std.StringHashMap(GeoSiteData),

    pub fn init(allocator: std.mem.Allocator) GeoData {
        return .{
            .allocator = allocator,
            .ip_data = std.StringHashMap(GeoIPData).init(allocator),
            .site_data = std.StringHashMap(GeoSiteData).init(allocator),
        };
    }

    /// Load GeoIP .dat file and parse entries for specified tags.
    pub fn loadGeoIP(self: *GeoData, file_path: []const u8, tags: []const []const u8) !void {
        const data = try std.fs.cwd().readFileAlloc(self.allocator, file_path, 64 * 1024 * 1024);

        // Parse GeoIPList (field 1 = GeoIP entries)
        var pos: usize = 0;
        while (pos < data.len) {
            const tag_raw = readVarint(data, &pos) orelse break;
            const field_num = tag_raw >> 3;
            const wire_type: u3 = @intCast(tag_raw & 0x7);

            if (field_num == 1 and wire_type == 2) {
                const entry_data = readLengthDelimited(data, &pos) orelse break;
                const cc = extractCountryCode(entry_data) orelse continue;

                // Check if this tag is requested
                for (tags) |t| {
                    if (std.ascii.eqlIgnoreCase(t, cc)) {
                        const parsed = try parseGeoIPEntry(self.allocator, entry_data);
                        try self.ip_data.put(try self.allocator.dupe(u8, cc), parsed);
                        break;
                    }
                }
            } else {
                if (!skipField(data, &pos, wire_type)) break;
            }
        }
    }

    /// Load GeoSite .dat file and parse entries for specified tags.
    pub fn loadGeoSite(self: *GeoData, file_path: []const u8, tags: []const []const u8) !void {
        const data = try std.fs.cwd().readFileAlloc(self.allocator, file_path, 64 * 1024 * 1024);

        var pos: usize = 0;
        while (pos < data.len) {
            const tag_raw = readVarint(data, &pos) orelse break;
            const field_num = tag_raw >> 3;
            const wire_type: u3 = @intCast(tag_raw & 0x7);

            if (field_num == 1 and wire_type == 2) {
                const entry_data = readLengthDelimited(data, &pos) orelse break;
                const cc = extractCountryCode(entry_data) orelse continue;

                for (tags) |t| {
                    if (std.ascii.eqlIgnoreCase(t, cc)) {
                        const parsed = try parseGeoSiteEntry(self.allocator, entry_data);
                        try self.site_data.put(try self.allocator.dupe(u8, cc), parsed);
                        break;
                    }
                }
            } else {
                if (!skipField(data, &pos, wire_type)) break;
            }
        }
    }

    /// Match an IP against loaded GeoIP data.
    pub fn matchIP(self: *const GeoData, tag: []const u8, ip: []const u8) bool {
        const geo = self.ip_data.get(tag) orelse return false;
        return geo.match(ip);
    }

    /// Match a domain against loaded GeoSite data.
    pub fn matchSite(self: *const GeoData, tag: []const u8, domain: []const u8) bool {
        const geo = self.site_data.get(tag) orelse return false;
        return geo.match(domain);
    }
};

// ── Parsing helpers ─────────────────────────────────────────────────────

fn extractCountryCode(entry_data: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos < entry_data.len) {
        const tag_raw = readVarint(entry_data, &pos) orelse return null;
        const field_num = tag_raw >> 3;
        const wire_type: u3 = @intCast(tag_raw & 0x7);

        if (field_num == 1 and wire_type == 2) {
            return readLengthDelimited(entry_data, &pos);
        } else {
            if (!skipField(entry_data, &pos, wire_type)) return null;
        }
    }
    return null;
}

fn parseGeoIPEntry(allocator: std.mem.Allocator, entry_data: []const u8) !GeoIPData {
    var cidrs_v4 = std.array_list.Managed(CIDR).init(allocator);
    var cidrs_v6 = std.array_list.Managed(CIDR).init(allocator);

    var pos: usize = 0;
    while (pos < entry_data.len) {
        const tag_raw = readVarint(entry_data, &pos) orelse break;
        const field_num = tag_raw >> 3;
        const wire_type: u3 = @intCast(tag_raw & 0x7);

        if (field_num == 2 and wire_type == 2) {
            // CIDR message
            const cidr_data = readLengthDelimited(entry_data, &pos) orelse break;
            if (parseCIDR(cidr_data)) |cidr| {
                if (cidr.is_v6) {
                    try cidrs_v6.append(cidr);
                } else {
                    try cidrs_v4.append(cidr);
                }
            }
        } else {
            if (!skipField(entry_data, &pos, wire_type)) break;
        }
    }

    return .{
        .cidrs_v4 = try cidrs_v4.toOwnedSlice(),
        .cidrs_v6 = try cidrs_v6.toOwnedSlice(),
    };
}

fn parseCIDR(data: []const u8) ?CIDR {
    var cidr = CIDR{ .prefix = 0, .is_v6 = false };
    var pos: usize = 0;

    while (pos < data.len) {
        const tag_raw = readVarint(data, &pos) orelse return null;
        const field_num = tag_raw >> 3;
        const wire_type: u3 = @intCast(tag_raw & 0x7);

        if (field_num == 1 and wire_type == 2) {
            // ip bytes
            const ip_bytes = readLengthDelimited(data, &pos) orelse return null;
            if (ip_bytes.len == 4) {
                @memcpy(cidr.addr[0..4], ip_bytes);
                cidr.is_v6 = false;
            } else if (ip_bytes.len == 16) {
                @memcpy(&cidr.addr, ip_bytes);
                cidr.is_v6 = true;
            } else return null;
        } else if (field_num == 2 and wire_type == 0) {
            // prefix
            const val = readVarint(data, &pos) orelse return null;
            cidr.prefix = @intCast(val);
        } else {
            if (!skipField(data, &pos, wire_type)) return null;
        }
    }
    return cidr;
}

fn parseGeoSiteEntry(allocator: std.mem.Allocator, entry_data: []const u8) !GeoSiteData {
    var full = std.StringHashMap(void).init(allocator);
    var suffix = std.StringHashMap(void).init(allocator);
    var plain = std.array_list.Managed([]const u8).init(allocator);

    var pos: usize = 0;
    while (pos < entry_data.len) {
        const tag_raw = readVarint(entry_data, &pos) orelse break;
        const field_num = tag_raw >> 3;
        const wire_type: u3 = @intCast(tag_raw & 0x7);

        if (field_num == 2 and wire_type == 2) {
            const domain_data = readLengthDelimited(entry_data, &pos) orelse break;
            parseDomainEntry(allocator, domain_data, &full, &suffix, &plain) catch continue;
        } else {
            if (!skipField(entry_data, &pos, wire_type)) break;
        }
    }

    return .{
        .full_domains = full,
        .suffix_domains = suffix,
        .plain_keywords = try plain.toOwnedSlice(),
    };
}

fn parseDomainEntry(
    allocator: std.mem.Allocator,
    data: []const u8,
    full: *std.StringHashMap(void),
    suffix: *std.StringHashMap(void),
    plain: *std.array_list.Managed([]const u8),
) !void {
    var dtype: DomainType = .plain;
    var value: ?[]const u8 = null;
    var pos: usize = 0;

    while (pos < data.len) {
        const tag_raw = readVarint(data, &pos) orelse return;
        const field_num = tag_raw >> 3;
        const wire_type: u3 = @intCast(tag_raw & 0x7);

        if (field_num == 1 and wire_type == 0) {
            const val = readVarint(data, &pos) orelse return;
            dtype = @enumFromInt(@as(u8, @intCast(val)));
        } else if (field_num == 2 and wire_type == 2) {
            value = readLengthDelimited(data, &pos);
        } else {
            if (!skipField(data, &pos, wire_type)) return;
        }
    }

    const v = value orelse return;
    var lower_buf: [256]u8 = undefined;
    const lower = toLower(v, &lower_buf) orelse return;
    const owned = try allocator.dupe(u8, lower);

    switch (dtype) {
        .full => try full.put(owned, {}),
        .domain_suffix => try suffix.put(owned, {}),
        .plain => try plain.append(owned),
        .regexp => {}, // skip regexp
    }
}

// ── IP parsing helpers ──────────────────────────────────────────────────

fn parseIPv4(s: []const u8) ?[4]u8 {
    const addr = std.net.Address.parseIp4(s, 0) catch return null;
    return std.mem.asBytes(&addr.in.sa.addr)[0..4].*;
}

fn parseIPv6(s: []const u8) ?[16]u8 {
    const addr = std.net.Address.parseIp6(s, 0) catch return null;
    return addr.in6.sa.addr;
}

fn toLower(s: []const u8, buf: []u8) ?[]const u8 {
    if (s.len > buf.len) return null;
    for (s, 0..) |ch, i| {
        buf[i] = std.ascii.toLower(ch);
    }
    return buf[0..s.len];
}
