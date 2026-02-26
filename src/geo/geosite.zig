const std = @import("std");
const protobuf = @import("protobuf_lite.zig");

/// GeoSite database for domain-based routing.
/// Parses V2Ray/Xray geosite.dat protobuf format.
///
/// Domain matching types:
///   - exact: full match (e.g., "google.com" matches only "google.com")
///   - suffix: domain suffix match (e.g., "google.com" matches "*.google.com")
///   - keyword: substring match (e.g., "google" matches any domain containing "google")
///   - regex: regex pattern match (stored but uses simple wildcard matching)
pub const GeoSite = struct {
    /// Per-tag domain lists
    tags: []Tag = &.{},
    allocator: std.mem.Allocator,

    pub const DomainType = enum(u8) {
        exact = 0,
        suffix = 1,
        keyword = 2,
        regex = 3,
    };

    pub const Domain = struct {
        value: []const u8,
        dtype: DomainType,
    };

    pub const Tag = struct {
        name: []const u8,
        domains: []Domain,
    };

    pub fn init(allocator: std.mem.Allocator) GeoSite {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *GeoSite) void {
        for (self.tags) |tag| {
            for (tag.domains) |d| {
                self.allocator.free(d.value);
            }
            self.allocator.free(tag.domains);
            self.allocator.free(tag.name);
        }
        if (self.tags.len > 0) self.allocator.free(self.tags);
    }

    /// Load from geosite.dat file.
    /// Uses a temporary arena for the raw file data — the protobuf bytes are
    /// only needed during parse() and freed as one block afterward, avoiding
    /// allocator fragmentation from a large alloc+free cycle.
    pub fn loadFromFile(self: *GeoSite, path: []const u8) !void {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const data = try file.readToEndAlloc(arena.allocator(), 128 * 1024 * 1024);
        try self.parse(data);
    }

    /// Parse geosite.dat protobuf data.
    /// Format: GeoSiteList { repeated GeoSite entry = 1; }
    /// GeoSite: { string country_code = 1; repeated Domain domain = 2; }
    /// Domain: { DomainType type = 1; string value = 2; }
    /// Helper: free all domain values in a domain_list and deinit the list.
    fn freeDomainList(self: *GeoSite, domain_list: *std.ArrayList(Domain)) void {
        for (domain_list.items) |d| {
            self.allocator.free(d.value);
        }
        domain_list.deinit(self.allocator);
    }

    /// Helper: free a domains slice and all its domain values.
    fn freeDomainSlice(self: *GeoSite, domains: []Domain) void {
        for (domains) |d| {
            self.allocator.free(d.value);
        }
        self.allocator.free(domains);
    }

    /// Helper: free all tags in tag_list and deinit the list.
    fn freeTagList(self: *GeoSite, tag_list: *std.ArrayList(Tag)) void {
        for (tag_list.items) |t| {
            self.freeDomainSlice(t.domains);
            self.allocator.free(t.name);
        }
        tag_list.deinit(self.allocator);
    }

    pub fn parse(self: *GeoSite, data: []const u8) !void {
        var tag_list: std.ArrayList(Tag) = .{};
        errdefer self.freeTagList(&tag_list);

        var reader = protobuf.ProtobufReader.init(data);
        while (!reader.isEof()) {
            const tag = reader.readTag() catch break;
            if (tag.field_number == 1 and tag.wire_type == protobuf.ProtobufReader.Tag.LENGTH_DELIMITED) {
                // GeoSite entry
                var sub = reader.subReader() catch break;
                var country_code: []const u8 = "";
                var domain_list: std.ArrayList(Domain) = .{};

                while (!sub.isEof()) {
                    const ftag = sub.readTag() catch break;
                    if (ftag.field_number == 1 and ftag.wire_type == protobuf.ProtobufReader.Tag.LENGTH_DELIMITED) {
                        // country_code
                        country_code = sub.readBytes() catch break;
                    } else if (ftag.field_number == 2 and ftag.wire_type == protobuf.ProtobufReader.Tag.LENGTH_DELIMITED) {
                        // Domain entry
                        var domain_reader = sub.subReader() catch break;
                        var dtype: DomainType = .exact;
                        var value: []const u8 = "";

                        while (!domain_reader.isEof()) {
                            const dtag = domain_reader.readTag() catch break;
                            if (dtag.field_number == 1 and dtag.wire_type == protobuf.ProtobufReader.Tag.VARINT) {
                                const t = domain_reader.readVarintU32() catch break;
                                dtype = switch (t) {
                                    0 => .exact,
                                    1 => .suffix,
                                    2 => .keyword,
                                    3 => .regex,
                                    else => .exact,
                                };
                            } else if (dtag.field_number == 2 and dtag.wire_type == protobuf.ProtobufReader.Tag.LENGTH_DELIMITED) {
                                value = domain_reader.readBytes() catch break;
                            } else {
                                domain_reader.skipField(dtag.wire_type) catch break;
                            }
                        }

                        if (value.len > 0) {
                            const owned_value = self.allocator.dupe(u8, value) catch {
                                self.freeDomainList(&domain_list);
                                return error.OutOfMemory;
                            };
                            domain_list.append(self.allocator, .{
                                .value = owned_value,
                                .dtype = dtype,
                            }) catch {
                                self.allocator.free(owned_value);
                                self.freeDomainList(&domain_list);
                                return error.OutOfMemory;
                            };
                        }
                    } else {
                        sub.skipField(ftag.wire_type) catch break;
                    }
                }

                if (country_code.len > 0 and domain_list.items.len > 0) {
                    const owned_name = self.allocator.dupe(u8, country_code) catch {
                        self.freeDomainList(&domain_list);
                        return error.OutOfMemory;
                    };
                    const domains = domain_list.toOwnedSlice(self.allocator) catch {
                        self.allocator.free(owned_name);
                        self.freeDomainList(&domain_list);
                        return error.OutOfMemory;
                    };
                    tag_list.append(self.allocator, .{
                        .name = owned_name,
                        .domains = domains,
                    }) catch {
                        self.allocator.free(owned_name);
                        self.freeDomainSlice(domains);
                        return error.OutOfMemory;
                    };
                } else {
                    // Clean up unused domains
                    self.freeDomainList(&domain_list);
                }
            } else {
                reader.skipField(tag.wire_type) catch break;
            }
        }

        self.tags = tag_list.toOwnedSlice(self.allocator) catch return error.OutOfMemory;
    }

    /// Check if a domain matches a specific tag (e.g., "cn", "google").
    pub fn matchDomain(self: *const GeoSite, domain: []const u8, tag_name: []const u8) bool {
        for (self.tags) |tag| {
            if (std.ascii.eqlIgnoreCase(tag.name, tag_name)) {
                return matchDomainInList(domain, tag.domains);
            }
        }
        return false;
    }

    /// Find which tag a domain belongs to (returns first match).
    pub fn lookupDomain(self: *const GeoSite, domain: []const u8) ?[]const u8 {
        for (self.tags) |tag| {
            if (matchDomainInList(domain, tag.domains)) {
                return tag.name;
            }
        }
        return null;
    }

    fn matchDomainInList(domain: []const u8, domains: []const Domain) bool {
        for (domains) |d| {
            if (matchSingleDomain(domain, d)) return true;
        }
        return false;
    }

    fn matchSingleDomain(domain: []const u8, rule: Domain) bool {
        return switch (rule.dtype) {
            .exact => std.ascii.eqlIgnoreCase(domain, rule.value),
            .suffix => matchSuffix(domain, rule.value),
            .keyword => containsIgnoreCase(domain, rule.value),
            .regex => simpleWildcardMatch(domain, rule.value),
        };
    }

    /// Suffix match: "google.com" matches "google.com", "www.google.com", "mail.google.com"
    fn matchSuffix(domain: []const u8, suffix: []const u8) bool {
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

    /// Case-insensitive substring search.
    fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
        if (needle.len > haystack.len) return false;
        if (needle.len == 0) return true;
        const end = haystack.len - needle.len + 1;
        for (0..end) |i| {
            if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) {
                return true;
            }
        }
        return false;
    }

    /// Simple wildcard match for regex patterns (supports * and ?).
    /// Full regex is not supported to avoid complexity.
    fn simpleWildcardMatch(str: []const u8, pattern: []const u8) bool {
        var si: usize = 0;
        var pi: usize = 0;
        var star_pi: usize = pattern.len;
        var star_si: usize = 0;

        while (si < str.len) {
            if (pi < pattern.len and (pattern[pi] == '?' or std.ascii.toLower(pattern[pi]) == std.ascii.toLower(str[si]))) {
                si += 1;
                pi += 1;
            } else if (pi < pattern.len and pattern[pi] == '*') {
                star_pi = pi;
                star_si = si;
                pi += 1;
            } else if (star_pi < pattern.len) {
                pi = star_pi + 1;
                star_si += 1;
                si = star_si;
            } else {
                return false;
            }
        }

        while (pi < pattern.len and pattern[pi] == '*') {
            pi += 1;
        }
        return pi == pattern.len;
    }

    pub fn tagCount(self: *const GeoSite) usize {
        return self.tags.len;
    }

    pub fn totalDomains(self: *const GeoSite) usize {
        var total: usize = 0;
        for (self.tags) |tag| {
            total += tag.domains.len;
        }
        return total;
    }
};

test "GeoSite suffix matching" {
    try std.testing.expect(GeoSite.matchSuffix("www.google.com", "google.com"));
    try std.testing.expect(GeoSite.matchSuffix("google.com", "google.com"));
    try std.testing.expect(GeoSite.matchSuffix("mail.google.com", "google.com"));
    try std.testing.expect(!GeoSite.matchSuffix("notgoogle.com", "google.com"));
    try std.testing.expect(!GeoSite.matchSuffix("com", "google.com"));
}

test "GeoSite keyword matching" {
    try std.testing.expect(GeoSite.containsIgnoreCase("www.google.com", "google"));
    try std.testing.expect(GeoSite.containsIgnoreCase("GOOGLE.COM", "google"));
    try std.testing.expect(!GeoSite.containsIgnoreCase("www.example.com", "google"));
}

test "GeoSite wildcard matching" {
    try std.testing.expect(GeoSite.simpleWildcardMatch("www.google.com", "*.google.com"));
    try std.testing.expect(GeoSite.simpleWildcardMatch("test.example.org", "*.example.*"));
    try std.testing.expect(!GeoSite.simpleWildcardMatch("www.google.com", "*.example.com"));
}

test "GeoSite empty lookup" {
    const allocator = std.testing.allocator;
    var geosite = GeoSite.init(allocator);
    defer geosite.deinit();
    try std.testing.expect(!geosite.matchDomain("google.com", "cn"));
    try std.testing.expectEqual(@as(?[]const u8, null), geosite.lookupDomain("google.com"));
}
