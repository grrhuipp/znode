const std = @import("std");
const protobuf = @import("protobuf_lite.zig");

/// GeoIP database for IP-to-country lookups.
/// Parses V2Ray/Xray geoip.dat protobuf format.
pub const GeoIP = struct {
    /// Sorted CIDR entries for binary search.
    entries_v4: []CidrEntry = &.{},
    entries_v6: []CidrEntryV6 = &.{},
    country_codes: [][]const u8 = &.{},
    allocator: std.mem.Allocator,

    pub const CidrEntry = struct {
        ip: u32, // network address in host byte order
        mask: u32, // bitmask
        country_idx: u16,
    };

    pub const CidrEntryV6 = struct {
        ip: [16]u8,
        prefix_len: u8,
        country_idx: u16,
    };

    pub fn init(allocator: std.mem.Allocator) GeoIP {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *GeoIP) void {
        if (self.entries_v4.len > 0) self.allocator.free(self.entries_v4);
        if (self.entries_v6.len > 0) self.allocator.free(self.entries_v6);
        for (self.country_codes) |cc| {
            self.allocator.free(cc);
        }
        if (self.country_codes.len > 0) self.allocator.free(self.country_codes);
    }

    /// Load from geoip.dat file.
    /// Uses a temporary arena for the raw file data — the protobuf bytes are
    /// only needed during parse() and freed as one block afterward, avoiding
    /// allocator fragmentation from a large alloc+free cycle.
    pub fn loadFromFile(self: *GeoIP, path: []const u8) !void {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const data = try file.readToEndAlloc(arena.allocator(), 64 * 1024 * 1024);
        try self.parse(data);
    }

    /// Helper: free all owned country code strings and deinit cc_list.
    fn freeCcList(allocator: std.mem.Allocator, cc_list: *std.ArrayList([]const u8)) void {
        for (cc_list.items) |cc| allocator.free(cc);
        cc_list.deinit(allocator);
    }

    /// Parse geoip.dat protobuf data.
    /// Format: repeated GeoIP { string country_code = 1; repeated CIDR cidr = 2; }
    /// CIDR: { bytes ip = 1; int32 prefix = 2; }
    pub fn parse(self: *GeoIP, data: []const u8) !void {
        var v4_list: std.ArrayList(CidrEntry) = .{};
        errdefer v4_list.deinit(self.allocator);
        var v6_list: std.ArrayList(CidrEntryV6) = .{};
        errdefer v6_list.deinit(self.allocator);
        var cc_list: std.ArrayList([]const u8) = .{};
        errdefer freeCcList(self.allocator, &cc_list);

        var reader = protobuf.ProtobufReader.init(data);
        while (!reader.isEof()) {
            const tag = reader.readTag() catch break;
            if (tag.field_number == 1 and tag.wire_type == protobuf.ProtobufReader.Tag.LENGTH_DELIMITED) {
                // GeoIP entry
                var sub = reader.subReader() catch break;
                var country_code: []const u8 = "";
                const country_idx: u16 = @intCast(cc_list.items.len);

                while (!sub.isEof()) {
                    const ftag = sub.readTag() catch break;
                    if (ftag.field_number == 1 and ftag.wire_type == protobuf.ProtobufReader.Tag.LENGTH_DELIMITED) {
                        country_code = sub.readBytes() catch break;
                    } else if (ftag.field_number == 2 and ftag.wire_type == protobuf.ProtobufReader.Tag.LENGTH_DELIMITED) {
                        // CIDR entry
                        var cidr_reader = sub.subReader() catch break;
                        var ip_bytes: []const u8 = "";
                        var prefix: u32 = 0;

                        while (!cidr_reader.isEof()) {
                            const ctag = cidr_reader.readTag() catch break;
                            if (ctag.field_number == 1 and ctag.wire_type == protobuf.ProtobufReader.Tag.LENGTH_DELIMITED) {
                                ip_bytes = cidr_reader.readBytes() catch break;
                            } else if (ctag.field_number == 2 and ctag.wire_type == protobuf.ProtobufReader.Tag.VARINT) {
                                prefix = cidr_reader.readVarintU32() catch break;
                            } else {
                                cidr_reader.skipField(ctag.wire_type) catch break;
                            }
                        }

                        if (ip_bytes.len == 4) {
                            const ip = (@as(u32, ip_bytes[0]) << 24) |
                                (@as(u32, ip_bytes[1]) << 16) |
                                (@as(u32, ip_bytes[2]) << 8) |
                                ip_bytes[3];
                            const mask = if (prefix >= 32) 0xFFFFFFFF else ~(@as(u32, 0xFFFFFFFF) >> @intCast(prefix));
                            v4_list.append(self.allocator, .{
                                .ip = ip & mask,
                                .mask = mask,
                                .country_idx = country_idx,
                            }) catch return error.OutOfMemory;
                        } else if (ip_bytes.len == 16) {
                            v6_list.append(self.allocator, .{
                                .ip = ip_bytes[0..16].*,
                                .prefix_len = @intCast(@min(prefix, 128)),
                                .country_idx = country_idx,
                            }) catch return error.OutOfMemory;
                        }
                    } else {
                        sub.skipField(ftag.wire_type) catch break;
                    }
                }

                if (country_code.len > 0) {
                    const owned_cc = self.allocator.dupe(u8, country_code) catch return error.OutOfMemory;
                    cc_list.append(self.allocator, owned_cc) catch {
                        self.allocator.free(owned_cc);
                        return error.OutOfMemory;
                    };
                }
            } else {
                reader.skipField(tag.wire_type) catch break;
            }
        }

        self.entries_v4 = v4_list.toOwnedSlice(self.allocator) catch return error.OutOfMemory;
        self.entries_v6 = v6_list.toOwnedSlice(self.allocator) catch return error.OutOfMemory;
        self.country_codes = cc_list.toOwnedSlice(self.allocator) catch return error.OutOfMemory;

        // Sort v4 entries by IP for binary search
        std.mem.sort(CidrEntry, self.entries_v4, {}, struct {
            fn lessThan(_: void, a: CidrEntry, b: CidrEntry) bool {
                return a.ip < b.ip;
            }
        }.lessThan);
    }

    /// Look up the country code for an IPv4 address.
    pub fn lookupIp4(self: *const GeoIP, ip: [4]u8) ?[]const u8 {
        const ip_val = (@as(u32, ip[0]) << 24) |
            (@as(u32, ip[1]) << 16) |
            (@as(u32, ip[2]) << 8) |
            ip[3];

        // Linear scan (can optimize with sorted search later)
        for (self.entries_v4) |entry| {
            if ((ip_val & entry.mask) == entry.ip) {
                if (entry.country_idx < self.country_codes.len) {
                    return self.country_codes[entry.country_idx];
                }
            }
        }
        return null;
    }

    /// Check if an IPv4 address belongs to a specific country.
    pub fn matchCountryIp4(self: *const GeoIP, ip: [4]u8, country: []const u8) bool {
        const result = self.lookupIp4(ip) orelse return false;
        return std.ascii.eqlIgnoreCase(result, country);
    }

    pub fn countryCount(self: *const GeoIP) usize {
        return self.country_codes.len;
    }

    pub fn entryCount(self: *const GeoIP) usize {
        return self.entries_v4.len + self.entries_v6.len;
    }
};

test "GeoIP empty lookup" {
    const allocator = std.testing.allocator;
    var geoip = GeoIP.init(allocator);
    defer geoip.deinit();
    try std.testing.expectEqual(@as(?[]const u8, null), geoip.lookupIp4(.{ 8, 8, 8, 8 }));
}
