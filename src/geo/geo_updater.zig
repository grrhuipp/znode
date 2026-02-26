const std = @import("std");
const log = @import("../core/log.zig");
const config_mod = @import("../core/config.zig");
const geoip_mod = @import("geoip.zig");
const geosite_mod = @import("geosite.zig");

/// Manages automatic downloading and periodic updating of GeoIP/GeoSite databases.
pub const GeoUpdater = struct {
    allocator: std.mem.Allocator,
    geoip: *geoip_mod.GeoIP,
    geosite: *geosite_mod.GeoSite,

    // Resolved absolute paths
    geoip_path_buf: [512]u8 = [_]u8{0} ** 512,
    geoip_path_len: u16 = 0,
    geosite_path_buf: [512]u8 = [_]u8{0} ** 512,
    geosite_path_len: u16 = 0,

    // Download URLs
    geoip_url: []const u8 = config_mod.default_geoip_url,
    geosite_url: []const u8 = config_mod.default_geosite_url,

    // Lazy loading: only load databases referenced by routing rules
    need_geoip: bool = true,
    need_geosite: bool = true,

    // Update control
    update_interval_ns: u64 = 24 * std.time.ns_per_hour,
    thread: ?std.Thread = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    logger: log.ScopedLogger = log.ScopedLogger.init(0, "geo"),

    pub fn init(allocator: std.mem.Allocator, config: *const config_mod.Config, geoip: *geoip_mod.GeoIP, geosite: *geosite_mod.GeoSite) GeoUpdater {
        var self = GeoUpdater{
            .allocator = allocator,
            .geoip = geoip,
            .geosite = geosite,
        };

        // Resolve geoip path (relative to config dir)
        self.resolvePath(&self.geoip_path_buf, &self.geoip_path_len, config.getConfigDir(), config.getGeoipPath());
        self.resolvePath(&self.geosite_path_buf, &self.geosite_path_len, config.getConfigDir(), config.getGeositePath());

        // URLs
        self.geoip_url = config.getGeoipUrl();
        self.geosite_url = config.getGeositeUrl();

        // Update interval
        self.update_interval_ns = @as(u64, config.geo_update_interval) * std.time.ns_per_hour;

        return self;
    }

    fn resolvePath(self: *GeoUpdater, buf: *[512]u8, len: *u16, config_dir: []const u8, relative: []const u8) void {
        _ = self;
        if (std.fs.path.isAbsolute(relative) or config_dir.len == 0) {
            const n: u16 = @intCast(@min(relative.len, buf.len));
            @memcpy(buf[0..n], relative[0..n]);
            len.* = n;
        } else {
            const result = std.fmt.bufPrint(buf, "{s}/{s}", .{ config_dir, relative }) catch {
                // Fallback: just use relative path
                const n: u16 = @intCast(@min(relative.len, buf.len));
                @memcpy(buf[0..n], relative[0..n]);
                len.* = n;
                return;
            };
            len.* = @intCast(result.len);
        }
    }

    fn getGeoipPath(self: *const GeoUpdater) []const u8 {
        return self.geoip_path_buf[0..self.geoip_path_len];
    }

    fn getGeositePath(self: *const GeoUpdater) []const u8 {
        return self.geosite_path_buf[0..self.geosite_path_len];
    }

    /// Scan route rules to determine which geo databases are actually needed.
    pub fn detectNeeded(self: *GeoUpdater, routes: []const config_mod.RouteEntry) void {
        var ip = false;
        var site = false;
        for (routes) |entry| {
            for (entry.rules) |rule| {
                if (rule.len > 6 and std.mem.startsWith(u8, rule, "geoip:")) ip = true;
                if (rule.len > 8 and std.mem.startsWith(u8, rule, "geosite:")) site = true;
                if (ip and site) break;
            }
            if (ip and site) break;
        }
        self.need_geoip = ip;
        self.need_geosite = site;
        if (!ip) self.logger.info("geoip: skipped (no geoip: rules)", .{});
        if (!site) self.logger.info("geosite: skipped (no geosite: rules)", .{});
    }

    /// Ensure geo database files exist (download if missing) and load them.
    /// Only loads databases flagged as needed by detectNeeded().
    pub fn ensureAndLoad(self: *GeoUpdater) void {
        if (self.need_geoip) {
            self.ensureFile(self.getGeoipPath(), self.geoip_url, "geoip");
            self.loadGeoip();
        }
        if (self.need_geosite) {
            self.ensureFile(self.getGeositePath(), self.geosite_url, "geosite");
            self.loadGeosite();
        }
    }

    fn ensureFile(self: *GeoUpdater, path: []const u8, url: []const u8, name: []const u8) void {
        // Check if file exists
        std.fs.cwd().access(path, .{}) catch {
            // File doesn't exist, download it
            self.logger.info("{s}: not found at {s}, downloading...", .{ name, path });
            self.downloadFile(url, path, name);
            return;
        };
        self.logger.info("{s}: found at {s}", .{ name, path });
    }

    fn loadGeoip(self: *GeoUpdater) void {
        self.geoip.loadFromFile(self.getGeoipPath()) catch |e| {
            self.logger.warn("geoip: failed to load {s}: {s}", .{ self.getGeoipPath(), @errorName(e) });
            return;
        };
        self.logger.info("geoip: loaded {d} IPv4 + {d} IPv6 entries, {d} countries", .{
            self.geoip.entries_v4.len,
            self.geoip.entries_v6.len,
            self.geoip.country_codes.len,
        });
    }

    fn loadGeosite(self: *GeoUpdater) void {
        self.geosite.loadFromFile(self.getGeositePath()) catch |e| {
            self.logger.warn("geosite: failed to load {s}: {s}", .{ self.getGeositePath(), @errorName(e) });
            return;
        };
        self.logger.info("geosite: loaded {d} tags", .{self.geosite.tags.len});
    }

    fn downloadFile(self: *GeoUpdater, url: []const u8, dest_path: []const u8, name: []const u8) void {
        // Stream HTTP response directly to temp file (no memory buffering)
        var tmp_buf: [516]u8 = undefined;
        const tmp_path = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{dest_path}) catch return;

        const tmp_file = std.fs.cwd().createFile(tmp_path, .{}) catch |e| {
            self.logger.err("{s}: failed to create temp file {s}: {s}", .{ name, tmp_path, @errorName(e) });
            return;
        };

        var file_buf: [8192]u8 = undefined;
        var fw = tmp_file.writerStreaming(&file_buf);

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .response_writer = &fw.interface,
        }) catch |e| {
            self.logger.err("{s}: download failed: {s} url={s}", .{ name, @errorName(e), url });
            tmp_file.close();
            std.fs.cwd().deleteFile(tmp_path) catch {};
            return;
        };

        // Flush remaining buffered data to file
        fw.interface.flush() catch {
            self.logger.err("{s}: failed to flush temp file", .{name});
            tmp_file.close();
            std.fs.cwd().deleteFile(tmp_path) catch {};
            return;
        };

        const file_size = tmp_file.getEndPos() catch 0;
        tmp_file.close();

        if (result.status != .ok) {
            self.logger.err("{s}: download HTTP {d} url={s}", .{ name, @intFromEnum(result.status), url });
            std.fs.cwd().deleteFile(tmp_path) catch {};
            return;
        }

        if (file_size == 0) {
            self.logger.err("{s}: download returned empty body", .{name});
            std.fs.cwd().deleteFile(tmp_path) catch {};
            return;
        }

        // Atomic rename
        std.fs.cwd().rename(tmp_path, dest_path) catch |e| {
            // rename may fail on Windows if dest exists; try delete + rename
            std.fs.cwd().deleteFile(dest_path) catch {};
            std.fs.cwd().rename(tmp_path, dest_path) catch |e2| {
                self.logger.err("{s}: rename failed: {s} (first: {s})", .{ name, @errorName(e2), @errorName(e) });
                std.fs.cwd().deleteFile(tmp_path) catch {};
                return;
            };
        };

        self.logger.info("{s}: downloaded {d} bytes to {s}", .{ name, file_size, dest_path });
    }

    /// Start background update thread.
    pub fn start(self: *GeoUpdater) !void {
        if (self.update_interval_ns == 0) return;
        self.running.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, updateLoop, .{self});
    }

    /// Stop background update thread.
    pub fn stop(self: *GeoUpdater) void {
        self.running.store(false, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn updateLoop(self: *GeoUpdater) void {
        while (self.running.load(.acquire)) {
            // Sleep in small increments to allow quick shutdown
            var remaining = self.update_interval_ns;
            const check_interval: u64 = 5 * std.time.ns_per_s; // check every 5s
            while (remaining > 0 and self.running.load(.acquire)) {
                const sleep_time = @min(remaining, check_interval);
                std.Thread.sleep(sleep_time);
                remaining -|= sleep_time;
            }

            if (!self.running.load(.acquire)) break;

            self.logger.info("geo: starting periodic update", .{});
            self.doUpdate();
        }
    }

    fn doUpdate(self: *GeoUpdater) void {
        // Download and reload only needed databases.
        // Note: brief inconsistency window is acceptable for geo data (updates every 24h,
        // queries are per-connection and don't hold references across calls)
        if (self.need_geoip) {
            self.downloadFile(self.geoip_url, self.getGeoipPath(), "geoip");
            self.geoip.deinit();
            self.geoip.* = geoip_mod.GeoIP.init(self.allocator);
            self.loadGeoip();
        }

        if (self.need_geosite) {
            self.downloadFile(self.geosite_url, self.getGeositePath(), "geosite");
            self.geosite.deinit();
            self.geosite.* = geosite_mod.GeoSite.init(self.allocator);
            self.loadGeosite();
        }
    }

    pub fn deinit(self: *GeoUpdater) void {
        self.stop();
    }
};

// ── Tests ──

test "GeoUpdater resolvePath absolute" {
    var updater = GeoUpdater{
        .allocator = std.testing.allocator,
        .geoip = undefined,
        .geosite = undefined,
    };
    var buf: [512]u8 = [_]u8{0} ** 512;
    var len: u16 = 0;

    // Absolute path stays absolute
    if (comptime @import("builtin").os.tag == .windows) {
        updater.resolvePath(&buf, &len, "C:\\config", "C:\\data\\geoip.dat");
        try std.testing.expectEqualStrings("C:\\data\\geoip.dat", buf[0..len]);
    } else {
        updater.resolvePath(&buf, &len, "/etc/znode", "/data/geoip.dat");
        try std.testing.expectEqualStrings("/data/geoip.dat", buf[0..len]);
    }
}

test "GeoUpdater resolvePath relative" {
    var updater = GeoUpdater{
        .allocator = std.testing.allocator,
        .geoip = undefined,
        .geosite = undefined,
    };
    var buf: [512]u8 = [_]u8{0} ** 512;
    var len: u16 = 0;

    updater.resolvePath(&buf, &len, "config", "geoip.dat");
    try std.testing.expectEqualStrings("config/geoip.dat", buf[0..len]);
}

test "GeoUpdater resolvePath empty dir" {
    var updater = GeoUpdater{
        .allocator = std.testing.allocator,
        .geoip = undefined,
        .geosite = undefined,
    };
    var buf: [512]u8 = [_]u8{0} ** 512;
    var len: u16 = 0;

    updater.resolvePath(&buf, &len, "", "geoip.dat");
    try std.testing.expectEqualStrings("geoip.dat", buf[0..len]);
}
