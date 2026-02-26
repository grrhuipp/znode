const std = @import("std");
const log = @import("../core/log.zig");
const config_mod = @import("../core/config.zig");
const user_store_mod = @import("../core/user_store.zig");
const trojan = @import("../protocol/trojan/trojan_protocol.zig");
const api_client_mod = @import("api_client.zig");
const traffic_collector_mod = @import("traffic_collector.zig");

/// Panel manager: runs on a dedicated thread, coordinates user sync,
/// traffic reporting, and heartbeat with the V2Board panel server.
///
/// On start, fetches ServerNodeInfo from the panel API to get runtime
/// protocol settings (port, transport, ws path, etc.).
///
/// Includes circuit breaker with exponential backoff to protect against
/// panel API failures causing request storms.
pub const PanelManager = struct {
    allocator: std.mem.Allocator,
    client: api_client_mod.ApiClient,
    store: *user_store_mod.UserStore,
    collector: *traffic_collector_mod.TrafficCollector,
    logger: log.ScopedLogger,
    protocol: config_mod.Protocol,
    name_buf: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    last_sync_count: usize = std.math.maxInt(usize),

    // Server node info fetched from panel API
    server_info: ?api_client_mod.ServerNodeInfo = null,

    // Intervals (set from ServerNodeInfo after fetchServerInfo)
    sync_interval_ns: u64 = 60 * std.time.ns_per_s,
    report_interval_ns: u64 = 60 * std.time.ns_per_s,

    // Thread control
    thread: ?std.Thread = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    // Stats
    sync_count: u64 = 0,
    sync_errors: u64 = 0,
    report_count: u64 = 0,
    report_errors: u64 = 0,

    // Circuit breaker state
    consecutive_failures: u32 = 0,
    backoff_until_ns: i128 = 0,

    /// Max consecutive failures before entering degraded mode (5-min interval).
    const max_failures_degraded: u32 = 10;
    /// Failures threshold to start exponential backoff.
    const backoff_threshold: u32 = 3;
    /// Base backoff duration in nanoseconds (5 seconds).
    const base_backoff_ns: u64 = 5 * std.time.ns_per_s;
    /// Maximum backoff duration in nanoseconds (5 minutes).
    const max_backoff_ns: u64 = 300 * std.time.ns_per_s;

    pub fn init(
        allocator: std.mem.Allocator,
        node_config: config_mod.NodeConfig,
        store: *user_store_mod.UserStore,
        collector: *traffic_collector_mod.TrafficCollector,
    ) PanelManager {
        var pm = PanelManager{
            .allocator = allocator,
            .client = api_client_mod.ApiClient.init(
                allocator,
                node_config.getApiUrl(),
                node_config.getApiKey(),
                node_config.node_id,
                node_config.getNodeTypeStr(),
            ),
            .store = store,
            .collector = collector,
            .logger = log.ScopedLogger.init(0, "panel"),
            .protocol = node_config.protocol,
        };
        pm.logger.to_app = true;
        const name = node_config.getName();
        const nn: u8 = @intCast(@min(name.len, pm.name_buf.len));
        @memcpy(pm.name_buf[0..nn], name[0..nn]);
        pm.name_len = nn;
        return pm;
    }

    pub fn getName(self: *const PanelManager) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn deinit(self: *PanelManager) void {
        self.client.deinit();
    }

    /// Fetch server node info from panel API (port, transport, ws settings).
    /// Should be called before start() to get the listen port.
    pub fn fetchServerInfo(self: *PanelManager) !api_client_mod.ServerNodeInfo {
        const info = try self.client.fetchNodeConfig(self.protocol);
        self.server_info = info;
        // Update intervals from panel API response
        self.sync_interval_ns = @as(u64, info.sync_interval) * std.time.ns_per_s;
        self.report_interval_ns = @as(u64, info.report_interval) * std.time.ns_per_s;
        return info;
    }

    /// Get the cached server node info (after fetchServerInfo).
    pub fn getServerInfo(self: *const PanelManager) ?api_client_mod.ServerNodeInfo {
        return self.server_info;
    }

    /// Perform initial user sync (blocking). Call before start().
    /// Returns the number of users loaded, or error if sync fails.
    pub fn syncUsersBlocking(self: *PanelManager) !usize {
        const panel_users = try self.client.fetchUsers();
        defer self.allocator.free(panel_users);

        const user_infos = try convertPanelUsers(self.allocator, panel_users);
        defer self.allocator.free(user_infos);

        try self.store.update(user_infos);
        self.logger.info("{s}: initial user sync: {d} users loaded", .{ self.getName(), panel_users.len });
        return panel_users.len;
    }

    /// Start the panel manager thread.
    pub fn start(self: *PanelManager) !void {
        self.running.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, PanelManager.run, .{self});
    }

    /// Signal the panel manager to stop.
    pub fn stop(self: *PanelManager) void {
        self.running.store(false, .release);
    }

    /// Wait for the panel thread to finish.
    pub fn join(self: *PanelManager) void {
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    // ── Circuit breaker ──

    /// Calculate backoff duration based on consecutive failure count.
    pub fn calcBackoffNs(failures: u32) u64 {
        if (failures < backoff_threshold) return 0;
        const exp = @min(failures - backoff_threshold, 20);
        const backoff = base_backoff_ns *| (@as(u64, 1) << @intCast(exp));
        return @min(backoff, max_backoff_ns);
    }

    /// Check if the circuit breaker allows a request right now.
    fn shouldSkipRequest(self: *PanelManager, now: i128) bool {
        if (self.consecutive_failures < backoff_threshold) return false;
        if (now < self.backoff_until_ns) {
            return true;
        }
        return false;
    }

    /// Record a successful API call — resets the circuit breaker.
    fn recordSuccess(self: *PanelManager) void {
        if (self.consecutive_failures > 0) {
            self.logger.info("{s}: panel API recovered after {d} failures", .{ self.getName(), self.consecutive_failures });
        }
        self.consecutive_failures = 0;
        self.backoff_until_ns = 0;
    }

    /// Record a failed API call — increments failure count and sets backoff.
    fn recordFailure(self: *PanelManager, now: i128) void {
        self.consecutive_failures += 1;
        const backoff = calcBackoffNs(self.consecutive_failures);
        if (backoff > 0) {
            self.backoff_until_ns = now + @as(i128, backoff);
            self.logger.warn("{s}: backoff {d}s after {d} consecutive failures", .{
                self.getName(),
                backoff / std.time.ns_per_s,
                self.consecutive_failures,
            });
        }
    }

    // ── Thread entry point ──

    fn run(self: *PanelManager) void {
        self.logger.info("{s}: panel started (sync={d}s, report={d}s)", .{
            self.getName(),
            self.sync_interval_ns / std.time.ns_per_s,
            self.report_interval_ns / std.time.ns_per_s,
        });

        // Initial sync immediately
        self.doSyncUsers();
        self.doHeartbeat();

        var last_sync: i128 = std.time.nanoTimestamp();
        var last_report: i128 = last_sync;
        var last_heartbeat: i128 = last_sync;

        const sleep_ns: u64 = 5 * std.time.ns_per_s;

        while (self.running.load(.acquire)) {
            std.Thread.sleep(sleep_ns);

            const now: i128 = std.time.nanoTimestamp();

            // In degraded mode, slow down to every 5 minutes
            const effective_sync_interval: i128 = if (self.consecutive_failures >= max_failures_degraded)
                @as(i128, max_backoff_ns)
            else
                @as(i128, self.sync_interval_ns);

            const effective_report_interval: i128 = if (self.consecutive_failures >= max_failures_degraded)
                @as(i128, max_backoff_ns)
            else
                @as(i128, self.report_interval_ns);

            if (now - last_sync >= effective_sync_interval) {
                self.doSyncUsers();
                last_sync = now;
            }

            if (now - last_report >= effective_report_interval) {
                self.doReportTraffic();
                last_report = now;
            }

            if (now - last_heartbeat >= effective_report_interval) {
                self.doHeartbeat();
                last_heartbeat = now;
            }
        }

        // Final traffic report before exit
        self.doReportTraffic();
        self.logger.info("{s}: panel stopped (syncs={d}, reports={d}, errors={d}/{d})", .{
            self.getName(),
            self.sync_count,
            self.report_count,
            self.sync_errors,
            self.report_errors,
        });
    }

    // ── Core operations ──

    fn doSyncUsers(self: *PanelManager) void {
        const now: i128 = std.time.nanoTimestamp();
        if (self.shouldSkipRequest(now)) return;

        const panel_users = self.client.fetchUsers() catch |e| {
            self.sync_errors += 1;
            self.recordFailure(now);
            self.logger.err("{s}: user sync failed: {}", .{ self.getName(), e });
            return;
        };
        defer self.allocator.free(panel_users);

        // Convert PanelUser -> UserStore.UserInfo
        const user_infos = convertPanelUsers(self.allocator, panel_users) catch {
            self.logger.err("user sync: OOM converting users", .{});
            return;
        };
        defer self.allocator.free(user_infos);

        // Atomic update
        self.store.update(user_infos) catch |e| {
            self.logger.err("user store update failed: {}", .{e});
            return;
        };

        self.recordSuccess();
        self.sync_count += 1;
        // Only log when user count changes to avoid repeating identical lines
        if (panel_users.len != self.last_sync_count) {
            self.last_sync_count = panel_users.len;
            const pname = self.getName();
            if (pname.len > 0) {
                self.logger.info("{s}: user sync ok: {d} users", .{ pname, panel_users.len });
            } else {
                self.logger.info("user sync ok: {d} users", .{panel_users.len});
            }
        }
    }

    fn doReportTraffic(self: *PanelManager) void {
        const now: i128 = std.time.nanoTimestamp();
        if (self.shouldSkipRequest(now)) {
            // Don't collect — leave data in collector so it's not lost during backoff
            self.logger.warn("{s}: traffic report deferred: backoff active ({d} users buffered)", .{ self.getName(), self.collector.pendingCount() });
            return;
        }

        const traffic = self.collector.swapAndCollect(self.allocator) catch |e| {
            self.logger.err("traffic collect failed: {}", .{e});
            return;
        };
        defer self.allocator.free(traffic);

        if (traffic.len == 0) return;

        self.client.pushTraffic(traffic) catch |e| {
            self.report_errors += 1;
            self.recordFailure(now);
            self.logger.err("{s}: traffic report failed ({d} users): {}", .{ self.getName(), traffic.len, e });
            return;
        };

        self.recordSuccess();
        self.report_count += 1;
        self.logger.info("{s}: traffic reported: {d} users", .{ self.getName(), traffic.len });
    }

    fn doHeartbeat(self: *PanelManager) void {
        const now: i128 = std.time.nanoTimestamp();
        if (self.shouldSkipRequest(now)) return;

        self.client.sendHeartbeat() catch |e| {
            self.recordFailure(now);
            self.logger.warn("{s}: heartbeat failed: {}", .{ self.getName(), e });
        };
    }
};

/// Convert PanelUser array to UserStore.UserInfo array.
/// Generates Trojan password hashes from UUID strings.
pub fn convertPanelUsers(
    allocator: std.mem.Allocator,
    panel_users: []const api_client_mod.PanelUser,
) ![]user_store_mod.UserStore.UserInfo {
    var infos = try allocator.alloc(user_store_mod.UserStore.UserInfo, panel_users.len);
    errdefer allocator.free(infos);

    for (panel_users, 0..) |pu, i| {
        infos[i] = .{
            .id = pu.id,
            .uuid = pu.uuid,
            .rate_limit = pu.speed_limit,
            .device_limit = pu.device_limit,
            .enabled = true,
        };
        // Copy email from panel user
        infos[i].setEmail(pu.getEmail());

        // Generate Trojan password hash: SHA224(uuid_hex_string)
        // V2Board uses the UUID string as Trojan password
        const uuid_str = api_client_mod.formatUuid(pu.uuid);
        infos[i].password_hash = trojan.hashPassword(&uuid_str);
    }

    return infos;
}

// ── Tests ──

const testing = std.testing;

test "PanelManager init and deinit" {
    const allocator = testing.allocator;
    var store = user_store_mod.UserStore.init(allocator);
    defer store.deinit();
    var collector = traffic_collector_mod.TrafficCollector.init(allocator);
    defer collector.deinit();

    var node_config = config_mod.NodeConfig{
        .node_id = 1,
    };
    node_config.setApiUrl("https://panel.example.com");
    node_config.setApiKey("test_key");

    var pm = PanelManager.init(allocator, node_config, &store, &collector);
    defer pm.deinit();

    // Default intervals before fetchServerInfo
    try testing.expectEqual(@as(u64, 60 * std.time.ns_per_s), pm.sync_interval_ns);
    try testing.expectEqual(@as(u64, 60 * std.time.ns_per_s), pm.report_interval_ns);
    try testing.expectEqual(@as(u64, 0), pm.sync_count);
    try testing.expectEqual(@as(u64, 0), pm.report_count);
    try testing.expectEqual(@as(u32, 0), pm.consecutive_failures);
    try testing.expectEqual(@as(i128, 0), pm.backoff_until_ns);
    try testing.expect(pm.server_info == null);
}

test "calcBackoffNs exponential backoff" {
    // Below threshold: no backoff
    try testing.expectEqual(@as(u64, 0), PanelManager.calcBackoffNs(0));
    try testing.expectEqual(@as(u64, 0), PanelManager.calcBackoffNs(1));
    try testing.expectEqual(@as(u64, 0), PanelManager.calcBackoffNs(2));

    // At threshold: base backoff (5s)
    try testing.expectEqual(5 * std.time.ns_per_s, PanelManager.calcBackoffNs(3));

    // Exponential: 10s, 20s, 40s ...
    try testing.expectEqual(10 * std.time.ns_per_s, PanelManager.calcBackoffNs(4));
    try testing.expectEqual(20 * std.time.ns_per_s, PanelManager.calcBackoffNs(5));
    try testing.expectEqual(40 * std.time.ns_per_s, PanelManager.calcBackoffNs(6));

    // Capped at max (300s)
    try testing.expectEqual(300 * std.time.ns_per_s, PanelManager.calcBackoffNs(20));
    try testing.expectEqual(300 * std.time.ns_per_s, PanelManager.calcBackoffNs(100));
}

test "PanelManager circuit breaker state" {
    const allocator = testing.allocator;
    var store = user_store_mod.UserStore.init(allocator);
    defer store.deinit();
    var collector = traffic_collector_mod.TrafficCollector.init(allocator);
    defer collector.deinit();

    var pm = PanelManager.init(allocator, .{}, &store, &collector);
    defer pm.deinit();

    // Initially: no skip
    try testing.expect(!pm.shouldSkipRequest(1000));

    // Simulate failures below threshold
    pm.recordFailure(1000);
    pm.recordFailure(2000);
    try testing.expectEqual(@as(u32, 2), pm.consecutive_failures);
    try testing.expect(!pm.shouldSkipRequest(3000)); // still below threshold

    // Third failure triggers backoff
    pm.recordFailure(3000);
    try testing.expectEqual(@as(u32, 3), pm.consecutive_failures);
    try testing.expect(pm.backoff_until_ns > 3000);

    // During backoff window: skip
    try testing.expect(pm.shouldSkipRequest(3000 + 1));

    // After backoff expires: allow
    try testing.expect(!pm.shouldSkipRequest(pm.backoff_until_ns + 1));

    // Success resets everything
    pm.recordSuccess();
    try testing.expectEqual(@as(u32, 0), pm.consecutive_failures);
    try testing.expectEqual(@as(i128, 0), pm.backoff_until_ns);
}

test "convertPanelUsers generates correct UserInfo" {
    const allocator = testing.allocator;
    const uuid = api_client_mod.parseUuid("550e8400-e29b-41d4-a716-446655440000").?;

    const panel_users = [_]api_client_mod.PanelUser{
        .{
            .id = 42,
            .uuid = uuid,
            .uuid_valid = true,
            .speed_limit = 12500000, // 100 Mbps in bytes/sec
            .device_limit = 3,
        },
    };

    const infos = try convertPanelUsers(allocator, &panel_users);
    defer allocator.free(infos);

    try testing.expectEqual(@as(usize, 1), infos.len);
    try testing.expectEqual(@as(i64, 42), infos[0].id);
    try testing.expectEqual(uuid, infos[0].uuid);
    try testing.expectEqual(@as(u64, 12500000), infos[0].rate_limit);
    try testing.expectEqual(@as(u32, 3), infos[0].device_limit);
    try testing.expect(infos[0].enabled);

    // Verify password hash is valid SHA224 hex (56 chars)
    for (infos[0].password_hash) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "convertPanelUsers password hash matches trojan hashPassword" {
    const allocator = testing.allocator;
    const uuid = api_client_mod.parseUuid("6ba7b810-9dad-11d1-80b4-00c04fd430c8").?;
    const uuid_str = api_client_mod.formatUuid(uuid);
    const expected_hash = trojan.hashPassword(&uuid_str);

    const panel_users = [_]api_client_mod.PanelUser{
        .{ .id = 1, .uuid = uuid, .uuid_valid = true },
    };
    const infos = try convertPanelUsers(allocator, &panel_users);
    defer allocator.free(infos);

    try testing.expectEqual(expected_hash, infos[0].password_hash);
}

test "convertPanelUsers empty input" {
    const allocator = testing.allocator;
    const infos = try convertPanelUsers(allocator, &.{});
    defer allocator.free(infos);
    try testing.expectEqual(@as(usize, 0), infos.len);
}

test "PanelManager running flag" {
    const allocator = testing.allocator;
    var store = user_store_mod.UserStore.init(allocator);
    defer store.deinit();
    var collector = traffic_collector_mod.TrafficCollector.init(allocator);
    defer collector.deinit();

    var pm = PanelManager.init(allocator, .{}, &store, &collector);
    defer pm.deinit();

    try testing.expect(!pm.running.load(.acquire));
    pm.running.store(true, .release);
    try testing.expect(pm.running.load(.acquire));
    pm.stop();
    try testing.expect(!pm.running.load(.acquire));
}
