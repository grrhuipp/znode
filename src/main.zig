const std = @import("std");
const xev = @import("xev");
const log = @import("core/log.zig");
const config_mod = @import("core/config.zig");
const Worker = @import("core/worker.zig").Worker;
const Dispatcher = @import("core/dispatcher.zig").Dispatcher;
const stats_mod = @import("core/stats.zig");
const api_client_mod = @import("panel/api_client.zig");
const self_signed = @import("transport/self_signed.zig");
const tls_mod = @import("transport/tls_stream.zig");
const tls_init = @import("transport/tls_init.zig");
const user_store_mod = @import("core/user_store.zig");
const traffic_collector_mod = @import("panel/traffic_collector.zig");
const panel_manager_mod = @import("panel/panel_manager.zig");
const dns_resolver_mod = @import("dns/resolver.zig");
const router_mod = @import("router/router.zig");
const geoip_mod = @import("geo/geoip.zig");
const geosite_mod = @import("geo/geosite.zig");
const geo_updater_mod = @import("geo/geo_updater.zig");
const trojan = @import("protocol/trojan/trojan_protocol.zig");
const vmess_hot_cache = @import("protocol/vmess/vmess_hot_cache.zig");
const ss_crypto = @import("protocol/shadowsocks/ss_crypto.zig");

// ── Global allocator (too large for stack on Windows) ──
var gpa = std.heap.GeneralPurposeAllocator(.{}){};

const max_panels = 16;

const PanelState = struct {
    user_store: *user_store_mod.UserStore,
    traffic_collector: *traffic_collector_mod.TrafficCollector,
    panel_mgr: ?*panel_manager_mod.PanelManager,
    tls_ctx: ?*tls_mod.TlsContext,
};

/// Intermediate state for async panel bootstrap (phase 1: network I/O).
const PanelBootstrap = struct {
    // Inputs (set before thread spawn)
    pm: *panel_manager_mod.PanelManager,
    store: *user_store_mod.UserStore,
    tc: *traffic_collector_mod.TrafficCollector,
    entry: *const config_mod.NodeConfig,
    panel_idx: u8,
    hot_cache_ttl: u32 = 0,
    dispatcher: *Dispatcher = undefined,
    allocator: std.mem.Allocator = undefined,

    // Outputs (set by thread)
    server_info: ?api_client_mod.ServerNodeInfo = null,
    user_count: usize = 0,
    fetch_ok: bool = false,

    // Pointer to PanelState entry (retry thread updates tls_ctx on success)
    panel_state: ?*PanelState = null,
};

/// Global retry thread control (single thread retries all failed panels).
var g_retry_running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true);
var g_retry_thread: ?std.Thread = null;

// ── Shutdown signal handling ──

var g_dispatcher: ?*Dispatcher = null;
var g_shutdown_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

fn handleShutdownSignal() void {
    const count = g_shutdown_count.fetchAdd(1, .monotonic);
    if (count >= 1) {
        // Second signal: force exit immediately
        log.info("forced exit", .{});
        std.process.exit(0);
    }
    log.info("shutdown signal received", .{});
    if (g_dispatcher) |d| d.stop();
}

const shutdown_impl = if (@import("builtin").os.tag == .windows) struct {
    const windows = std.os.windows;

    fn ctrlHandler(ctrl_type: windows.DWORD) callconv(.winapi) windows.BOOL {
        // CTRL_C_EVENT = 0, CTRL_CLOSE_EVENT = 2
        if (ctrl_type == 0 or ctrl_type == 2) {
            handleShutdownSignal();
            return 1; // TRUE — handled
        }
        return 0;
    }

    fn register() void {
        _ = windows.kernel32.SetConsoleCtrlHandler(@ptrCast(&ctrlHandler), 1);
    }
} else struct {
    // POSIX signal handling (Linux/macOS)
    fn register() void {
        // On POSIX, the event loop interruption from SIGINT/SIGTERM
        // will cause loop.run() to return. No explicit handler needed
        // beyond the default behavior.
    }
};

pub fn main() void {
    appMain() catch |e| {
        // Print clear error message with error return trace
        std.debug.print("\nFATAL: {s}\n", .{@errorName(e)});
        if (@errorReturnTrace()) |trace| {
            std.debug.print("Error return trace:\n", .{});
            for (trace.instruction_addresses[0..@min(trace.index, trace.instruction_addresses.len)]) |addr| {
                std.debug.print("  0x{x}\n", .{addr});
            }
        }
        log.err("fatal error: {s}", .{@errorName(e)});
    };
}

fn appMain() !void {
    defer {
        const check = gpa.deinit();
        if (check == .leak) log.err("memory leak detected!", .{});
    }
    const allocator = gpa.allocator();

    // Parse command-line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Determine config directory: -d <dir> or default "./config"
    var config_dir: []const u8 = "config";
    {
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "-d") and i + 1 < args.len) {
                config_dir = args[i + 1];
                i += 1;
            }
        }
    }

    // Build config file path: <config_dir>/config.toml
    var config_path_buf: [512]u8 = undefined;
    const config_path = std.fmt.bufPrint(&config_path_buf, "{s}/config.toml", .{config_dir}) catch "config/config.toml";

    // Load configuration (heap-allocated — Config may be large)
    const config = try allocator.create(config_mod.Config);
    defer allocator.destroy(config);
    config.* = config_mod.loadFromFile(allocator, config_path) catch blk: {
        log.warn("failed to load config from '{s}', using defaults", .{config_path});
        break :blk config_mod.Config{};
    };
    defer config.deinit(allocator);

    log.setLevel(config.log_level);
    if (config.log_dir_len > 0) {
        log.init(config.log_dir[0..config.log_dir_len], config.log_max_days, config.log_clean_on_start);
    }
    defer log.shutdown();
    defer tls_init.deinitDynamicCert(allocator);
    log.info("znode proxy server starting", .{});

    const worker_count = config.getWorkerCount();
    log.info("worker count: {d}", .{worker_count});

    // ── Per-panel state tracking ──
    var panel_states: [max_panels]PanelState = undefined;
    var panel_state_count: u8 = 0;
    defer for (panel_states[0..panel_state_count]) |*ps| {
        if (ps.panel_mgr) |pm| {
            pm.stop();
            pm.join(); // Must join before deinit — thread may still be sleeping
            pm.deinit();
            allocator.destroy(pm);
        }
        if (ps.tls_ctx) |ctx| {
            var c = ctx;
            c.deinit();
            allocator.destroy(ctx);
        }
        ps.traffic_collector.deinit();
        allocator.destroy(ps.traffic_collector);
        ps.user_store.deinit();
        allocator.destroy(ps.user_store);
    };

    // ── Standalone listener UserStores (for VMess UUID auth without panel) ──
    var standalone_stores: [config_mod.max_config_listeners]?*user_store_mod.UserStore = [_]?*user_store_mod.UserStore{null} ** config_mod.max_config_listeners;
    defer for (&standalone_stores) |*sp| {
        if (sp.*) |store| {
            store.deinit();
            allocator.destroy(store);
        }
    };

    // Async DNS resolver (shared by all workers, runs on dedicated thread)
    var dns_async = dns_resolver_mod.AsyncResolver.init(
        allocator,
        config.dns.servers,
        config.dns.cache_size,
        config.dns.min_ttl,
        config.dns.max_ttl,
    );
    if (config.dns.route_count > 0) {
        dns_async.dns_routes = config.dns.routes[0..config.dns.route_count];
        log.info("DNS: {d} routing rules configured", .{config.dns.route_count});
    }
    defer dns_async.deinit();
    try dns_async.start();
    // NOTE: dns_async.stop()/join() is done explicitly in the shutdown
    // section below (before workers.deinit) to avoid use-after-free
    // on worker.async_notify. See shutdown comment for details.

    // Create workers (heap-allocated array)
    const workers = try allocator.alloc(Worker, worker_count);
    defer allocator.free(workers);

    // Initialize geo databases (auto-download if missing)
    var geoip = geoip_mod.GeoIP.init(allocator);
    defer geoip.deinit();
    var geosite = geosite_mod.GeoSite.init(allocator);
    defer geosite.deinit();

    var geo_updater = geo_updater_mod.GeoUpdater.init(allocator, config, &geoip, &geosite);
    defer geo_updater.deinit();
    geo_updater.detectNeeded(config.routes);
    geo_updater.ensureAndLoad();

    // Initialize router with geo databases
    const has_geoip = geoip.entries_v4.len > 0 or geoip.entries_v6.len > 0;
    const has_geosite = geosite.tags.len > 0;
    var router = router_mod.Router.init(
        config.routes,
        if (has_geoip) &geoip else null,
        if (has_geosite) &geosite else null,
    );
    if (config.routes.len > 0) {
        log.info("routes: {d} entries", .{config.routes.len});
    }

    // Initialize workers with global shared context
    for (workers, 0..) |*w, i| {
        w.* = try Worker.init(@intCast(i), allocator);
        // Wire batch pointer AFTER Worker is in its final heap location
        w.logger = log.ScopedLogger.withBatch(w.id, "worker", &w.log_batch);
        w.logger.to_app = true;
        w.log_batch.to_app = true;
        w.dns_resolver = &dns_async;
        w.router = &router;
        w.handshake_timeout_ms = config.limits.handshake_timeout_ms;
        w.idle_timeout_ms = config.limits.relay_idle_timeout_ms;
        w.half_close_grace_ms = config.limits.half_close_grace_ms;
    }
    defer {
        // Stop and join workers before deinit in ALL exit paths (including error returns).
        // Without this, an early error return (e.g. from try w.spawn() or try dispatcher.run())
        // causes deinit() to close the epoll fd while the worker thread is still running →
        // epoll_wait returns EBADF → unreachable → panic in ReleaseSafe builds.
        // stop() and join() are idempotent: if the normal shutdown path already called them
        // (lines below), join() finds thread == null and returns immediately.
        for (workers) |*w| w.stop();
        for (workers) |*w| w.join();
        for (workers) |*w| w.deinit();
    }

    // Create dispatcher (heap-allocated — contains xev.Loop which is large on Windows)
    const dispatcher = try allocator.create(Dispatcher);
    defer allocator.destroy(dispatcher);
    try dispatcher.initInPlace(workers, allocator);
    defer dispatcher.deinit();

    // Configure dispatch strategy
    const AffinityTable = @import("core/affinity.zig").AffinityTable;
    dispatcher.strategy = config.limits.dispatch_strategy;
    if (dispatcher.strategy == .ip_hash) {
        dispatcher.affinity = try allocator.create(AffinityTable);
        dispatcher.affinity.?.* = AffinityTable{};
    }
    defer if (dispatcher.affinity) |a| allocator.destroy(a);
    if (dispatcher.strategy == .random) {
        dispatcher.prng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
    }
    log.info("dispatch strategy: {s}", .{@tagName(config.limits.dispatch_strategy)});

    // Register shutdown signal handler
    g_dispatcher = dispatcher;
    shutdown_impl.register();
    defer g_dispatcher = null;

    // ── Panel setup: all HTTP moved to background (prevents startup hang) ──
    var bootstraps: [max_panels]PanelBootstrap = undefined;
    var bootstrap_count: u8 = 0;

    for (config.panel) |*entry| {
        if (bootstrap_count >= max_panels) {
            log.warn("max panels ({d}) reached, skipping remaining", .{max_panels});
            break;
        }
        const idx = bootstrap_count;
        const store = allocator.create(user_store_mod.UserStore) catch {
            log.err("panel[{d}] {s}: OOM creating UserStore", .{ idx, entry.getName() });
            continue;
        };
        store.* = user_store_mod.UserStore.init(allocator);

        const tc = allocator.create(traffic_collector_mod.TrafficCollector) catch {
            log.err("panel[{d}] {s}: OOM creating TrafficCollector", .{ idx, entry.getName() });
            store.deinit();
            allocator.destroy(store);
            continue;
        };
        tc.* = traffic_collector_mod.TrafficCollector.init(allocator);

        const pm = allocator.create(panel_manager_mod.PanelManager) catch {
            log.err("panel[{d}] {s}: OOM creating PanelManager", .{ idx, entry.getName() });
            tc.deinit();
            allocator.destroy(tc);
            store.deinit();
            allocator.destroy(store);
            continue;
        };
        pm.* = panel_manager_mod.PanelManager.init(allocator, entry.*, store, tc);

        bootstraps[idx] = .{
            .pm = pm,
            .store = store,
            .tc = tc,
            .entry = entry,
            .panel_idx = idx,
            .hot_cache_ttl = config.limits.vmess_hot_cache_ttl,
            .dispatcher = dispatcher,
            .allocator = allocator,
        };
        bootstrap_count += 1;

        // All panels deferred to background thread (HTTP has no timeout, would block startup)
        panel_states[panel_state_count] = .{ .user_store = store, .traffic_collector = tc, .panel_mgr = pm, .tls_ctx = null };
        bootstraps[idx].panel_state = &panel_states[panel_state_count];
        panel_state_count += 1;
        log.info("panel[{d}] {s}: queued for background setup", .{ idx, entry.getName() });
    }

    // Background thread handles all panel HTTP (fetch, sync, listen) — first attempt is immediate
    if (bootstrap_count > 0) {
        g_retry_running.store(true, .release);
        g_retry_thread = std.Thread.spawn(.{}, panelRetryLoop, .{bootstraps[0..bootstrap_count]}) catch null;
    }
    defer {
        g_retry_running.store(false, .release);
        if (g_retry_thread) |t| {
            t.join();
            g_retry_thread = null;
        }
    }

    // ── Standalone [[listeners]] mode ──
    if (config.listener_count > 0) {
        for (config.listeners[0..config.listener_count]) |lc| {
            dispatcher.listen(lc.getListenAddr(), lc.port) catch |e| {
                log.err("failed to listen on {s}:{d}: {}", .{ lc.getListenAddr(), lc.port, e });
                continue;
            };

            const lid: u8 = @intCast(dispatcher.listeners.items.len - 1);
            if (lid >= config_mod.max_listeners) {
                log.err("listener {s}:{d}: too many listeners (max {d})", .{ lc.getListenAddr(), lc.port, config_mod.max_listeners });
                continue;
            }
            var info = Worker.ListenerInfo{
                .protocol = lc.protocol,
                .tls_enabled = lc.tls_enabled,
                .sniff_enabled = lc.sniff_enabled,
                .sniff_redirect = lc.sniff_redirect,
            };
            // Format inbound tag
            {
                const proto_str = @tagName(lc.protocol);
                if (lc.name_len > 0) {
                    const tag = std.fmt.bufPrint(&info.tag_buf, "{s}-{s}-{d}", .{ lc.getName(), proto_str, lc.port }) catch "";
                    info.tag_len = @intCast(tag.len);
                } else {
                    const tag = std.fmt.bufPrint(&info.tag_buf, "{s}-{d}", .{ proto_str, lc.port }) catch "";
                    info.tag_len = @intCast(tag.len);
                }
            }
            // Parse send_through address (per-listener)
            if (lc.send_through_len > 0) {
                const st_str = lc.getSendThrough();
                var st_ip4: [4]u8 = undefined;
                if (parseIpv4(st_str, &st_ip4)) {
                    info.send_through_addr = std.net.Address.initIp4(st_ip4, 0);
                    log.info("listener {s}:{d} send_through: {s}", .{ lc.getListenAddr(), lc.port, st_str });
                } else {
                    log.warn("listener {s}:{d} invalid send_through: {s}", .{ lc.getListenAddr(), lc.port, st_str });
                }
            }
            // Parse fallback address
            if (lc.fallback_addr_len > 0 and lc.fallback_port > 0) {
                var fb_ip4: [4]u8 = undefined;
                if (parseIpv4(lc.getFallbackAddr(), &fb_ip4)) {
                    info.fallback_addr = std.net.Address.initIp4(fb_ip4, lc.fallback_port);
                }
            }
            // TLS context for standalone listener
            if (lc.tls_enabled) {
                var prefix_buf: [64]u8 = undefined;
                const prefix = std.fmt.bufPrint(&prefix_buf, "listener {s}:{d}", .{ lc.getListenAddr(), lc.port }) catch "listener[?]";
                info.tls_ctx = tls_init.initServerTlsContext(
                    allocator,
                    if (lc.cert_file_len > 0) lc.getCertFileZ() else null,
                    if (lc.key_file_len > 0) lc.getKeyFileZ() else null,
                    prefix,
                );
            }
            // Shadowsocks inbound for standalone listener
            if (lc.protocol == .shadowsocks and lc.ss_password_len > 0 and lc.ss_method_len > 0) {
                if (ss_crypto.Method.fromString(lc.getSsMethod())) |method| {
                    info.ss_inbound = .{
                        .psk = ss_crypto.evpBytesToKey(lc.getSsPassword(), method.keySize()),
                        .method = @intFromEnum(method),
                        .key_len = @intCast(method.keySize()),
                    };
                    log.info("listener shadowsocks: method={s}", .{lc.getSsMethod()});
                }
            }
            // Configure per-listener VMess hot cache TTL
            if (lc.protocol == .vmess and config.limits.vmess_hot_cache_ttl > 0) {
                info.hot_cache = vmess_hot_cache.HotCache.init(@intCast(config.limits.vmess_hot_cache_ttl));
            }
            // Routing + Transport + WebSocket path
            info.enable_routing = lc.enable_routing;
            info.transport = lc.transport;
            if (lc.ws_path_len > 0) {
                const wp_n: u8 = @intCast(@min(lc.ws_path_len, info.ws_path_buf.len));
                @memcpy(info.ws_path_buf[0..wp_n], lc.ws_path_buf[0..wp_n]);
                info.ws_path_len = wp_n;
            }
            // Standalone VMess UUID → create UserStore with single user
            if (lc.uuid_len > 0 and lc.protocol == .vmess) {
                if (config_mod.OutboundConfig.parseUuid(lc.getUuid())) |uuid_bytes| {
                    const store = allocator.create(user_store_mod.UserStore) catch {
                        log.err("listener {s}:{d}: OOM creating UserStore", .{ lc.getListenAddr(), lc.port });
                        continue;
                    };
                    store.* = user_store_mod.UserStore.init(allocator);
                    const user = user_store_mod.UserStore.UserInfo{ .id = 0, .uuid = uuid_bytes };
                    store.update(&[_]user_store_mod.UserStore.UserInfo{user}) catch {
                        log.err("listener {s}:{d}: failed to init UserStore", .{ lc.getListenAddr(), lc.port });
                        store.deinit();
                        allocator.destroy(store);
                        continue;
                    };
                    info.user_store = store;
                    standalone_stores[lid] = store;
                    log.info("listener {s}:{d} vmess uuid configured", .{ lc.getListenAddr(), lc.port });
                } else {
                    log.warn("listener {s}:{d}: invalid uuid format", .{ lc.getListenAddr(), lc.port });
                }
            }

            for (workers) |*w| {
                w.listener_infos[lid] = info;
                w.listener_info_count = @max(w.listener_info_count, lid + 1);
            }

            log.info("listener: {s}:{d} ({s}{s}{s})", .{
                lc.getListenAddr(),
                lc.port,
                @tagName(lc.protocol),
                if (lc.transport == .ws or lc.transport == .wss) "+ws" else "",
                if (lc.tls_enabled) "+tls" else "",
            });
        }
    }

    // Verify at least one listener is active
    if (dispatcher.listeners.items.len == 0 and bootstrap_count == 0) {
        log.err("no listeners configured", .{});
        std.debug.print("ERROR: no listeners configured\n", .{});
        return;
    }

    if (dispatcher.listeners.items.len > 0) {
        log.info("znode ready with {d} listener(s), press Ctrl+C to stop", .{dispatcher.listeners.items.len});
    } else {
        log.info("znode ready, {d} panel(s) starting in background, press Ctrl+C to stop", .{bootstrap_count});
    }

    // Start worker threads (after all listeners are configured)
    for (workers) |*w| {
        try w.spawn();
    }

    // Start geo database auto-updater (background thread, periodic refresh)
    if (config.geo_update_interval > 0) {
        geo_updater.start() catch |e| {
            log.warn("geo updater start failed: {}", .{e});
        };
    }

    // Run dispatcher on main thread (blocks until stop)
    try dispatcher.run();

    // ── Shutdown ──
    log.info("shutting down...", .{});

    // Stop geo updater first (independent background thread)
    geo_updater.stop();

    // Stop DNS thread BEFORE workers — DNS callbacks access worker.async_notify.
    // If workers deinit first, DNS callbacks would use-after-free on async_notify.
    dns_async.stop();
    dns_async.join();

    for (workers) |*w| w.stop();
    for (workers) |*w| w.join();
    log.info("znode stopped", .{});
}

/// Build Worker.ListenerInfo from panel config + server info.
fn buildWorkerListenerInfo(
    entry: *const config_mod.NodeConfig,
    server_info: api_client_mod.ServerNodeInfo,
    panel_tls_ctx: ?*tls_mod.TlsContext,
    store: *user_store_mod.UserStore,
    hot_cache_ttl: u32,
    panel_idx: u8,
) Worker.ListenerInfo {
    const listen_port = server_info.server_port;
    const node_needs_tls = server_info.transport == .tls or server_info.transport == .wss;
    var info = Worker.ListenerInfo{
        .protocol = entry.protocol,
        .tls_enabled = node_needs_tls and panel_tls_ctx != null,
        .tls_ctx = panel_tls_ctx,
        .user_store = store,
        .sniff_enabled = entry.sniff_enabled,
        .sniff_redirect = entry.sniff_redirect,
    };
    {
        const proto_str = @tagName(entry.protocol);
        if (entry.name_len > 0) {
            const tag = std.fmt.bufPrint(&info.tag_buf, "{s}-{s}-{d}", .{ entry.getName(), proto_str, listen_port }) catch "";
            info.tag_len = @intCast(tag.len);
        } else {
            const tag = std.fmt.bufPrint(&info.tag_buf, "{s}-{d}", .{ proto_str, listen_port }) catch "";
            info.tag_len = @intCast(tag.len);
        }
    }
    if (entry.send_through_len > 0) {
        const st_str = entry.getSendThrough();
        var st_ip4: [4]u8 = undefined;
        if (parseIpv4(st_str, &st_ip4)) {
            info.send_through_addr = std.net.Address.initIp4(st_ip4, 0);
            log.info("panel[{d}] send_through: {s}", .{ panel_idx, st_str });
        } else {
            log.warn("panel[{d}] invalid send_through: {s}", .{ panel_idx, st_str });
        }
    }
    if (entry.fallback_addr_len > 0 and entry.fallback_port > 0) {
        var fb_ip4: [4]u8 = undefined;
        if (parseIpv4(entry.getFallbackAddr(), &fb_ip4)) {
            info.fallback_addr = std.net.Address.initIp4(fb_ip4, entry.fallback_port);
        }
    }
    if (entry.protocol == .shadowsocks and entry.ss_password_len > 0 and entry.ss_method_len > 0) {
        if (ss_crypto.Method.fromString(entry.getSsMethod())) |method| {
            info.ss_inbound = .{
                .psk = ss_crypto.evpBytesToKey(entry.getSsPassword(), method.keySize()),
                .method = @intFromEnum(method),
                .key_len = @intCast(method.keySize()),
            };
        }
    }
    if (entry.protocol == .vmess and hot_cache_ttl > 0) {
        info.hot_cache = vmess_hot_cache.HotCache.init(@intCast(hot_cache_ttl));
    }
    return info;
}

/// Background panel initialization: parallel first attempt, then serial retry with backoff.
fn panelRetryLoop(bootstraps: []PanelBootstrap) void {
    // ── Round 1: parallel first attempt (one thread per panel) ──
    var threads: [max_panels]?std.Thread = [_]?std.Thread{null} ** max_panels;
    for (bootstraps, 0..) |*b, i| {
        threads[i] = std.Thread.spawn(.{}, panelSetupOne, .{ b, @as(u32, 1) }) catch null;
    }
    for (bootstraps, 0..) |_, i| {
        if (threads[i]) |t| t.join();
    }

    // Check if all panels are online
    var has_pending = false;
    for (bootstraps) |*b| {
        if (!b.fetch_ok) { has_pending = true; break; }
    }
    if (!has_pending) {
        log.info("all panels online", .{});
        return;
    }

    // ── Rounds 2+: serial retry with exponential backoff ──
    var attempt: u32 = 1;
    while (g_retry_running.load(.acquire)) {
        const delay: u64 = @min(
            @as(u64, 5) * std.time.ns_per_s *| (@as(u64, 1) << @intCast(@min(attempt - 1, 20))),
            300 * std.time.ns_per_s,
        );
        log.info("panel retry: round {d}, next attempt in {d}s", .{ attempt + 1, delay / std.time.ns_per_s });

        var slept: u64 = 0;
        while (slept < delay and g_retry_running.load(.acquire)) {
            std.Thread.sleep(1 * std.time.ns_per_s);
            slept += 1 * std.time.ns_per_s;
        }
        if (!g_retry_running.load(.acquire)) break;
        attempt += 1;

        var pending: u8 = 0;
        for (bootstraps) |*b| {
            if (b.fetch_ok) continue;
            pending += 1;
            panelSetupOne(b, attempt);
        }

        if (pending == 0) {
            log.info("all panels online", .{});
            break;
        }
    }
}

/// Try to set up a single panel: fetch config, sync users, register listener.
fn panelSetupOne(b: *PanelBootstrap, attempt: u32) void {
    if (b.fetch_ok) return;
    const name = b.entry.getName();

    const server_info = b.pm.fetchServerInfo() catch |e| {
        log.warn("panel[{d}] {s}: attempt {d} fetch failed: {s}", .{ b.panel_idx, name, attempt, @errorName(e) });
        return;
    };
    b.server_info = server_info;

    b.user_count = b.pm.syncUsersBlocking() catch |e| blk: {
        log.warn("panel[{d}] {s}: user sync failed: {s}, will retry in background", .{ b.panel_idx, name, @errorName(e) });
        break :blk 0;
    };

    const node_needs_tls = server_info.transport == .tls or server_info.transport == .wss;

    var panel_tls_ctx: ?*tls_mod.TlsContext = null;
    if (b.entry.tls_enabled) {
        var prefix_buf: [64]u8 = undefined;
        const prefix = std.fmt.bufPrint(&prefix_buf, "panel[{d}]", .{b.panel_idx}) catch "panel[?]";
        panel_tls_ctx = tls_init.initServerTlsContext(
            b.allocator,
            if (b.entry.cert_file_len > 0) b.entry.getCertFileZ() else null,
            if (b.entry.cert_file_len > 0) b.entry.getKeyFileZ() else null,
            prefix,
        );
    }
    if (node_needs_tls and panel_tls_ctx == null) {
        log.warn("panel[{d}] {s}: panel requires TLS but local TLS not configured, forcing TLS off", .{ b.panel_idx, name });
    }

    const worker_info = buildWorkerListenerInfo(
        b.entry, server_info, panel_tls_ctx, b.store, b.hot_cache_ttl, b.panel_idx,
    );
    b.dispatcher.listenLive(b.entry.getListenAddr(), server_info.server_port, worker_info) catch |e| {
        log.err("panel[{d}] {s}: listenLive failed: {}", .{ b.panel_idx, name, e });
        if (panel_tls_ctx) |ctx| {
            var c2 = ctx;
            c2.deinit();
            b.allocator.destroy(ctx);
        }
        return;
    };

    b.pm.start() catch |e| {
        log.err("panel[{d}] {s}: failed to start panel manager: {}", .{ b.panel_idx, name, e });
    };

    if (b.panel_state) |ps| {
        ps.tls_ctx = panel_tls_ctx;
    }

    b.fetch_ok = true;
    log.info("panel[{d}] {s}: online (attempt {d}), port={d}, {d} users", .{
        b.panel_idx, name, attempt, server_info.server_port, b.user_count,
    });
}

/// Parse "a.b.c.d" IPv4 string into 4 bytes.
fn parseIpv4(s: []const u8, out: *[4]u8) bool {
    var octet: u8 = 0;
    var idx: u8 = 0;
    var digits: u8 = 0;
    for (s) |c| {
        if (c == '.') {
            if (digits == 0 or idx >= 3) return false;
            out[idx] = octet;
            idx += 1;
            octet = 0;
            digits = 0;
        } else if (c >= '0' and c <= '9') {
            const val = @as(u16, octet) * 10 + (c - '0');
            if (val > 255) return false;
            octet = @intCast(val);
            digits += 1;
        } else {
            return false;
        }
    }
    if (digits == 0 or idx != 3) return false;
    out[idx] = octet;
    return true;
}

// ── Module imports for tests ──
test {
    _ = @import("core/errors.zig");
    _ = @import("core/log.zig");
    _ = @import("core/config.zig");
    _ = @import("core/stats.zig");
    _ = @import("core/buffer_pool.zig");
    _ = @import("core/affinity.zig");
    _ = @import("core/session.zig");
    _ = @import("core/user_store.zig");
    _ = @import("transport/stream.zig");
    _ = @import("dns/cache.zig");
    _ = @import("dns/resolver.zig");
    _ = @import("geo/protobuf_lite.zig");
    _ = @import("geo/geoip.zig");
    _ = @import("geo/geosite.zig");
    _ = @import("router/router.zig");
    _ = @import("router/regex_lite.zig");
    _ = @import("sniff/sniffer.zig");
    _ = @import("sniff/tls_sniffer.zig");
    _ = @import("sniff/http_sniffer.zig");
    _ = @import("transport/tls_stream.zig");
    _ = @import("transport/self_signed.zig");
    _ = @import("transport/ws_stream.zig");
    _ = @import("core/connection_fsm.zig");
    _ = @import("protocol/trojan/trojan_protocol.zig");
    _ = @import("protocol/vmess/vmess_crypto.zig");
    _ = @import("protocol/vmess/vmess_hot_cache.zig");
    _ = @import("protocol/vmess/vmess_protocol.zig");
    _ = @import("protocol/vmess/vmess_stream.zig");
    _ = @import("protocol/vmess/xudp_mux.zig");
    _ = @import("udp/udp_packet.zig");
    _ = @import("udp/udp_session.zig");
    _ = @import("udp/udp_relay.zig");
    _ = @import("core/rate_limiter.zig");
    _ = @import("core/conn_limiter.zig");
    _ = @import("panel/api_client.zig");
    _ = @import("panel/traffic_collector.zig");
    _ = @import("panel/panel_manager.zig");
    _ = @import("core/worker.zig");
    _ = @import("core/proxy_connection.zig");
    _ = @import("core/dispatcher.zig");
    _ = @import("protocol/shadowsocks/ss_crypto.zig");
    _ = @import("protocol/shadowsocks/ss_protocol.zig");
    _ = @import("protocol/shadowsocks/ss_inbound.zig");
    _ = @import("protocol/shadowsocks/ss_outbound.zig");
    _ = @import("protocol/trojan/trojan_inbound.zig");
    _ = @import("protocol/trojan/trojan_outbound.zig");
    _ = @import("protocol/vmess/vmess_inbound.zig");
    _ = @import("protocol/vmess/vmess_outbound.zig");
    _ = @import("transport/outbound_transport.zig");
    _ = @import("geo/geo_updater.zig");
    _ = @import("transport/dynamic_cert.zig");
}

