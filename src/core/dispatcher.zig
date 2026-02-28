const std = @import("std");
const zio = @import("zio");
const log = @import("log.zig");
const Worker = @import("worker.zig").Worker;
const config_mod = @import("config.zig");
const session_handler = @import("session_handler.zig");
const ip_error_ban_mod = @import("ip_error_ban.zig");

/// ConnectionDispatcher: accepts connections and spawns session handler coroutines.
/// Uses zio coroutines for accept loops + session handling (replaces xev + Worker threads).
///
/// Architecture:
///   accept loop (per listener) → accept → spawn(handleSession) → zio runtime schedules
pub const Dispatcher = struct {
    // ── Type declarations ──
    const max_pending_live = 16;

    /// Pre-configured listener (address stored, server created in run()).
    pub const Listener = struct {
        addr_buf: [64]u8 = [_]u8{0} ** 64,
        addr_len: u8 = 0,
        port: u16 = 0,
        tag: [64]u8 = [_]u8{0} ** 64,
        tag_len: u8 = 0,
        listener_id: u8 = 0,
    };

    /// Pending live listener request (queued by panel background threads).
    pub const PendingLiveListener = struct {
        addr_buf: [64]u8 = [_]u8{0} ** 64,
        addr_len: u8 = 0,
        port: u16 = 0,
        tag: [64]u8 = [_]u8{0} ** 64,
        tag_len: u8 = 0,
        worker_info: Worker.ListenerInfo,
    };

    // ── Fields ──
    logger: log.ScopedLogger,
    allocator: std.mem.Allocator,

    // Per-listener info (set by main.zig, read by accept loops)
    // Uses workers[0] as canonical storage (all workers have identical listener_infos)
    listener_infos: *[config_mod.max_listeners]Worker.ListenerInfo,
    listener_info_count: *u8,

    // Listener configs (populated by listen(), servers created in run())
    listeners: std.ArrayList(Listener) = .{},

    // Stats
    total_accepted: u64 = 0,

    // Shutdown
    stopping: bool = false,

    // Session management (zio coroutine-based)
    shared: ?*session_handler.Shared = null,
    session_group: zio.Group = .init,

    // Live listener queue (panel background threads → monitor coroutine)
    pending_live_mutex: std.Thread.Mutex = .{},
    pending_live: [max_pending_live]PendingLiveListener = undefined,
    pending_live_count: u8 = 0,

    // Retry queue: bind failures re-queued here, retried next poll cycle.
    // Only accessed from liveListenerLoop coroutine — no mutex needed.
    retry_live: [max_pending_live]PendingLiveListener = undefined,
    retry_live_count: u8 = 0,

    // Active servers (created in run() and processLiveListeners())
    servers: std.ArrayList(zio.net.Server) = .{},

    pub fn init(
        listener_infos: *[config_mod.max_listeners]Worker.ListenerInfo,
        listener_info_count: *u8,
        allocator: std.mem.Allocator,
    ) Dispatcher {
        return .{
            .logger = log.ScopedLogger.init(0, "dispatcher"),
            .allocator = allocator,
            .listener_infos = listener_infos,
            .listener_info_count = listener_info_count,
        };
    }

    pub fn deinit(self: *Dispatcher) void {
        for (self.servers.items) |s| s.close();
        self.servers.deinit(self.allocator);
        self.listeners.deinit(self.allocator);
    }

    /// Add a listen address. Call before run().
    /// Validates the address and stores the config; actual server creation happens in run().
    pub fn listen(self: *Dispatcher, address: []const u8, port: u16) !void {
        // Validate address format early (fail fast)
        _ = try parseAddress(address, port);

        var listener = Listener{ .port = port };
        listener.listener_id = @intCast(self.listeners.items.len);
        const n: u8 = @intCast(@min(address.len, listener.addr_buf.len));
        @memcpy(listener.addr_buf[0..n], address[0..n]);
        listener.addr_len = n;
        const tag = std.fmt.bufPrint(&listener.tag, "{s}:{d}", .{ address, port }) catch "";
        listener.tag_len = @intCast(tag.len);

        try self.listeners.append(self.allocator, listener);
    }

    /// Stop the dispatcher. For graceful shutdown from signal handlers.
    pub fn stop(self: *Dispatcher) void {
        self.stopping = true;
    }

    /// Queue a live listener (called from panel background threads, thread-safe).
    /// Address validation only — server creation is deferred to the monitor coroutine.
    pub fn listenLive(self: *Dispatcher, address: []const u8, port: u16, worker_info: Worker.ListenerInfo) !void {
        // Validate address format
        _ = try parseAddress(address, port);

        self.pending_live_mutex.lock();
        defer self.pending_live_mutex.unlock();

        if (self.pending_live_count >= max_pending_live) return error.Unexpected;

        const idx = self.pending_live_count;
        self.pending_live[idx] = .{ .port = port, .worker_info = worker_info };
        const n: u8 = @intCast(@min(address.len, self.pending_live[idx].addr_buf.len));
        @memcpy(self.pending_live[idx].addr_buf[0..n], address[0..n]);
        self.pending_live[idx].addr_len = n;
        const tag = std.fmt.bufPrint(&self.pending_live[idx].tag, "{s}:{d}", .{ address, port }) catch "";
        self.pending_live[idx].tag_len = @intCast(tag.len);
        self.pending_live_count += 1;

    }

    /// Run the dispatcher. Must be called from a zio coroutine context.
    /// Creates servers, spawns accept loops, and blocks until shutdown signal.
    pub fn run(self: *Dispatcher) !void {
        self.session_group = zio.Group.init;

        // Start async log writer (file I/O offloaded from worker coroutines).
        try log.startAsync();

        var accept_group: zio.Group = .init;
        defer {
            accept_group.cancel(); // 1. Stop accepting new connections
            self.session_group.cancel(); // 2. Cancel all active sessions
            log.drainAsync(); // 3. Flush remaining log entries to disk
        }

        // Create zio servers for pre-configured listeners
        for (self.listeners.items) |*lc| {
            self.startListener(lc.addr_buf[0..lc.addr_len], lc.port, lc.listener_id, &accept_group) catch |e| {
                self.logger.err("failed to start listener {s}: {}", .{ lc.tag[0..lc.tag_len], e });
            };
        }

        // Spawn live listener monitor (checks pending queue every 500ms)
        try accept_group.spawn(liveListenerLoop, .{ self, &accept_group });

        // Wait for shutdown signal (SIGINT or SIGTERM)
        var sig_int = try zio.Signal.init(.interrupt);
        defer sig_int.deinit();
        var sig_term = try zio.Signal.init(.terminate);
        defer sig_term.deinit();

        _ = zio.select(.{ .sig_int = &sig_int, .sig_term = &sig_term }) catch {};

        self.stopping = true;
        // defer block: accept_group.cancel() then session_group.cancel()
    }

    // ── Internal: server lifecycle ──

    fn startListener(self: *Dispatcher, addr_str: []const u8, port: u16, listener_id: u8, group: *zio.Group) !void {
        const zio_addr = try parseZioAddress(addr_str, port);
        const server = try zio_addr.listen(.{ .reuse_address = true, .kernel_backlog = std.math.maxInt(u31) });
        errdefer server.close();

        const sid: u8 = @intCast(self.servers.items.len);
        try self.servers.append(self.allocator, server);

        try group.spawn(acceptLoop, .{ self, sid, listener_id });
    }

    // ── Internal: coroutine tasks ──

    fn acceptLoop(self: *Dispatcher, server_idx: u8, listener_id: u8) !void {
        const shared = self.shared orelse return;

        while (true) {
            self.logger.debug("acceptLoop waiting: sid={d} lid={d} total={d}", .{ server_idx, listener_id, self.total_accepted });
            const stream = self.servers.items[server_idx].accept() catch |err| {
                if (err == error.Canceled) return error.Canceled;
                self.logger.err("accept error on lid={d}: {}", .{ listener_id, err });
                zio.sleep(.fromMilliseconds(10)) catch return error.Canceled;
                continue;
            };

            self.total_accepted += 1;

            const client_ip_hash = ip_error_ban_mod.hashIpAddress(stream.socket.address.ip);
            if (shared.ip_error_ban.isBanned(client_ip_hash, std.time.milliTimestamp())) {
                self.logger.debug("blocked banned client hash={x} on lid={d}", .{ client_ip_hash, listener_id });
                stream.close();
                continue;
            }

            // Spawn session handler coroutine (zio runtime schedules across executors)
            const info = &self.listener_infos[listener_id];
            self.session_group.spawn(session_handler.handleSession, .{ stream, info, shared }) catch |err| {
                self.logger.err("session spawn FAILED on lid={d}: {s}", .{ listener_id, @errorName(err) });
                stream.close();
            };
            self.logger.debug("spawn ok on lid={d}", .{listener_id});
        }
    }

    fn liveListenerLoop(self: *Dispatcher, group: *zio.Group) void {
        while (true) {
            zio.sleep(.fromMilliseconds(500)) catch return;
            self.processLiveListeners(group);
        }
    }

    fn processLiveListeners(self: *Dispatcher, group: *zio.Group) void {
        // Snapshot new pending items under lock.
        self.pending_live_mutex.lock();
        const new_count = self.pending_live_count;
        var new_pending: [max_pending_live]PendingLiveListener = undefined;
        if (new_count > 0) {
            @memcpy(new_pending[0..new_count], self.pending_live[0..new_count]);
            self.pending_live_count = 0;
        }
        self.pending_live_mutex.unlock();

        // Build combined batch: previous retry items first, then freshly queued items.
        // Both arrays are bounded by max_pending_live, so the combined size fits in 2×.
        var batch: [max_pending_live * 2]PendingLiveListener = undefined;
        const retry_count = self.retry_live_count;
        if (retry_count > 0) @memcpy(batch[0..retry_count], self.retry_live[0..retry_count]);
        if (new_count > 0) @memcpy(batch[retry_count .. retry_count + new_count], new_pending[0..new_count]);
        const total = retry_count + new_count;
        self.retry_live_count = 0; // reset; failures below will re-populate

        next_pending: for (batch[0..total]) |*pl| {
            if (self.stopping) return;

            const lid: u8 = @intCast(self.listeners.items.len);

            if (lid >= config_mod.max_listeners) {
                self.logger.err("too many listeners (max {d}), dropping {s}", .{ config_mod.max_listeners, pl.tag[0..pl.tag_len] });
                continue;
            }

            // Duplicate port detection — prevents silent EADDRINUSE on bind.
            for (self.listeners.items) |existing| {
                if (existing.port == pl.port) {
                    self.logger.err("live listener port {d} already bound by lid={d}, skipping", .{ pl.port, existing.listener_id });
                    continue :next_pending;
                }
            }

            // Bind first — only commit the lid slot on success.
            self.startListener(
                pl.addr_buf[0..pl.addr_len],
                pl.port,
                lid,
                group,
            ) catch |e| {
                self.logger.warn("live listener {s} bind failed ({s}), will retry next cycle", .{ pl.tag[0..pl.tag_len], @errorName(e) });
                if (self.retry_live_count < max_pending_live) {
                    self.retry_live[self.retry_live_count] = pl.*;
                    self.retry_live_count += 1;
                } else {
                    self.logger.err("retry queue full, dropping listener {s}", .{pl.tag[0..pl.tag_len]});
                }
                continue;
            };

            // Bind succeeded — commit listener info and register slot.
            self.listener_infos[lid] = pl.worker_info;
            self.listener_info_count.* = @max(self.listener_info_count.*, lid + 1);

            var listener = Listener{
                .port = pl.port,
                .listener_id = lid,
            };
            @memcpy(listener.addr_buf[0..pl.addr_len], pl.addr_buf[0..pl.addr_len]);
            listener.addr_len = pl.addr_len;
            @memcpy(listener.tag[0..pl.tag_len], pl.tag[0..pl.tag_len]);
            listener.tag_len = pl.tag_len;
            self.listeners.append(self.allocator, listener) catch {
                self.logger.err("OOM registering live listener lid={d}", .{lid});
            };
        }
    }

    // ── Address resolution ──

    /// Parse address string to zio.net.IpAddress.
    fn parseZioAddress(address: []const u8, port: u16) !zio.net.IpAddress {
        if (address.len == 0) {
            return zio.net.IpAddress.initIp4(.{ 0, 0, 0, 0 }, port);
        }
        return zio.net.IpAddress.parseIp(address, port) catch {
            log.err("invalid listen address: '{s}', binding to 0.0.0.0", .{address});
            return zio.net.IpAddress.initIp4(.{ 0, 0, 0, 0 }, port);
        };
    }

    /// Parse address string to std.net.Address (for validation only).
    fn parseAddress(address: []const u8, port: u16) !std.net.Address {
        if (address.len == 0) {
            return std.net.Address.parseIp4("0.0.0.0", port) catch unreachable;
        }
        if (std.net.Address.parseIp4(address, port)) |addr| {
            return addr;
        } else |_| {}

        if (std.net.Address.parseIp6(address, port)) |addr| {
            return addr;
        } else |_| {}

        log.err("invalid listen address: '{s}', binding to 0.0.0.0", .{address});
        return std.net.Address.parseIp4("0.0.0.0", port) catch unreachable;
    }
};
