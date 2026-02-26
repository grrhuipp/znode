const std = @import("std");
const xev = @import("xev");
const log = @import("log.zig");
const Worker = @import("worker.zig").Worker;
const config_mod = @import("config.zig");
const AffinityTable = @import("affinity.zig").AffinityTable;

/// ConnectionDispatcher: single acceptor that distributes connections to workers.
/// Runs on the main thread's xev.Loop.
///
/// Connection distribution strategy:
///   1. Check affinity table for existing IP -> worker mapping
///   2. If no affinity, select worker with least active connections
///   3. Update affinity table for future connections from same IP
pub const Dispatcher = struct {
    // ── Type declarations ──
    const max_pending_live = 16;

    pub const Listener = struct {
        tcp: xev.TCP,
        accept_completion: xev.Completion = .{},
        close_completion: xev.Completion = .{},
        tag: [64]u8 = [_]u8{0} ** 64,
        tag_len: u8 = 0,
        listener_id: u8 = 0,
    };

    pub const PendingLiveListener = struct {
        tcp: xev.TCP,
        tag: [64]u8 = [_]u8{0} ** 64,
        tag_len: u8 = 0,
        worker_info: Worker.ListenerInfo,
    };

    // ── Fields ──
    loop: xev.Loop,
    workers: []Worker,
    logger: log.ScopedLogger,
    allocator: std.mem.Allocator,

    // Dispatch strategy
    strategy: config_mod.DispatchStrategy = .least_connections,
    affinity: ?*AffinityTable = null,
    prng: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0),

    // Acceptor state
    listeners: std.ArrayList(Listener) = .{},
    next_worker: u16 = 0,

    // Stats
    total_accepted: u64 = 0,
    stats_timer: ?xev.Timer = null,
    stats_timer_comp: xev.Completion = .{},

    // Shutdown state
    stopping: bool = false,
    stop_notify: ?xev.Async = null,
    stop_completion: xev.Completion = .{},

    // Live listener addition (async panel bootstrap — background threads add listeners at runtime)
    pending_live_mutex: std.Thread.Mutex = .{},
    pending_live: [max_pending_live]PendingLiveListener = undefined,
    pending_live_count: u8 = 0,
    live_notify: ?xev.Async = null,
    live_completion: xev.Completion = .{},

    /// Initialize in-place to avoid stack-allocating xev.Loop (very large on Windows/IOCP).
    pub fn initInPlace(self: *Dispatcher, workers: []Worker, allocator: std.mem.Allocator) !void {
        self.* = .{
            .loop = undefined,
            .workers = workers,
            .logger = log.ScopedLogger.init(0, "dispatcher"),
            .allocator = allocator,
            .listeners = .{},
            .stop_notify = null,
            .stop_completion = .{},
        };
        // Init loop directly into heap memory (xev.Loop is too large for the stack)
        self.loop = try xev.Loop.init(.{});
        errdefer self.loop.deinit();

        self.stop_notify = try xev.Async.init();
        self.live_notify = try xev.Async.init();
        self.stats_timer = try xev.Timer.init();

        // Pre-allocate listener capacity so append never reallocates after AcceptEx is posted.
        try self.listeners.ensureTotalCapacity(self.allocator, 32);
    }

    pub fn deinit(self: *Dispatcher) void {
        if (self.stats_timer) |*st| st.deinit();
        if (self.live_notify) |*ln| ln.deinit();
        if (self.stop_notify) |*sn| sn.deinit();
        self.listeners.deinit(self.allocator);
        self.loop.deinit();
    }

    /// Add a listen address. Call before run().
    pub fn listen(self: *Dispatcher, address: []const u8, port: u16) !void {
        const addr = try parseAddress(address, port);
        var tcp = try xev.TCP.init(addr);
        try tcp.bind(addr);
        try tcp.listen(128);

        var listener = Listener{ .tcp = tcp };
        listener.listener_id = @intCast(self.listeners.items.len);
        // Store tag
        const tag = std.fmt.bufPrint(&listener.tag, "{s}:{d}", .{ address, port }) catch "";
        listener.tag_len = @intCast(tag.len);

        try self.listeners.append(self.allocator, listener);

        self.logger.info("listening on {s}:{d}", .{ address, port });
    }

    /// Run the dispatcher event loop (blocks on main thread).
    pub fn run(self: *Dispatcher) !void {
        // Start accepting on all listeners
        for (self.listeners.items) |*listener| {
            listener.tcp.accept(&self.loop, &listener.accept_completion, Dispatcher, self, &onAccept);
        }

        // Register stop notification handler
        if (self.stop_notify) |*sn| {
            sn.wait(&self.loop, &self.stop_completion, Dispatcher, self, &onStopNotify);
        }

        // Register live listener notification handler (for async panel bootstrap)
        if (self.live_notify) |*ln| {
            ln.wait(&self.loop, &self.live_completion, Dispatcher, self, &onLiveNotify);
        }

        // Start periodic stats timer (every 60s)
        if (self.stats_timer) |*st| {
            st.run(&self.loop, &self.stats_timer_comp, 60_000, Dispatcher, self, &onStatsTimer);
        }

        self.logger.info("dispatcher started with {d} workers", .{self.workers.len});

        try self.loop.run(.until_done);
    }

    /// Stop the dispatcher — signals the event loop to close listeners and exit.
    pub fn stop(self: *Dispatcher) void {
        self.stopping = true;
        if (self.stop_notify) |*sn| {
            sn.notify() catch {
                self.logger.err("failed to notify dispatcher stop", .{});
            };
        }
    }

    fn onStopNotify(ud: ?*Dispatcher, l: *xev.Loop, _: *xev.Completion, _: xev.Async.WaitError!void) xev.CallbackAction {
        const self = ud.?;
        self.logger.info("dispatcher stopping, closing {d} listeners", .{self.listeners.items.len});

        // Close all listener sockets to cancel pending accept completions.
        // This triggers onAccept with an error → disarm, then onListenerClose → disarm.
        // Once all completions disarm, loop.run(.until_done) returns.
        for (self.listeners.items) |*listener| {
            listener.tcp.close(l, &listener.close_completion, Dispatcher, self, &onListenerClose);
        }

        return .disarm;
    }

    fn onListenerClose(_: ?*Dispatcher, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.CloseError!void) xev.CallbackAction {
        return .disarm;
    }

    // ── Live listener addition (called from background bootstrap threads) ──

    /// Add a listener while the event loop is running. Thread-safe.
    /// The listener is queued and activated on the next event loop tick.
    pub fn listenLive(self: *Dispatcher, address: []const u8, port: u16, worker_info: Worker.ListenerInfo) !void {
        const addr = try parseAddress(address, port);
        var tcp = try xev.TCP.init(addr);
        tcp.bind(addr) catch |e| {
            std.posix.close(tcp.fd);
            return e;
        };
        tcp.listen(128) catch |e| {
            std.posix.close(tcp.fd);
            return e;
        };

        self.pending_live_mutex.lock();
        defer self.pending_live_mutex.unlock();

        if (self.pending_live_count >= max_pending_live) {
            std.posix.close(tcp.fd);
            return error.Unexpected;
        }

        const idx = self.pending_live_count;
        self.pending_live[idx] = .{ .tcp = tcp, .worker_info = worker_info };
        const tag = std.fmt.bufPrint(&self.pending_live[idx].tag, "{s}:{d}", .{ address, port }) catch "";
        self.pending_live[idx].tag_len = @intCast(tag.len);
        self.pending_live_count += 1;

        // Wake the event loop to process the pending listener
        if (self.live_notify) |*ln| ln.notify() catch {};

        self.logger.info("queued live listen on {s}:{d}", .{ address, port });
    }

    /// Event-loop callback: activate all pending live listeners.
    /// Runs on the main thread so ArrayList/worker modifications are safe.
    fn onLiveNotify(ud: ?*Dispatcher, l: *xev.Loop, _: *xev.Completion, _: xev.Async.WaitError!void) xev.CallbackAction {
        const self = ud.?;
        if (self.stopping) return .disarm;

        self.pending_live_mutex.lock();
        defer self.pending_live_mutex.unlock();

        for (self.pending_live[0..self.pending_live_count]) |*pl| {
            const lid: u8 = @intCast(self.listeners.items.len);

            if (lid >= config_mod.max_listeners) {
                self.logger.err("too many listeners (max {d}), skipping", .{config_mod.max_listeners});
                continue;
            }

            // Set worker infos BEFORE starting accept (so arriving connections see valid config)
            for (self.workers) |*w| {
                w.listener_infos[lid] = pl.worker_info;
                w.listener_info_count = @max(w.listener_info_count, lid + 1);
            }

            var listener = Listener{ .tcp = pl.tcp };
            listener.listener_id = lid;
            @memcpy(listener.tag[0..pl.tag_len], pl.tag[0..pl.tag_len]);
            listener.tag_len = pl.tag_len;

            self.listeners.append(self.allocator, listener) catch {
                self.logger.err("failed to register live listener lid={d}", .{lid});
                continue;
            };

            // Start accepting — use stable pointer from ArrayList (capacity pre-allocated)
            const new_listener = &self.listeners.items[self.listeners.items.len - 1];
            new_listener.tcp.accept(l, &new_listener.accept_completion, Dispatcher, self, &onAccept);

            self.logger.info("live listener activated: lid={d} {s}", .{
                lid, new_listener.tag[0..new_listener.tag_len],
            });
        }
        self.pending_live_count = 0;

        return .rearm;
    }

    // ── Internal ──

    fn onAccept(ud: ?*Dispatcher, l: *xev.Loop, c: *xev.Completion, r: xev.AcceptError!xev.TCP) xev.CallbackAction {
        const self = ud.?;

        // Stop accepting if shutdown requested
        if (self.stopping) return .disarm;

        const client_tcp = r catch |e| {
            self.logger.err("accept error: {}", .{e});
            // On Windows IOCP: clear internal_accept_socket so xev creates a
            // fresh socket for the next AcceptEx (xev bug workaround).
            if (@import("builtin").os.tag == .windows) {
                c.op.accept.internal_accept_socket = null;
            }
            return if (self.stopping) .disarm else .rearm;
        };

        self.total_accepted += 1;

        // Get the raw fd to dispatch to worker
        const fd = client_tcp.fd;

        // Identify which listener accepted (by matching completion pointer)
        const listener_id = self.findListenerId(c);

        // Resolve client address via getpeername (does NOT touch completion buffer)
        const src_addr = self.resolvePeerAddr(fd, c);
        // Resolve local address via getsockname (for SendThrough: same IP in/out)
        const local_addr = self.resolveLocalAddr(fd);

        // Select target worker using configured strategy
        const worker_id = self.selectWorker(src_addr);

        // Dispatch to worker
        if (!self.workers[worker_id].dispatchConnection(fd, src_addr, local_addr, listener_id)) {
            self.logger.warn("worker {d} rejected connection", .{worker_id});
            std.posix.close(fd);
        }

        _ = l;

        // On Windows IOCP: xev's reset() doesn't clear internal_accept_socket,
        // so on rearm it would reuse the socket we just gave to the worker.
        // This causes AcceptEx to fail and CloseHandle to close the worker's socket.
        // Setting it to null forces xev to create a fresh socket for the next accept.
        if (@import("builtin").os.tag == .windows) {
            c.op.accept.internal_accept_socket = null;
        }

        return .rearm; // Continue accepting
    }

    fn selectWorker(self: *Dispatcher, src_addr: ?std.net.Address) u16 {
        return switch (self.strategy) {
            .least_connections => self.selectLeastConn(),
            .round_robin => self.selectRoundRobin(),
            .random => self.selectRandom(),
            .ip_hash => self.selectIpHash(src_addr),
        };
    }

    fn selectLeastConn(self: *Dispatcher) u16 {
        var min_conns: u32 = std.math.maxInt(u32);
        var best_worker: u16 = 0;
        for (self.workers, 0..) |*w, i| {
            const conns = w.getActiveConnections();
            if (conns < min_conns) {
                min_conns = conns;
                best_worker = @intCast(i);
            }
        }
        return best_worker;
    }

    fn selectRoundRobin(self: *Dispatcher) u16 {
        const id = self.next_worker;
        self.next_worker = (self.next_worker + 1) % @as(u16, @intCast(self.workers.len));
        return id;
    }

    fn selectRandom(self: *Dispatcher) u16 {
        return @intCast(self.prng.random().uintLessThan(usize, self.workers.len));
    }

    fn selectIpHash(self: *Dispatcher, src_addr: ?std.net.Address) u16 {
        const affinity = self.affinity orelse return self.selectLeastConn();
        const addr = src_addr orelse return self.selectLeastConn();
        const ip_bytes = addrToIpBytes(addr);
        const hash = AffinityTable.hashIp(&ip_bytes);
        if (affinity.lookup(hash)) |wid| {
            if (wid < self.workers.len) return wid;
        }
        const wid = self.selectLeastConn();
        affinity.update(hash, wid);
        return wid;
    }

    fn addrToIpBytes(addr: std.net.Address) [4]u8 {
        const sa: *const [16]u8 = @ptrCast(std.mem.asBytes(&addr.any));
        return sa[4..8].*;
    }

    fn onStatsTimer(ud: ?*Dispatcher, l: *xev.Loop, _: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        const self = ud.?;
        _ = r catch return .disarm;
        if (self.stopping) return .disarm;
        self.logStats();
        // Reschedule
        if (self.stats_timer) |*st| {
            st.run(l, &self.stats_timer_comp, 60_000, Dispatcher, self, &onStatsTimer);
        }
        return .disarm;
    }

    fn logStats(self: *Dispatcher) void {
        var total_active: u32 = 0;
        var total_relay: u32 = 0;
        var total_outbound: u32 = 0;
        var total_alloc: usize = 0;
        var total_in_use: usize = 0;
        for (self.workers) |*w| {
            total_active += w.getActiveConnections();
            total_relay += w.conns_relay.load(.monotonic);
            total_outbound += w.conns_outbound.load(.monotonic);
            const m = w.pool.memoryUsage();
            total_alloc += m.total_allocated;
            total_in_use += m.total_in_use;
        }
        self.logger.info("stats: accepted={d} hs={d} active={d} relay={d} outbound={d} pool={d}/{d}KB", .{
            self.total_accepted,
            total_active -| total_relay, // handshake/connecting phase
            total_active,
            total_relay,
            total_outbound,
            total_in_use / 1024,
            total_alloc / 1024,
        });
    }

    /// Resolve peer address via setsockopt + getpeername (does NOT touch completion buffer).
    fn resolvePeerAddr(self: *Dispatcher, fd: std.posix.fd_t, c: *xev.Completion) ?std.net.Address {
        _ = self;
        var buf: [128]u8 = std.mem.zeroes([128]u8);
        if (@import("builtin").os.tag == .windows) {
            const W = struct {
                extern "ws2_32" fn getpeername(s: usize, name: [*]u8, namelen: *c_int) callconv(.winapi) c_int;
                extern "ws2_32" fn setsockopt(s: usize, level: c_int, optname: c_int, optval: [*]const u8, optlen: c_int) callconv(.winapi) c_int;
            };
            const sock = @intFromPtr(fd);
            // SO_UPDATE_ACCEPT_CONTEXT: enables getpeername on AcceptEx sockets.
            // Only touches the accepted socket, NOT the completion buffer.
            const ls = @intFromPtr(c.op.accept.socket);
            _ = W.setsockopt(sock, 0xFFFF, 0x700B, @ptrCast(std.mem.asBytes(&ls)), @sizeOf(usize));
            var len: c_int = @intCast(buf.len);
            if (W.getpeername(sock, &buf, &len) != 0) return null;
        } else {
            // Use raw syscall to avoid std.posix.getpeername's unexpectedErrno noise
            // (ENOTCONN is common when client disconnects before getpeername)
            var len: std.posix.socklen_t = @intCast(buf.len);
            const rc = std.os.linux.getpeername(fd, @ptrCast(@alignCast(&buf)), &len);
            if (rc != 0) return null;
        }
        const family = @as(u16, buf[0]) | (@as(u16, buf[1]) << 8);
        if (family == 2) { // AF_INET
            const port: u16 = (@as(u16, buf[2]) << 8) | buf[3];
            return std.net.Address.initIp4(buf[4..8].*, port);
        }
        return null;
    }

    /// Resolve local (server-side) address via getsockname.
    /// Returns the IP the client connected TO — used for SendThrough (same IP in/out).
    fn resolveLocalAddr(_: *Dispatcher, fd: std.posix.fd_t) ?std.net.Address {
        var buf: [128]u8 = std.mem.zeroes([128]u8);
        if (@import("builtin").os.tag == .windows) {
            const W = struct {
                extern "ws2_32" fn getsockname(s: usize, name: [*]u8, namelen: *c_int) callconv(.winapi) c_int;
            };
            var len: c_int = @intCast(buf.len);
            if (W.getsockname(@intFromPtr(fd), &buf, &len) != 0) return null;
        } else {
            var len: std.posix.socklen_t = buf.len;
            std.posix.getsockname(fd, @ptrCast(@alignCast(&buf)), &len) catch return null;
        }
        const family = @as(u16, buf[0]) | (@as(u16, buf[1]) << 8);
        if (family == 2) { // AF_INET
            return std.net.Address.initIp4(buf[4..8].*, 0); // port=0 for outbound bind
        }
        return null;
    }

    fn findListenerId(self: *Dispatcher, c: *xev.Completion) u8 {
        for (self.listeners.items) |*listener| {
            if (&listener.accept_completion == c) return listener.listener_id;
        }
        return 0;
    }

    fn parseAddress(address: []const u8, port: u16) !std.net.Address {
        if (address.len == 0) {
            return std.net.Address.parseIp4("0.0.0.0", port) catch unreachable;
        }
        // Try IPv4 first, then IPv6
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
