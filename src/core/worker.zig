const std = @import("std");
const xev = @import("xev");
const log = @import("log.zig");
const stats_mod = @import("stats.zig");
const buffer_pool = @import("buffer_pool.zig");
const config_mod = @import("config.zig");
const tls_mod = @import("../transport/tls_stream.zig");
const user_store_mod = @import("user_store.zig");
const dns_resolver_mod = @import("../dns/resolver.zig");
const proxy_conn = @import("proxy_connection.zig");
const router_mod = @import("../router/router.zig");
const vmess_protocol = @import("../protocol/vmess/vmess_protocol.zig");
const vmess_hot_cache = @import("../protocol/vmess/vmess_hot_cache.zig");

/// Worker thread: owns an independent xev.Loop and handles connections.
/// Each worker is pinned to its own thread with isolated resources.
pub const Worker = struct {
    id: u16,
    loop: xev.Loop,
    pool: buffer_pool.BufferPool,
    stats: stats_mod.StatsShard,
    logger: log.ScopedLogger,
    log_batch: log.LogBatch = .{},
    allocator: std.mem.Allocator,

    // Cross-thread connection queue (lock-free SPSC)
    pending_fds: FdQueue,
    async_notify: xev.Async,
    async_completion: xev.Completion = .{},

    // Shared context (set by main, read by Session)
    dns_resolver: ?*dns_resolver_mod.AsyncResolver = null,
    listen_fd: ?std.posix.fd_t = null, // for SO_UPDATE_ACCEPT_CONTEXT

    // Router: route connections to outbound by rules
    router: ?*const router_mod.Router = null,

    // Timeout settings (from config.limits, 0 = disabled)
    handshake_timeout_ms: u32 = 0,
    idle_timeout_ms: u32 = 0,
    half_close_grace_ms: u32 = 0, // hard cap on half-close duration (0 = no grace limit)

    // VMess replay protection (per-worker, shared by all VMess connections on this worker)
    replay_filter: vmess_protocol.ReplayFilter = .{},

    // Per-listener configuration (for multi-port)
    listener_infos: [config_mod.max_listeners]ListenerInfo = [_]ListenerInfo{.{}} ** config_mod.max_listeners,
    listener_info_count: u8 = 0,

    // DNS result delivery queue (DNS thread → Worker thread, SPSC)
    dns_results: DnsResultQueue = .{},

    // UDP downlink delivery (recv threads → worker thread, MPSC with mutex)
    udp_downlink: UdpDownlinkQueue = .{},

    // Connection tracking
    active_connections: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    conns_relay: std.atomic.Value(u32) = std.atomic.Value(u32).init(0), // connections in relay/half_close/udp_relay phase
    conns_outbound: std.atomic.Value(u32) = std.atomic.Value(u32).init(0), // connections with target TCP established
    leaked_sessions: std.atomic.Value(u32) = std.atomic.Value(u32).init(0), // sessions force-destroyed via LEAK_DETECT
    thread: ?std.Thread = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    close_counter: u32 = 0,

    // Session object pool (intrusive free list).
    // Avoids GPA alloc/free overhead per connection — reuses fixed-size structs.
    // Single-thread access only (worker thread), no synchronization needed.
    conn_pool_head: ?*ConnNode = null,
    conn_pool_count: u32 = 0,

    const ConnNode = struct { next: ?*ConnNode };
    const max_pooled_conns: u32 = 64; // ~192KB per worker at ~3KB per Session

    /// Allocate a Session: try pool first, then GPA.
    pub fn allocConn(self: *Worker) ?*proxy_conn.Session {
        if (self.conn_pool_head) |head| {
            self.conn_pool_head = head.next;
            self.conn_pool_count -= 1;
            return @ptrCast(@alignCast(head));
        }
        return self.allocator.create(proxy_conn.Session) catch null;
    }

    /// Return a Session to the pool, or free to GPA if pool is full.
    pub fn freeConn(self: *Worker, conn: *proxy_conn.Session) void {
        if (self.conn_pool_count < max_pooled_conns) {
            const node: *ConnNode = @ptrCast(@alignCast(conn));
            node.next = self.conn_pool_head;
            self.conn_pool_head = node;
            self.conn_pool_count += 1;
        } else {
            self.allocator.destroy(conn);
        }
    }

    pub const max_pending_fds = 1024;

    pub const ListenerInfo = struct {
        protocol: config_mod.Protocol = .vmess,
        tls_enabled: bool = false,
        send_through_addr: ?std.net.Address = null,
        fallback_addr: ?std.net.Address = null,
        // Multi-level fallbacks (path/ALPN conditional)
        fallbacks: [config_mod.max_fallbacks]config_mod.FallbackEntry = [_]config_mod.FallbackEntry{.{}} ** config_mod.max_fallbacks,
        fallback_count: u8 = 0,
        tag_buf: [64]u8 = [_]u8{0} ** 64,
        tag_len: u8 = 0,
        // Per-panel context (set by main.zig for each panel's listener)
        tls_ctx: ?*tls_mod.TlsContext = null,
        user_store: ?*user_store_mod.UserStore = null,
        // VMess hot user cache (per-listener isolation for multi-panel)
        hot_cache: vmess_hot_cache.HotCache = vmess_hot_cache.HotCache.init(vmess_hot_cache.HotCache.default_ttl),
        // Shadowsocks inbound credentials (optional, set when protocol == .shadowsocks)
        ss_inbound: ?SsInbound = null,
        // Sniff: detect TLS SNI / HTTP Host from initial payload
        sniff_enabled: bool = true,
        sniff_redirect: bool = true,
        // Transport: tcp (default), ws, wss
        transport: config_mod.Transport = .tcp,
        // WebSocket path (only used when transport == .ws or .wss)
        ws_path_buf: [128]u8 = [_]u8{0} ** 128,
        ws_path_len: u8 = 0,
        // Routing: whether to use route rules for this listener
        enable_routing: bool = false,

        pub const SsInbound = struct {
            psk: [32]u8,
            method: u8,
            key_len: u8,
        };

        pub fn getTag(self: *const ListenerInfo) []const u8 {
            return self.tag_buf[0..self.tag_len];
        }

        pub fn getWsPath(self: *const ListenerInfo) []const u8 {
            if (self.ws_path_len == 0) return "/";
            return self.ws_path_buf[0..self.ws_path_len];
        }
    };

    /// Lock-free SPSC ring buffer for async DNS results.
    /// Producer: DNS thread (push). Consumer: Worker thread (pop).
    pub const DnsResultQueue = struct {
        items: [dns_capacity]Entry = undefined,
        head: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        tail: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

        // DNS callbacks can burst under high concurrency (especially when many
        // domains resolve around the same time). Keep this queue larger to
        // reduce backpressure and avoid callback drops.
        const dns_capacity = 1024;

        pub const Entry = struct {
            conn: *proxy_conn.Session,
            result: ?dns_resolver_mod.ResolveResult,
            cache_hit: bool = false,
        };

        pub fn push(self: *DnsResultQueue, entry: Entry) bool {
            const tail = self.tail.load(.monotonic);
            const next_tail = (tail + 1) % dns_capacity;
            if (next_tail == self.head.load(.acquire)) return false; // full
            self.items[tail] = entry;
            self.tail.store(next_tail, .release);
            return true;
        }

        pub fn pop(self: *DnsResultQueue) ?Entry {
            const head = self.head.load(.monotonic);
            if (head == self.tail.load(.acquire)) return null; // empty
            const item = self.items[head];
            self.head.store((head + 1) % dns_capacity, .release);
            return item;
        }
    };

    /// Mutex-protected MPSC queue for UDP downlink packets.
    /// Producer: UDP recv threads (multiple). Consumer: Worker thread (single).
    pub const UdpDownlinkQueue = struct {
        mutex: std.Thread.Mutex = .{},
        items: [capacity]Entry = undefined,
        head: usize = 0,
        tail: usize = 0,

        const capacity = 512;

        pub const Entry = struct {
            conn: *proxy_conn.Session,
            src_ip4: [4]u8 = .{ 0, 0, 0, 0 },
            src_ip6: [16]u8 = .{0} ** 16,
            src_port: u16 = 0,
            is_ipv6: bool = false,
            data_len: u16 = 0, // 0 = sentinel (recv thread exiting)
            data: [1500]u8 = undefined,
        };

        pub fn push(self: *@This(), entry: Entry) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            const next = (self.tail + 1) % capacity;
            if (next == self.head) return false;
            self.items[self.tail] = entry;
            self.tail = next;
            return true;
        }

        pub fn pop(self: *@This()) ?Entry {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.head == self.tail) return null;
            const item = self.items[self.head];
            self.head = (self.head + 1) % capacity;
            return item;
        }
    };

    /// Lock-free SPSC ring buffer for fd dispatch.
    /// Producer: Dispatcher thread (push). Consumer: Worker thread (pop).
    /// Classic Lamport queue — no CAS, no mutex, just atomic load/store.
    pub const FdQueue = struct {
        fds: [max_pending_fds]PendingFd = undefined,
        /// Written by consumer (Worker), read by producer (Dispatcher).
        head: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        /// Written by producer (Dispatcher), read by consumer (Worker).
        tail: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

        pub const PendingFd = struct {
            fd: std.posix.fd_t,
            src_addr: ?std.net.Address,
            local_addr: ?std.net.Address = null, // SendThrough: local IP for outbound bind
            listener_id: u8 = 0,
        };

        /// Push a new fd (Dispatcher thread only).
        pub fn push(self: *FdQueue, fd: std.posix.fd_t, src_addr: ?std.net.Address, local_addr: ?std.net.Address, listener_id: u8) bool {
            const tail = self.tail.load(.monotonic);
            const next_tail = (tail + 1) % max_pending_fds;
            // Acquire head to see consumer's latest progress.
            if (next_tail == self.head.load(.acquire)) return false; // full
            self.fds[tail] = .{ .fd = fd, .src_addr = src_addr, .local_addr = local_addr, .listener_id = listener_id };
            // Release tail so consumer sees the written data.
            self.tail.store(next_tail, .release);
            return true;
        }

        /// Undo the last push (Producer/Dispatcher thread only).
        /// Used when notify fails after push — retracts the tail to prevent use-after-close.
        pub fn popLast(self: *FdQueue) void {
            const tail = self.tail.load(.monotonic);
            const prev_tail = if (tail == 0) max_pending_fds - 1 else tail - 1;
            self.tail.store(prev_tail, .release);
        }

        /// Pop a pending fd (Worker thread only).
        pub fn pop(self: *FdQueue) ?PendingFd {
            const head = self.head.load(.monotonic);
            // Acquire tail to see producer's written data.
            if (head == self.tail.load(.acquire)) return null; // empty
            const item = self.fds[head];
            // Release head so producer sees we've consumed.
            self.head.store((head + 1) % max_pending_fds, .release);
            return item;
        }
    };

    /// Create a new worker. Does not start the thread.
    pub fn init(id: u16, allocator: std.mem.Allocator) !Worker {
        var loop = try xev.Loop.init(.{});
        errdefer loop.deinit();

        var async_notify = try xev.Async.init();
        errdefer async_notify.deinit();

        return Worker{
            .id = id,
            .loop = loop,
            .pool = buffer_pool.BufferPool.init(allocator),
            .stats = .{},
            .logger = log.ScopedLogger.init(id, "worker"), // batch wired after move
            .allocator = allocator,
            .pending_fds = .{},
            .async_notify = async_notify,
        };
    }

    pub fn deinit(self: *Worker) void {
        self.log_batch.flushToChannel();
        for (self.listener_infos[0..self.listener_info_count]) |*info| {
            info.hot_cache.deinit(self.allocator);
        }
        // Drain connection object pool
        while (self.conn_pool_head) |head| {
            self.conn_pool_head = head.next;
            const conn: *proxy_conn.Session = @ptrCast(@alignCast(head));
            self.allocator.destroy(conn);
        }
        self.pool.deinit();
        self.async_notify.deinit();
        self.loop.deinit();
    }

    /// Start the worker in a new OS thread.
    pub fn spawn(self: *Worker) !void {
        self.running.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, Worker.run, .{self});
    }

    /// Wait for the worker thread to finish.
    pub fn join(self: *Worker) void {
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    /// Signal the worker to stop.
    pub fn stop(self: *Worker) void {
        self.running.store(false, .release);
        // Notify to wake the loop if it's waiting
        self.async_notify.notify() catch {};
    }

    /// Dispatch a new connection fd to this worker (called from dispatcher thread).
    pub fn dispatchConnection(self: *Worker, fd: std.posix.fd_t, src_addr: ?std.net.Address, local_addr: ?std.net.Address, listener_id: u8) bool {
        if (!self.pending_fds.push(fd, src_addr, local_addr, listener_id)) {
            self.logger.warn("fd queue full, dropping connection", .{});
            return false;
        }
        // Wake up the worker's event loop
        self.async_notify.notify() catch {
            // Notify failed — fd is already in queue but worker won't wake up.
            // Pop it back out so the caller can safely close it without use-after-close.
            _ = self.pending_fds.popLast();
            self.logger.err("failed to notify worker", .{});
            return false;
        };
        return true;
    }

    /// Get current active connection count (for load balancing).
    pub fn getActiveConnections(self: *const Worker) u32 {
        return self.active_connections.load(.acquire);
    }

    // ── Internal: worker thread entry point ──

    fn run(self: *Worker) void {
        self.logger.info("worker started", .{});

        // Preallocate buffer pool
        self.pool.prealloc() catch |e| {
            self.logger.warn("buffer pool prealloc failed: {}", .{e});
        };

        // Register async notification handler
        self.async_notify.wait(&self.loop, &self.async_completion, Worker, self, &onAsyncNotify);

        // Run the event loop
        self.loop.run(.until_done) catch |e| {
            self.logger.err("event loop error: {}", .{e});
        };

        self.logger.info("worker stopped (total conns={d})", .{
            self.stats.connections_total.load(.monotonic),
        });
    }

    fn onAsyncNotify(ud: ?*Worker, l: *xev.Loop, _: *xev.Completion, _: xev.Async.WaitError!void) xev.CallbackAction {
        const self = ud.?;

        // Process all pending connections
        while (self.pending_fds.pop()) |pending| {
            self.handleNewConnection(l, pending.fd, pending.src_addr, pending.local_addr, pending.listener_id);
        }

        // Process all pending DNS results
        while (self.dns_results.pop()) |dns| {
            dns.conn.onDnsResult(l, dns.result, dns.cache_hit);
        }

        // Process all pending UDP downlink packets
        while (self.udp_downlink.pop()) |entry| {
            entry.conn.onUdpDownlink(l, entry);
        }

        // Keep listening if still running
        if (self.running.load(.acquire)) {
            return .rearm;
        }

        // Shutting down: drain remaining fds and close them to prevent leaks
        while (self.pending_fds.pop()) |pending| {
            std.posix.close(pending.fd);
        }
        // Drain DNS results — close connections waiting for DNS
        while (self.dns_results.pop()) |dns| {
            dns.conn.onDnsResult(l, null, false); // null result → close
        }
        // Drain UDP downlink
        while (self.udp_downlink.pop()) |entry| {
            entry.conn.onUdpDownlink(l, entry);
        }

        return .disarm;
    }

    fn handleNewConnection(self: *Worker, loop: *xev.Loop, fd: std.posix.fd_t, src_addr: ?std.net.Address, local_addr: ?std.net.Address, listener_id: u8) void {
        self.stats.connectionOpened();
        _ = self.active_connections.fetchAdd(1, .monotonic);

        // Resolve per-listener config (ListenerInfo is the authoritative source)
        if (listener_id >= self.listener_info_count) {
            self.logger.err("invalid listener_id={d} (max={d}), dropping connection", .{ listener_id, self.listener_info_count });
            std.posix.close(fd);
            _ = self.active_connections.fetchSub(1, .monotonic);
            self.stats.connectionClosed();
            return;
        }
        const info = self.listener_infos[listener_id];
        const protocol = info.protocol;
        const use_tls = info.tls_enabled;
        const fb_addr = info.fallback_addr;
        const inbound_tag: []const u8 = if (info.tag_len > 0) info.getTag() else "";
        const conn_tls_ctx = info.tls_ctx;
        const conn_user_store = info.user_store;

        // Create proxy connection (full pipeline: TLS → protocol → relay)
        const conn = proxy_conn.Session.create(fd, self, protocol, use_tls, fb_addr, inbound_tag, conn_tls_ctx, conn_user_store, listener_id) orelse {
            std.posix.close(fd);
            _ = self.active_connections.fetchSub(1, .monotonic);
            self.stats.connectionClosed();
            return;
        };

        conn.metrics.src_addr = src_addr;
        if (src_addr) |sa| conn.cfg.logger.setClientIp(sa);
        conn.cfg.local_addr = local_addr;
        conn.start(loop);
    }

    pub fn connectionClosed(self: *Worker) void {
        const active = self.active_connections.fetchSub(1, .monotonic) -% 1;
        self.stats.connectionClosed();

        if (active == 0) {
            // All connections closed — immediate full shrink to reclaim all idle memory
            self.pool.shrink(0);
        } else {
            // Periodic shrink: every 8 closes, keep only active/4 headroom
            self.close_counter +%= 1;
            if (self.close_counter % 8 == 0) {
                self.pool.shrink(active);
            }
        }
    }
};

// ── Tests ──

test "FdQueue push pop single" {
    var q = Worker.FdQueue{};
    const dummy_fd: std.posix.fd_t = @ptrFromInt(42);
    try std.testing.expect(q.push(dummy_fd, null, null, 0));
    const item = q.pop().?;
    try std.testing.expectEqual(dummy_fd, item.fd);
    try std.testing.expect(item.src_addr == null);
}

test "FdQueue push pop multiple FIFO" {
    var q = Worker.FdQueue{};
    for (0..5) |i| {
        const fd: std.posix.fd_t = @ptrFromInt(100 + i);
        try std.testing.expect(q.push(fd, null, null, 0));
    }
    for (0..5) |i| {
        const item = q.pop().?;
        try std.testing.expectEqual(@as(std.posix.fd_t, @ptrFromInt(100 + i)), item.fd);
    }
    try std.testing.expect(q.pop() == null);
}

test "FdQueue full returns false" {
    var q = Worker.FdQueue{};
    // Fill the queue (capacity is max_pending_fds - 1 due to ring buffer)
    for (0..Worker.max_pending_fds - 1) |i| {
        const fd: std.posix.fd_t = @ptrFromInt(i + 1);
        try std.testing.expect(q.push(fd, null, null, 0));
    }
    // Next push should fail
    const overflow_fd: std.posix.fd_t = @ptrFromInt(9999);
    try std.testing.expect(!q.push(overflow_fd, null, null, 0));
}

test "FdQueue empty returns null" {
    var q = Worker.FdQueue{};
    try std.testing.expect(q.pop() == null);
}

test "FdQueue wrap around" {
    var q = Worker.FdQueue{};
    // Fill and drain multiple times to force wrap
    for (0..3) |round| {
        for (0..100) |i| {
            const fd: std.posix.fd_t = @ptrFromInt(round * 1000 + i + 1);
            try std.testing.expect(q.push(fd, null, null, 0));
        }
        for (0..100) |i| {
            const item = q.pop().?;
            try std.testing.expectEqual(@as(std.posix.fd_t, @ptrFromInt(round * 1000 + i + 1)), item.fd);
        }
        try std.testing.expect(q.pop() == null);
    }
}

test "DnsResultQueue push pop" {
    var q = Worker.DnsResultQueue{};

    const dummy_conn: *proxy_conn.Session = @ptrFromInt(@alignOf(proxy_conn.Session));

    for (0..700) |i| {
        try std.testing.expect(q.push(.{
            .conn = dummy_conn,
            .result = null,
            .cache_hit = (i % 2) == 0,
        }));
    }

    for (0..700) |i| {
        const entry = q.pop().?;
        try std.testing.expectEqual(dummy_conn, entry.conn);
        try std.testing.expectEqual((i % 2) == 0, entry.cache_hit);
    }
    try std.testing.expect(q.pop() == null);

    // Push again after drain to exercise wrap-around.
    for (0..300) |_| {
        try std.testing.expect(q.push(.{
            .conn = dummy_conn,
            .result = null,
            .cache_hit = false,
        }));
    }

    var count: usize = 0;
    while (q.pop()) |_| count += 1;
    try std.testing.expectEqual(@as(usize, 300), count);
}
