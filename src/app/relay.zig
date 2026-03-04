/// TCP relay — bidirectional forwarding with token bucket rate limiting.
///
/// Spawns two threads: uplink (client→target) and downlink (target→client).
/// Uses atomic EOF flags for half-close handling.
/// Per-connection token bucket for downstream rate limiting.
const std = @import("std");
const stats_mod = @import("stats.zig");

pub const RelayResult = struct {
    bytes_up: u64 = 0,
    bytes_down: u64 = 0,
    err: ?anyerror = null,
};

pub const RelayConfig = struct {
    speed_limit: u64 = 0, // bytes/sec, 0 = unlimited
    uplink_only_timeout_ms: u64 = 2000,
    downlink_only_timeout_ms: u64 = 5000,
};

const Direction = enum { uplink, downlink };

const RelayState = struct {
    client: *std.net.Stream,
    target: *std.net.Stream,
    stats: ?*stats_mod.StatsShard,
    config: RelayConfig,
    uplink_eof: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    downlink_eof: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    bytes_up: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bytes_down: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn closeBoth(self: *RelayState) void {
        if (self.closed.cmpxchgStrong(false, true, .acq_rel, .acquire) == null) {
            self.client.close();
            self.target.close();
        }
    }
};

/// Execute bidirectional relay between client and target streams.
pub fn doRelay(
    client: *std.net.Stream,
    target: *std.net.Stream,
    shard: ?*stats_mod.StatsShard,
    config: RelayConfig,
) RelayResult {
    var state = RelayState{
        .client = client,
        .target = target,
        .stats = shard,
        .config = config,
    };

    // Spawn uplink thread (client → target)
    const ul_thread = std.Thread.spawn(.{}, relayWorker, .{ &state, Direction.uplink }) catch {
        if (shard) |s| s.onError();
        return .{ .err = error.ThreadSpawnFailed };
    };

    // Run downlink in current thread (target → client)
    relayWorker(&state, Direction.downlink);
    ul_thread.join();
    state.closeBoth();

    return .{
        .bytes_up = state.bytes_up.load(.monotonic),
        .bytes_down = state.bytes_down.load(.monotonic),
    };
}

/// Execute relay with initial payload sent to target first.
pub fn doRelayWithFirstPacket(
    client: *std.net.Stream,
    target: *std.net.Stream,
    first_packet: []const u8,
    shard: ?*stats_mod.StatsShard,
    config: RelayConfig,
) RelayResult {
    // Send first packet to target
    if (first_packet.len > 0) {
        target.writeAll(first_packet) catch |err| {
            if (shard) |s| s.onError();
            return .{ .err = err };
        };
        if (shard) |s| s.addBytesUp(first_packet.len);
    }

    var result = doRelay(client, target, shard, config);
    result.bytes_up += first_packet.len;
    return result;
}

fn relayWorker(state: *RelayState, direction: Direction) void {
    const from: *std.net.Stream = if (direction == .uplink) state.client else state.target;
    const to: *std.net.Stream = if (direction == .uplink) state.target else state.client;

    var bucket = TokenBucket.init(
        if (direction == .downlink) state.config.speed_limit else 0,
    );

    var buf: [32 * 1024]u8 = undefined;

    while (true) {
        // Check if peer direction has closed
        const peer_eof = if (direction == .uplink)
            state.downlink_eof.load(.acquire)
        else
            state.uplink_eof.load(.acquire);

        if (peer_eof) break;

        const n = from.read(&buf) catch {
            if (state.stats) |s| s.onError();
            break;
        };

        if (n == 0) {
            // EOF — set our flag
            if (direction == .uplink) {
                state.uplink_eof.store(true, .release);
            } else {
                state.downlink_eof.store(true, .release);
            }

            // Half-close wait
            const timeout_ms = if (direction == .uplink)
                state.config.uplink_only_timeout_ms
            else
                state.config.downlink_only_timeout_ms;

            if (timeout_ms > 0) {
                waitForPeerEof(state, direction, timeout_ms);
            }
            break;
        }

        // Rate limit (downstream only)
        if (direction == .downlink) {
            const wait_ms = bucket.consume(n);
            if (wait_ms > 0) {
                std.Thread.sleep(wait_ms * std.time.ns_per_ms);
            }
        }

        to.writeAll(buf[0..n]) catch {
            if (state.stats) |s| s.onError();
            break;
        };

        if (direction == .uplink) {
            _ = state.bytes_up.fetchAdd(@intCast(n), .monotonic);
            if (state.stats) |s| s.addBytesUp(n);
        } else {
            _ = state.bytes_down.fetchAdd(@intCast(n), .monotonic);
            if (state.stats) |s| s.addBytesDown(n);
        }
    }

    state.closeBoth();
}

fn waitForPeerEof(state: *RelayState, direction: Direction, timeout_ms: u64) void {
    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (std.time.milliTimestamp() < deadline) {
        const peer_closed = if (direction == .uplink)
            state.downlink_eof.load(.acquire)
        else
            state.uplink_eof.load(.acquire);

        if (peer_closed) break;
        std.Thread.sleep(10 * std.time.ns_per_ms); // 10ms poll
    }
}

// ── Token Bucket Rate Limiter ────────────────────────────────────────────

const TokenBucket = struct {
    rate: u64, // bytes/sec, 0 = unlimited
    tokens: u64,
    last_time_ms: i64,

    fn init(rate: u64) TokenBucket {
        return .{
            .rate = rate,
            .tokens = rate * 2, // initial burst = 2× rate
            .last_time_ms = std.time.milliTimestamp(),
        };
    }

    /// Consume `bytes` tokens. Returns wait time in milliseconds (0 = immediate).
    fn consume(self: *TokenBucket, bytes: usize) u64 {
        if (self.rate == 0) return 0;

        const now = std.time.milliTimestamp();
        const elapsed_ms: u64 = @intCast(@max(now - self.last_time_ms, 0));
        self.last_time_ms = now;

        // Refill tokens
        const new_tokens = (self.rate * elapsed_ms) / 1000;
        self.tokens = @min(self.tokens + new_tokens, self.rate * 2); // cap at 2× rate

        const needed: u64 = @intCast(bytes);
        if (self.tokens >= needed) {
            self.tokens -= needed;
            return 0;
        }

        // Not enough tokens — calculate wait
        const deficit = needed - self.tokens;
        self.tokens = 0;
        return (deficit * 1000) / self.rate + 1;
    }
};

const RelayError = error{
    ThreadSpawnFailed,
};

// ── StreamAdapter — type-erased stream for relay ─────────────────────────

/// Type-erased stream adapter for relay with any stream type.
/// Function pointer overhead is negligible vs I/O syscall cost.
pub const StreamAdapter = struct {
    ctx: *anyopaque,
    read_fn: *const fn (*anyopaque, []u8) anyerror!usize,
    write_all_fn: *const fn (*anyopaque, []const u8) anyerror!void,
    close_fn: *const fn (*anyopaque) void,

    pub fn read(self: *const StreamAdapter, buf: []u8) !usize {
        return self.read_fn(self.ctx, buf);
    }

    pub fn writeAll(self: *const StreamAdapter, data: []const u8) !void {
        return self.write_all_fn(self.ctx, data);
    }

    pub fn close(self: *const StreamAdapter) void {
        self.close_fn(self.ctx);
    }

    /// Create a StreamAdapter from any type with read/write/close methods.
    pub fn from(comptime T: type, ptr: *T) StreamAdapter {
        return .{
            .ctx = @ptrCast(ptr),
            .read_fn = struct {
                fn f(ctx: *anyopaque, buf: []u8) anyerror!usize {
                    const self: *T = @ptrCast(@alignCast(ctx));
                    return self.read(buf);
                }
            }.f,
            .write_all_fn = struct {
                fn f(ctx: *anyopaque, data: []const u8) anyerror!void {
                    const self: *T = @ptrCast(@alignCast(ctx));
                    // Try writeAll if available, otherwise loop write
                    if (@hasDecl(T, "writeAll")) {
                        return self.writeAll(data);
                    } else {
                        var sent: usize = 0;
                        while (sent < data.len) {
                            const n = try self.write(data[sent..]);
                            if (n == 0) return error.BrokenPipe;
                            sent += n;
                        }
                    }
                }
            }.f,
            .close_fn = struct {
                fn f(ctx: *anyopaque) void {
                    const self: *T = @ptrCast(@alignCast(ctx));
                    self.close();
                }
            }.f,
        };
    }

    /// No-op adapter (for cases where close is managed externally).
    pub fn noop() StreamAdapter {
        return .{
            .ctx = undefined,
            .read_fn = struct {
                fn f(_: *anyopaque, _: []u8) anyerror!usize {
                    return 0;
                }
            }.f,
            .write_all_fn = struct {
                fn f(_: *anyopaque, _: []const u8) anyerror!void {}
            }.f,
            .close_fn = struct {
                fn f(_: *anyopaque) void {}
            }.f,
        };
    }

    /// Create a StreamAdapter from std.net.Stream (value-receiver methods).
    pub fn fromNetStream(ptr: *std.net.Stream) StreamAdapter {
        return .{
            .ctx = @ptrCast(ptr),
            .read_fn = struct {
                fn f(ctx: *anyopaque, buf: []u8) anyerror!usize {
                    const s: *std.net.Stream = @ptrCast(@alignCast(ctx));
                    return s.read(buf);
                }
            }.f,
            .write_all_fn = struct {
                fn f(ctx: *anyopaque, data: []const u8) anyerror!void {
                    const s: *std.net.Stream = @ptrCast(@alignCast(ctx));
                    return s.writeAll(data);
                }
            }.f,
            .close_fn = struct {
                fn f(ctx: *anyopaque) void {
                    const s: *std.net.Stream = @ptrCast(@alignCast(ctx));
                    s.close();
                }
            }.f,
        };
    }
};

// ── StreamAdapter-based relay ────────────────────────────────────────────

const AdaptedState = struct {
    client: StreamAdapter,
    target: StreamAdapter,
    stats: ?*stats_mod.StatsShard,
    cfg: RelayConfig,
    uplink_eof: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    downlink_eof: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    bytes_up: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bytes_down: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn closeBoth(self: *AdaptedState) void {
        if (self.closed.cmpxchgStrong(false, true, .acq_rel, .acquire) == null) {
            self.client.close();
            self.target.close();
        }
    }
};

/// Bidirectional relay using StreamAdapter (type-erased streams).
/// Supports VMess/SS chunked streams on either side.
pub fn doRelayAdapted(
    client: StreamAdapter,
    target: StreamAdapter,
    shard: ?*stats_mod.StatsShard,
    cfg: RelayConfig,
) RelayResult {
    var state = AdaptedState{
        .client = client,
        .target = target,
        .stats = shard,
        .cfg = cfg,
    };

    const ul_thread = std.Thread.spawn(.{}, adaptedWorker, .{ &state, Direction.uplink }) catch {
        if (shard) |s| s.onError();
        return .{ .err = error.ThreadSpawnFailed };
    };

    adaptedWorker(&state, Direction.downlink);
    ul_thread.join();
    state.closeBoth();

    return .{
        .bytes_up = state.bytes_up.load(.monotonic),
        .bytes_down = state.bytes_down.load(.monotonic),
    };
}

/// StreamAdapter relay with initial payload sent to target first.
pub fn doRelayAdaptedWithFirstPacket(
    client: StreamAdapter,
    target: StreamAdapter,
    first_packet: []const u8,
    shard: ?*stats_mod.StatsShard,
    cfg: RelayConfig,
) RelayResult {
    if (first_packet.len > 0) {
        target.writeAll(first_packet) catch |err| {
            if (shard) |s| s.onError();
            return .{ .err = err };
        };
        if (shard) |s| s.addBytesUp(first_packet.len);
    }

    var result = doRelayAdapted(client, target, shard, cfg);
    result.bytes_up += first_packet.len;
    return result;
}

fn adaptedWorker(state: *AdaptedState, direction: Direction) void {
    const from: *const StreamAdapter = if (direction == .uplink) &state.client else &state.target;
    const to: *const StreamAdapter = if (direction == .uplink) &state.target else &state.client;

    var bucket = TokenBucket.init(
        if (direction == .downlink) state.cfg.speed_limit else 0,
    );

    var buf: [32 * 1024]u8 = undefined;

    while (true) {
        const peer_eof = if (direction == .uplink)
            state.downlink_eof.load(.acquire)
        else
            state.uplink_eof.load(.acquire);

        if (peer_eof) break;

        const n = from.read(&buf) catch {
            if (state.stats) |s| s.onError();
            break;
        };

        if (n == 0) {
            if (direction == .uplink) {
                state.uplink_eof.store(true, .release);
            } else {
                state.downlink_eof.store(true, .release);
            }

            const timeout_ms = if (direction == .uplink)
                state.cfg.uplink_only_timeout_ms
            else
                state.cfg.downlink_only_timeout_ms;

            if (timeout_ms > 0) {
                waitForPeerEofAdapted(state, direction, timeout_ms);
            }
            break;
        }

        if (direction == .downlink) {
            const wait_ms = bucket.consume(n);
            if (wait_ms > 0) {
                std.Thread.sleep(wait_ms * std.time.ns_per_ms);
            }
        }

        to.writeAll(buf[0..n]) catch {
            if (state.stats) |s| s.onError();
            break;
        };

        if (direction == .uplink) {
            _ = state.bytes_up.fetchAdd(@intCast(n), .monotonic);
            if (state.stats) |s| s.addBytesUp(n);
        } else {
            _ = state.bytes_down.fetchAdd(@intCast(n), .monotonic);
            if (state.stats) |s| s.addBytesDown(n);
        }
    }

    state.closeBoth();
}

fn waitForPeerEofAdapted(state: *AdaptedState, direction: Direction, timeout_ms: u64) void {
    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (std.time.milliTimestamp() < deadline) {
        const peer_closed = if (direction == .uplink)
            state.downlink_eof.load(.acquire)
        else
            state.uplink_eof.load(.acquire);

        if (peer_closed) break;
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }
}
