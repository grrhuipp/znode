/// Sharded statistics — cache-line aligned hot/cold counters.
///
/// Hot counters (bytes_up/down) updated per I/O op → separate cache line.
/// Cold counters (connections, errors) updated per connection → separate cache line.
const std = @import("std");
const types = @import("../common/types.zig");

/// Hot stats: updated every I/O operation (relay loop).
/// 64-byte aligned to avoid false sharing.
const HotShard = struct {
    bytes_up: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bytes_down: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    _pad: [48]u8 = undefined, // pad to 64 bytes

    fn addUp(self: *HotShard, n: u64) void {
        _ = self.bytes_up.fetchAdd(n, .monotonic);
    }
    fn addDown(self: *HotShard, n: u64) void {
        _ = self.bytes_down.fetchAdd(n, .monotonic);
    }
};

/// Cold stats: updated per connection open/close.
/// 64-byte aligned to avoid false sharing.
const ColdShard = struct {
    conn_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    conn_active: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    _pad: [40]u8 = undefined, // pad to 64 bytes

    fn onAccepted(self: *ColdShard) void {
        _ = self.conn_total.fetchAdd(1, .monotonic);
        _ = self.conn_active.fetchAdd(1, .monotonic);
    }
    fn onClosed(self: *ColdShard) void {
        _ = self.conn_active.fetchSub(1, .monotonic);
    }
    fn onError(self: *ColdShard) void {
        _ = self.errors.fetchAdd(1, .monotonic);
    }
};

/// Per-worker stats shard.
pub const StatsShard = struct {
    hot: HotShard = .{},
    cold: ColdShard = .{},

    pub fn onAccepted(self: *StatsShard) void {
        self.cold.onAccepted();
    }
    pub fn onClosed(self: *StatsShard) void {
        self.cold.onClosed();
    }
    pub fn onError(self: *StatsShard) void {
        self.cold.onError();
    }
    pub fn addBytesUp(self: *StatsShard, n: usize) void {
        self.hot.addUp(@intCast(n));
    }
    pub fn addBytesDown(self: *StatsShard, n: usize) void {
        self.hot.addDown(@intCast(n));
    }
};

/// Per-connection local accumulator (no atomics, batch-commit on close).
pub const LocalAccumulator = struct {
    bytes_up: u64 = 0,
    bytes_down: u64 = 0,

    pub fn addUp(self: *LocalAccumulator, n: usize) void {
        self.bytes_up += @intCast(n);
    }
    pub fn addDown(self: *LocalAccumulator, n: usize) void {
        self.bytes_down += @intCast(n);
    }

    pub fn commit(self: *const LocalAccumulator, shard: *StatsShard) void {
        if (self.bytes_up > 0) _ = shard.hot.bytes_up.fetchAdd(self.bytes_up, .monotonic);
        if (self.bytes_down > 0) _ = shard.hot.bytes_down.fetchAdd(self.bytes_down, .monotonic);
    }
};

pub const Snapshot = struct {
    active_connections: u64,
    total_connections: u64,
    bytes_up: u64,
    bytes_down: u64,
    errors: u64,
};

/// Global stats aggregator across multiple shards.
pub const ShardedStats = struct {
    shards: []StatsShard,

    pub fn init(allocator: std.mem.Allocator, num_workers: usize) !ShardedStats {
        const n = @max(num_workers, 1);
        const shards = try allocator.alloc(StatsShard, n);
        for (shards) |*s| s.* = .{};
        return .{ .shards = shards };
    }

    pub fn getShard(self: *ShardedStats, worker_id: u32) *StatsShard {
        return &self.shards[worker_id % self.shards.len];
    }

    pub fn aggregate(self: *const ShardedStats) Snapshot {
        var snap = Snapshot{
            .active_connections = 0,
            .total_connections = 0,
            .bytes_up = 0,
            .bytes_down = 0,
            .errors = 0,
        };
        for (self.shards) |*s| {
            snap.bytes_up += s.hot.bytes_up.load(.monotonic);
            snap.bytes_down += s.hot.bytes_down.load(.monotonic);
            snap.total_connections += s.cold.conn_total.load(.monotonic);
            snap.active_connections += s.cold.conn_active.load(.monotonic);
            snap.errors += s.cold.errors.load(.monotonic);
        }
        return snap;
    }

    pub fn log(self: *const ShardedStats) void {
        const s = self.aggregate();
        var up_buf: [32]u8 = undefined;
        var down_buf: [32]u8 = undefined;
        const up = types.formatBytes(s.bytes_up, &up_buf);
        const down = types.formatBytes(s.bytes_down, &down_buf);

        std.log.info("conn={d}/{d} up={s} down={s} err={d}", .{
            s.active_connections,
            s.total_connections,
            up,
            down,
            s.errors,
        });
    }
};

// Keep backward-compatible Stats alias (single shard)
pub const Stats = StatsShard;
