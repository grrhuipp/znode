const std = @import("std");

/// Cache-line aligned atomic statistics shard.
/// Each worker owns one shard to minimize false sharing.
pub const StatsShard = struct {
    // Hot data: frequently updated, own cache line
    bytes_in: std.atomic.Value(u64) align(64) = std.atomic.Value(u64).init(0),
    bytes_out: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // Cold data: connection-level updates, own cache line
    connections_total: std.atomic.Value(u64) align(64) = std.atomic.Value(u64).init(0),
    connections_active: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    errors_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // Single-writer helpers: avoid x86 `lock xadd` (~20ns) by using
    // load+store (~1ns). Safe because only the owning Worker thread writes.
    pub fn addBytesIn(self: *StatsShard, n: u64) void {
        self.bytes_in.store(self.bytes_in.load(.monotonic) +% n, .monotonic);
    }

    pub fn addBytesOut(self: *StatsShard, n: u64) void {
        self.bytes_out.store(self.bytes_out.load(.monotonic) +% n, .monotonic);
    }

    pub fn connectionOpened(self: *StatsShard) void {
        self.connections_total.store(self.connections_total.load(.monotonic) +% 1, .monotonic);
        self.connections_active.store(self.connections_active.load(.monotonic) +% 1, .monotonic);
    }

    pub fn connectionClosed(self: *StatsShard) void {
        self.connections_active.store(self.connections_active.load(.monotonic) -% 1, .monotonic);
    }

    pub fn addError(self: *StatsShard) void {
        self.errors_total.store(self.errors_total.load(.monotonic) +% 1, .monotonic);
    }

    pub fn snapshot(self: *const StatsShard) Snapshot {
        return .{
            .bytes_in = self.bytes_in.load(.monotonic),
            .bytes_out = self.bytes_out.load(.monotonic),
            .connections_total = self.connections_total.load(.monotonic),
            .connections_active = self.connections_active.load(.monotonic),
            .errors_total = self.errors_total.load(.monotonic),
        };
    }
};

pub const Snapshot = struct {
    bytes_in: u64,
    bytes_out: u64,
    connections_total: u64,
    connections_active: u64,
    errors_total: u64,
};

/// Aggregates snapshots from multiple worker shards.
pub fn aggregate(shards: []const *const StatsShard) Snapshot {
    var result = Snapshot{
        .bytes_in = 0,
        .bytes_out = 0,
        .connections_total = 0,
        .connections_active = 0,
        .errors_total = 0,
    };
    for (shards) |shard| {
        const s = shard.snapshot();
        result.bytes_in += s.bytes_in;
        result.bytes_out += s.bytes_out;
        result.connections_total += s.connections_total;
        result.connections_active += s.connections_active;
        result.errors_total += s.errors_total;
    }
    return result;
}

/// Format bytes as human-readable string.
pub fn formatBytes(bytes: u64) struct { value: f64, unit: []const u8 } {
    if (bytes >= 1024 * 1024 * 1024) {
        return .{ .value = @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0 * 1024.0), .unit = "GB" };
    } else if (bytes >= 1024 * 1024) {
        return .{ .value = @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0), .unit = "MB" };
    } else if (bytes >= 1024) {
        return .{ .value = @as(f64, @floatFromInt(bytes)) / 1024.0, .unit = "KB" };
    } else {
        return .{ .value = @as(f64, @floatFromInt(bytes)), .unit = "B" };
    }
}

test "StatsShard basic operations" {
    var shard = StatsShard{};
    shard.addBytesIn(100);
    shard.addBytesOut(200);
    shard.connectionOpened();
    shard.connectionOpened();
    shard.connectionClosed();

    const s = shard.snapshot();
    try std.testing.expectEqual(@as(u64, 100), s.bytes_in);
    try std.testing.expectEqual(@as(u64, 200), s.bytes_out);
    try std.testing.expectEqual(@as(u64, 2), s.connections_total);
    try std.testing.expectEqual(@as(u64, 1), s.connections_active);
}

test "aggregate multiple shards" {
    var shard1 = StatsShard{};
    var shard2 = StatsShard{};
    shard1.addBytesIn(100);
    shard1.addBytesOut(200);
    shard1.connectionOpened();
    shard2.addBytesIn(300);
    shard2.addBytesOut(400);
    shard2.connectionOpened();
    shard2.connectionOpened();
    shard2.addError();

    const ptrs = [_]*const StatsShard{ &shard1, &shard2 };
    const result = aggregate(&ptrs);
    try std.testing.expectEqual(@as(u64, 400), result.bytes_in);
    try std.testing.expectEqual(@as(u64, 600), result.bytes_out);
    try std.testing.expectEqual(@as(u64, 3), result.connections_total);
    try std.testing.expectEqual(@as(u64, 3), result.connections_active);
    try std.testing.expectEqual(@as(u64, 1), result.errors_total);
}

test "formatBytes units" {
    const b = formatBytes(500);
    try std.testing.expectEqualStrings("B", b.unit);

    const kb = formatBytes(2048);
    try std.testing.expectEqualStrings("KB", kb.unit);
    try std.testing.expect(kb.value == 2.0);

    const mb = formatBytes(5 * 1024 * 1024);
    try std.testing.expectEqualStrings("MB", mb.unit);
    try std.testing.expect(mb.value == 5.0);

    const gb = formatBytes(3 * 1024 * 1024 * 1024);
    try std.testing.expectEqualStrings("GB", gb.unit);
    try std.testing.expect(gb.value == 3.0);
}
