const std = @import("std");
const api_client = @import("api_client.zig");

/// Cross-thread per-user traffic collector.
///
/// Workers call `record()` when a connection closes to accumulate traffic.
/// The Panel thread calls `swapAndCollect()` periodically to harvest data.
///
/// Lock contention is minimal because:
/// - `record()` is called once per connection close (not per packet)
/// - `swapAndCollect()` is called once per report interval (e.g. every 60s)
/// - Mutex hold time is very short (HashMap lookup + addition)
pub const TrafficCollector = struct {
    mutex: std.Thread.Mutex = .{},
    entries: std.AutoHashMap(i64, TrafficEntry),
    allocator: std.mem.Allocator,

    pub const TrafficEntry = struct {
        bytes_up: u64 = 0,
        bytes_down: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator) TrafficCollector {
        return .{
            .entries = std.AutoHashMap(i64, TrafficEntry).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TrafficCollector) void {
        self.entries.deinit();
    }

    /// Record traffic for a user. Called by Worker threads on connection close.
    pub fn record(self: *TrafficCollector, user_id: i64, bytes_up: u64, bytes_down: u64) void {
        if (user_id < 0) return; // Unauthenticated connections
        if (bytes_up == 0 and bytes_down == 0) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        const result = self.entries.getOrPut(user_id) catch return;
        if (!result.found_existing) {
            result.value_ptr.* = .{};
        }
        result.value_ptr.bytes_up += bytes_up;
        result.value_ptr.bytes_down += bytes_down;
    }

    /// Harvest all accumulated traffic data and reset.
    /// Called by Panel thread on report interval.
    /// Caller owns the returned slice and must free it.
    pub fn swapAndCollect(self: *TrafficCollector, allocator: std.mem.Allocator) ![]api_client.TrafficData {
        self.mutex.lock();
        defer self.mutex.unlock();

        const count = self.entries.count();
        if (count == 0) return &.{};

        const data = try allocator.alloc(api_client.TrafficData, count);
        errdefer allocator.free(data);

        var idx: usize = 0;
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            data[idx] = .{
                .user_id = entry.key_ptr.*,
                .bytes_up = entry.value_ptr.bytes_up,
                .bytes_down = entry.value_ptr.bytes_down,
            };
            idx += 1;
        }

        self.entries.clearRetainingCapacity();

        return data;
    }

    /// Get the number of users with pending traffic data.
    pub fn pendingCount(self: *TrafficCollector) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.count();
    }
};

// ── Tests ──

const testing = std.testing;

test "TrafficCollector record single user" {
    var tc = TrafficCollector.init(testing.allocator);
    defer tc.deinit();

    tc.record(1, 100, 200);
    try testing.expectEqual(@as(usize, 1), tc.pendingCount());

    const data = try tc.swapAndCollect(testing.allocator);
    defer testing.allocator.free(data);

    try testing.expectEqual(@as(usize, 1), data.len);
    try testing.expectEqual(@as(i64, 1), data[0].user_id);
    try testing.expectEqual(@as(u64, 100), data[0].bytes_up);
    try testing.expectEqual(@as(u64, 200), data[0].bytes_down);
}

test "TrafficCollector accumulate same user" {
    var tc = TrafficCollector.init(testing.allocator);
    defer tc.deinit();

    tc.record(1, 100, 200);
    tc.record(1, 50, 80);
    tc.record(1, 30, 20);

    try testing.expectEqual(@as(usize, 1), tc.pendingCount());

    const data = try tc.swapAndCollect(testing.allocator);
    defer testing.allocator.free(data);

    try testing.expectEqual(@as(usize, 1), data.len);
    try testing.expectEqual(@as(u64, 180), data[0].bytes_up);
    try testing.expectEqual(@as(u64, 300), data[0].bytes_down);
}

test "TrafficCollector multiple users" {
    var tc = TrafficCollector.init(testing.allocator);
    defer tc.deinit();

    tc.record(1, 100, 200);
    tc.record(2, 300, 400);
    tc.record(3, 50, 60);

    try testing.expectEqual(@as(usize, 3), tc.pendingCount());

    const data = try tc.swapAndCollect(testing.allocator);
    defer testing.allocator.free(data);

    try testing.expectEqual(@as(usize, 3), data.len);

    // Verify total traffic
    var total_up: u64 = 0;
    var total_down: u64 = 0;
    for (data) |d| {
        total_up += d.bytes_up;
        total_down += d.bytes_down;
    }
    try testing.expectEqual(@as(u64, 450), total_up);
    try testing.expectEqual(@as(u64, 660), total_down);
}

test "TrafficCollector ignores negative user_id" {
    var tc = TrafficCollector.init(testing.allocator);
    defer tc.deinit();

    tc.record(-1, 100, 200);
    try testing.expectEqual(@as(usize, 0), tc.pendingCount());
}

test "TrafficCollector ignores zero traffic" {
    var tc = TrafficCollector.init(testing.allocator);
    defer tc.deinit();

    tc.record(1, 0, 0);
    try testing.expectEqual(@as(usize, 0), tc.pendingCount());
}

test "TrafficCollector swapAndCollect clears entries" {
    var tc = TrafficCollector.init(testing.allocator);
    defer tc.deinit();

    tc.record(1, 100, 200);
    tc.record(2, 300, 400);

    const data1 = try tc.swapAndCollect(testing.allocator);
    defer testing.allocator.free(data1);
    try testing.expectEqual(@as(usize, 2), data1.len);

    // After swap, should be empty
    try testing.expectEqual(@as(usize, 0), tc.pendingCount());

    // New records go into fresh map
    tc.record(1, 50, 60);
    const data2 = try tc.swapAndCollect(testing.allocator);
    defer testing.allocator.free(data2);
    try testing.expectEqual(@as(usize, 1), data2.len);
    try testing.expectEqual(@as(u64, 50), data2[0].bytes_up);
}
