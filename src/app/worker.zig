/// Worker architecture — SO_REUSEPORT multi-threaded accept model.
///
/// Each Worker runs in its own thread with:
///   - Independent TCP listeners (SO_REUSEPORT shares port across workers)
///   - Per-worker DNS cache
///   - Per-worker user managers (updated via atomic snapshot)
///   - Per-worker traffic accumulator
///   - Thread pool for connection handling
const std = @import("std");
const config = @import("../infra/config.zig");
const types = @import("../common/types.zig");

pub const WorkerConfig = struct {
    worker_id: u32,
    total_workers: u32,
    inbounds: []const config.InboundConfig,
    timeouts: config.TimeoutsConfig,
    limits: config.LimitsConfig,
};

/// Per-worker traffic accumulator (lock-free for single-worker access).
pub const WorkerTraffic = struct {
    entries: std.AutoHashMap(i64, Traffic),

    const Traffic = struct {
        upload: u64 = 0,
        download: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator) WorkerTraffic {
        return .{ .entries = std.AutoHashMap(i64, Traffic).init(allocator) };
    }

    pub fn add(self: *WorkerTraffic, user_id: i64, up: u64, down: u64) void {
        if (user_id <= 0) return;
        const gop = self.entries.getOrPut(user_id) catch return;
        if (gop.found_existing) {
            gop.value_ptr.upload += up;
            gop.value_ptr.download += down;
        } else {
            gop.value_ptr.* = .{ .upload = up, .download = down };
        }
    }

    /// Collect and reset traffic. Returns entries and clears accumulator.
    pub fn collectAndReset(self: *WorkerTraffic, allocator: std.mem.Allocator) ![]TrafficEntry {
        var list = std.array_list.Managed(TrafficEntry).init(allocator);
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.upload > 0 or entry.value_ptr.download > 0) {
                try list.append(.{
                    .user_id = entry.key_ptr.*,
                    .upload = entry.value_ptr.upload,
                    .download = entry.value_ptr.download,
                });
            }
        }
        self.entries.clearRetainingCapacity();
        return try list.toOwnedSlice();
    }
};

pub const TrafficEntry = struct {
    user_id: i64,
    upload: u64,
    download: u64,
};

/// Set SO_REUSEPORT on a socket (Linux only).
pub fn setReusePort(fd: std.posix.socket_t) !void {
    // SO_REUSEPORT = 15 on Linux
    const SO_REUSEPORT = 15;
    const val: c_int = 1;
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, SO_REUSEPORT, std.mem.asBytes(&val)) catch |err| {
        // Not available on all platforms, log and continue
        std.log.warn("SO_REUSEPORT 设置失败: {s}", .{@errorName(err)});
        return err;
    };
}

/// Create a listener with SO_REUSEPORT enabled.
pub fn createReusePortListener(address: std.net.Address) !std.net.Server {
    const server = try address.listen(.{
        .reuse_address = true,
        .kernel_backlog = 1024,
    });

    // Try to set SO_REUSEPORT (may fail on non-Linux)
    setReusePort(server.stream.handle) catch {};

    return server;
}

/// Worker-level connection counter with global cap.
pub const ConnectionGuard = struct {
    active: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    max: u32,

    pub fn init(max_connections: u32) ConnectionGuard {
        return .{ .max = max_connections };
    }

    /// Try to acquire a connection slot. Returns false if at limit.
    pub fn acquire(self: *ConnectionGuard) bool {
        if (self.max == 0) return true; // unlimited
        const cur = self.active.fetchAdd(1, .acq_rel);
        if (cur >= self.max) {
            _ = self.active.fetchSub(1, .acq_rel);
            return false;
        }
        return true;
    }

    pub fn release(self: *ConnectionGuard) void {
        if (self.max == 0) return;
        _ = self.active.fetchSub(1, .acq_rel);
    }

    pub fn count(self: *const ConnectionGuard) u32 {
        return self.active.load(.acquire);
    }
};
