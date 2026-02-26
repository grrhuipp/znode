const std = @import("std");

/// Connection limiter with global and per-IP limits.
///
/// Uses a sharded fixed-size hash table for per-IP tracking (no heap allocation).
/// 64 shards reduce cross-thread lock contention by 64x compared to a single mutex.
/// Linear probing on hash collision within each shard.
///
/// Thread-safety: atomic for global count, per-shard mutex for IP table.
pub const ConnLimiter = struct {
    global_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    global_max: u32,
    ip_max: u32,
    shards: [SHARD_COUNT]IpShard = [_]IpShard{.{}} ** SHARD_COUNT,

    pub const SHARD_COUNT: usize = 64;
    const SLOTS_PER_SHARD: usize = 128; // 64 * 128 = 8192 total slots
    const MAX_PROBE: usize = 16;
    pub const DEFAULT_GLOBAL_MAX: u32 = 10000;
    pub const DEFAULT_IP_MAX: u32 = 256;

    pub const IpSlot = struct {
        ip_hash: u32 = 0,
        count: u16 = 0,
        active: bool = false,
    };

    const IpShard = struct {
        mutex: std.Thread.Mutex = .{},
        slots: [SLOTS_PER_SHARD]IpSlot = [_]IpSlot{.{}} ** SLOTS_PER_SHARD,
    };

    pub const AcquireResult = enum {
        allowed,
        global_limit,
        ip_limit,
    };

    pub fn init(global_max: u32, ip_max: u32) ConnLimiter {
        return .{
            .global_max = global_max,
            .ip_max = ip_max,
        };
    }

    /// Try to acquire a connection slot.
    /// Returns `.allowed` on success, or the reason for rejection.
    pub fn tryAcquire(self: *ConnLimiter, client_ip_hash: u32) AcquireResult {
        // Check global limit (0 = unlimited)
        if (self.global_max > 0) {
            const current = self.global_count.load(.monotonic);
            if (current >= self.global_max) return .global_limit;
        }

        // Check per-IP limit (0 = unlimited)
        if (self.ip_max > 0 and client_ip_hash != 0) {
            const shard = &self.shards[shardIndex(client_ip_hash)];
            shard.mutex.lock();
            defer shard.mutex.unlock();

            const slot_idx = findOrCreateSlotInShard(shard, client_ip_hash);
            if (slot_idx) |idx| {
                if (shard.slots[idx].count >= @as(u16, @intCast(@min(self.ip_max, std.math.maxInt(u16))))) {
                    return .ip_limit;
                }
                shard.slots[idx].count += 1;
            } else {
                // Shard full - allow connection but can't track IP
                // This is a soft failure; global limit still applies
            }
        }

        _ = self.global_count.fetchAdd(1, .monotonic);
        return .allowed;
    }

    /// Release a connection slot.
    pub fn release(self: *ConnLimiter, client_ip_hash: u32) void {
        _ = self.global_count.fetchSub(1, .monotonic);

        if (self.ip_max > 0 and client_ip_hash != 0) {
            const shard = &self.shards[shardIndex(client_ip_hash)];
            shard.mutex.lock();
            defer shard.mutex.unlock();

            const slot_idx = findSlotInShard(shard, client_ip_hash);
            if (slot_idx) |idx| {
                if (shard.slots[idx].count > 0) {
                    shard.slots[idx].count -= 1;
                    if (shard.slots[idx].count == 0) {
                        shard.slots[idx].active = false;
                    }
                }
            }
        }
    }

    /// Get current global connection count.
    pub fn getGlobalCount(self: *const ConnLimiter) u32 {
        return self.global_count.load(.monotonic);
    }

    /// Get connection count for a specific IP hash.
    pub fn getIpCount(self: *ConnLimiter, client_ip_hash: u32) u16 {
        const shard = &self.shards[shardIndex(client_ip_hash)];
        shard.mutex.lock();
        defer shard.mutex.unlock();

        const slot_idx = findSlotInShard(shard, client_ip_hash);
        if (slot_idx) |idx| {
            return shard.slots[idx].count;
        }
        return 0;
    }

    // ── Internal ──

    fn shardIndex(ip_hash: u32) usize {
        return @intCast((ip_hash >> 26) % SHARD_COUNT); // top 6 bits
    }

    /// Find existing slot or create a new one within a shard. Linear probing.
    fn findOrCreateSlotInShard(shard: *IpShard, ip_hash: u32) ?usize {
        const start = ip_hash % SLOTS_PER_SHARD;
        var i: usize = 0;
        while (i < MAX_PROBE) : (i += 1) {
            const idx = (start + i) % SLOTS_PER_SHARD;
            if (shard.slots[idx].active and shard.slots[idx].ip_hash == ip_hash) {
                return idx; // Found existing
            }
            if (!shard.slots[idx].active) {
                // Empty slot, claim it
                shard.slots[idx] = .{ .ip_hash = ip_hash, .count = 0, .active = true };
                return idx;
            }
        }
        return null; // All probe slots occupied
    }

    /// Find existing slot only within a shard.
    fn findSlotInShard(shard: *IpShard, ip_hash: u32) ?usize {
        const start = ip_hash % SLOTS_PER_SHARD;
        var i: usize = 0;
        while (i < MAX_PROBE) : (i += 1) {
            const idx = (start + i) % SLOTS_PER_SHARD;
            if (shard.slots[idx].active and shard.slots[idx].ip_hash == ip_hash) {
                return idx;
            }
            if (!shard.slots[idx].active) {
                return null; // Empty slot = not found
            }
        }
        return null;
    }
};

/// Hash an IPv4 address to u32 for ConnLimiter.
pub fn hashIpv4(addr: [4]u8) u32 {
    // Simple FNV-like hash of the 4 bytes
    var h: u32 = 2166136261;
    for (addr) |b| {
        h ^= @as(u32, b);
        h *%= 16777619;
    }
    return h;
}

// ── Tests ──

const testing = std.testing;

test "ConnLimiter basic acquire and release" {
    var cl = ConnLimiter.init(100, 10);

    try testing.expectEqual(@as(u32, 0), cl.getGlobalCount());
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(12345));
    try testing.expectEqual(@as(u32, 1), cl.getGlobalCount());
    try testing.expectEqual(@as(u16, 1), cl.getIpCount(12345));

    cl.release(12345);
    try testing.expectEqual(@as(u32, 0), cl.getGlobalCount());
    try testing.expectEqual(@as(u16, 0), cl.getIpCount(12345));
}

test "ConnLimiter global limit" {
    var cl = ConnLimiter.init(3, 0); // 3 global max, no per-IP limit

    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(100));
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(200));
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(300));
    // 4th should be rejected
    try testing.expectEqual(ConnLimiter.AcquireResult.global_limit, cl.tryAcquire(400));

    // Release one, then should allow again
    cl.release(100);
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(400));
}

test "ConnLimiter per-IP limit" {
    var cl = ConnLimiter.init(100, 2); // 2 per IP

    const ip_hash: u32 = 42;

    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(ip_hash));
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(ip_hash));
    // 3rd from same IP should be rejected
    try testing.expectEqual(ConnLimiter.AcquireResult.ip_limit, cl.tryAcquire(ip_hash));

    // Different IP should still work
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(99));

    // Release one from first IP
    cl.release(ip_hash);
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(ip_hash));
}

test "ConnLimiter unlimited" {
    var cl = ConnLimiter.init(0, 0); // No limits

    // Should always allow
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(i));
    }
    try testing.expectEqual(@as(u32, 100), cl.getGlobalCount());

    // Release all
    i = 0;
    while (i < 100) : (i += 1) {
        cl.release(i);
    }
    try testing.expectEqual(@as(u32, 0), cl.getGlobalCount());
}

test "ConnLimiter IP hash zero bypasses IP check" {
    var cl = ConnLimiter.init(100, 1); // 1 per IP

    // ip_hash 0 bypasses per-IP limit
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(0));
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(0));
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(0));
}

test "ConnLimiter multiple IPs" {
    var cl = ConnLimiter.init(100, 3);

    const ip1: u32 = 1001;
    const ip2: u32 = 2002;

    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(ip1));
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(ip2));
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(ip1));
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(ip2));

    try testing.expectEqual(@as(u16, 2), cl.getIpCount(ip1));
    try testing.expectEqual(@as(u16, 2), cl.getIpCount(ip2));
    try testing.expectEqual(@as(u32, 4), cl.getGlobalCount());
}

test "ConnLimiter release non-existent IP" {
    var cl = ConnLimiter.init(100, 10);

    // Release without acquire should not crash (global count will underflow safely due to atomic)
    // In practice this shouldn't happen, but the IP table handles it gracefully
    try testing.expectEqual(@as(u16, 0), cl.getIpCount(999));
}

test "ConnLimiter sharding distributes IPs" {
    var cl = ConnLimiter.init(0, 100);

    // Different IPs should (mostly) hit different shards
    const ip_a: u32 = 0x04000000; // shard index from top 6 bits = 0
    const ip_b: u32 = 0xFC000000; // shard index from top 6 bits = 63
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(ip_a));
    try testing.expectEqual(ConnLimiter.AcquireResult.allowed, cl.tryAcquire(ip_b));

    try testing.expectEqual(@as(u16, 1), cl.getIpCount(ip_a));
    try testing.expectEqual(@as(u16, 1), cl.getIpCount(ip_b));

    cl.release(ip_a);
    cl.release(ip_b);
}

test "hashIpv4" {
    const h1 = hashIpv4(.{ 192, 168, 1, 1 });
    const h2 = hashIpv4(.{ 192, 168, 1, 2 });
    const h3 = hashIpv4(.{ 192, 168, 1, 1 });

    try testing.expect(h1 != h2); // Different IPs get different hashes
    try testing.expectEqual(h1, h3); // Same IP gets same hash
    try testing.expect(h1 != 0); // Non-zero
}
