const std = @import("std");

/// 256-shard DNS cache with TTL + strict LRU eviction per shard.
///
/// Concurrency model:
/// - Lookup uses shared lock on the selected shard.
/// - Insert/eviction uses exclusive lock on the selected shard.
/// - LRU timestamp is updated on lookup via a short write lock section.
pub const DnsCache = struct {
    shards: [shard_count]Shard,
    min_ttl: u32,
    max_ttl: u32,

    pub const shard_count: usize = 256;
    const default_capacity_per_shard: usize = 16;

    pub const CachedEntry = struct {
        addresses: [max_addrs]Address = undefined,
        addr_count: u8 = 0,
        expire_at: i64 = 0,
        last_access_us: i64 = 0,
        is_negative: bool = false, // NXDOMAIN

        pub const max_addrs: usize = 8;

        pub const Address = struct {
            ip4: ?[4]u8 = null,
            ip6: ?[16]u8 = null,
        };

        pub fn isExpired(self: *const CachedEntry) bool {
            return self.isExpiredAt(std.time.timestamp());
        }

        pub fn isExpiredAt(self: *const CachedEntry, now_sec: i64) bool {
            return now_sec >= self.expire_at;
        }

        pub fn getAddresses(self: *const CachedEntry) []const Address {
            return self.addresses[0..self.addr_count];
        }
    };

    const Shard = struct {
        rwlock: std.Thread.RwLock = .{},
        entries: std.StringHashMapUnmanaged(CachedEntry) = .{},
        count: usize = 0,
        capacity: usize = default_capacity_per_shard,
        hits: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        misses: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    };

    pub fn init(min_ttl: u32, max_ttl: u32, total_capacity: usize) DnsCache {
        var cache = DnsCache{
            .shards = [_]Shard{.{}} ** shard_count,
            .min_ttl = min_ttl,
            .max_ttl = max_ttl,
        };

        const baseline = shard_count * default_capacity_per_shard;
        const effective_total = if (total_capacity > 0) @max(total_capacity, baseline) else baseline;
        const per_shard_capacity = @max(default_capacity_per_shard, (effective_total + shard_count - 1) / shard_count);
        for (&cache.shards) |*shard| {
            shard.capacity = per_shard_capacity;
        }

        return cache;
    }

    pub fn deinit(self: *DnsCache, allocator: std.mem.Allocator) void {
        for (&self.shards) |*shard| {
            shard.rwlock.lock();
            var it = shard.entries.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
            }
            shard.entries.deinit(allocator);
            shard.count = 0;
            shard.rwlock.unlock();
        }
    }

    /// Look up a domain in cache. Expired entries are treated as miss.
    pub fn lookup(self: *DnsCache, domain: []const u8) ?CachedEntry {
        const now_sec = std.time.timestamp();
        const now_us = std.time.microTimestamp();
        const shard = &self.shards[shardIndex(domain)];

        shard.rwlock.lockShared();
        const cached = shard.entries.get(domain);
        shard.rwlock.unlockShared();

        if (cached) |entry| {
            if (entry.isExpiredAt(now_sec)) {
                _ = shard.misses.fetchAdd(1, .monotonic);
                return null;
            }

            _ = shard.hits.fetchAdd(1, .monotonic);

            // Best-effort LRU touch (strict per successful lookup).
            shard.rwlock.lock();
            if (shard.entries.getPtr(domain)) |live| {
                if (!live.isExpiredAt(now_sec)) {
                    live.last_access_us = now_us;
                }
            }
            shard.rwlock.unlock();

            return entry;
        }

        _ = shard.misses.fetchAdd(1, .monotonic);
        return null;
    }

    /// Insert or update an entry with TTL clamping and LRU timestamp.
    pub fn insert(self: *DnsCache, allocator: std.mem.Allocator, domain: []const u8, entry: CachedEntry, ttl: u32) !void {
        const now_sec = std.time.timestamp();
        const now_us = std.time.microTimestamp();
        const clamped_ttl = @max(self.min_ttl, @min(ttl, self.max_ttl));

        var stored = entry;
        stored.expire_at = now_sec + @as(i64, clamped_ttl);
        stored.last_access_us = now_us;

        const shard = &self.shards[shardIndex(domain)];
        shard.rwlock.lock();
        defer shard.rwlock.unlock();

        // Update in place if key already exists.
        if (shard.entries.getPtr(domain)) |existing| {
            existing.* = stored;
            return;
        }

        // Reclaim expired entries first.
        self.evictExpiredLocked(shard, allocator, now_sec);

        // Strict LRU eviction when at capacity.
        if (shard.count >= shard.capacity) {
            self.evictLruLocked(shard, allocator, now_sec);
        }

        // Dupe the key BEFORE getOrPut to avoid leaving a dangling key
        // in the HashMap if dupe fails after getOrPut creates a new slot.
        const owned_key = try allocator.dupe(u8, domain);
        const result = shard.entries.getOrPut(allocator, domain) catch {
            allocator.free(owned_key);
            return error.OutOfMemory;
        };
        if (!result.found_existing) {
            result.key_ptr.* = owned_key;
            shard.count += 1;
        } else {
            allocator.free(owned_key);
        }
        result.value_ptr.* = stored;
    }

    /// Insert a negative cache entry (NXDOMAIN).
    pub fn insertNegative(self: *DnsCache, allocator: std.mem.Allocator, domain: []const u8) !void {
        var entry = CachedEntry{};
        entry.is_negative = true;
        try self.insert(allocator, domain, entry, self.min_ttl);
    }

    fn evictExpiredLocked(self: *DnsCache, shard: *Shard, allocator: std.mem.Allocator, now_sec: i64) void {
        _ = self;
        while (true) {
            var removed = false;
            var it = shard.entries.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.isExpiredAt(now_sec)) {
                    const key = entry.key_ptr.*;
                    if (shard.entries.fetchRemove(key)) |kv| {
                        allocator.free(kv.key);
                        shard.count -|= 1;
                    }
                    removed = true;
                    break;
                }
            }
            if (!removed) break;
        }
    }

    fn evictLruLocked(self: *DnsCache, shard: *Shard, allocator: std.mem.Allocator, now_sec: i64) void {
        _ = self;
        var victim_key: ?[]const u8 = null;
        var oldest_access: i64 = std.math.maxInt(i64);

        var it = shard.entries.iterator();
        while (it.next()) |entry| {
            const value = entry.value_ptr.*;
            if (value.isExpiredAt(now_sec)) {
                victim_key = entry.key_ptr.*;
                break; // Prefer expired as first eviction candidate.
            }
            if (value.last_access_us < oldest_access) {
                oldest_access = value.last_access_us;
                victim_key = entry.key_ptr.*;
            }
        }

        if (victim_key) |key| {
            if (shard.entries.fetchRemove(key)) |kv| {
                allocator.free(kv.key);
                shard.count -|= 1;
            }
        }
    }

    /// Get aggregate cache statistics.
    pub fn getStats(self: *DnsCache) CacheStats {
        var stats = CacheStats{};
        for (&self.shards) |*shard| {
            shard.rwlock.lockShared();
            stats.total_entries += shard.count;
            stats.total_hits += shard.hits.load(.monotonic);
            stats.total_misses += shard.misses.load(.monotonic);
            shard.rwlock.unlockShared();
        }
        return stats;
    }

    fn shardIndex(domain: []const u8) u8 {
        var hash: u32 = 2166136261;
        for (domain) |b| {
            hash ^= b;
            hash *%= 16777619;
        }
        return @truncate(hash);
    }
};

pub const CacheStats = struct {
    total_entries: usize = 0,
    total_hits: u64 = 0,
    total_misses: u64 = 0,

    pub fn hitRate(self: CacheStats) f64 {
        const total = self.total_hits + self.total_misses;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.total_hits)) / @as(f64, @floatFromInt(total)) * 100.0;
    }
};

test "DnsCache basic operations" {
    const allocator = std.testing.allocator;
    var cache = DnsCache.init(60, 3600, 4096);
    defer cache.deinit(allocator);

    // Miss on empty cache
    try std.testing.expectEqual(@as(?DnsCache.CachedEntry, null), cache.lookup("example.com"));

    // Insert and hit
    var entry = DnsCache.CachedEntry{};
    entry.addresses[0] = .{ .ip4 = .{ 93, 184, 216, 34 } };
    entry.addr_count = 1;
    try cache.insert(allocator, "example.com", entry, 300);

    const result = cache.lookup("example.com");
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u8, 1), result.?.addr_count);

    // Stats
    const stats = cache.getStats();
    try std.testing.expectEqual(@as(u64, 1), stats.total_hits);
    try std.testing.expectEqual(@as(u64, 1), stats.total_misses);
}

test "DnsCache negative entry" {
    const allocator = std.testing.allocator;
    var cache = DnsCache.init(60, 3600, 4096);
    defer cache.deinit(allocator);

    try cache.insertNegative(allocator, "nonexistent.example.com");
    const result = cache.lookup("nonexistent.example.com");
    try std.testing.expect(result != null);
    try std.testing.expect(result.?.is_negative);
}

test "DnsCache custom capacity distribution" {
    const cache = DnsCache.init(60, 3600, 8192);
    const idx = 0;
    try std.testing.expectEqual(@as(usize, 32), cache.shards[idx].capacity);
}
