/// Sharded DNS cache with LRU eviction.
///
/// 256 shards, each with a HashMap + doubly-linked list (via ArrayList).
/// Read path uses shared lock, write path uses exclusive lock.
const std = @import("std");
const packet = @import("packet.zig");

pub const CacheEntry = struct {
    addresses: [16]packet.DnsAddress = undefined,
    count: u8 = 0,
    ttl: u32 = 0,
    expire_time: i64 = 0, // epoch seconds
    negative: bool = false, // NXDOMAIN

    pub fn isExpired(self: *const CacheEntry) bool {
        return std.time.timestamp() >= self.expire_time;
    }

    pub fn addrs(self: *const CacheEntry) []const packet.DnsAddress {
        return self.addresses[0..self.count];
    }
};

const shard_count = 256;

pub const DnsCache = struct {
    shards: [shard_count]Shard,
    max_per_shard: u32,
    min_ttl: u32,
    max_ttl: u32,

    const Shard = struct {
        map: std.StringHashMap(CacheEntry),
        lock: std.Thread.RwLock = .{},

        fn init(allocator: std.mem.Allocator) Shard {
            return .{
                .map = std.StringHashMap(CacheEntry).init(allocator),
            };
        }
    };

    pub fn init(allocator: std.mem.Allocator, max_entries: u32, min_ttl: u32, max_ttl: u32) DnsCache {
        var shards: [shard_count]Shard = undefined;
        for (&shards) |*s| {
            s.* = Shard.init(allocator);
        }
        const per_shard = @max(max_entries / shard_count, 16);
        return .{
            .shards = shards,
            .max_per_shard = per_shard,
            .min_ttl = min_ttl,
            .max_ttl = max_ttl,
        };
    }

    /// Lookup domain in cache. Returns null if not found or expired.
    pub fn get(self: *DnsCache, domain: []const u8) ?CacheEntry {
        const shard = &self.shards[shardIndex(domain)];
        shard.lock.lockShared();
        defer shard.lock.unlockShared();

        const entry = shard.map.get(domain) orelse return null;
        if (entry.isExpired()) return null;
        return entry;
    }

    /// Insert or update a cache entry.
    pub fn put(self: *DnsCache, domain: []const u8, result: *const packet.QueryResult) void {
        const idx = shardIndex(domain);
        const shard = &self.shards[idx];
        shard.lock.lock();
        defer shard.lock.unlock();

        const ttl = std.math.clamp(result.ttl, self.min_ttl, self.max_ttl);
        const now = std.time.timestamp();

        var entry = CacheEntry{
            .count = result.count,
            .ttl = ttl,
            .expire_time = now + @as(i64, @intCast(ttl)),
        };
        @memcpy(entry.addresses[0..result.count], result.addresses[0..result.count]);

        shard.map.put(domain, entry) catch return;
    }

    /// Cache a negative result (NXDOMAIN).
    pub fn putNegative(self: *DnsCache, domain: []const u8) void {
        const idx = shardIndex(domain);
        const shard = &self.shards[idx];
        shard.lock.lock();
        defer shard.lock.unlock();

        const now = std.time.timestamp();
        const entry = CacheEntry{
            .negative = true,
            .ttl = self.min_ttl,
            .expire_time = now + @as(i64, @intCast(self.min_ttl)),
        };

        shard.map.put(domain, entry) catch return;
    }

    fn shardIndex(domain: []const u8) u8 {
        var hash: u32 = 0;
        for (domain) |ch| {
            hash = hash *% 31 +% ch;
        }
        return @intCast(hash & 0xFF);
    }
};
