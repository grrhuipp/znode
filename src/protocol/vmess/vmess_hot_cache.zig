const std = @import("std");
const vmess_crypto = @import("vmess_crypto.zig");

/// Per-worker VMess hot user cache.
/// Caches recently authenticated users' derived keys for fast re-authentication.
/// Entries are keyed by user ID and evicted by TTL. No upper size limit.
///
/// The cache stores keys independently (not pointers into UserMap), so RCU swaps
/// do not invalidate cached entries. After a hot-cache hit, the caller must verify
/// the user still exists in the current UserMap via findById().
pub const HotCache = struct {
    pub const Entry = struct {
        cmd_key: [16]u8,
        auth_key: [16]u8,
        last_seen: i64,
    };

    pub const default_ttl: i64 = 300; // 5 minutes
    const cleanup_interval: i64 = 60;

    entries: std.AutoHashMapUnmanaged(i64, Entry) = .{},
    ttl: i64,
    last_cleanup: i64 = 0,

    pub fn init(ttl: i64) HotCache {
        return .{ .ttl = if (ttl > 0) ttl else default_ttl };
    }

    pub fn deinit(self: *HotCache, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
    }

    /// Try to authenticate an AuthID against cached entries.
    /// Returns (cmd_key, user_id) on match, null on miss.
    pub fn tryAuth(
        self: *HotCache,
        auth_id: vmess_crypto.AuthID,
        now: i64,
        allocator: std.mem.Allocator,
    ) ?struct { cmd_key: [16]u8, user_id: i64 } {
        // Lazy cleanup
        if (now - self.last_cleanup >= cleanup_interval) {
            self.evictExpired(now);
            self.last_cleanup = now;
        }

        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const entry = kv.value_ptr;
            // Skip expired entries
            if (now - entry.last_seen > self.ttl) continue;
            // Try AES-ECB decrypt + CRC32 check
            if (vmess_crypto.validateAuthId(auth_id, entry.auth_key, now)) |_| {
                entry.last_seen = now;
                return .{ .cmd_key = entry.cmd_key, .user_id = kv.key_ptr.* };
            }
        }
        _ = allocator;
        return null;
    }

    /// Record a successful authentication in the cache.
    pub fn recordAuth(
        self: *HotCache,
        user_id: i64,
        cmd_key: [16]u8,
        auth_key: [16]u8,
        now: i64,
        allocator: std.mem.Allocator,
    ) void {
        const gop = self.entries.getOrPut(allocator, user_id) catch return;
        gop.value_ptr.* = .{
            .cmd_key = cmd_key,
            .auth_key = auth_key,
            .last_seen = now,
        };
    }

    /// Remove a specific user from the cache (e.g. after user removal from UserMap).
    pub fn evictUser(self: *HotCache, user_id: i64) void {
        _ = self.entries.fetchRemove(user_id);
    }

    /// Remove all entries whose last_seen + ttl < now.
    fn evictExpired(self: *HotCache, now: i64) void {
        // Collect expired keys first to avoid modifying map during iteration
        var to_remove: [256]i64 = undefined;
        var remove_count: usize = 0;

        var it = self.entries.iterator();
        while (it.next()) |kv| {
            if (now - kv.value_ptr.last_seen > self.ttl) {
                if (remove_count < to_remove.len) {
                    to_remove[remove_count] = kv.key_ptr.*;
                    remove_count += 1;
                }
            }
        }

        for (to_remove[0..remove_count]) |id| {
            _ = self.entries.fetchRemove(id);
        }
    }
};

// ── Tests ──

test "HotCache init and deinit" {
    const allocator = std.testing.allocator;
    var cache = HotCache.init(60);
    defer cache.deinit(allocator);

    try std.testing.expectEqual(@as(i64, 60), cache.ttl);
    try std.testing.expectEqual(@as(usize, 0), cache.entries.count());
}

test "HotCache recordAuth and tryAuth roundtrip" {
    const allocator = std.testing.allocator;
    var cache = HotCache.init(300);
    defer cache.deinit(allocator);

    // Generate a valid AuthID for a known user
    const uuid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const cmd_key = vmess_crypto.deriveCmdKey(uuid);
    const auth_key = vmess_crypto.deriveAuthKey(cmd_key);

    const now: i64 = 1700000000;
    const auth_id = vmess_crypto.generateAuthIdWithRandom(auth_key, now, 0x12345678);

    // Record auth
    cache.recordAuth(42, cmd_key, auth_key, now, allocator);
    try std.testing.expectEqual(@as(usize, 1), cache.entries.count());

    // tryAuth should hit
    const hit = cache.tryAuth(auth_id, now, allocator).?;
    try std.testing.expectEqual(@as(i64, 42), hit.user_id);
    try std.testing.expectEqual(cmd_key, hit.cmd_key);
}

test "HotCache miss returns null" {
    const allocator = std.testing.allocator;
    var cache = HotCache.init(300);
    defer cache.deinit(allocator);

    // Random AuthID should not match anything
    const fake_auth_id = [_]u8{0xff} ** 16;
    try std.testing.expect(cache.tryAuth(fake_auth_id, 1700000000, allocator) == null);
}

test "HotCache expired entries not matched" {
    const allocator = std.testing.allocator;
    var cache = HotCache.init(10); // 10 second TTL
    defer cache.deinit(allocator);

    const uuid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const cmd_key = vmess_crypto.deriveCmdKey(uuid);
    const auth_key = vmess_crypto.deriveAuthKey(cmd_key);

    const t0: i64 = 1700000000;
    cache.recordAuth(1, cmd_key, auth_key, t0, allocator);

    // 15 seconds later, entry should be expired
    const t1 = t0 + 15;
    const auth_id = vmess_crypto.generateAuthIdWithRandom(auth_key, t1, 0xAABBCCDD);
    try std.testing.expect(cache.tryAuth(auth_id, t1, allocator) == null);
}

test "HotCache evictUser removes entry" {
    const allocator = std.testing.allocator;
    var cache = HotCache.init(300);
    defer cache.deinit(allocator);

    const key = [_]u8{0xAA} ** 16;
    cache.recordAuth(99, key, key, 1700000000, allocator);
    try std.testing.expectEqual(@as(usize, 1), cache.entries.count());

    cache.evictUser(99);
    try std.testing.expectEqual(@as(usize, 0), cache.entries.count());
}

test "HotCache lazy cleanup sweeps expired" {
    const allocator = std.testing.allocator;
    var cache = HotCache.init(10); // 10s TTL
    defer cache.deinit(allocator);

    const key = [_]u8{0xBB} ** 16;
    const t0: i64 = 1700000000;
    cache.recordAuth(1, key, key, t0, allocator);
    cache.recordAuth(2, key, key, t0, allocator);
    cache.recordAuth(3, key, key, t0 + 50, allocator); // fresh entry
    try std.testing.expectEqual(@as(usize, 3), cache.entries.count());

    // Trigger cleanup at t0 + 61 (>= cleanup_interval from last_cleanup=0)
    // Users 1 and 2 (last_seen=t0) should be expired (t0+61 - t0 = 61 > 10)
    // User 3 (last_seen=t0+50) should survive (t0+61 - (t0+50) = 11 > 10)... also expired
    // Let's adjust: user 3 at t0+55
    cache.entries.getPtr(3).?.last_seen = t0 + 55;

    const fake_auth = [_]u8{0xff} ** 16;
    _ = cache.tryAuth(fake_auth, t0 + 61, allocator); // triggers cleanup

    // Users 1,2 expired (61-0=61 > 10), user 3 also expired (61-55=6 < 10? no, 61-55=6 ≤ 10)
    // Wait: now - last_seen > ttl means 61-55=6 > 10 is false, so user 3 survives
    try std.testing.expectEqual(@as(usize, 1), cache.entries.count());
    try std.testing.expect(cache.entries.get(3) != null);
}
