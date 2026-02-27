const std = @import("std");
const vmess_crypto = @import("vmess_crypto.zig");

/// Per-listener VMess hot user cache.
///
/// Data structure: HashMap(user_id → *Node) + intrusive doubly-linked list
/// ordered by last_seen (head = oldest, tail = most recently seen).
///
/// This layout gives:
///   tryAuth  phase 1  O(n) AES scan          shared lock — parallel across executors
///   tryAuth  phase 2  O(1) moveToTail        exclusive lock — brief
///   evictExpired      O(k) pop from head      no restart, no allocation
///   evictLru          O(1) pop head           instant
///   recordAuth        O(1) append to tail     + map insert
///
/// Capacity is caller-driven: recordAuth accepts max_entries so the caller can
/// derive it from the live user count (e.g. @max(1, user_map.users.len / 10)).
pub const HotCache = struct {
    const Node = struct {
        user_id: i64,
        cmd_key: [16]u8,
        auth_key: [16]u8,
        last_seen: i64,
        prev: ?*Node = null,
        next: ?*Node = null,
    };

    pub const default_ttl: i64 = 300; // 5 minutes
    const cleanup_interval: i64 = 60;

    rwlock: std.Thread.RwLock = .{},
    entries: std.AutoHashMapUnmanaged(i64, *Node) = .{},
    head: ?*Node = null, // oldest last_seen (LRU eviction / TTL expiry candidate)
    tail: ?*Node = null, // most recently seen
    ttl: i64,
    last_cleanup: i64 = 0,

    pub fn init(ttl: i64) HotCache {
        return .{ .ttl = if (ttl > 0) ttl else default_ttl };
    }

    pub fn deinit(self: *HotCache, allocator: std.mem.Allocator) void {
        var node = self.head;
        while (node) |n| {
            const next = n.next;
            allocator.destroy(n);
            node = next;
        }
        self.entries.deinit(allocator);
    }

    /// Try to authenticate an AuthID against cached entries.
    /// Returns (cmd_key, user_id) on match, null on miss.
    ///
    /// Phase 1 (shared lock): O(n) AES-ECB scan — runs concurrently across executors.
    /// Phase 2 (exclusive lock): O(1) moveToTail + lazy O(k) TTL cleanup.
    pub fn tryAuth(
        self: *HotCache,
        auth_id: vmess_crypto.AuthID,
        now: i64,
        allocator: std.mem.Allocator,
    ) ?struct { cmd_key: [16]u8, user_id: i64 } {
        // ── Phase 1: parallel AES scan (shared lock) ──
        self.rwlock.lockShared();
        var found_id: ?i64 = null;
        const need_cleanup = now - self.last_cleanup >= cleanup_interval;

        var it = self.entries.valueIterator();
        while (it.next()) |node_ptr| {
            const node = node_ptr.*;
            if (now - node.last_seen > self.ttl) continue;
            if (vmess_crypto.validateAuthId(auth_id, node.auth_key, now)) |_| {
                found_id = node.user_id;
                break;
            }
        }
        self.rwlock.unlockShared();

        // ── Phase 2: writes (exclusive lock) ──
        var result_cmd_key: [16]u8 = undefined;
        var confirmed = false;

        if (found_id != null or need_cleanup) {
            self.rwlock.lock();

            if (now - self.last_cleanup >= cleanup_interval) {
                self.evictExpired(now, allocator);
                self.last_cleanup = now;
            }

            if (found_id) |uid| {
                // Re-lookup under exclusive lock: node may have been evicted between phases.
                if (self.entries.get(uid)) |node| {
                    result_cmd_key = node.cmd_key;
                    node.last_seen = now;
                    self.moveToTail(node);
                    confirmed = true;
                }
            }

            self.rwlock.unlock();
        }

        return if (confirmed) .{ .cmd_key = result_cmd_key, .user_id = found_id.? } else null;
    }

    /// Record a successful authentication.
    /// max_entries: capacity limit — caller passes @max(1, user_map.users.len / 10).
    /// New entry → append to tail. Existing entry → update in place + move to tail.
    /// At capacity with a new entry → evict head (LRU) first.
    pub fn recordAuth(
        self: *HotCache,
        user_id: i64,
        cmd_key: [16]u8,
        auth_key: [16]u8,
        now: i64,
        allocator: std.mem.Allocator,
        max_entries: usize,
    ) void {
        self.rwlock.lock();
        defer self.rwlock.unlock();

        // Existing user: update keys + move to tail.
        if (self.entries.get(user_id)) |node| {
            node.cmd_key = cmd_key;
            node.auth_key = auth_key;
            node.last_seen = now;
            self.moveToTail(node);
            return;
        }

        // New user: evict LRU if at capacity.
        if (self.entries.count() >= max_entries) {
            self.removeHead(allocator);
        }

        const node = allocator.create(Node) catch return;
        node.* = .{
            .user_id = user_id,
            .cmd_key = cmd_key,
            .auth_key = auth_key,
            .last_seen = now,
        };
        self.entries.put(allocator, user_id, node) catch {
            allocator.destroy(node);
            return;
        };
        self.appendToTail(node);
    }

    /// Remove a specific user (e.g. after removal from UserMap).
    pub fn evictUser(self: *HotCache, user_id: i64, allocator: std.mem.Allocator) void {
        self.rwlock.lock();
        defer self.rwlock.unlock();
        if (self.entries.fetchRemove(user_id)) |kv| {
            self.unlinkNode(kv.value);
            allocator.destroy(kv.value);
        }
    }

    // ── Private helpers (caller must hold rwlock exclusively) ──

    /// Pop from head while head is expired. O(k).
    fn evictExpired(self: *HotCache, now: i64, allocator: std.mem.Allocator) void {
        while (self.head) |node| {
            if (now - node.last_seen <= self.ttl) break;
            self.removeHead(allocator);
        }
    }

    /// Remove and free the head node. O(1).
    fn removeHead(self: *HotCache, allocator: std.mem.Allocator) void {
        const node = self.head orelse return;
        _ = self.entries.remove(node.user_id);
        self.head = node.next;
        if (node.next) |n| {
            n.prev = null;
        } else {
            self.tail = null;
        }
        allocator.destroy(node);
    }

    /// Unlink a node from the list without freeing it. O(1).
    fn unlinkNode(self: *HotCache, node: *Node) void {
        if (node.prev) |p| p.next = node.next else self.head = node.next;
        if (node.next) |n| n.prev = node.prev else self.tail = node.prev;
        node.prev = null;
        node.next = null;
    }

    /// Append a node to the tail. O(1).
    fn appendToTail(self: *HotCache, node: *Node) void {
        node.prev = self.tail;
        node.next = null;
        if (self.tail) |t| t.next = node else self.head = node;
        self.tail = node;
    }

    /// Move an existing node to the tail (refresh its LRU position). O(1).
    fn moveToTail(self: *HotCache, node: *Node) void {
        if (self.tail == node) return;
        self.unlinkNode(node);
        self.appendToTail(node);
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

    const uuid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const cmd_key = vmess_crypto.deriveCmdKey(uuid);
    const auth_key = vmess_crypto.deriveAuthKey(cmd_key);
    const now: i64 = 1700000000;
    const auth_id = vmess_crypto.generateAuthIdWithRandom(auth_key, now, 0x12345678);

    cache.recordAuth(42, cmd_key, auth_key, now, allocator, 100);
    try std.testing.expectEqual(@as(usize, 1), cache.entries.count());

    const hit = cache.tryAuth(auth_id, now, allocator).?;
    try std.testing.expectEqual(@as(i64, 42), hit.user_id);
    try std.testing.expectEqual(cmd_key, hit.cmd_key);
}

test "HotCache miss returns null" {
    const allocator = std.testing.allocator;
    var cache = HotCache.init(300);
    defer cache.deinit(allocator);

    const fake_auth_id = [_]u8{0xff} ** 16;
    try std.testing.expect(cache.tryAuth(fake_auth_id, 1700000000, allocator) == null);
}

test "HotCache expired entries not matched" {
    const allocator = std.testing.allocator;
    var cache = HotCache.init(10);
    defer cache.deinit(allocator);

    const uuid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const cmd_key = vmess_crypto.deriveCmdKey(uuid);
    const auth_key = vmess_crypto.deriveAuthKey(cmd_key);
    const t0: i64 = 1700000000;

    cache.recordAuth(1, cmd_key, auth_key, t0, allocator, 100);
    const auth_id = vmess_crypto.generateAuthIdWithRandom(auth_key, t0 + 15, 0xAABBCCDD);
    try std.testing.expect(cache.tryAuth(auth_id, t0 + 15, allocator) == null);
}

test "HotCache evictUser removes entry" {
    const allocator = std.testing.allocator;
    var cache = HotCache.init(300);
    defer cache.deinit(allocator);

    const key = [_]u8{0xAA} ** 16;
    cache.recordAuth(99, key, key, 1700000000, allocator, 100);
    try std.testing.expectEqual(@as(usize, 1), cache.entries.count());

    cache.evictUser(99, allocator);
    try std.testing.expectEqual(@as(usize, 0), cache.entries.count());
}

test "HotCache lazy cleanup sweeps expired from head" {
    const allocator = std.testing.allocator;
    var cache = HotCache.init(10); // 10s TTL
    defer cache.deinit(allocator);

    const key = [_]u8{0xBB} ** 16;
    const t0: i64 = 1700000000;

    // Insert in order: 1 and 2 are old (expired), 3 is fresh.
    cache.recordAuth(1, key, key, t0, allocator, 100);
    cache.recordAuth(2, key, key, t0, allocator, 100);
    cache.recordAuth(3, key, key, t0 + 55, allocator, 100); // last_seen = t0+55
    try std.testing.expectEqual(@as(usize, 3), cache.entries.count());

    // At t0+61: entries 1 and 2 expired (61-0=61 > 10), entry 3 alive (61-55=6 ≤ 10).
    const fake_auth = [_]u8{0xff} ** 16;
    _ = cache.tryAuth(fake_auth, t0 + 61, allocator);

    try std.testing.expectEqual(@as(usize, 1), cache.entries.count());
    try std.testing.expect(cache.entries.get(3) != null);
    // list head should be entry 3 now
    try std.testing.expectEqual(@as(i64, 3), cache.head.?.user_id);
    try std.testing.expectEqual(@as(i64, 3), cache.tail.?.user_id);
}

test "HotCache lazy cleanup removes all expired entries" {
    const allocator = std.testing.allocator;
    var cache = HotCache.init(10);
    defer cache.deinit(allocator);

    const key = [_]u8{0xCC} ** 16;
    const t0: i64 = 1700000000;

    var i: i64 = 0;
    while (i < 600) : (i += 1) {
        cache.recordAuth(i, key, key, t0, allocator, 1000);
    }
    try std.testing.expectEqual(@as(usize, 600), cache.entries.count());

    const fake_auth = [_]u8{0xff} ** 16;
    _ = cache.tryAuth(fake_auth, t0 + 61, allocator);

    try std.testing.expectEqual(@as(usize, 0), cache.entries.count());
    try std.testing.expect(cache.head == null);
    try std.testing.expect(cache.tail == null);
}

test "HotCache LRU eviction at capacity" {
    const allocator = std.testing.allocator;
    var cache = HotCache.init(300);
    defer cache.deinit(allocator);

    const key = [_]u8{0xDD} ** 16;
    const t0: i64 = 1700000000;
    const cap: usize = 50;

    var i: i64 = 0;
    while (i < cap) : (i += 1) {
        cache.recordAuth(i, key, key, t0 + i, allocator, cap);
    }
    try std.testing.expectEqual(cap, cache.entries.count());
    // head = user 0 (oldest), tail = user 49 (newest)
    try std.testing.expectEqual(@as(i64, 0), cache.head.?.user_id);
    try std.testing.expectEqual(@as(i64, cap - 1), cache.tail.?.user_id);

    // Insert user 9999 → evicts head (user 0)
    cache.recordAuth(9999, key, key, t0 + 9999, allocator, cap);
    try std.testing.expectEqual(cap, cache.entries.count());
    try std.testing.expect(cache.entries.get(0) == null);    // evicted
    try std.testing.expect(cache.entries.get(9999) != null); // inserted
    try std.testing.expectEqual(@as(i64, 1), cache.head.?.user_id); // new head
    try std.testing.expectEqual(@as(i64, 9999), cache.tail.?.user_id); // new tail
}

test "HotCache tryAuth hit moves node to tail" {
    const allocator = std.testing.allocator;
    var cache = HotCache.init(300);
    defer cache.deinit(allocator);

    const uuid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const cmd_key = vmess_crypto.deriveCmdKey(uuid);
    const auth_key = vmess_crypto.deriveAuthKey(cmd_key);
    const t0: i64 = 1700000000;

    const key2 = [_]u8{0xAB} ** 16;
    cache.recordAuth(1, cmd_key, auth_key, t0, allocator, 100); // head
    cache.recordAuth(2, key2, key2, t0 + 1, allocator, 100);   // tail

    // hit user 1 → moves to tail
    const auth_id = vmess_crypto.generateAuthIdWithRandom(auth_key, t0 + 2, 0xDEADBEEF);
    _ = cache.tryAuth(auth_id, t0 + 2, allocator);

    try std.testing.expectEqual(@as(i64, 2), cache.head.?.user_id); // user 2 is now head
    try std.testing.expectEqual(@as(i64, 1), cache.tail.?.user_id); // user 1 is now tail
}
