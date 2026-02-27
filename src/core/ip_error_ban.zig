const std = @import("std");
const zio = @import("zio");

/// Per-IP error counter with temporary ban.
///
/// Rule:
/// - if one IP hits `error_threshold` errors within `window_ms`,
///   ban that IP for `ban_ms`.
/// - threshold=0 disables the feature.
///
/// Design:
/// - fixed-size sharded hash table, no heap allocation
/// - per-shard mutex for low lock contention
pub const IpErrorBan = struct {
    error_threshold: u16 = 15,
    window_ms: u64 = 60 * 1000,
    ban_ms: u64 = 5 * 60 * 1000,

    shards: [SHARD_COUNT]Shard = [_]Shard{.{}} ** SHARD_COUNT,

    const SHARD_COUNT: usize = 64;
    const SLOTS_PER_SHARD: usize = 128;
    const MAX_PROBE: usize = 16;

    const Slot = struct {
        ip_hash: u32 = 0,
        active: bool = false,
        window_start_ms: i64 = 0,
        error_count: u16 = 0,
        ban_until_ms: i64 = 0,
        last_seen_ms: i64 = 0,
    };

    const Shard = struct {
        mutex: std.Thread.Mutex = .{},
        slots: [SLOTS_PER_SHARD]Slot = [_]Slot{.{}} ** SLOTS_PER_SHARD,
    };

    pub const RecordEvent = struct {
        counted: bool = false,
        banned_now: bool = false,
        error_count: u16 = 0,
        ban_until_ms: i64 = 0,
    };

    pub fn init(error_threshold: u16, window_sec: u16, ban_sec: u16) IpErrorBan {
        return .{
            .error_threshold = error_threshold,
            .window_ms = @as(u64, window_sec) * 1000,
            .ban_ms = @as(u64, ban_sec) * 1000,
        };
    }

    pub fn enabled(self: *const IpErrorBan) bool {
        return self.error_threshold > 0 and self.window_ms > 0 and self.ban_ms > 0;
    }

    pub fn threshold(self: *const IpErrorBan) u16 {
        return self.error_threshold;
    }

    pub fn windowSeconds(self: *const IpErrorBan) u16 {
        return @intCast(self.window_ms / 1000);
    }

    pub fn banSeconds(self: *const IpErrorBan) u16 {
        return @intCast(self.ban_ms / 1000);
    }

    /// Check whether an IP is currently banned.
    pub fn isBanned(self: *IpErrorBan, ip_hash: u32, now_ms: i64) bool {
        if (!self.enabled() or ip_hash == 0) return false;

        const shard = &self.shards[shardIndex(ip_hash)];
        shard.mutex.lock();
        defer shard.mutex.unlock();

        if (findSlot(shard, ip_hash)) |idx| {
            const slot = &shard.slots[idx];
            slot.last_seen_ms = now_ms;
            if (slot.ban_until_ms > now_ms) return true;
            if (slot.ban_until_ms != 0 and slot.ban_until_ms <= now_ms) {
                slot.ban_until_ms = 0;
                slot.error_count = 0;
                slot.window_start_ms = 0;
            }
        }
        return false;
    }

    /// Record one error for an IP. May trigger ban.
    pub fn recordError(self: *IpErrorBan, ip_hash: u32, now_ms: i64) RecordEvent {
        if (!self.enabled() or ip_hash == 0) return .{};

        const shard = &self.shards[shardIndex(ip_hash)];
        shard.mutex.lock();
        defer shard.mutex.unlock();

        const cleanup_ms = @as(i64, @intCast(@max(self.window_ms, self.ban_ms) * 2));
        const idx = findOrCreateSlot(shard, ip_hash, now_ms, cleanup_ms) orelse return .{};
        const slot = &shard.slots[idx];
        slot.last_seen_ms = now_ms;

        // Still in ban period
        if (slot.ban_until_ms > now_ms) {
            return .{
                .counted = true,
                .banned_now = false,
                .error_count = slot.error_count,
                .ban_until_ms = slot.ban_until_ms,
            };
        }

        // Ban expired: reset rolling window
        if (slot.ban_until_ms != 0 and slot.ban_until_ms <= now_ms) {
            slot.ban_until_ms = 0;
            slot.error_count = 0;
            slot.window_start_ms = 0;
        }

        const window_i64: i64 = @intCast(self.window_ms);
        if (slot.window_start_ms == 0 or now_ms - slot.window_start_ms > window_i64) {
            slot.window_start_ms = now_ms;
            slot.error_count = 1;
        } else {
            slot.error_count +|= 1;
        }

        if (slot.error_count >= self.error_threshold) {
            slot.ban_until_ms = now_ms + @as(i64, @intCast(self.ban_ms));
            slot.error_count = 0;
            slot.window_start_ms = 0;
            return .{
                .counted = true,
                .banned_now = true,
                .ban_until_ms = slot.ban_until_ms,
            };
        }

        return .{
            .counted = true,
            .error_count = slot.error_count,
            .ban_until_ms = slot.ban_until_ms,
        };
    }

    fn shardIndex(ip_hash: u32) usize {
        return @intCast((ip_hash >> 26) % SHARD_COUNT);
    }

    fn clearSlot(slot: *Slot) void {
        slot.* = .{};
    }

    fn claimSlot(slot: *Slot, ip_hash: u32, now_ms: i64) void {
        slot.* = .{
            .ip_hash = ip_hash,
            .active = true,
            .last_seen_ms = now_ms,
        };
    }

    fn canReclaim(slot: *const Slot, now_ms: i64, cleanup_ms: i64) bool {
        if (!slot.active) return true;
        if (slot.ban_until_ms > now_ms) return false;
        return now_ms - slot.last_seen_ms > cleanup_ms;
    }

    fn findSlot(shard: *Shard, ip_hash: u32) ?usize {
        const start = ip_hash % SLOTS_PER_SHARD;
        var i: usize = 0;
        while (i < MAX_PROBE) : (i += 1) {
            const idx = (start + i) % SLOTS_PER_SHARD;
            const slot = &shard.slots[idx];
            if (slot.active and slot.ip_hash == ip_hash) return idx;
            if (!slot.active) return null;
        }
        return null;
    }

    fn findOrCreateSlot(shard: *Shard, ip_hash: u32, now_ms: i64, cleanup_ms: i64) ?usize {
        const start = ip_hash % SLOTS_PER_SHARD;
        var reclaim_idx: ?usize = null;
        var i: usize = 0;
        while (i < MAX_PROBE) : (i += 1) {
            const idx = (start + i) % SLOTS_PER_SHARD;
            const slot = &shard.slots[idx];
            if (slot.active and slot.ip_hash == ip_hash) return idx;
            if (!slot.active) {
                claimSlot(slot, ip_hash, now_ms);
                return idx;
            }
            if (reclaim_idx == null and canReclaim(slot, now_ms, cleanup_ms)) {
                reclaim_idx = idx;
            }
        }

        if (reclaim_idx) |idx| {
            clearSlot(&shard.slots[idx]);
            claimSlot(&shard.slots[idx], ip_hash, now_ms);
            return idx;
        }
        return null;
    }
};

/// Hash client IP (v4 or v6) into a stable non-zero u32.
pub fn hashIpAddress(addr: zio.net.IpAddress) u32 {
    var h: u32 = 2166136261; // FNV-1a
    switch (addr.getFamily()) {
        .ipv4 => {
            const ip4 = @as(*const [4]u8, @ptrCast(&addr.in.addr)).*;
            fnv1aUpdate(&h, &ip4);
            fnv1aUpdate(&h, &[_]u8{0x04});
        },
        .ipv6 => {
            const ip6 = addr.in6.addr;
            fnv1aUpdate(&h, &ip6);
            fnv1aUpdate(&h, &[_]u8{0x06});
        },
    }
    return if (h == 0) 1 else h;
}

fn fnv1aUpdate(h: *u32, bytes: []const u8) void {
    for (bytes) |b| {
        h.* ^= @as(u32, b);
        h.* *%= 16777619;
    }
}

const testing = std.testing;

test "ip error ban triggers and expires" {
    var ban = IpErrorBan.init(3, 60, 5);
    const ip: u32 = 1234;
    const t0: i64 = 1_000;

    try testing.expect(!ban.isBanned(ip, t0));
    try testing.expect(!ban.recordError(ip, t0).banned_now);
    try testing.expect(!ban.recordError(ip, t0 + 1_000).banned_now);
    const ev = ban.recordError(ip, t0 + 2_000);
    try testing.expect(ev.banned_now);
    try testing.expect(ban.isBanned(ip, t0 + 2_500));
    try testing.expect(!ban.isBanned(ip, t0 + 8_000));
}

test "ip error ban window reset" {
    var ban = IpErrorBan.init(3, 2, 5);
    const ip: u32 = 5678;
    const t0: i64 = 10_000;

    _ = ban.recordError(ip, t0);
    _ = ban.recordError(ip, t0 + 500);
    // Outside 2s window, counter resets
    const ev = ban.recordError(ip, t0 + 2_500);
    try testing.expect(!ev.banned_now);
    try testing.expectEqual(@as(u16, 1), ev.error_count);
}

test "ip error ban disabled when threshold is zero" {
    var ban = IpErrorBan.init(0, 60, 300);
    const ip: u32 = 42;
    try testing.expect(!ban.enabled());
    try testing.expect(!ban.isBanned(ip, 0));
    try testing.expect(!ban.recordError(ip, 0).counted);
}
