/// Per-IP connection rate limiter — lock-free open-addressing hash table.
///
/// Features:
///   - Per-IP concurrent connection limit
///   - Per-IP new connections/second rate limit
///   - Auth failure counting with time-based bans
///   - 64-byte cache-line aligned slots
///   - FNV-1a hashing, linear probing (max 32)
const std = @import("std");

pub const RateLimitConfig = struct {
    max_connections: u32 = 0,
    max_conn_per_ip: u32 = 0,
    max_rate_per_ip: u32 = 0,
    auth_fail_limit: u32 = 10,
    auth_fail_window: u32 = 60,
    auth_ban_seconds: u32 = 180,
};

pub const CheckResult = enum {
    allowed,
    global_limit,
    ip_conn_limit,
    ip_rate_limit,
    ip_banned,
};

const max_probe = 32;

/// 64-byte aligned slot for per-IP state.
const Slot = extern struct {
    hash: std.atomic.Value(u64) align(64) = std.atomic.Value(u64).init(0),
    conns: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    rate: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    rate_ts: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    auth_fails: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    auth_ts: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    ban_until: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    _pad: [8]u32 = .{0} ** 8,

    fn clear(self: *Slot) void {
        self.conns.store(0, .monotonic);
        self.rate.store(0, .monotonic);
        self.rate_ts.store(0, .monotonic);
        self.auth_fails.store(0, .monotonic);
        self.auth_ts.store(0, .monotonic);
        self.ban_until.store(0, .monotonic);
    }
};

comptime {
    if (@sizeOf(Slot) != 64) @compileError("Slot must be 64 bytes");
}

pub fn RateLimiter(comptime N: usize) type {
    const mask: usize = N - 1;

    return struct {
        const Self = @This();

        slots: [N]Slot = [_]Slot{.{}} ** N,
        total: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        config: RateLimitConfig,

        pub fn init(cfg: RateLimitConfig) Self {
            return .{ .config = cfg };
        }

        /// Check if a connection from `ip` is allowed.
        /// On success, increments connection counters; caller must call `release` on disconnect.
        pub fn check(self: *Self, ip: []const u8) CheckResult {
            const now: u32 = @intCast(@as(u64, @bitCast(std.time.timestamp())) & 0xFFFFFFFF);

            // Global limit
            if (self.config.max_connections > 0) {
                const cur = self.total.fetchAdd(1, .acq_rel);
                if (cur >= self.config.max_connections) {
                    _ = self.total.fetchSub(1, .acq_rel);
                    return .global_limit;
                }
            }

            // Per-IP check
            if (self.config.max_conn_per_ip == 0 and self.config.max_rate_per_ip == 0) {
                return .allowed;
            }

            const h = fnv1a64(ip);
            const slot = self.findOrCreate(h, now) orelse return .allowed; // graceful degradation

            // Ban check
            const ban = slot.ban_until.load(.acquire);
            if (ban > 0 and ban > now) {
                if (self.config.max_connections > 0) _ = self.total.fetchSub(1, .acq_rel);
                return .ip_banned;
            }

            // Connection limit
            if (self.config.max_conn_per_ip > 0) {
                const conns = slot.conns.fetchAdd(1, .acq_rel);
                if (conns >= self.config.max_conn_per_ip) {
                    _ = slot.conns.fetchSub(1, .acq_rel);
                    if (self.config.max_connections > 0) _ = self.total.fetchSub(1, .acq_rel);
                    return .ip_conn_limit;
                }
            }

            // Rate limit
            if (self.config.max_rate_per_ip > 0) {
                const ts = slot.rate_ts.load(.acquire);
                if (ts != now) {
                    slot.rate.store(1, .release);
                    slot.rate_ts.store(now, .release);
                } else {
                    const r = slot.rate.fetchAdd(1, .acq_rel);
                    if (r >= self.config.max_rate_per_ip) {
                        if (self.config.max_conn_per_ip > 0) _ = slot.conns.fetchSub(1, .acq_rel);
                        if (self.config.max_connections > 0) _ = self.total.fetchSub(1, .acq_rel);
                        return .ip_rate_limit;
                    }
                }
            }

            return .allowed;
        }

        /// Release counters on disconnect.
        pub fn release(self: *Self, ip: []const u8) void {
            if (self.config.max_connections > 0) _ = self.total.fetchSub(1, .acq_rel);

            if (self.config.max_conn_per_ip > 0) {
                const h = fnv1a64(ip);
                if (self.find(h)) |slot| {
                    _ = slot.conns.fetchSub(1, .acq_rel);
                }
            }
        }

        /// Record an auth failure for `ip`. May trigger a ban.
        pub fn recordAuthFail(self: *Self, ip: []const u8) void {
            if (self.config.auth_fail_limit == 0) return;
            const now: u32 = @intCast(@as(u64, @bitCast(std.time.timestamp())) & 0xFFFFFFFF);
            const h = fnv1a64(ip);
            const slot = self.findOrCreate(h, now) orelse return;

            const prev_ts = slot.auth_ts.load(.acquire);
            // 1-second dedup
            if (prev_ts == now) return;

            // Window reset
            if (now > prev_ts and now - prev_ts > self.config.auth_fail_window) {
                slot.auth_fails.store(0, .release);
            }

            slot.auth_ts.store(now, .release);
            const fails = slot.auth_fails.fetchAdd(1, .acq_rel) + 1;
            if (fails >= self.config.auth_fail_limit) {
                slot.ban_until.store(now + self.config.auth_ban_seconds, .release);
                std.log.warn("IP 被封禁: 认证失败过多", .{});
            }
        }

        fn find(self: *Self, h: u64) ?*Slot {
            const start = h & mask;
            for (0..max_probe) |i| {
                const idx = (start + i) & mask;
                const slot_hash = self.slots[idx].hash.load(.acquire);
                if (slot_hash == h) return &self.slots[idx];
                if (slot_hash == 0) return null;
            }
            return null;
        }

        fn findOrCreate(self: *Self, h: u64, now: u32) ?*Slot {
            const start = h & mask;
            var first_idle: ?*Slot = null;

            for (0..max_probe) |i| {
                const idx = (start + i) & mask;
                const slot = &self.slots[idx];
                const slot_hash = slot.hash.load(.acquire);

                if (slot_hash == h) return slot;
                if (slot_hash == 0) {
                    // Try to claim empty slot
                    if (slot.hash.cmpxchgStrong(0, h, .acq_rel, .acquire) == null) {
                        return slot;
                    }
                    // CAS failed — re-check if it's ours now
                    if (slot.hash.load(.acquire) == h) return slot;
                    continue;
                }

                // Track first idle slot (conns==0, not banned) for eviction
                if (first_idle == null) {
                    const conns = slot.conns.load(.acquire);
                    const ban = slot.ban_until.load(.acquire);
                    if (conns == 0 and (ban == 0 or ban <= now)) {
                        first_idle = slot;
                    }
                }
            }

            // Evict idle slot
            if (first_idle) |slot| {
                slot.hash.store(h, .release);
                slot.clear();
                return slot;
            }

            return null; // table full, graceful degradation
        }
    };
}

/// Default rate limiter with 65536 slots.
pub const DefaultRateLimiter = RateLimiter(65536);

fn fnv1a64(data: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (data) |b| {
        h ^= b;
        h *%= 0x100000001b3;
    }
    return h;
}
