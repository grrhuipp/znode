const std = @import("std");

/// Token Bucket rate limiter.
///
/// Limits throughput in bytes per second. Each `consume()` call deducts tokens;
/// tokens refill over time based on the configured rate.
///
/// Design:
/// - Capacity = rate * 2 (allows 2-second burst)
/// - Microsecond precision refill
/// - Rate of 0 means unlimited (no limiting applied)
/// - Thread-safe: single owner, no shared state
pub const RateLimiter = struct {
    tokens: u64,
    capacity: u64,
    refill_rate: u64, // bytes per second, 0 = unlimited
    last_refill_us: i64,

    pub const ConsumeResult = union(enum) {
        allowed,
        wait_us: u64,
    };

    /// Create a rate limiter with the given bytes-per-second limit.
    /// Pass 0 for unlimited throughput.
    pub fn init(rate_bytes_per_sec: u64) RateLimiter {
        const cap = if (rate_bytes_per_sec == 0) 0 else rate_bytes_per_sec * 2;
        return .{
            .tokens = cap,
            .capacity = cap,
            .refill_rate = rate_bytes_per_sec,
            .last_refill_us = 0,
        };
    }

    /// Create a rate limiter with a specific starting time.
    pub fn initWithTime(rate_bytes_per_sec: u64, now_us: i64) RateLimiter {
        var rl = init(rate_bytes_per_sec);
        rl.last_refill_us = now_us;
        return rl;
    }

    /// Check if this limiter is unlimited (rate == 0).
    pub fn isUnlimited(self: *const RateLimiter) bool {
        return self.refill_rate == 0;
    }

    /// Try to consume `bytes` tokens. Returns `.allowed` if sufficient tokens
    /// are available, or `.{ .wait_us = N }` with the microseconds to wait.
    pub fn consume(self: *RateLimiter, bytes: u64, now_us: i64) ConsumeResult {
        if (self.refill_rate == 0) return .allowed;
        if (bytes == 0) return .allowed;

        self.refill(now_us);

        if (self.tokens >= bytes) {
            self.tokens -= bytes;
            return .allowed;
        }

        // Calculate wait time for enough tokens
        const deficit = bytes - self.tokens;
        // wait_us = deficit * 1_000_000 / refill_rate
        const wait = (deficit * 1_000_000 + self.refill_rate - 1) / self.refill_rate;
        return .{ .wait_us = wait };
    }

    /// Refill tokens based on elapsed time since last refill.
    pub fn refill(self: *RateLimiter, now_us: i64) void {
        if (self.refill_rate == 0) return;
        if (now_us <= self.last_refill_us) return;

        const elapsed_us: u64 = @intCast(now_us - self.last_refill_us);
        // new_tokens = elapsed_us * refill_rate / 1_000_000
        const new_tokens = elapsed_us * self.refill_rate / 1_000_000;

        if (new_tokens > 0) {
            self.tokens = @min(self.tokens + new_tokens, self.capacity);
            // Only advance by the time actually accounted for (avoid drift)
            const accounted_us = new_tokens * 1_000_000 / self.refill_rate;
            self.last_refill_us += @as(i64, @intCast(accounted_us));
        }
    }

    /// Get current available tokens.
    pub fn available(self: *const RateLimiter) u64 {
        return self.tokens;
    }

    /// Update the rate limit. Resets tokens to new capacity.
    pub fn setRate(self: *RateLimiter, rate_bytes_per_sec: u64) void {
        self.refill_rate = rate_bytes_per_sec;
        self.capacity = if (rate_bytes_per_sec == 0) 0 else rate_bytes_per_sec * 2;
        self.tokens = self.capacity;
    }
};

// ── Tests ──

const testing = std.testing;

test "RateLimiter unlimited" {
    var rl = RateLimiter.init(0);
    try testing.expect(rl.isUnlimited());

    // Should always allow
    try testing.expectEqual(RateLimiter.ConsumeResult.allowed, rl.consume(1_000_000, 0));
    try testing.expectEqual(RateLimiter.ConsumeResult.allowed, rl.consume(999_999_999, 100));
}

test "RateLimiter basic consume" {
    // 1000 bytes/sec → capacity = 2000
    var rl = RateLimiter.initWithTime(1000, 0);
    try testing.expect(!rl.isUnlimited());
    try testing.expectEqual(@as(u64, 2000), rl.capacity);
    try testing.expectEqual(@as(u64, 2000), rl.tokens);

    // Consume within budget
    try testing.expectEqual(RateLimiter.ConsumeResult.allowed, rl.consume(500, 0));
    try testing.expectEqual(@as(u64, 1500), rl.tokens);

    // Consume more
    try testing.expectEqual(RateLimiter.ConsumeResult.allowed, rl.consume(1500, 0));
    try testing.expectEqual(@as(u64, 0), rl.tokens);
}

test "RateLimiter consume exceeds tokens" {
    // 1000 bytes/sec
    var rl = RateLimiter.initWithTime(1000, 0);

    // Drain all tokens
    try testing.expectEqual(RateLimiter.ConsumeResult.allowed, rl.consume(2000, 0));

    // Next consume should require waiting
    const result = rl.consume(100, 0);
    switch (result) {
        .wait_us => |wait| {
            // Need 100 bytes at 1000 bytes/sec = 100_000 us
            try testing.expectEqual(@as(u64, 100_000), wait);
        },
        .allowed => return error.TestExpectedWait,
    }
}

test "RateLimiter refill over time" {
    // 1000 bytes/sec
    var rl = RateLimiter.initWithTime(1000, 0);

    // Drain all
    try testing.expectEqual(RateLimiter.ConsumeResult.allowed, rl.consume(2000, 0));
    try testing.expectEqual(@as(u64, 0), rl.tokens);

    // 500ms later → refill 500 bytes
    rl.refill(500_000);
    try testing.expectEqual(@as(u64, 500), rl.tokens);

    // 1s later (from start) → refill another 500 bytes
    rl.refill(1_000_000);
    try testing.expectEqual(@as(u64, 1000), rl.tokens);
}

test "RateLimiter refill capped at capacity" {
    // 1000 bytes/sec, capacity = 2000
    var rl = RateLimiter.initWithTime(1000, 0);

    // Already at capacity, wait 10 seconds
    rl.refill(10_000_000);
    // Should still be at capacity
    try testing.expectEqual(@as(u64, 2000), rl.tokens);
}

test "RateLimiter burst allows 2x rate" {
    // 1000 bytes/sec → capacity = 2000 (2s burst)
    var rl = RateLimiter.initWithTime(1000, 0);

    // Can consume 2000 bytes at once (burst)
    try testing.expectEqual(RateLimiter.ConsumeResult.allowed, rl.consume(2000, 0));

    // But not 2001
    rl.setRate(1000);
    try testing.expectEqual(RateLimiter.ConsumeResult.allowed, rl.consume(2000, 0));
    const result = rl.consume(1, 0);
    switch (result) {
        .wait_us => |wait| {
            try testing.expect(wait > 0);
        },
        .allowed => return error.TestExpectedWait,
    }
}

test "RateLimiter consume zero bytes" {
    var rl = RateLimiter.initWithTime(1000, 0);
    // Zero bytes always allowed
    try testing.expectEqual(RateLimiter.ConsumeResult.allowed, rl.consume(0, 0));
    // Tokens unchanged
    try testing.expectEqual(@as(u64, 2000), rl.tokens);
}

test "RateLimiter setRate changes capacity" {
    var rl = RateLimiter.init(1000);

    // Change to 5000 bytes/sec
    rl.setRate(5000);
    try testing.expectEqual(@as(u64, 5000), rl.refill_rate);
    try testing.expectEqual(@as(u64, 10000), rl.capacity);
    try testing.expectEqual(@as(u64, 10000), rl.tokens);

    // Change to unlimited
    rl.setRate(0);
    try testing.expect(rl.isUnlimited());
    try testing.expectEqual(RateLimiter.ConsumeResult.allowed, rl.consume(999_999, 0));
}

test "RateLimiter refill precision" {
    // 10 bytes/sec (very slow rate)
    var rl = RateLimiter.initWithTime(10, 0);

    // Drain
    try testing.expectEqual(RateLimiter.ConsumeResult.allowed, rl.consume(20, 0));
    try testing.expectEqual(@as(u64, 0), rl.tokens);

    // 100ms = 1 byte
    rl.refill(100_000);
    try testing.expectEqual(@as(u64, 1), rl.tokens);

    // 50ms more = not enough for another byte (sub-byte granularity lost)
    rl.refill(150_000);
    // Should have accumulated 0.5 more byte, but integer math floors it
    // Total: 150ms * 10 bytes/sec = 1.5 → 1 (already accounted for 100ms = 1 byte)
    // Remaining time: last_refill_us was moved to 100_000, so 50ms more = 0.5 byte = 0
    try testing.expectEqual(@as(u64, 1), rl.tokens);

    // 100ms more (total 250ms from start) → should get 1 more byte
    rl.refill(250_000);
    try testing.expectEqual(@as(u64, 2), rl.tokens);
}
