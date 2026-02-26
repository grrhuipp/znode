const std = @import("std");

/// Two-tier buffer pool: 8KB / 20KB.
/// Per-worker, no cross-thread sharing needed.
///
/// The iodata tier (20KB) exists because remote VMess/SS servers can send up to
/// 16KB AEAD chunks. decrypt_buf, send_buf, and pending buffers must hold a full
/// decrypted chunk plus protocol overhead (~16KB payload + 34B AEAD + 18B WS + 37B TLS ≈ 16.4KB).
/// 8KB is too small; 32KB wastes memory. 20KB fits the max with headroom.
pub const BufferPool = struct {
    medium: Tier, // 8KB buffers — standard I/O (matches Xray buf.Size)
    iodata: Tier, // 20KB buffers — decrypt/send/pending (holds max AEAD chunk + overhead)
    allocator: std.mem.Allocator,
    total_allocated: usize = 0,
    total_in_use: usize = 0,
    max_memory: usize = 0, // 0 = unlimited (no cap)

    pub const medium_size: usize = 8192; // 8KB (Xray buf.Size)
    pub const iodata_size: usize = 20480; // 20KB — max AEAD chunk (16KB) + protocol overhead

    const medium_prealloc: usize = 16;
    const iodata_prealloc: usize = 8;

    // Max idle buffers per tier — excess freed directly to OS on release().
    // Prevents unbounded RSS growth after traffic spikes.
    //   medium (8KB × 64)  = 512KB idle max per worker
    //   iodata (20KB × 32) = 640KB idle max per worker
    // Total: ~1.1MB idle max per worker
    const medium_max_free: usize = 64;
    const iodata_max_free: usize = 32;

    pub fn init(allocator: std.mem.Allocator) BufferPool {
        return .{
            .medium = Tier.init(medium_size, medium_max_free),
            .iodata = Tier.init(iodata_size, iodata_max_free),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BufferPool) void {
        self.medium.deinit(self.allocator);
        self.iodata.deinit(self.allocator);
    }

    /// Preallocate buffers for each tier.
    pub fn prealloc(self: *BufferPool) !void {
        try self.medium.prealloc(self.allocator, medium_prealloc);
        try self.iodata.prealloc(self.allocator, iodata_prealloc);
        self.total_allocated =
            medium_prealloc * medium_size +
            iodata_prealloc * iodata_size;
    }

    /// Acquire a buffer of at least `min_size` bytes.
    pub fn acquire(self: *BufferPool, min_size: usize) ![]u8 {
        const tier = self.selectTier(min_size);
        if (tier) |t| {
            if (t.pop()) |buf| {
                self.total_in_use += buf.len;
                return buf;
            }
            // Tier empty, allocate new buffer (check memory limit)
            if (self.max_memory > 0 and self.total_allocated + t.buf_size > self.max_memory) {
                return error.BufferExhausted;
            }
            const buf = try self.allocator.alloc(u8, t.buf_size);
            self.total_allocated += t.buf_size;
            self.total_in_use += t.buf_size;
            return buf;
        }
        // Size exceeds all tiers, allocate directly (check memory limit)
        if (self.max_memory > 0 and self.total_allocated + min_size > self.max_memory) {
            return error.BufferExhausted;
        }
        const buf = try self.allocator.alloc(u8, min_size);
        self.total_allocated += min_size;
        self.total_in_use += min_size;
        return buf;
    }

    /// Release a buffer back to the pool.
    /// If the tier's free list is at capacity (max_free), the buffer is freed
    /// directly to the OS instead of being pooled — this keeps RSS stable.
    pub fn release(self: *BufferPool, buf: []u8) void {
        self.total_in_use -|= buf.len;
        const tier = self.selectTierExact(buf.len);
        if (tier) |t| {
            if (t.max_free > 0 and t.free_count >= t.max_free) {
                // Tier full — free directly to OS (prevents RSS bloat)
                self.total_allocated -|= buf.len;
                self.allocator.free(buf);
            } else {
                t.push(buf);
            }
        } else {
            // Non-standard size, just free it
            self.total_allocated -|= buf.len;
            self.allocator.free(buf);
        }
    }

    /// Aggressively shrink pools: keep only active/4 headroom in freelist.
    /// Frees memory quickly after traffic spikes. New connections will re-allocate
    /// from OS if needed (cheap: ~50ns per alloc via mmap).
    pub fn shrink(self: *BufferPool, active_connections: usize) void {
        const headroom = active_connections / 4 + 2;
        self.shrinkTier(&self.medium, headroom);
        self.shrinkTier(&self.iodata, headroom);
    }

    fn shrinkTier(self: *BufferPool, tier: *Tier, min_keep: usize) void {
        while (tier.free_count > min_keep) {
            if (tier.pop()) |buf| {
                self.total_allocated -|= buf.len;
                self.allocator.free(buf);
            } else break;
        }
    }

    fn selectTier(self: *BufferPool, size: usize) ?*Tier {
        if (size <= medium_size) return &self.medium;
        if (size <= iodata_size) return &self.iodata;
        return null;
    }

    fn selectTierExact(self: *BufferPool, size: usize) ?*Tier {
        if (size == medium_size) return &self.medium;
        if (size == iodata_size) return &self.iodata;
        return null;
    }

    pub fn memoryUsage(self: *const BufferPool) MemoryUsage {
        return .{
            .total_allocated = self.total_allocated,
            .total_in_use = self.total_in_use,
            .medium_free = self.medium.free_count,
            .iodata_free = self.iodata.free_count,
        };
    }
};

pub const MemoryUsage = struct {
    total_allocated: usize,
    total_in_use: usize,
    medium_free: usize,
    iodata_free: usize,
};

/// Intrusive free-list tier using buffer memory for the linked list node.
const Tier = struct {
    buf_size: usize,
    free_count: usize = 0,
    max_free: usize = 0, // 0 = unlimited
    head: ?*Node = null,

    const Node = struct {
        next: ?*Node,
    };

    fn init(buf_size: usize, max_free: usize) Tier {
        return .{ .buf_size = buf_size, .max_free = max_free };
    }

    fn deinit(self: *Tier, allocator: std.mem.Allocator) void {
        while (self.pop()) |buf| {
            allocator.free(buf);
        }
    }

    fn prealloc(self: *Tier, allocator: std.mem.Allocator, count: usize) !void {
        for (0..count) |_| {
            const buf = try allocator.alloc(u8, self.buf_size);
            self.push(buf);
        }
    }

    fn push(self: *Tier, buf: []u8) void {
        const node: *Node = @ptrCast(@alignCast(buf.ptr));
        node.next = self.head;
        self.head = node;
        self.free_count += 1;
    }

    fn pop(self: *Tier) ?[]u8 {
        const node = self.head orelse return null;
        self.head = node.next;
        self.free_count -= 1;
        const ptr: [*]u8 = @ptrCast(node);
        return ptr[0..self.buf_size];
    }
};

test "BufferPool acquire and release" {
    const allocator = std.testing.allocator;
    var pool = BufferPool.init(allocator);
    defer pool.deinit();

    const buf1 = try pool.acquire(1024);
    try std.testing.expectEqual(@as(usize, BufferPool.medium_size), buf1.len);

    const buf2 = try pool.acquire(4096);
    try std.testing.expectEqual(@as(usize, BufferPool.medium_size), buf2.len);

    const buf3 = try pool.acquire(16384);
    try std.testing.expectEqual(@as(usize, BufferPool.iodata_size), buf3.len);

    pool.release(buf1);
    pool.release(buf2);
    pool.release(buf3);

    // Re-acquire should reuse from pool
    const buf4 = try pool.acquire(100);
    try std.testing.expectEqual(@as(usize, BufferPool.medium_size), buf4.len);
    pool.release(buf4);
}

test "BufferPool oversized allocation" {
    const allocator = std.testing.allocator;
    var pool = BufferPool.init(allocator);
    defer pool.deinit();

    // 256KB exceeds all tiers — direct allocation
    const buf = try pool.acquire(256 * 1024);
    try std.testing.expectEqual(@as(usize, 256 * 1024), buf.len);
    pool.release(buf);
}

test "BufferPool memory limit" {
    const allocator = std.testing.allocator;
    var pool = BufferPool.init(allocator);
    defer pool.deinit();

    pool.max_memory = 16384;

    const buf1 = try pool.acquire(100);
    try std.testing.expectEqual(@as(usize, BufferPool.medium_size), buf1.len);

    const buf2 = try pool.acquire(100);

    const result = pool.acquire(100);
    try std.testing.expectError(error.BufferExhausted, result);

    pool.release(buf1);
    pool.release(buf2);
}

test "BufferPool shrink releases excess" {
    const allocator = std.testing.allocator;
    var pool = BufferPool.init(allocator);
    defer pool.deinit();

    var bufs: [10][]u8 = undefined;
    for (&bufs) |*b| b.* = try pool.acquire(BufferPool.medium_size);
    for (&bufs) |b| pool.release(b);
    try std.testing.expectEqual(@as(usize, 10), pool.medium.free_count);

    pool.shrink(4); // headroom = 4/4 + 2 = 3
    try std.testing.expectEqual(@as(usize, 3), pool.medium.free_count);
}

test "BufferPool max_free cap releases to OS" {
    const allocator = std.testing.allocator;
    var pool = BufferPool.init(allocator);
    defer pool.deinit();

    // Override max_free to a small value for testing
    pool.medium.max_free = 3;

    // Allocate and release 5 buffers
    var bufs: [5][]u8 = undefined;
    for (&bufs) |*b| b.* = try pool.acquire(BufferPool.medium_size);

    // Release all 5: first 3 go to free list, last 2 freed to OS
    for (&bufs) |b| pool.release(b);

    // Only 3 should be in free list (capped by max_free)
    try std.testing.expectEqual(@as(usize, 3), pool.medium.free_count);

    // total_allocated should reflect the 2 freed to OS
    // Started with 5 * 8192 = 40960, freed 2 * 8192 = 16384
    try std.testing.expectEqual(@as(usize, 3 * BufferPool.medium_size), pool.total_allocated);
}
