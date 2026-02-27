// ══════════════════════════════════════════════════════════════
//  buf — sharded heap-backed slab pool
//
//  Sessions borrow fixed-size slabs per phase and return them ASAP:
//
//    Handshake:  work + plain + payload  (3 slabs, returned after hs)
//    Relay:      read_accum × 2 + dec × 2 + transient enc slabs
//
//  slab_size = 16 KB:
//    • fits SS AEAD max payload (16 383 B) in one dec slab
//    • fits AEAD enc output with headroom (slab_size − enc_overhead)
//    • covers most VMess chunks; rare >16 KB frames grow to heap
//
//  Pool: 8 shards × (256/8 = 32) max-idle each.
//        Threads route by thread-ID bitmask → lock contention = 1/8.
//        Pre-allocates 256 slabs at startup (4 MB total).
//        Grows on demand; shrinks per-shard when idle > max_idle_per_shard.
//  Steady-state per session: 4 slabs = 64 KB (vs old 216 KB)
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const buf_pool_mod = @import("buf_pool.zig");

/// Fixed-size slab — the unit of borrowing from BufPool.
pub const slab_size: usize = 16 * 1024;

pub const Buf = struct {
    data: [slab_size]u8 align(8) = undefined,
};

/// Maximum plaintext we encrypt per pool enc-slab call.
/// Leaves 64 B headroom for all AEAD overhead (tag + length prefix + padding).
pub const max_enc_per_slab: usize = slab_size - 64;

/// Number of independent shards — must be a power of two.
/// Match executor (thread) count so each thread gets its own shard: zero steady-state contention.
const n_shards: usize = 32;

/// Total idle slabs retained across all shards (256 × 16 KB = 4 MB).
/// Each shard keeps at most pool_max_idle / n_shards = 8 slabs idle.
const pool_max_idle: usize = 256;

/// Pre-allocated slabs at startup — fill pool to capacity, zero cold-start penalty.
const pool_init_cap: usize = pool_max_idle;

/// Shared slab pool — all sessions borrow from here.
/// Wraps ShardedDynPool(Buf, 8): sharded by thread ID, grow/shrink per shard.
pub const BufPool = struct {
    inner: buf_pool_mod.ShardedDynPool(Buf, n_shards),

    pub fn init(allocator: std.mem.Allocator) !BufPool {
        return .{ .inner = try buf_pool_mod.ShardedDynPool(Buf, n_shards).init(
            allocator,
            pool_init_cap,
            pool_max_idle,
        ) };
    }

    pub fn acquire(self: *BufPool) !*Buf {
        return self.inner.acquire();
    }

    pub fn release(self: *BufPool, ptr: *Buf) void {
        self.inner.release(ptr);
    }

    pub fn deinit(self: *BufPool) void {
        self.inner.deinit();
    }
};
