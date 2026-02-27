// ══════════════════════════════════════════════════════════════
//  ShardedDynPool — Sharded heap-backed slab pool
//
//  N independent shards, each with its own mutex + free-list.
//  Threads are routed to shards by thread ID, reducing lock
//  contention to 1/N compared to a single-mutex pool.
//
//  Each shard independently grows on demand and shrinks when
//  its idle count exceeds max_idle_per_shard.
//
//  Usage:
//    var pool = try ShardedDynPool(Buf, 8).init(allocator, 256, 256);
//    defer pool.deinit();
//    const slab = try pool.acquire();
//    defer pool.release(slab);
//
//  Lifecycle per shard:
//    acquire(): pop from shard free-list  OR  allocator.create (grow)
//    release(): push to shard free-list   OR  allocator.destroy (shrink)
// ══════════════════════════════════════════════════════════════

const std = @import("std");

/// Sharded thread-safe slab pool: heap-backed, pre-allocated, grow/shrink.
/// n_shards must be a power of two for cheap modulo via bitmask.
pub fn ShardedDynPool(comptime T: type, comptime n_shards: usize) type {
    comptime std.debug.assert(n_shards > 0 and std.math.isPowerOfTwo(n_shards));

    return struct {
        const Self = @This();

        /// Free-list node — overlaid onto the released object's memory.
        const Node = struct {
            next: ?*Node,
        };

        comptime {
            std.debug.assert(@alignOf(T) >= @alignOf(Node));
        }

        const Shard = struct {
            mutex: std.Thread.Mutex = .{},
            head: ?*Node = null,
            idle: usize = 0,
        };

        shards: [n_shards]Shard,
        max_idle_per_shard: usize,
        allocator: std.mem.Allocator,

        /// Init: distribute init_cap slabs round-robin across shards.
        /// max_idle is split evenly; each shard shrinks independently.
        pub fn init(allocator: std.mem.Allocator, init_cap: usize, max_idle: usize) !Self {
            var self = Self{
                .shards = [_]Shard{.{}} ** n_shards,
                .max_idle_per_shard = (max_idle + n_shards - 1) / n_shards, // ceil
                .allocator = allocator,
            };
            errdefer self.deinit();
            var i: usize = 0;
            while (i < init_cap) : (i += 1) {
                const shard = &self.shards[i & (n_shards - 1)]; // fast modulo
                const ptr = try allocator.create(T);
                const node: *Node = @ptrCast(@alignCast(ptr));
                node.next = shard.head;
                shard.head = node;
                shard.idle += 1;
            }
            return self;
        }

        /// Acquire a slab — reuses from this thread's shard or allocates fresh (grow).
        pub fn acquire(self: *Self) !*T {
            const shard = &self.shards[shardIndex()];
            shard.mutex.lock();
            if (shard.head) |node| {
                shard.head = node.next;
                shard.idle -= 1;
                shard.mutex.unlock();
                const ptr: *T = @ptrCast(@alignCast(node));
                ptr.* = .{};
                return ptr;
            }
            shard.mutex.unlock();
            // Shard exhausted — grow: allocate a fresh slab.
            return try self.allocator.create(T);
        }

        /// Release a slab — caches in this thread's shard or frees (shrink).
        pub fn release(self: *Self, ptr: *T) void {
            const shard = &self.shards[shardIndex()];
            shard.mutex.lock();
            if (shard.idle < self.max_idle_per_shard) {
                const node: *Node = @ptrCast(@alignCast(ptr));
                node.next = shard.head;
                shard.head = node;
                shard.idle += 1;
                shard.mutex.unlock();
            } else {
                // Over high-water mark — shrink: return slab to allocator.
                shard.mutex.unlock();
                self.allocator.destroy(ptr);
            }
        }

        /// Drain all shards (for shutdown).
        pub fn deinit(self: *Self) void {
            for (&self.shards) |*shard| {
                shard.mutex.lock();
                while (shard.head) |node| {
                    shard.head = node.next;
                    shard.idle -= 1;
                    const ptr: *T = @ptrCast(@alignCast(node));
                    self.allocator.destroy(ptr);
                }
                shard.mutex.unlock();
            }
        }

        /// Route to shard by current thread ID (bitmask, no division).
        inline fn shardIndex() usize {
            return @as(usize, @intCast(std.Thread.getCurrentId())) & (n_shards - 1);
        }
    };
}
