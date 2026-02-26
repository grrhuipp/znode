// ══════════════════════════════════════════════════════════════
//  FixedPool — Thread-safe free-list pool for fixed-size objects
//
//  Avoids per-session heap allocation for large structs like
//  SessionBufs (~216KB each). Caches up to max_cached items;
//  overflow is released back to the allocator.
//
//  Usage:
//    var pool = FixedPool(SessionBufs, 64).init(allocator);
//    const buf = try pool.acquire();
//    defer pool.release(buf);
// ══════════════════════════════════════════════════════════════

const std = @import("std");

/// Generic thread-safe object pool with bounded caching.
pub fn FixedPool(comptime T: type, comptime max_cached: u32) type {
    return struct {
        const Self = @This();

        /// Free-list node — overlaid onto the released object's memory.
        const Node = struct {
            next: ?*Node,
        };

        comptime {
            // Node overlays the first bytes of T; T must be at least pointer-aligned.
            std.debug.assert(@alignOf(T) >= @alignOf(Node));
        }

        mutex: std.Thread.Mutex = .{},
        head: ?*Node = null,
        cached: u32 = 0,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .allocator = allocator };
        }

        /// Acquire an object — reuses from cache or allocates fresh.
        pub fn acquire(self: *Self) !*T {
            self.mutex.lock();
            if (self.head) |node| {
                self.head = node.next;
                self.cached -= 1;
                self.mutex.unlock();
                const ptr: *T = @ptrCast(@alignCast(node));
                ptr.* = .{};
                return ptr;
            }
            self.mutex.unlock();
            return try self.allocator.create(T);
        }

        /// Release an object — caches if under limit, else frees.
        pub fn release(self: *Self, ptr: *T) void {
            self.mutex.lock();
            if (self.cached < max_cached) {
                const node: *Node = @ptrCast(@alignCast(ptr));
                node.next = self.head;
                self.head = node;
                self.cached += 1;
                self.mutex.unlock();
            } else {
                self.mutex.unlock();
                self.allocator.destroy(ptr);
            }
        }

        /// Drain all cached objects (for shutdown).
        pub fn deinit(self: *Self) void {
            self.mutex.lock();
            while (self.head) |node| {
                self.head = node.next;
                self.cached -= 1;
                const ptr: *T = @ptrCast(@alignCast(node));
                self.allocator.destroy(ptr);
            }
            self.mutex.unlock();
        }
    };
}
