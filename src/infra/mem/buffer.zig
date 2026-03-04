const std = @import("std");

/// Fixed 8KB buffer block (matches Xray buf.Buffer / cnode Buffer).
///
/// Uses start/end cursors: advance() consumes data (zero memmove),
/// produce() records written bytes.
pub const Buffer = struct {
    pub const size: u32 = 8192;

    data: [size]u8 = undefined,
    start: u32 = 0,
    end: u32 = 0,

    /// Valid data slice [start, end).
    pub fn bytes(self: *Buffer) []u8 {
        return self.data[self.start..self.end];
    }

    pub fn constBytes(self: *const Buffer) []const u8 {
        return self.data[self.start..self.end];
    }

    /// Writable tail [end, size).
    pub fn tail(self: *Buffer) []u8 {
        return self.data[self.end..size];
    }

    pub fn len(self: *const Buffer) u32 {
        return self.end - self.start;
    }

    pub fn available(self: *const Buffer) u32 {
        return size - self.end;
    }

    pub fn isEmpty(self: *const Buffer) bool {
        return self.start == self.end;
    }

    /// Consume n bytes (advance start cursor, zero memmove).
    pub fn advance(self: *Buffer, n: u32) void {
        self.start += n;
    }

    /// After writing n bytes to tail(), call this to record.
    pub fn produce(self: *Buffer, n: u32) void {
        self.end += n;
    }

    /// Reset cursors for reuse.
    pub fn reset(self: *Buffer) void {
        self.start = 0;
        self.end = 0;
    }
};

/// MultiBuffer — list of Buffer pointers (matches Xray buf.MultiBuffer / cnode MultiBuffer).
///
/// Ownership: whoever holds the MultiBuffer must call deinit() to free all buffers.
pub const MultiBuffer = struct {
    items: std.ArrayList(*Buffer),

    pub fn init(allocator: std.mem.Allocator) MultiBuffer {
        return .{ .items = std.ArrayList(*Buffer).init(allocator) };
    }

    pub fn deinit(self: *MultiBuffer, pool: *Pool) void {
        for (self.items.items) |buf| {
            pool.release(buf);
        }
        self.items.deinit();
    }

    pub fn append(self: *MultiBuffer, buf: *Buffer) !void {
        try self.items.append(buf);
    }

    pub fn totalLen(self: *const MultiBuffer) usize {
        var n: usize = 0;
        for (self.items.items) |buf| {
            n += buf.len();
        }
        return n;
    }

    pub fn isEmpty(self: *const MultiBuffer) bool {
        return self.items.items.len == 0;
    }

    /// Write all buffered data into a contiguous slice. Returns bytes written.
    pub fn copyTo(self: *const MultiBuffer, dest: []u8) usize {
        var offset: usize = 0;
        for (self.items.items) |buf| {
            const data = buf.constBytes();
            if (offset + data.len > dest.len) break;
            @memcpy(dest[offset..][0..data.len], data);
            offset += data.len;
        }
        return offset;
    }
};

// ============================================================================
// Pool — thread-local free list for Buffer reuse
//
// Design:
//   - Each thread keeps a stack of freed buffers (intrusive free list via
//     the buffer's data area storing the next pointer).
//   - acquire() pops from free list or allocates via page_allocator.
//   - release() pushes back. If free list exceeds high-water mark, truly free.
//   - No atomics on the hot path (thread-local).
// ============================================================================

pub const Pool = struct {
    const max_free: usize = 256;

    allocator: std.mem.Allocator,
    free_list: std.ArrayList(*Buffer),

    pub fn init(allocator: std.mem.Allocator) Pool {
        return .{
            .allocator = allocator,
            .free_list = std.ArrayList(*Buffer).init(allocator),
        };
    }

    pub fn deinit(self: *Pool) void {
        for (self.free_list.items) |buf| {
            self.allocator.destroy(buf);
        }
        self.free_list.deinit();
    }

    pub fn acquire(self: *Pool) !*Buffer {
        if (self.free_list.popOrNull()) |buf| {
            buf.reset();
            return buf;
        }
        const buf = try self.allocator.create(Buffer);
        buf.* = Buffer{};
        return buf;
    }

    pub fn release(self: *Pool, buf: *Buffer) void {
        if (self.free_list.items.len >= max_free) {
            self.allocator.destroy(buf);
            return;
        }
        self.free_list.append(buf) catch {
            self.allocator.destroy(buf);
        };
    }
};
