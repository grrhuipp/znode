const std = @import("std");
const frame_mod = @import("frame.zig");
const FrameHeader = frame_mod.FrameHeader;
const Opcode = frame_mod.Opcode;
const c = @import("../../infra/crypto/bindings.zig").c;

pub const WsError = error{
    ConnectionClosed,
    InvalidFrame,
    InnerStreamError,
    HandshakeFailed,
};

/// WebSocket stream over an inner stream.
///
/// comptime Inner must provide:
///   - fn read(self: *Inner, buf: []u8) anyerror!usize
///   - fn write(self: *Inner, data: []const u8) anyerror!usize
///   - fn close(self: *Inner) void
///
/// `is_client`: if true, outgoing frames are masked (RFC 6455 §5.3).
pub fn WsStream(comptime Inner: type, comptime is_client: bool) type {
    return struct {
        const Self = @This();

        inner: Inner,
        // Pending data from handshake or partial frame reads
        pending_buf: [4096]u8 = undefined,
        pending_len: usize = 0,
        pending_pos: usize = 0,
        // Current frame state
        frame_remaining: u64 = 0,
        frame_mask_key: [4]u8 = .{ 0, 0, 0, 0 },
        frame_mask_offset: usize = 0,
        frame_masked: bool = false,
        write_closed: bool = false,

        pub fn init(inner: Inner) Self {
            return .{ .inner = inner };
        }

        pub fn initWithPending(inner: Inner, pending: []const u8) Self {
            var self = Self{ .inner = inner };
            if (pending.len > 0) {
                const len = @min(pending.len, self.pending_buf.len);
                @memcpy(self.pending_buf[0..len], pending[0..len]);
                self.pending_len = len;
            }
            return self;
        }

        pub fn close(self: *Self) void {
            self.sendCloseFrame();
            self.inner.close();
        }

        pub fn read(self: *Self, buf: []u8) !usize {
            while (true) {
                // If we have payload remaining from current data frame, deliver it
                if (self.frame_remaining > 0) {
                    return self.readFramePayload(buf);
                }

                // Get next data frame (skip control frames)
                if (!try self.prepareNextDataFrame()) {
                    return error.ConnectionClosed;
                }
            }
        }

        pub fn write(self: *Self, data: []const u8) !usize {
            if (data.len == 0) return 0;

            var header_buf: [FrameHeader.max_header_size]u8 = undefined;
            var header = FrameHeader{
                .fin = true,
                .opcode = .binary,
                .masked = is_client,
                .payload_len = data.len,
            };

            if (is_client) {
                // Generate random mask key
                _ = c.RAND_bytes(&header.mask_key, 4);
            }

            const header_len = header.encode(&header_buf);

            // Write header
            writeAllInner(&self.inner, header_buf[0..header_len]) catch return error.InnerStreamError;

            // Write payload (masked if client)
            if (is_client) {
                // Mask and write in chunks
                var chunk_buf: [8192]u8 = undefined;
                var offset: usize = 0;
                while (offset < data.len) {
                    const chunk_len = @min(data.len - offset, chunk_buf.len);
                    @memcpy(chunk_buf[0..chunk_len], data[offset .. offset + chunk_len]);
                    frame_mod.maskData(chunk_buf[0..chunk_len], header.mask_key, offset);
                    writeAllInner(&self.inner, chunk_buf[0..chunk_len]) catch return error.InnerStreamError;
                    offset += chunk_len;
                }
            } else {
                writeAllInner(&self.inner, data) catch return error.InnerStreamError;
            }

            return data.len;
        }

        pub fn shutdownWrite(self: *Self) void {
            self.sendCloseFrame();
        }

        // ── Internal ──────────────────────────────────────────────────────

        fn prepareNextDataFrame(self: *Self) !bool {
            while (true) {
                // Read enough bytes for frame header
                var header_buf: [FrameHeader.max_header_size]u8 = undefined;
                var header_filled: usize = 0;

                // First drain pending buffer
                while (self.pending_pos < self.pending_len and header_filled < FrameHeader.min_header_size) {
                    header_buf[header_filled] = self.pending_buf[self.pending_pos];
                    header_filled += 1;
                    self.pending_pos += 1;
                }

                // Read more if needed
                while (header_filled < FrameHeader.min_header_size) {
                    const n = self.innerRead(header_buf[header_filled..]) catch return error.InnerStreamError;
                    if (n == 0) return false;
                    header_filled += n;
                }

                // Try to parse, may need more bytes for extended length / mask
                while (true) {
                    if (FrameHeader.parse(header_buf[0..header_filled])) |result| {
                        self.frame_remaining = result.header.payload_len;
                        self.frame_masked = result.header.masked;
                        self.frame_mask_key = result.header.mask_key;
                        self.frame_mask_offset = 0;

                        // Handle control frames
                        switch (result.header.opcode) {
                            .ping, .pong => {
                                // Consume payload and skip
                                try self.skipBytes(self.frame_remaining);
                                self.frame_remaining = 0;
                                continue; // next frame
                            },
                            .close => {
                                try self.skipBytes(self.frame_remaining);
                                self.frame_remaining = 0;
                                return false; // EOF
                            },
                            else => return true, // data frame ready
                        }
                    }

                    // Need more header bytes
                    if (header_filled >= header_buf.len) return error.InvalidFrame;

                    // Try from pending first
                    if (self.pending_pos < self.pending_len) {
                        header_buf[header_filled] = self.pending_buf[self.pending_pos];
                        header_filled += 1;
                        self.pending_pos += 1;
                    } else {
                        const n = self.innerRead(header_buf[header_filled..]) catch return error.InnerStreamError;
                        if (n == 0) return false;
                        header_filled += n;
                    }
                }
            }
        }

        fn readFramePayload(self: *Self, buf: []u8) !usize {
            const to_read: usize = @intCast(@min(self.frame_remaining, buf.len));
            var total: usize = 0;

            // Drain pending first
            while (total < to_read and self.pending_pos < self.pending_len) {
                buf[total] = self.pending_buf[self.pending_pos];
                total += 1;
                self.pending_pos += 1;
            }

            // Read from inner
            while (total < to_read) {
                const n = self.innerRead(buf[total..to_read]) catch return error.InnerStreamError;
                if (n == 0) return error.ConnectionClosed;
                total += n;
            }

            // Unmask if needed
            if (self.frame_masked) {
                frame_mod.maskData(buf[0..total], self.frame_mask_key, self.frame_mask_offset);
                self.frame_mask_offset += total;
            }

            self.frame_remaining -= total;
            return total;
        }

        fn skipBytes(self: *Self, count: u64) !void {
            var remaining = count;
            var discard: [512]u8 = undefined;
            while (remaining > 0) {
                const to_skip: usize = @intCast(@min(remaining, discard.len));
                // Drain pending
                var got: usize = 0;
                while (got < to_skip and self.pending_pos < self.pending_len) {
                    discard[got] = self.pending_buf[self.pending_pos];
                    got += 1;
                    self.pending_pos += 1;
                }
                while (got < to_skip) {
                    const n = self.innerRead(discard[got..to_skip]) catch return error.InnerStreamError;
                    if (n == 0) return error.ConnectionClosed;
                    got += n;
                }
                remaining -= got;
            }
        }

        fn sendCloseFrame(self: *Self) void {
            if (self.write_closed) return;
            self.write_closed = true;

            var close_payload: [2]u8 = undefined;
            _ = frame_mod.encodeClosePayload(&close_payload, 1000);

            var header = FrameHeader{
                .fin = true,
                .opcode = .close,
                .masked = is_client,
                .payload_len = 2,
            };

            if (is_client) {
                _ = c.RAND_bytes(&header.mask_key, 4);
            }

            var header_buf: [FrameHeader.max_header_size]u8 = undefined;
            const header_len = header.encode(&header_buf);

            if (is_client) {
                frame_mod.maskData(&close_payload, header.mask_key, 0);
            }

            writeAllInner(&self.inner, header_buf[0..header_len]) catch {};
            writeAllInner(&self.inner, &close_payload) catch {};
        }

        fn innerRead(self: *Self, buf: []u8) !usize {
            return self.inner.read(buf);
        }

        fn writeAllInner(inner: *Inner, data: []const u8) !void {
            var sent: usize = 0;
            while (sent < data.len) {
                const n = try inner.write(data[sent..]);
                if (n == 0) return error.InnerStreamError;
                sent += n;
            }
        }
    };
}
