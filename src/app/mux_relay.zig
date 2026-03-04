/// Mux.Cool relay — demultiplex sub-sessions from a single encrypted stream.
///
/// Each Mux connection carries multiple TCP/UDP sub-sessions identified by session_id.
/// Frames are decoded, dispatched to outbound, and replies multiplexed back.
const std = @import("std");
const types = @import("../common/types.zig");
const mux_codec = @import("../protocol/mux/codec.zig");
const TcpStream = @import("../transport/stream.zig").TcpStream;

/// Per-TCP sub-session state.
const TcpSub = struct {
    session_id: u16,
    target: types.TargetAddress,
    outbound_stream: ?TcpStream = null,
    closed: bool = false,
};

/// Reply to be sent back to the mux client.
pub const MuxReply = struct {
    data: []const u8,
    data_len: usize,
};

/// Process Mux.Cool frames from the client stream.
///
/// This reads frames in a loop, dispatching NEW/KEEP/END to sub-sessions.
/// For production use, sub-session outbound I/O should be handled in
/// separate fibers/threads.
pub fn handleMuxStream(
    allocator: std.mem.Allocator,
    comptime Stream: type,
    stream: *Stream,
) !void {
    var frame_buf: [65536]u8 = undefined;
    var buf_len: usize = 0;
    var tcp_subs = std.AutoHashMap(u16, TcpSub).init(allocator);
    defer tcp_subs.deinit();

    while (true) {
        // Read more data
        if (buf_len < frame_buf.len) {
            const n = stream.read(frame_buf[buf_len..]) catch break;
            if (n == 0) break;
            buf_len += n;
        }

        // Parse frames
        while (buf_len > 0) {
            const frame = mux_codec.decodeFrame(frame_buf[0..buf_len]) catch |err| switch (err) {
                error.NeedMoreData => break,
                error.InvalidFrame => {
                    // Skip 1 byte for resync
                    std.mem.copyForwards(u8, &frame_buf, frame_buf[1..buf_len]);
                    buf_len -= 1;
                    continue;
                },
            };

            // Process frame
            switch (frame.status) {
                .keepalive => {
                    // Echo keepalive
                    var reply: [6]u8 = undefined;
                    const n = mux_codec.encodeKeepAlive(&reply);
                    stream.writeAll(reply[0..n]) catch break;
                },
                .new => {
                    const target = frame.target orelse {
                        // Consume frame and continue
                        consumeFrame(&frame_buf, &buf_len, frame.frame_size);
                        continue;
                    };

                    if (frame.network == .tcp) {
                        try tcp_subs.put(frame.session_id, .{
                            .session_id = frame.session_id,
                            .target = target,
                        });

                        // In a full implementation, we'd dial the target here
                        // and spawn a reverse reader fiber
                    }
                },
                .keep => {
                    if (frame.payload) |payload| {
                        if (tcp_subs.get(frame.session_id)) |sub| {
                            if (sub.outbound_stream) |*out| {
                                out.writeAll(payload) catch {
                                    // Send END on write failure
                                    var end_buf: [8]u8 = undefined;
                                    const n = mux_codec.encodeEnd(frame.session_id, true, &end_buf);
                                    stream.writeAll(end_buf[0..n]) catch {};
                                };
                            }
                        }
                    }
                },
                .end => {
                    if (tcp_subs.fetchRemove(frame.session_id)) |kv| {
                        if (kv.value.outbound_stream) |*out| {
                            out.close();
                        }
                    }
                    // Echo END back
                    var end_buf: [8]u8 = undefined;
                    const n = mux_codec.encodeEnd(frame.session_id, false, &end_buf);
                    stream.writeAll(end_buf[0..n]) catch {};
                },
            }

            consumeFrame(&frame_buf, &buf_len, frame.frame_size);
        }
    }

    // Cleanup remaining sub-sessions
    var iter = tcp_subs.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.outbound_stream) |*out| {
            out.close();
        }
    }
}

fn consumeFrame(buf: []u8, len: *usize, consumed: usize) void {
    const remaining = len.* - consumed;
    if (remaining > 0) {
        std.mem.copyForwards(u8, buf[0..remaining], buf[consumed..len.*]);
    }
    len.* = remaining;
}
