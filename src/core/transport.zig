// ══════════════════════════════════════════════════════════════
//  Transport — Pluggable transport layer vtable interface
//
//  Decorator pattern: each layer wraps a lower Transport.
//  Combinations are free: Raw, TLS(Raw), WS(TLS(Raw)), etc.
//
//  Aligned with Xray's internet.Dialer / net.Conn philosophy:
//  protocol layer only sees read/write, never knows the transport.
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const zio = @import("zio");
const log = @import("log.zig");
const tls_mod = @import("../transport/tls_stream.zig");
const ws_mod = @import("../transport/ws_stream.zig");

/// Unified transport interface — protocol layer uses only this.
pub const Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        readFn: *const fn (ptr: *anyopaque, buf: []u8, timeout: zio.Timeout) anyerror!usize,
        writeFn: *const fn (ptr: *anyopaque, data: []const u8, timeout: zio.Timeout) anyerror!void,
    };

    pub inline fn read(self: Transport, buf: []u8, timeout: zio.Timeout) anyerror!usize {
        return self.vtable.readFn(self.ptr, buf, timeout);
    }

    pub inline fn write(self: Transport, data: []const u8, timeout: zio.Timeout) anyerror!void {
        return self.vtable.writeFn(self.ptr, data, timeout);
    }

    /// Read exactly buf.len bytes, looping until all bytes are received.
    pub fn readExact(self: Transport, buf: []u8, timeout: zio.Timeout) anyerror!void {
        var accumulated: usize = 0;
        while (accumulated < buf.len) {
            const n = try self.vtable.readFn(self.ptr, buf[accumulated..], timeout);
            if (n == 0) return error.ConnectionClosed;
            accumulated += n;
        }
    }
};

// ── PrefixedTransport ──

/// Transport wrapper that replays a captured prefix before reading from lower.
/// Used for protocol sniff/detection paths where we must pre-read bytes safely.
pub const PrefixedTransport = struct {
    lower: Transport,
    prefix_buf: [8192]u8 = undefined,
    prefix_len: usize = 0,
    prefix_pos: usize = 0,

    const prefixed_vtable = VTable{
        .readFn = prefixedRead,
        .writeFn = prefixedWrite,
    };

    pub fn init(lower: Transport, prefix: []const u8) PrefixedTransport {
        var p = PrefixedTransport{ .lower = lower };
        p.prefix_len = @min(prefix.len, p.prefix_buf.len);
        if (p.prefix_len > 0) {
            @memcpy(p.prefix_buf[0..p.prefix_len], prefix[0..p.prefix_len]);
        }
        return p;
    }

    pub fn transport(self: *PrefixedTransport) Transport {
        return .{ .ptr = @ptrCast(self), .vtable = &prefixed_vtable };
    }

    const VTable = Transport.VTable;

    fn prefixedRead(ptr: *anyopaque, buf: []u8, timeout: zio.Timeout) anyerror!usize {
        const self: *PrefixedTransport = @ptrCast(@alignCast(ptr));
        if (self.prefix_pos < self.prefix_len) {
            const avail = self.prefix_len - self.prefix_pos;
            const n = @min(buf.len, avail);
            if (n > 0) {
                @memcpy(buf[0..n], self.prefix_buf[self.prefix_pos .. self.prefix_pos + n]);
                self.prefix_pos += n;
                return n;
            }
        }
        return self.lower.read(buf, timeout);
    }

    fn prefixedWrite(ptr: *anyopaque, data: []const u8, timeout: zio.Timeout) anyerror!void {
        const self: *PrefixedTransport = @ptrCast(@alignCast(ptr));
        return self.lower.write(data, timeout);
    }
};

// ── RawTransport ──

/// Direct TCP transport — no encryption, no framing.
pub const RawTransport = struct {
    stream: zio.net.Stream,

    const raw_vtable = VTable{
        .readFn = rawRead,
        .writeFn = rawWrite,
    };

    pub fn transport(self: *RawTransport) Transport {
        return .{ .ptr = @ptrCast(self), .vtable = &raw_vtable };
    }

    const VTable = Transport.VTable;

    fn rawRead(ptr: *anyopaque, buf: []u8, timeout: zio.Timeout) anyerror!usize {
        const self: *RawTransport = @ptrCast(@alignCast(ptr));
        return self.stream.read(buf, timeout);
    }

    fn rawWrite(ptr: *anyopaque, data: []const u8, timeout: zio.Timeout) anyerror!void {
        const self: *RawTransport = @ptrCast(@alignCast(ptr));
        return self.stream.writeAll(data, timeout);
    }
};

// ── TlsTransport ──

/// TLS transport layer — wraps any lower Transport with BoringSSL encryption.
/// Uses Memory BIO: feedNetworkData → SSL_read/write → getNetworkData.
pub const TlsTransport = struct {
    lower: Transport,
    tls: *tls_mod.TlsStream,
    read_buf: []u8, // for raw network data (read path)
    write_buf: []u8, // for encrypted output (write path)

    const tls_vtable = VTable{
        .readFn = tlsRead,
        .writeFn = tlsWrite,
    };

    pub fn transport(self: *TlsTransport) Transport {
        return .{ .ptr = @ptrCast(self), .vtable = &tls_vtable };
    }

    const VTable = Transport.VTable;

    /// Drive TLS handshake to completion (call before using read/write).
    pub fn doHandshake(self: *TlsTransport, timeout: zio.Timeout) !void {
        var rounds: u32 = 0;
        while (true) {
            rounds += 1;
            // Flush any pending TLS output first
            try self.flushOutput(timeout);

            const hs_result = self.tls.handshake();
            switch (hs_result) {
                .done => {
                    try self.flushOutput(timeout);
                    return;
                },
                .want_read => {
                    // BoringSSL can produce ServerHello AND return want_read in one call;
                    // flush before blocking on read to avoid deadlock.
                    try self.flushOutput(timeout);
                    const n = try self.lower.read(self.read_buf, timeout);
                    if (n == 0) return error.ConnectionClosed;
                    _ = try self.tls.feedNetworkData(self.read_buf[0..n]);
                },
                .want_write => {}, // Flushed at top of loop
                .err => return error.TlsHandshakeFailed,
            }
        }
    }

    fn tlsRead(ptr: *anyopaque, buf: []u8, timeout: zio.Timeout) anyerror!usize {
        const self: *TlsTransport = @ptrCast(@alignCast(ptr));

        // First check if TLS has buffered decrypted data
        switch (self.tls.readDecrypted(buf)) {
            .bytes => |n| return n,
            .want_read => {},
            .want_write => {},
            .closed => return 0,
            .err => return error.TlsReadError,
        }

        // Need more network data from lower transport
        const n = try self.lower.read(self.read_buf, timeout);
        if (n == 0) return 0;

        _ = try self.tls.feedNetworkData(self.read_buf[0..n]);

        // Try to get decrypted data
        switch (self.tls.readDecrypted(buf)) {
            .bytes => |dn| return dn,
            .want_read => return error.TlsNeedMore,
            .want_write => return error.TlsNeedMore,
            .closed => return 0,
            .err => return error.TlsReadError,
        }
    }

    fn tlsWrite(ptr: *anyopaque, data: []const u8, timeout: zio.Timeout) anyerror!void {
        const self: *TlsTransport = @ptrCast(@alignCast(ptr));

        switch (self.tls.writeEncrypted(data)) {
            .bytes => {},
            .closed => return error.TlsClosed,
            .err => return error.TlsWriteError,
            .want_read, .want_write => {},
        }
        try self.flushOutput(timeout);
    }

    fn flushOutput(self: *TlsTransport, timeout: zio.Timeout) !void {
        while (self.tls.hasNetworkDataPending()) {
            const n = self.tls.getNetworkData(self.write_buf);
            if (n > 0) {
                try self.lower.write(self.write_buf[0..n], timeout);
            }
        }
    }
};

// ── WsTransport ──

/// WebSocket transport layer — wraps any lower Transport with WS framing.
/// Handles ping/pong automatically. Client frames are masked per RFC 6455.
pub const WsTransport = struct {
    lower: Transport,
    ws: *ws_mod.WsStream,
    read_buf: []u8, // for WS framed data from lower transport
    write_buf: []u8, // for WS frame encoding output
    // Pending decrypted payload from the current WS frame.
    // Needed because upper layers may read in small chunks (e.g. VMess header 42B).
    pending_len: usize = 0,
    pending_pos: usize = 0,

    const ws_vtable = VTable{
        .readFn = wsRead,
        .writeFn = wsWrite,
    };

    pub fn transport(self: *WsTransport) Transport {
        return .{ .ptr = @ptrCast(self), .vtable = &ws_vtable };
    }

    const VTable = Transport.VTable;

    /// Drive WS handshake to completion (call before using read/write).
    pub fn doHandshake(self: *WsTransport, timeout: zio.Timeout) !void {
        while (true) {
            // Flush WS output (handshake response / upgrade request)
            try self.flushWsOutput(timeout);

            switch (self.ws.handshake()) {
                .bytes => return, // handshake complete
                .want_read => {
                    const cap = @min(self.read_buf.len, self.ws.inputSpace());
                    if (cap == 0) return error.WsHandshakeBufferFull;
                    const n = try self.lower.read(self.read_buf[0..cap], timeout);
                    if (n == 0) return error.WsConnectionClosed;
                    _ = try self.ws.feedNetworkData(self.read_buf[0..n]);
                },
                .want_write => {}, // Flushed at top of loop
                .closed => return error.WsConnectionClosed,
                .err => return error.WsHandshakeFailed,
            }
        }
    }

    fn wsRead(ptr: *anyopaque, buf: []u8, timeout: zio.Timeout) anyerror!usize {
        const self: *WsTransport = @ptrCast(@alignCast(ptr));

        if (buf.len == 0) return 0;

        // Serve buffered decrypted bytes first.
        if (self.pending_pos < self.pending_len) {
            const available = self.pending_len - self.pending_pos;
            const n_copy = @min(buf.len, available);
            @memcpy(buf[0..n_copy], self.read_buf[self.pending_pos .. self.pending_pos + n_copy]);
            self.pending_pos += n_copy;
            if (self.pending_pos == self.pending_len) {
                self.pending_pos = 0;
                self.pending_len = 0;
            }
            return n_copy;
        }

        while (true) {
            // Try to decode a frame from buffered WS data
            switch (self.ws.readDecrypted(self.read_buf)) {
                .bytes => |n| {
                    const n_copy = @min(buf.len, n);
                    @memcpy(buf[0..n_copy], self.read_buf[0..n_copy]);
                    if (n_copy < n) {
                        self.pending_pos = n_copy;
                        self.pending_len = n;
                    }
                    return n_copy;
                },
                .closed => return 0,
                .err => return error.WsReadError,
                .want_read, .want_write => {},
            }

            // Flush any pending WS output (pong responses)
            try self.flushWsOutput(timeout);

            // Need more data from lower transport
            const cap = @min(self.read_buf.len, self.ws.inputSpace());
            if (cap == 0) {
                const dbg = self.ws.debugState();
                const pending_unread = self.pending_len - self.pending_pos;
                log.warn("ws frame buffer full before read: hs_len={d} leftover={d} avail={d} space={d} pending={d} out_pending={d} hs_done={} hdr={} opcode={d} fin={} masked={} payload={d} hdr_size={d} frame_total={d} frame_complete={} parse_blocked={}", .{
                    dbg.hs_len,
                    dbg.leftover_start,
                    dbg.available,
                    dbg.input_space,
                    pending_unread,
                    dbg.out_pending,
                    dbg.handshake_done,
                    dbg.has_frame_header,
                    dbg.frame_opcode,
                    dbg.frame_fin,
                    dbg.frame_masked,
                    dbg.frame_payload_len,
                    dbg.frame_header_size,
                    dbg.frame_total_size,
                    dbg.frame_complete,
                    dbg.parse_blocked,
                });
                return error.WsFrameBufferFull;
            }
            const n = try self.lower.read(self.read_buf[0..cap], timeout);
            if (n == 0) return 0; // EOF

            _ = self.ws.feedNetworkData(self.read_buf[0..n]) catch {
                const dbg = self.ws.debugState();
                const pending_unread = self.pending_len - self.pending_pos;
                log.warn("ws frame buffer full on feed: read={d} hs_len={d} leftover={d} avail={d} space={d} pending={d} out_pending={d} hs_done={} hdr={} opcode={d} fin={} masked={} payload={d} hdr_size={d} frame_total={d} frame_complete={} parse_blocked={}", .{
                    n,
                    dbg.hs_len,
                    dbg.leftover_start,
                    dbg.available,
                    dbg.input_space,
                    pending_unread,
                    dbg.out_pending,
                    dbg.handshake_done,
                    dbg.has_frame_header,
                    dbg.frame_opcode,
                    dbg.frame_fin,
                    dbg.frame_masked,
                    dbg.frame_payload_len,
                    dbg.frame_header_size,
                    dbg.frame_total_size,
                    dbg.frame_complete,
                    dbg.parse_blocked,
                });
                return error.WsFrameBufferFull;
            };
        }
    }

    fn wsWrite(ptr: *anyopaque, data: []const u8, timeout: zio.Timeout) anyerror!void {
        const self: *WsTransport = @ptrCast(@alignCast(ptr));
        const mask = (self.ws.role == .client);
        const n = ws_mod.encodeFrame(self.write_buf, .binary, data, mask) orelse return error.WsFrameTooLarge;
        try self.lower.write(self.write_buf[0..n], timeout);
    }

    fn flushWsOutput(self: *WsTransport, timeout: zio.Timeout) !void {
        while (self.ws.hasNetworkDataPending()) {
            const n = self.ws.getNetworkData(self.write_buf);
            if (n > 0) {
                try self.lower.write(self.write_buf[0..n], timeout);
            }
        }
    }
};

// ── Transport Storage ──

/// Holds concrete transport instances — lifetime must outlive the Transport vtable.
/// Allocated on stack in session_handler, one per transport direction (inbound/outbound).
pub const TransportStorage = struct {
    prefixed_transport: PrefixedTransport = undefined,
    raw: RawTransport = undefined,
    tls_transport: TlsTransport = undefined,
    ws_transport: WsTransport = undefined,
};
