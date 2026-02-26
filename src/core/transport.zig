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
                    const n = try self.lower.read(self.read_buf, timeout);
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

        while (true) {
            // Try to decode a frame from buffered WS data
            switch (self.ws.readDecrypted(buf)) {
                .bytes => |n| return n,
                .closed => return 0,
                .err => return error.WsReadError,
                .want_read, .want_write => {},
            }

            // Flush any pending WS output (pong responses)
            try self.flushWsOutput(timeout);

            // Need more data from lower transport
            const n = try self.lower.read(self.read_buf, timeout);
            if (n == 0) return 0; // EOF

            _ = self.ws.feedNetworkData(self.read_buf[0..n]) catch return error.WsFrameBufferFull;
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
    raw: RawTransport = undefined,
    tls_transport: TlsTransport = undefined,
    ws_transport: WsTransport = undefined,
};
