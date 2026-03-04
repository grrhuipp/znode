const std = @import("std");
const c = @import("../../infra/crypto/bindings.zig").c;
const SslContext = @import("context.zig").SslContext;

pub const TlsStreamError = error{
    SslCreationFailed,
    BioCreationFailed,
    HandshakeFailed,
    SslReadFailed,
    SslWriteFailed,
    ConnectionClosed,
    InnerStreamError,
};

const io_buf_size = 4096;

/// TLS stream over an inner stream using Memory BIO mode.
///
/// comptime Inner must provide:
///   - fn read(self: *Inner, buf: []u8) anyerror!usize
///   - fn write(self: *Inner, data: []const u8) anyerror!usize
///   - fn close(self: *Inner) void
pub fn TlsStream(comptime Inner: type) type {
    return struct {
        const Self = @This();

        inner: Inner,
        ssl: *c.SSL,
        // Note: read_bio/write_bio are owned by SSL after SSL_set_bio,
        // SSL_free will free them. We keep pointers for BIO_write/BIO_read.
        read_bio: *c.BIO,
        write_bio: *c.BIO,
        is_server: bool,
        handshake_done: bool = false,
        shutdown_initiated: bool = false,

        /// Wrap an existing inner stream with TLS.
        pub fn init(inner: Inner, ssl_ctx: *const SslContext, is_server: bool) TlsStreamError!Self {
            const ssl = c.SSL_new(ssl_ctx.native()) orelse return error.SslCreationFailed;
            errdefer c.SSL_free(ssl);

            const read_bio = c.BIO_new(c.BIO_s_mem()) orelse return error.BioCreationFailed;
            const write_bio = c.BIO_new(c.BIO_s_mem()) orelse {
                _ = c.BIO_free(read_bio);
                return error.BioCreationFailed;
            };

            // Set non-blocking mode for memory BIOs
            _ = c.BIO_set_nbio(read_bio, 1);
            _ = c.BIO_set_nbio(write_bio, 1);

            // Attach BIOs to SSL — SSL takes ownership
            c.SSL_set_bio(ssl, read_bio, write_bio);

            if (is_server) {
                c.SSL_set_accept_state(ssl);
            } else {
                c.SSL_set_connect_state(ssl);
            }

            return .{
                .inner = inner,
                .ssl = ssl,
                .read_bio = read_bio,
                .write_bio = write_bio,
                .is_server = is_server,
            };
        }

        pub fn deinit(self: *Self) void {
            if (!self.shutdown_initiated) {
                _ = c.SSL_shutdown(self.ssl);
                self.flushWriteBio() catch {};
            }
            c.SSL_free(self.ssl); // Also frees attached BIOs
        }

        pub fn close(self: *Self) void {
            self.deinit();
            self.inner.close();
        }

        // ── SNI / ALPN configuration (must be called before handshake) ────

        pub fn setServerName(self: *Self, name: [*:0]const u8) void {
            if (!self.is_server) {
                _ = c.SSL_set_tlsext_host_name(self.ssl, name);
            }
        }

        pub fn setAlpn(self: *Self, protocols: []const []const u8) TlsStreamError!void {
            // Build wire format: [len1][proto1][len2][proto2]...
            var buf: [256]u8 = undefined;
            var pos: usize = 0;
            for (protocols) |proto| {
                if (pos + 1 + proto.len > buf.len) break;
                buf[pos] = @intCast(proto.len);
                pos += 1;
                @memcpy(buf[pos .. pos + proto.len], proto);
                pos += proto.len;
            }
            if (pos > 0) {
                _ = c.SSL_set_alpn_protos(self.ssl, &buf, @intCast(pos));
            }
        }

        pub fn receivedSni(self: *const Self) ?[]const u8 {
            if (!self.is_server) return null;
            const name = c.SSL_get_servername(self.ssl, c.TLSEXT_NAMETYPE_host_name);
            if (name) |ptr| {
                return std.mem.span(ptr);
            }
            return null;
        }

        pub fn negotiatedAlpn(self: *const Self) ?[]const u8 {
            var data: [*c]const u8 = null;
            var len: c_uint = 0;
            c.SSL_get0_alpn_selected(self.ssl, &data, &len);
            if (len > 0 and data != null) {
                return data[0..len];
            }
            return null;
        }

        // ── Handshake ─────────────────────────────────────────────────────

        pub fn handshake(self: *Self) !void {
            if (self.handshake_done) return;

            while (true) {
                const ret = c.SSL_do_handshake(self.ssl);
                if (ret == 1) {
                    self.handshake_done = true;
                    return;
                }

                const err = c.SSL_get_error(self.ssl, ret);
                switch (err) {
                    c.SSL_ERROR_WANT_READ => {
                        try self.flushWriteBio();
                        try self.feedFromInner();
                    },
                    c.SSL_ERROR_WANT_WRITE => {
                        try self.flushWriteBio();
                    },
                    else => return error.HandshakeFailed,
                }
            }
        }

        // ── Read / Write (auto-handshake on first call) ───────────────────

        pub fn read(self: *Self, buf: []u8) !usize {
            if (!self.handshake_done) try self.handshake();

            while (true) {
                const ret = c.SSL_read(self.ssl, buf.ptr, @intCast(@min(buf.len, std.math.maxInt(c_int))));
                if (ret > 0) {
                    return @intCast(ret);
                }

                const err = c.SSL_get_error(self.ssl, ret);
                switch (err) {
                    c.SSL_ERROR_ZERO_RETURN => return error.ConnectionClosed,
                    c.SSL_ERROR_WANT_READ => {
                        try self.flushWriteBio();
                        const n = self.inner.read(buf) catch return error.InnerStreamError;
                        if (n == 0) return error.ConnectionClosed;
                        if (c.BIO_write(self.read_bio, buf.ptr, @intCast(n)) <= 0) {
                            return error.SslReadFailed;
                        }
                    },
                    c.SSL_ERROR_WANT_WRITE => {
                        try self.flushWriteBio();
                    },
                    else => return error.SslReadFailed,
                }
            }
        }

        pub fn write(self: *Self, data: []const u8) !usize {
            if (!self.handshake_done) try self.handshake();

            var total: usize = 0;
            while (total < data.len) {
                const chunk_len: c_int = @intCast(@min(data.len - total, std.math.maxInt(c_int)));
                const ret = c.SSL_write(self.ssl, data.ptr + total, chunk_len);

                if (ret > 0) {
                    total += @intCast(ret);
                    try self.flushWriteBio();
                } else {
                    const err = c.SSL_get_error(self.ssl, ret);
                    switch (err) {
                        c.SSL_ERROR_WANT_WRITE => {
                            try self.flushWriteBio();
                        },
                        c.SSL_ERROR_WANT_READ => {
                            try self.feedFromInner();
                        },
                        else => {
                            if (total > 0) return total;
                            return error.SslWriteFailed;
                        },
                    }
                }
            }
            return total;
        }

        /// Send TLS close_notify.
        pub fn shutdownWrite(self: *Self) void {
            if (!self.handshake_done or self.shutdown_initiated) return;
            self.shutdown_initiated = true;
            _ = c.SSL_shutdown(self.ssl);
            self.flushWriteBio() catch {};
        }

        // ── Internal BIO pump ─────────────────────────────────────────────

        /// Read encrypted data from write_bio and send to inner stream.
        fn flushWriteBio(self: *Self) !void {
            var buf: [io_buf_size]u8 = undefined;
            while (true) {
                const pending = c.BIO_ctrl_pending(self.write_bio);
                if (pending == 0) return;

                const to_read: c_int = @intCast(@min(pending, buf.len));
                const n = c.BIO_read(self.write_bio, &buf, to_read);
                if (n <= 0) return;

                const chunk: usize = @intCast(n);
                var sent: usize = 0;
                while (sent < chunk) {
                    const w = self.inner.write(buf[sent..chunk]) catch return error.InnerStreamError;
                    if (w == 0) return error.InnerStreamError;
                    sent += w;
                }
            }
        }

        /// Read data from inner stream and feed into read_bio.
        fn feedFromInner(self: *Self) !void {
            var buf: [io_buf_size]u8 = undefined;
            const n = self.inner.read(&buf) catch return error.InnerStreamError;
            if (n == 0) return error.ConnectionClosed;
            if (c.BIO_write(self.read_bio, &buf, @intCast(n)) <= 0) {
                return error.SslReadFailed;
            }
        }
    };
}
