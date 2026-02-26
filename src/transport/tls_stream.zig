const std = @import("std");
const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/evp.h");
});

/// TLS stream using BoringSSL with Memory BIO.
///
/// Memory BIO approach (decoupled from socket layer):
///   Network recv -> BIO_write(read_bio) -> SSL_read() -> app plaintext
///   App plaintext -> SSL_write() -> BIO_read(write_bio) -> network send
///
/// This allows integration with libxev's proactor model where we manage I/O.
pub const TlsStream = struct {
    ssl: *c.SSL,
    read_bio: *c.BIO, // Network data IN  -> OpenSSL reads from here
    write_bio: *c.BIO, // OpenSSL writes -> Network data OUT
    handshake_done: bool = false,

    /// Create a TLS client stream.
    pub fn initClient(ctx: *c.SSL_CTX, hostname: ?[]const u8) !TlsStream {
        return initInternal(ctx, hostname, false);
    }

    /// Create a TLS server stream.
    pub fn initServer(ctx: *c.SSL_CTX) !TlsStream {
        return initInternal(ctx, null, true);
    }

    fn initInternal(ctx: *c.SSL_CTX, hostname: ?[]const u8, is_server: bool) !TlsStream {
        const ssl_obj = c.SSL_new(ctx) orelse return error.TlsInitFailed;
        errdefer c.SSL_free(ssl_obj);

        // Create memory BIO pair
        const read_bio = c.BIO_new(c.BIO_s_mem()) orelse {
            return error.TlsInitFailed;
        };
        const write_bio = c.BIO_new(c.BIO_s_mem()) orelse {
            _ = c.BIO_free(read_bio);
            return error.TlsInitFailed;
        };

        // Attach BIOs to SSL (SSL takes ownership, don't free them separately)
        c.SSL_set_bio(ssl_obj, read_bio, write_bio);

        if (is_server) {
            c.SSL_set_accept_state(ssl_obj);
        } else {
            c.SSL_set_connect_state(ssl_obj);
            // Set SNI hostname (BoringSSL provides this as a real function)
            if (hostname) |host| {
                if (host.len > 0 and host.len < 256) {
                    var buf: [256]u8 = undefined;
                    @memcpy(buf[0..host.len], host);
                    buf[host.len] = 0;
                    _ = c.SSL_set_tlsext_host_name(ssl_obj, &buf);
                }
            }
        }

        return TlsStream{
            .ssl = ssl_obj,
            .read_bio = read_bio,
            .write_bio = write_bio,
        };
    }

    pub fn deinit(self: *TlsStream) void {
        // SSL_free also frees the attached BIOs
        c.SSL_free(self.ssl);
    }

    /// Feed raw network data into the TLS engine.
    /// Call this when you receive data from the network (libxev recv).
    pub fn feedNetworkData(self: *TlsStream, data: []const u8) !usize {
        const written = c.BIO_write(self.read_bio, data.ptr, @intCast(data.len));
        if (written <= 0) return error.TlsBioWriteFailed;
        return @intCast(written);
    }

    /// Read decrypted application data from TLS.
    /// Call after feedNetworkData() to get plaintext.
    pub fn readDecrypted(self: *TlsStream, buf: []u8) TlsResult {
        const n = c.SSL_read(self.ssl, buf.ptr, @intCast(buf.len));
        if (n > 0) {
            return .{ .bytes = @intCast(n) };
        }
        return self.mapSslError(n);
    }

    /// Encrypt application data for sending over the network.
    /// The encrypted output should be retrieved with getNetworkData().
    pub fn writeEncrypted(self: *TlsStream, data: []const u8) TlsResult {
        const n = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (n > 0) {
            return .{ .bytes = @intCast(n) };
        }
        return self.mapSslError(n);
    }

    /// Get encrypted data that needs to be sent over the network.
    /// Call this after writeEncrypted() or after handshake steps.
    pub fn getNetworkData(self: *TlsStream, buf: []u8) usize {
        const pending = c.BIO_ctrl_pending(self.write_bio);
        if (pending == 0) return 0;

        const to_read: c_int = @intCast(@min(pending, buf.len));
        const n = c.BIO_read(self.write_bio, buf.ptr, to_read);
        if (n <= 0) return 0;
        return @intCast(n);
    }

    /// Check if there's encrypted data pending to be sent.
    pub fn hasNetworkDataPending(self: *TlsStream) bool {
        return c.BIO_ctrl_pending(self.write_bio) > 0;
    }

    /// Drive the TLS handshake forward.
    pub fn handshake(self: *TlsStream) HandshakeResult {
        const ret = c.SSL_do_handshake(self.ssl);
        if (ret == 1) {
            self.handshake_done = true;
            return .done;
        }
        const err = c.SSL_get_error(self.ssl, ret);
        return switch (err) {
            c.SSL_ERROR_WANT_READ => .want_read,
            c.SSL_ERROR_WANT_WRITE => .want_write,
            else => .err,
        };
    }

    /// Initiate TLS shutdown.
    pub fn shutdown(self: *TlsStream) HandshakeResult {
        const ret = c.SSL_shutdown(self.ssl);
        if (ret >= 0) return .done;
        const err = c.SSL_get_error(self.ssl, ret);
        return switch (err) {
            c.SSL_ERROR_WANT_READ => .want_read,
            c.SSL_ERROR_WANT_WRITE => .want_write,
            else => .err,
        };
    }

    pub fn isHandshakeDone(self: *const TlsStream) bool {
        return self.handshake_done;
    }

    /// Override the per-connection certificate and private key (before handshake).
    /// Used for dynamic SNI-based self-signed certificates.
    /// Takes *anyopaque to avoid cross-module @cImport type conflicts.
    pub fn overrideCert(self: *TlsStream, cert_raw: *anyopaque, key_raw: *anyopaque) void {
        _ = c.SSL_use_certificate(self.ssl, @ptrCast(cert_raw));
        _ = c.SSL_use_PrivateKey(self.ssl, @ptrCast(key_raw));
    }

    /// Get the negotiated ALPN protocol (e.g. "h2", "http/1.1").
    pub fn getAlpnProtocol(self: *const TlsStream) ?[]const u8 {
        var proto: [*c]const u8 = null;
        var proto_len: c_uint = 0;
        c.SSL_get0_alpn_selected(self.ssl, &proto, &proto_len);
        if (proto != null and proto_len > 0) {
            return proto[0..proto_len];
        }
        return null;
    }

    fn mapSslError(self: *TlsStream, ret: c_int) TlsResult {
        const err = c.SSL_get_error(self.ssl, ret);
        return switch (err) {
            c.SSL_ERROR_WANT_READ => .want_read,
            c.SSL_ERROR_WANT_WRITE => .want_write,
            c.SSL_ERROR_ZERO_RETURN => .closed,
            else => .err,
        };
    }

    pub const TlsResult = @import("stream.zig").TransportResult;

    pub const HandshakeResult = enum {
        done,
        want_read,
        want_write,
        err,
    };
};

/// TLS context wrapper.
pub const TlsContext = struct {
    ctx: *c.SSL_CTX,

    pub fn initServer() !TlsContext {
        const method = c.TLS_server_method() orelse return error.TlsInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return error.TlsInitFailed;
        return .{ .ctx = ctx };
    }

    /// Create a client TLS context with optional certificate verification and ALPN.
    pub fn initClient() !TlsContext {
        const method = c.TLS_method() orelse return error.TlsInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return error.TlsInitFailed;
        return .{ .ctx = ctx };
    }

    /// Configure client context for outbound TLS with verification and ALPN.
    /// skip_verify: if true, skip certificate verification (allowInsecure).
    /// sni: optional SNI hostname for certificate CN/SAN validation.
    pub fn configureOutbound(self: *TlsContext, skip_verify: bool, sni: ?[]const u8) void {
        if (skip_verify) {
            c.SSL_CTX_set_verify(self.ctx, c.SSL_VERIFY_NONE, null);
        } else {
            // Enable certificate verification with default CA store
            c.SSL_CTX_set_verify(self.ctx, c.SSL_VERIFY_PEER, null);
            // Load system default CA certificates
            _ = c.SSL_CTX_set_default_verify_paths(self.ctx);
            // Set verification depth
            c.SSL_CTX_set_verify_depth(self.ctx, 4);
            // Enable hostname checking if SNI is provided
            if (sni) |hostname| {
                if (hostname.len > 0) {
                    const param = c.SSL_CTX_get0_param(self.ctx);
                    if (param) |p| {
                        var buf: [256]u8 = undefined;
                        const n = @min(hostname.len, 255);
                        @memcpy(buf[0..n], hostname[0..n]);
                        buf[n] = 0;
                        _ = c.X509_VERIFY_PARAM_set1_host(p, &buf, n);
                    }
                }
            }
        }

        // Set ALPN: h2, http/1.1 (wire format: length-prefixed list)
        const alpn_protos = "\x02h2\x08http/1.1";
        _ = c.SSL_CTX_set_alpn_protos(self.ctx, alpn_protos, alpn_protos.len);
    }

    pub fn deinit(self: *TlsContext) void {
        c.SSL_CTX_free(self.ctx);
    }

    /// Load certificate chain from PEM file.
    pub fn loadCertFile(self: *TlsContext, path: [*:0]const u8) !void {
        if (c.SSL_CTX_use_certificate_chain_file(self.ctx, path) != 1) {
            return error.TlsCertLoadFailed;
        }
    }

    /// Load private key from PEM file.
    pub fn loadKeyFile(self: *TlsContext, path: [*:0]const u8) !void {
        if (c.SSL_CTX_use_PrivateKey_file(self.ctx, path, c.SSL_FILETYPE_PEM) != 1) {
            return error.TlsKeyLoadFailed;
        }
    }

    /// Load certificate from PEM data in memory.
    pub fn loadCertPem(self: *TlsContext, pem: []const u8) !void {
        const bio = c.BIO_new_mem_buf(pem.ptr, @intCast(pem.len)) orelse return error.TlsCertLoadFailed;
        defer _ = c.BIO_free(bio);
        const cert = c.PEM_read_bio_X509(bio, null, null, null) orelse return error.TlsCertLoadFailed;
        defer c.X509_free(cert);
        if (c.SSL_CTX_use_certificate(self.ctx, cert) != 1) return error.TlsCertLoadFailed;
    }

    /// Load private key from PEM data in memory.
    pub fn loadKeyPem(self: *TlsContext, pem: []const u8) !void {
        const bio = c.BIO_new_mem_buf(pem.ptr, @intCast(pem.len)) orelse return error.TlsKeyLoadFailed;
        defer _ = c.BIO_free(bio);
        const pkey = c.PEM_read_bio_PrivateKey(bio, null, null, null) orelse return error.TlsKeyLoadFailed;
        defer c.EVP_PKEY_free(pkey);
        if (c.SSL_CTX_use_PrivateKey(self.ctx, pkey) != 1) return error.TlsKeyLoadFailed;
    }

    /// Verify that the certificate and private key match.
    pub fn checkPrivateKey(self: *TlsContext) !void {
        if (c.SSL_CTX_check_private_key(self.ctx) != 1) {
            return error.TlsKeyMismatch;
        }
    }

    /// Load client certificate for mutual TLS (mTLS) authentication.
    pub fn loadClientCertFile(self: *TlsContext, path: [*:0]const u8) !void {
        if (c.SSL_CTX_use_certificate_chain_file(self.ctx, path) != 1) {
            return error.TlsCertLoadFailed;
        }
    }

    /// Load client private key for mutual TLS (mTLS) authentication.
    pub fn loadClientKeyFile(self: *TlsContext, path: [*:0]const u8) !void {
        if (c.SSL_CTX_use_PrivateKey_file(self.ctx, path, c.SSL_FILETYPE_PEM) != 1) {
            return error.TlsKeyLoadFailed;
        }
    }

    pub fn newClient(self: *TlsContext, hostname: ?[]const u8) !TlsStream {
        return TlsStream.initClient(self.ctx, hostname);
    }

    pub fn newServer(self: *TlsContext) !TlsStream {
        return TlsStream.initServer(self.ctx);
    }
};

test "TlsContext creation" {
    var server_ctx = try TlsContext.initServer();
    defer server_ctx.deinit();

    var client_ctx = try TlsContext.initClient();
    defer client_ctx.deinit();
}

test "TlsStream Memory BIO creation" {
    var ctx = try TlsContext.initClient();
    defer ctx.deinit();

    var stream = try ctx.newClient("example.com");
    defer stream.deinit();

    try std.testing.expect(!stream.isHandshakeDone());
    try std.testing.expect(!stream.hasNetworkDataPending());
}

test "TlsContext mTLS methods exist" {
    var client_ctx = try TlsContext.initClient();
    defer client_ctx.deinit();

    // Verify mTLS methods are callable (will fail with file not found, but that's ok)
    const cert_err = client_ctx.loadClientCertFile("nonexistent.pem");
    try std.testing.expect(cert_err == error.TlsCertLoadFailed);

    const key_err = client_ctx.loadClientKeyFile("nonexistent.pem");
    try std.testing.expect(key_err == error.TlsKeyLoadFailed);
}

test "TlsStream handshake produces ClientHello" {
    var ctx = try TlsContext.initClient();
    defer ctx.deinit();

    var stream = try ctx.newClient("example.com");
    defer stream.deinit();

    // Kick off handshake - should produce ClientHello
    const result = stream.handshake();
    try std.testing.expect(result == .want_read or result == .want_write);

    // Check if there's data to send (ClientHello)
    var buf: [4096]u8 = undefined;
    const n = stream.getNetworkData(&buf);
    try std.testing.expect(n > 0);
    // First byte should be TLS record type 0x16 (Handshake)
    try std.testing.expectEqual(@as(u8, 0x16), buf[0]);
}

test "TlsContext configureOutbound skip verify" {
    var ctx = try TlsContext.initClient();
    defer ctx.deinit();
    ctx.configureOutbound(true, null);
    // Should not crash — just verifies API works
}

test "TlsContext configureOutbound with verification" {
    var ctx = try TlsContext.initClient();
    defer ctx.deinit();
    ctx.configureOutbound(false, "example.com");
    // Should load default CA paths and set hostname verification
}

test "TlsStream ALPN after configureOutbound" {
    var ctx = try TlsContext.initClient();
    defer ctx.deinit();
    ctx.configureOutbound(true, null);

    var stream = try ctx.newClient("example.com");
    defer stream.deinit();

    // Before handshake, no ALPN selected
    try std.testing.expect(stream.getAlpnProtocol() == null);
}
