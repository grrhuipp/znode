const std = @import("std");
const c = @import("../../infra/crypto/bindings.zig").c;

pub const TlsError = error{
    SslContextCreationFailed,
    CertificateLoadFailed,
    PrivateKeyLoadFailed,
    KeyMismatch,
    SelfSignedGenerationFailed,
    AlpnSetupFailed,
};

/// RAII wrapper around SSL_CTX.
pub const SslContext = struct {
    ctx: *c.SSL_CTX,

    pub fn deinit(self: *SslContext) void {
        c.SSL_CTX_free(self.ctx);
    }

    pub fn native(self: *const SslContext) *c.SSL_CTX {
        return self.ctx;
    }

    // ── Server: load cert/key from files ──────────────────────────────────

    pub fn createServer(cert_file: [*:0]const u8, key_file: [*:0]const u8) TlsError!SslContext {
        const method = c.TLS_server_method() orelse return error.SslContextCreationFailed;
        const ctx = c.SSL_CTX_new(method) orelse return error.SslContextCreationFailed;
        errdefer c.SSL_CTX_free(ctx);

        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION);
        _ = c.SSL_CTX_set_max_proto_version(ctx, c.TLS1_3_VERSION);

        if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_file) != 1) {
            return error.CertificateLoadFailed;
        }
        if (c.SSL_CTX_use_PrivateKey_file(ctx, key_file, c.SSL_FILETYPE_PEM) != 1) {
            return error.PrivateKeyLoadFailed;
        }
        if (c.SSL_CTX_check_private_key(ctx) != 1) {
            return error.KeyMismatch;
        }

        // Default ALPN callback: prefer h2, fallback http/1.1
        c.SSL_CTX_set_alpn_select_cb(ctx, alpnSelectCallback, null);

        return .{ .ctx = ctx };
    }

    // ── Server: self-signed certificate ───────────────────────────────────

    pub fn createServerSelfSigned() TlsError!SslContext {
        // Generate RSA 2048 key
        const pkey_ctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null) orelse
            return error.SelfSignedGenerationFailed;
        defer c.EVP_PKEY_CTX_free(pkey_ctx);

        if (c.EVP_PKEY_keygen_init(pkey_ctx) != 1) return error.SelfSignedGenerationFailed;
        if (c.EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) != 1) return error.SelfSignedGenerationFailed;

        var pkey: ?*c.EVP_PKEY = null;
        if (c.EVP_PKEY_keygen(pkey_ctx, &pkey) != 1) return error.SelfSignedGenerationFailed;
        defer c.EVP_PKEY_free(pkey);

        // Create X509 certificate
        const x509 = c.X509_new() orelse return error.SelfSignedGenerationFailed;
        defer c.X509_free(x509);

        _ = c.X509_set_version(x509, 2); // v3
        _ = c.ASN1_INTEGER_set(c.X509_get_serialNumber(x509), 1);
        _ = c.X509_gmtime_adj(c.X509_get_notBefore(x509), 0);
        _ = c.X509_gmtime_adj(c.X509_get_notAfter(x509), 365 * 24 * 3600);
        _ = c.X509_set_pubkey(x509, pkey);

        const name = c.X509_get_subject_name(x509);
        _ = c.X509_NAME_add_entry_by_txt(name, "CN", c.MBSTRING_ASC, "localhost", -1, -1, 0);
        _ = c.X509_set_issuer_name(x509, name);

        if (c.X509_sign(x509, pkey, c.EVP_sha256()) == 0) {
            return error.SelfSignedGenerationFailed;
        }

        // Create SSL_CTX with generated cert/key
        const method = c.TLS_server_method() orelse return error.SslContextCreationFailed;
        const ctx = c.SSL_CTX_new(method) orelse return error.SslContextCreationFailed;
        errdefer c.SSL_CTX_free(ctx);

        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION);
        _ = c.SSL_CTX_set_max_proto_version(ctx, c.TLS1_3_VERSION);

        if (c.SSL_CTX_use_certificate(ctx, x509) != 1) return error.CertificateLoadFailed;
        if (c.SSL_CTX_use_PrivateKey(ctx, pkey) != 1) return error.PrivateKeyLoadFailed;
        if (c.SSL_CTX_check_private_key(ctx) != 1) return error.KeyMismatch;

        c.SSL_CTX_set_alpn_select_cb(ctx, alpnSelectCallback, null);

        return .{ .ctx = ctx };
    }

    // ── Client ────────────────────────────────────────────────────────────

    pub fn createClient(allow_insecure: bool) TlsError!SslContext {
        const method = c.TLS_client_method() orelse return error.SslContextCreationFailed;
        const ctx = c.SSL_CTX_new(method) orelse return error.SslContextCreationFailed;
        errdefer c.SSL_CTX_free(ctx);

        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION);
        _ = c.SSL_CTX_set_max_proto_version(ctx, c.TLS1_3_VERSION);

        if (allow_insecure) {
            c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
        } else {
            c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
            _ = c.SSL_CTX_set_default_verify_paths(ctx);
        }

        return .{ .ctx = ctx };
    }

    // ── ALPN callback (server-side) ───────────────────────────────────────

    fn alpnSelectCallback(
        _: ?*c.SSL,
        out: *[*c]const u8,
        out_len: *u8,
        in_data: [*c]const u8,
        in_len: c_uint,
        _: ?*anyopaque,
    ) callconv(.c) c_int {
        // Server preference list: h2, http/1.1
        const preferred = "\x02h2\x08http/1.1";
        _ = c.SSL_select_next_proto(
            @constCast(@ptrCast(out)),
            out_len,
            preferred,
            preferred.len,
            in_data,
            in_len,
        );
        // Always accept — if no match, client's first protocol is selected
        return c.SSL_TLSEXT_ERR_OK;
    }
};
