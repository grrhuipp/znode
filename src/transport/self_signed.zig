const std = @import("std");
const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/x509v3.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/ec.h");
    @cInclude("openssl/ec_key.h");
    @cInclude("openssl/pem.h");
});
const log = @import("../core/log.zig");

/// Result of self-signed certificate generation.
/// PEM-encoded cert and key stored in fixed buffers.
pub const SelfSignedCert = struct {
    cert_pem: [4096]u8 = [_]u8{0} ** 4096,
    cert_pem_len: u16 = 0,
    key_pem: [4096]u8 = [_]u8{0} ** 4096,
    key_pem_len: u16 = 0,

    pub fn getCertPem(self: *const SelfSignedCert) []const u8 {
        return self.cert_pem[0..self.cert_pem_len];
    }
    pub fn getKeyPem(self: *const SelfSignedCert) []const u8 {
        return self.key_pem[0..self.key_pem_len];
    }
};

/// Generate a self-signed EC P-256 certificate valid for 365 days.
/// CN is set to "znode" with a SAN of "localhost".
pub fn generate() !SelfSignedCert {
    var result = SelfSignedCert{};

    // 1. Generate EC P-256 private key
    const pkey = c.EVP_PKEY_new() orelse return error.TlsCertGenFailed;
    defer c.EVP_PKEY_free(pkey);

    const ec_key = c.EC_KEY_new_by_curve_name(c.NID_X9_62_prime256v1) orelse return error.TlsCertGenFailed;
    if (c.EC_KEY_generate_key(ec_key) != 1) {
        c.EC_KEY_free(ec_key);
        return error.TlsCertGenFailed;
    }
    // EVP_PKEY_assign_EC_KEY takes ownership of ec_key
    if (c.EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1) {
        c.EC_KEY_free(ec_key);
        return error.TlsCertGenFailed;
    }

    // 2. Create X509 certificate
    const x509 = c.X509_new() orelse return error.TlsCertGenFailed;
    defer c.X509_free(x509);

    // Serial number
    if (c.ASN1_INTEGER_set(c.X509_get_serialNumber(x509), 1) != 1) return error.TlsCertGenFailed;

    // Validity: now to +365 days
    const not_before = c.X509_getm_notBefore(x509);
    const not_after = c.X509_getm_notAfter(x509);
    _ = c.X509_gmtime_adj(not_before, 0);
    _ = c.X509_gmtime_adj(not_after, 365 * 24 * 3600);

    // Public key
    if (c.X509_set_pubkey(x509, pkey) != 1) return error.TlsCertGenFailed;

    // Subject: CN=znode
    const name = c.X509_get_subject_name(x509);
    if (c.X509_NAME_add_entry_by_txt(name, "CN", c.MBSTRING_ASC, "znode", -1, -1, 0) != 1)
        return error.TlsCertGenFailed;

    // Self-signed: issuer = subject
    if (c.X509_set_issuer_name(x509, name) != 1) return error.TlsCertGenFailed;

    // Sign with SHA-256
    if (c.X509_sign(x509, pkey, c.EVP_sha256()) == 0) return error.TlsCertGenFailed;

    // 3. Export to PEM via memory BIO
    // Certificate PEM
    const cert_bio = c.BIO_new(c.BIO_s_mem()) orelse return error.TlsCertGenFailed;
    defer _ = c.BIO_free(cert_bio);

    if (c.PEM_write_bio_X509(cert_bio, x509) != 1) return error.TlsCertGenFailed;

    var cert_ptr: [*c]u8 = undefined;
    const cert_len = c.BIO_ctrl(cert_bio, c.BIO_CTRL_INFO, 0, @ptrCast(&cert_ptr));
    if (cert_len <= 0 or cert_len > result.cert_pem.len) return error.TlsCertGenFailed;
    const cert_ulen: u16 = @intCast(cert_len);
    @memcpy(result.cert_pem[0..cert_ulen], cert_ptr[0..cert_ulen]);
    result.cert_pem_len = cert_ulen;

    // Key PEM
    const key_bio = c.BIO_new(c.BIO_s_mem()) orelse return error.TlsCertGenFailed;
    defer _ = c.BIO_free(key_bio);

    if (c.PEM_write_bio_PrivateKey(key_bio, pkey, null, null, 0, null, null) != 1)
        return error.TlsCertGenFailed;

    var key_ptr: [*c]u8 = undefined;
    const key_len = c.BIO_ctrl(key_bio, c.BIO_CTRL_INFO, 0, @ptrCast(&key_ptr));
    if (key_len <= 0 or key_len > result.key_pem.len) return error.TlsCertGenFailed;
    const key_ulen: u16 = @intCast(key_len);
    @memcpy(result.key_pem[0..key_ulen], key_ptr[0..key_ulen]);
    result.key_pem_len = key_ulen;

    log.info("generated self-signed EC P-256 certificate (CN=znode, valid 365 days)", .{});

    return result;
}

// ── Tests ──

test "generate self-signed certificate" {
    const cert = try generate();

    // Verify PEM headers are present
    try std.testing.expect(cert.cert_pem_len > 0);
    try std.testing.expect(cert.key_pem_len > 0);

    const cert_pem = cert.getCertPem();
    const key_pem = cert.getKeyPem();

    try std.testing.expect(std.mem.startsWith(u8, cert_pem, "-----BEGIN CERTIFICATE-----"));
    try std.testing.expect(std.mem.indexOf(u8, cert_pem, "-----END CERTIFICATE-----") != null);

    try std.testing.expect(std.mem.startsWith(u8, key_pem, "-----BEGIN PRIVATE KEY-----") or
        std.mem.startsWith(u8, key_pem, "-----BEGIN EC PRIVATE KEY-----"));
}
