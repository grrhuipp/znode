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
    @cInclude("openssl/bn.h");
    @cInclude("openssl/asn1.h");
});
const log = @import("../core/log.zig");

/// Dynamic SNI-based self-signed certificate provider.
/// Generates certificates on-the-fly matching the client's requested hostname,
/// so the TLS handshake doesn't reveal the proxy backend type.
///
/// Thread-safe: shared by all workers, protected by mutex.
/// Uses a single EC P-256 key pair for all generated certs (fast: only X509 signing per host).
pub const DynamicCertProvider = struct {
    shared_key: ?*c.EVP_PKEY = null,
    cache: [cache_size]CacheSlot = [_]CacheSlot{.{}} ** cache_size,
    mutex: std.Thread.Mutex = .{},

    const cache_size = 256;

    const CacheSlot = struct {
        hostname: [253]u8 = [_]u8{0} ** 253,
        hostname_len: u8 = 0,
        x509: ?*c.X509 = null,
    };

    /// Opaque cert+key pair for cross-module use (avoids @cImport type issues).
    pub const CertPair = struct {
        cert: *anyopaque,
        key: *anyopaque,
    };

    pub fn init() !DynamicCertProvider {
        var provider: DynamicCertProvider = .{};
        provider.shared_key = generateEcKey() orelse return error.TlsCertGenFailed;
        return provider;
    }

    pub fn deinit(self: *DynamicCertProvider) void {
        for (&self.cache) |*slot| {
            if (slot.x509) |x| c.X509_free(x);
            slot.x509 = null;
        }
        if (self.shared_key) |k| c.EVP_PKEY_free(k);
        self.shared_key = null;
    }

    /// Load a default certificate (CN=localhost) onto an SSL_CTX.
    /// Used for connections that don't send SNI.
    /// Takes *anyopaque to avoid cross-module @cImport type conflicts.
    pub fn installDefaultCert(self: *DynamicCertProvider, ssl_ctx_raw: *anyopaque) void {
        const ctx: *c.SSL_CTX = @ptrCast(ssl_ctx_raw);
        const key = self.shared_key orelse return;
        const default_cert = createCertForHost("localhost", key) orelse return;
        defer c.X509_free(default_cert);
        _ = c.SSL_CTX_use_certificate(ctx, default_cert);
        _ = c.SSL_CTX_use_PrivateKey(ctx, key);
    }

    /// Thread-safe: look up or generate a certificate for the given hostname.
    pub fn getOrCreateCert(self: *DynamicCertProvider, hostname: []const u8) ?CertPair {
        if (hostname.len == 0 or hostname.len > 253) return null;
        const key = self.shared_key orelse return null;

        self.mutex.lock();
        defer self.mutex.unlock();

        const slot_idx = hashHostname(hostname) % cache_size;
        const slot = &self.cache[slot_idx];

        // Cache hit?
        if (slot.x509 != null and
            slot.hostname_len == hostname.len and
            std.mem.eql(u8, slot.hostname[0..slot.hostname_len], hostname))
        {
            return .{ .cert = @ptrCast(slot.x509.?), .key = @ptrCast(key) };
        }

        // Cache miss: generate new cert
        const x509 = createCertForHost(hostname, key) orelse return null;

        // Evict old entry if present
        if (slot.x509) |old| c.X509_free(old);

        // Store new entry
        @memcpy(slot.hostname[0..hostname.len], hostname);
        slot.hostname_len = @intCast(hostname.len);
        slot.x509 = x509;

        return .{ .cert = @ptrCast(x509), .key = @ptrCast(key) };
    }

    fn hashHostname(hostname: []const u8) usize {
        var h: u32 = 2166136261; // FNV-1a offset basis
        for (hostname) |b| {
            h ^= b;
            h *%= 16777619;
        }
        return h;
    }

    fn generateEcKey() ?*c.EVP_PKEY {
        const pkey = c.EVP_PKEY_new() orelse return null;
        const ec = c.EC_KEY_new_by_curve_name(c.NID_X9_62_prime256v1) orelse {
            c.EVP_PKEY_free(pkey);
            return null;
        };
        if (c.EC_KEY_generate_key(ec) != 1) {
            c.EC_KEY_free(ec);
            c.EVP_PKEY_free(pkey);
            return null;
        }
        // EVP_PKEY_assign_EC_KEY takes ownership of ec on success
        if (c.EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
            c.EC_KEY_free(ec);
            c.EVP_PKEY_free(pkey);
            return null;
        }
        return pkey;
    }

    fn createCertForHost(hostname: []const u8, pkey: *c.EVP_PKEY) ?*c.X509 {
        const x509 = c.X509_new() orelse return null;

        // Serial, version, validity
        _ = c.ASN1_INTEGER_set(c.X509_get_serialNumber(x509), 1);
        _ = c.X509_set_version(x509, 2); // v3
        _ = c.X509_gmtime_adj(c.X509_getm_notBefore(x509), 0);
        _ = c.X509_gmtime_adj(c.X509_getm_notAfter(x509), 365 * 24 * 3600);
        _ = c.X509_set_pubkey(x509, pkey);

        // CN = hostname (null-terminated for C API)
        var cn_buf: [254]u8 = undefined;
        const cn_len = @min(hostname.len, 253);
        @memcpy(cn_buf[0..cn_len], hostname[0..cn_len]);
        cn_buf[cn_len] = 0;

        const name = c.X509_get_subject_name(x509);
        _ = c.X509_NAME_add_entry_by_txt(name, "CN", c.MBSTRING_ASC, &cn_buf, @intCast(cn_len), -1, 0);

        // Self-signed: issuer = subject
        _ = c.X509_set_issuer_name(x509, name);

        // SAN extension: DNS:<hostname>
        var san_buf: [260]u8 = undefined;
        const san_slice = std.fmt.bufPrint(&san_buf, "DNS:{s}", .{hostname[0..cn_len]}) catch {
            c.X509_free(x509);
            return null;
        };
        san_buf[san_slice.len] = 0; // null-terminate

        var ext_ctx: c.X509V3_CTX = undefined;
        c.X509V3_set_ctx(&ext_ctx, x509, x509, null, null, 0);
        if (c.X509V3_EXT_nconf_nid(null, &ext_ctx, c.NID_subject_alt_name, &san_buf)) |ext| {
            _ = c.X509_add_ext(x509, ext, -1);
            c.X509_EXTENSION_free(ext);
        }

        // Sign with SHA-256
        if (c.X509_sign(x509, pkey, c.EVP_sha256()) == 0) {
            c.X509_free(x509);
            return null;
        }

        return x509;
    }
};

// ══════════════════════════════════════════════════════════════
//  SNI Parser — pure binary, no BoringSSL dependency
// ══════════════════════════════════════════════════════════════

/// Parse the SNI hostname from a raw TLS ClientHello record.
/// Returns a slice into the input data (no allocation).
/// Returns null if no SNI extension is found or data is malformed.
pub fn parseSniFromClientHello(data: []const u8) ?[]const u8 {
    // TLS Record: ContentType(1) + Version(2) + Length(2)
    if (data.len < 5) return null;
    if (data[0] != 0x16) return null; // Not Handshake
    const record_len = readU16(data[3..5]);
    if (data.len < 5 + record_len) return null;

    const hs = data[5..];

    // Handshake: Type(1) + Length(3)
    if (hs.len < 4) return null;
    if (hs[0] != 0x01) return null; // Not ClientHello

    const hs_len = readU24(hs[1..4]);
    if (hs.len < 4 + hs_len) return null;

    var pos: usize = 4; // past handshake header

    // ClientHello: Version(2) + Random(32)
    if (pos + 34 > hs.len) return null;
    pos += 34;

    // Session ID (variable)
    if (pos + 1 > hs.len) return null;
    const sid_len = hs[pos];
    pos += 1 + sid_len;
    if (pos > hs.len) return null;

    // Cipher Suites (variable, 2-byte length)
    if (pos + 2 > hs.len) return null;
    const cs_len = readU16(hs[pos .. pos + 2]);
    pos += 2 + cs_len;
    if (pos > hs.len) return null;

    // Compression Methods (variable, 1-byte length)
    if (pos + 1 > hs.len) return null;
    const cm_len = hs[pos];
    pos += 1 + cm_len;
    if (pos > hs.len) return null;

    // Extensions (variable, 2-byte total length)
    if (pos + 2 > hs.len) return null;
    const ext_total_len = readU16(hs[pos .. pos + 2]);
    pos += 2;
    const ext_end = pos + ext_total_len;
    if (ext_end > hs.len) return null;

    // Walk extensions looking for server_name (type 0x0000)
    while (pos + 4 <= ext_end) {
        const ext_type = readU16(hs[pos .. pos + 2]);
        const ext_len = readU16(hs[pos + 2 .. pos + 4]);
        pos += 4;
        if (pos + ext_len > ext_end) return null;

        if (ext_type == 0x0000) { // server_name
            return parseServerNameExtension(hs[pos .. pos + ext_len]);
        }
        pos += ext_len;
    }

    return null;
}

fn parseServerNameExtension(data: []const u8) ?[]const u8 {
    // ServerNameList: Length(2) + [NameType(1) + Length(2) + Name]...
    if (data.len < 2) return null;
    const list_len = readU16(data[0..2]);
    if (data.len < 2 + list_len) return null;

    var pos: usize = 2;
    const end = 2 + list_len;
    while (pos + 3 <= end) {
        const name_type = data[pos];
        const name_len = readU16(data[pos + 1 .. pos + 3]);
        pos += 3;
        if (pos + name_len > end) return null;

        if (name_type == 0x00) { // host_name
            return data[pos .. pos + name_len];
        }
        pos += name_len;
    }
    return null;
}

fn readU16(b: []const u8) usize {
    return (@as(usize, b[0]) << 8) | b[1];
}

fn readU24(b: []const u8) usize {
    return (@as(usize, b[0]) << 16) | (@as(usize, b[1]) << 8) | b[2];
}

// ══════════════════════════════════════════════════════════════
//  Tests
// ══════════════════════════════════════════════════════════════

test "parseSniFromClientHello — valid ClientHello with SNI" {
    // Minimal TLS 1.2 ClientHello with SNI extension for "example.com"
    const hostname = "example.com";
    var buf: [512]u8 = undefined;
    const n = buildTestClientHello(&buf, hostname);
    const result = parseSniFromClientHello(buf[0..n]);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings(hostname, result.?);
}

test "parseSniFromClientHello — no SNI" {
    // ClientHello with no extensions
    var buf: [512]u8 = undefined;
    const n = buildTestClientHelloNoSni(&buf);
    const result = parseSniFromClientHello(buf[0..n]);
    try std.testing.expect(result == null);
}

test "parseSniFromClientHello — truncated data" {
    try std.testing.expect(parseSniFromClientHello("") == null);
    try std.testing.expect(parseSniFromClientHello("\x16\x03\x01") == null);
    try std.testing.expect(parseSniFromClientHello("\x17\x03\x01\x00\x05\x01\x00\x00\x01\x00") == null); // wrong record type
}

test "parseSniFromClientHello — various hostnames" {
    const hostnames = [_][]const u8{
        "a.com",
        "subdomain.example.org",
        "very-long-subdomain.deep.nested.domain.example.com",
        "1.2.3.4", // IP-based SNI (some clients do this)
    };
    for (hostnames) |hostname| {
        var buf: [512]u8 = undefined;
        const n = buildTestClientHello(&buf, hostname);
        const result = parseSniFromClientHello(buf[0..n]);
        try std.testing.expect(result != null);
        try std.testing.expectEqualStrings(hostname, result.?);
    }
}

test "DynamicCertProvider init and deinit" {
    var provider = try DynamicCertProvider.init();
    defer provider.deinit();
    try std.testing.expect(provider.shared_key != null);
}

test "DynamicCertProvider getOrCreateCert" {
    var provider = try DynamicCertProvider.init();
    defer provider.deinit();

    const pair = provider.getOrCreateCert("example.com");
    try std.testing.expect(pair != null);

    // Second call should hit cache
    const pair2 = provider.getOrCreateCert("example.com");
    try std.testing.expect(pair2 != null);
    try std.testing.expectEqual(pair.?.cert, pair2.?.cert); // same X509 pointer

    // Different hostname
    const pair3 = provider.getOrCreateCert("other.com");
    try std.testing.expect(pair3 != null);
}

test "DynamicCertProvider empty hostname" {
    var provider = try DynamicCertProvider.init();
    defer provider.deinit();
    try std.testing.expect(provider.getOrCreateCert("") == null);
}

// ── Test helpers ──

fn buildTestClientHello(buf: []u8, hostname: []const u8) usize {
    var pos: usize = 0;

    // We'll build the inner content first, then wrap with headers
    // Start after TLS record header (5) + handshake header (4) = 9
    const inner_start: usize = 9;
    pos = inner_start;

    // ClientHello body:
    // Version: TLS 1.2
    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2;

    // Random (32 bytes)
    @memset(buf[pos .. pos + 32], 0xAA);
    pos += 32;

    // Session ID length (0)
    buf[pos] = 0;
    pos += 1;

    // Cipher suites: length=2, one cipher
    buf[pos] = 0x00;
    buf[pos + 1] = 0x02;
    buf[pos + 2] = 0xC0;
    buf[pos + 3] = 0x2F; // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    pos += 4;

    // Compression methods: length=1, null
    buf[pos] = 0x01;
    buf[pos + 1] = 0x00;
    pos += 2;

    // Extensions
    const ext_start = pos + 2; // skip extensions total length
    var ext_pos = ext_start;

    // server_name extension (type=0x0000)
    buf[ext_pos] = 0x00;
    buf[ext_pos + 1] = 0x00; // extension type
    const sni_data_len: u16 = @intCast(hostname.len + 5); // list_len(2) + type(1) + name_len(2) + name
    buf[ext_pos + 2] = @intCast(sni_data_len >> 8);
    buf[ext_pos + 3] = @intCast(sni_data_len & 0xFF);
    ext_pos += 4;

    // ServerNameList
    const name_list_len: u16 = @intCast(hostname.len + 3); // type(1) + name_len(2) + name
    buf[ext_pos] = @intCast(name_list_len >> 8);
    buf[ext_pos + 1] = @intCast(name_list_len & 0xFF);
    ext_pos += 2;

    // HostName entry
    buf[ext_pos] = 0x00; // host_name type
    buf[ext_pos + 1] = @intCast(hostname.len >> 8);
    buf[ext_pos + 2] = @intCast(hostname.len & 0xFF);
    ext_pos += 3;
    @memcpy(buf[ext_pos .. ext_pos + hostname.len], hostname);
    ext_pos += hostname.len;

    // Write extensions total length
    const ext_total_len: u16 = @intCast(ext_pos - ext_start);
    buf[pos] = @intCast(ext_total_len >> 8);
    buf[pos + 1] = @intCast(ext_total_len & 0xFF);
    pos = ext_pos;

    // Now write headers
    const ch_body_len = pos - inner_start;

    // Handshake header at offset 5
    buf[5] = 0x01; // ClientHello
    buf[6] = @intCast((ch_body_len >> 16) & 0xFF);
    buf[7] = @intCast((ch_body_len >> 8) & 0xFF);
    buf[8] = @intCast(ch_body_len & 0xFF);

    // TLS Record header at offset 0
    const record_len = ch_body_len + 4; // handshake header + body
    buf[0] = 0x16; // Handshake
    buf[1] = 0x03;
    buf[2] = 0x01; // TLS 1.0 record version
    buf[3] = @intCast((record_len >> 8) & 0xFF);
    buf[4] = @intCast(record_len & 0xFF);

    return pos;
}

fn buildTestClientHelloNoSni(buf: []u8) usize {
    var pos: usize = 0;
    const inner_start: usize = 9;
    pos = inner_start;

    // Version
    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2;

    // Random
    @memset(buf[pos .. pos + 32], 0xBB);
    pos += 32;

    // Session ID length (0)
    buf[pos] = 0;
    pos += 1;

    // Cipher suites
    buf[pos] = 0x00;
    buf[pos + 1] = 0x02;
    buf[pos + 2] = 0xC0;
    buf[pos + 3] = 0x2F;
    pos += 4;

    // Compression methods
    buf[pos] = 0x01;
    buf[pos + 1] = 0x00;
    pos += 2;

    // No extensions — total length = 0
    buf[pos] = 0x00;
    buf[pos + 1] = 0x00;
    pos += 2;

    const ch_body_len = pos - inner_start;
    buf[5] = 0x01;
    buf[6] = @intCast((ch_body_len >> 16) & 0xFF);
    buf[7] = @intCast((ch_body_len >> 8) & 0xFF);
    buf[8] = @intCast(ch_body_len & 0xFF);

    const record_len = ch_body_len + 4;
    buf[0] = 0x16;
    buf[1] = 0x03;
    buf[2] = 0x01;
    buf[3] = @intCast((record_len >> 8) & 0xFF);
    buf[4] = @intCast(record_len & 0xFF);

    return pos;
}
