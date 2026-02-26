const std = @import("std");
const log = @import("../core/log.zig");
const tls_mod = @import("tls_stream.zig");
const self_signed = @import("self_signed.zig");
const dynamic_cert = @import("dynamic_cert.zig");

/// Global dynamic cert provider — shared by all self-signed TLS contexts.
/// Created lazily on first self-signed listener, freed by deinitDynamicCert().
var g_dynamic_cert: ?*dynamic_cert.DynamicCertProvider = null;

/// Get the global dynamic cert provider (null if no self-signed listeners).
pub fn getDynamicCertProvider() ?*dynamic_cert.DynamicCertProvider {
    return g_dynamic_cert;
}

/// Free the global dynamic cert provider. Call during shutdown.
pub fn deinitDynamicCert(allocator: std.mem.Allocator) void {
    if (g_dynamic_cert) |p| {
        p.deinit();
        allocator.destroy(p);
        g_dynamic_cert = null;
    }
}

/// Initialize a server-side TLS context with certificate and key.
/// If cert_file_z / key_file_z are provided, loads from files.
/// Otherwise uses dynamic SNI-based self-signed certificates.
/// Returns null on any failure (errors are logged internally).
pub fn initServerTlsContext(
    allocator: std.mem.Allocator,
    cert_file_z: ?[*:0]const u8,
    key_file_z: ?[*:0]const u8,
    log_prefix: []const u8,
) ?*tls_mod.TlsContext {
    const ctx = allocator.create(tls_mod.TlsContext) catch {
        log.err("{s}: OOM creating TLS context", .{log_prefix});
        return null;
    };
    ctx.* = tls_mod.TlsContext.initServer() catch |e| {
        log.err("{s}: TLS init failed: {}", .{ log_prefix, e });
        allocator.destroy(ctx);
        return null;
    };

    if (cert_file_z) |cert_z| {
        const key_z = key_file_z orelse {
            log.err("{s}: cert file provided but no key file", .{log_prefix});
            var c = ctx;
            c.deinit();
            allocator.destroy(ctx);
            return null;
        };
        ctx.loadCertFile(cert_z) catch |e| {
            log.err("{s}: cert load failed: {}", .{ log_prefix, e });
            var c = ctx;
            c.deinit();
            allocator.destroy(ctx);
            return null;
        };
        ctx.loadKeyFile(key_z) catch |e| {
            log.err("{s}: key load failed: {}", .{ log_prefix, e });
            var c = ctx;
            c.deinit();
            allocator.destroy(ctx);
            return null;
        };
        log.info("{s} TLS: cert={s}, key={s}", .{ log_prefix, std.mem.span(cert_z), std.mem.span(key_z) });
    } else {
        // Dynamic SNI self-signed: create global provider if needed
        if (g_dynamic_cert == null) {
            const provider = allocator.create(dynamic_cert.DynamicCertProvider) catch {
                log.err("{s}: OOM creating DynamicCertProvider", .{log_prefix});
                var c = ctx;
                c.deinit();
                allocator.destroy(ctx);
                return null;
            };
            provider.* = dynamic_cert.DynamicCertProvider.init() catch |e| {
                log.err("{s}: DynamicCertProvider init failed: {}", .{ log_prefix, e });
                allocator.destroy(provider);
                var c = ctx;
                c.deinit();
                allocator.destroy(ctx);
                return null;
            };
            g_dynamic_cert = provider;
        }

        // Install default cert on SSL_CTX (for connections without SNI)
        g_dynamic_cert.?.installDefaultCert(@ptrCast(ctx.ctx));
        log.info("{s} TLS: dynamic SNI self-signed certificate", .{log_prefix});
    }

    return ctx;
}
