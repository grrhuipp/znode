/// DNS resolution service — async UDP queries with caching.
///
/// Uses zio fiber-aware UDP sockets for non-blocking DNS queries.
/// Sends A record queries to configured DNS servers.
/// Caches results with configurable TTL bounds.
/// Falls through servers on failure.
const std = @import("std");
const zio = @import("zio");
const packet = @import("packet.zig");
const cache_mod = @import("cache.zig");
const config = @import("../infra/config.zig");

pub const DnsError = error{
    ResolveFailed,
    Timeout,
    NoRecord,
    ServerFailed,
    FormatError,
    Refused,
    NetworkError,
};

pub const DnsService = struct {
    servers: []const []const u8,
    cache: cache_mod.DnsCache,
    timeout_ms: u32,
    txid_counter: std.atomic.Value(u16) = std.atomic.Value(u16).init(1),

    pub fn init(
        allocator: std.mem.Allocator,
        dns_config: config.DnsConfig,
    ) DnsService {
        const servers = if (dns_config.servers.len > 0)
            dns_config.servers
        else
            @as([]const []const u8, &.{ "8.8.8.8", "1.1.1.1" });

        return .{
            .servers = servers,
            .cache = cache_mod.DnsCache.init(
                allocator,
                dns_config.cache_size,
                dns_config.min_ttl,
                dns_config.max_ttl,
            ),
            .timeout_ms = dns_config.timeout * 1000,
        };
    }

    /// Resolve domain to first IPv4 address. Uses cache.
    /// Fiber-safe: suspends current fiber during UDP I/O, does not block the thread.
    pub fn resolve(self: *DnsService, domain: []const u8) DnsError![]const u8 {
        // Check cache
        if (self.cache.get(domain)) |entry| {
            if (entry.negative) return error.NoRecord;
            if (entry.count > 0) return entry.addrs()[0].text();
        }

        // Query DNS servers (fiber suspends here, not blocking)
        const result = self.queryServers(domain) catch |err| return err;

        // Cache result
        if (result.rcode == .name_error) {
            self.cache.putNegative(domain);
            return error.NoRecord;
        }

        if (result.count > 0) {
            self.cache.put(domain, &result);
            return result.addrs()[0].text();
        }

        return error.NoRecord;
    }

    fn queryServers(self: *DnsService, domain: []const u8) DnsError!packet.QueryResult {
        var last_err: DnsError = error.ResolveFailed;

        for (self.servers) |server| {
            const result = self.querySingle(domain, server) catch |err| {
                last_err = err;
                continue;
            };

            if (result.rcode == .name_error) return result; // NXDOMAIN is authoritative
            if (result.rcode == .ok and result.count > 0) return result;

            last_err = switch (result.rcode) {
                .server_failure => error.ServerFailed,
                .refused => error.Refused,
                .format_error => error.FormatError,
                else => error.ResolveFailed,
            };
        }

        return last_err;
    }

    fn querySingle(self: *DnsService, domain: []const u8, server: []const u8) DnsError!packet.QueryResult {
        const txid = self.txid_counter.fetchAdd(1, .monotonic);

        // Build query
        var query_buf: [512]u8 = undefined;
        const query_len = packet.buildQuery(domain, .a, txid, &query_buf) orelse
            return error.FormatError;

        // Parse server address into zio format
        const ip_addr = zio.net.IpAddress.parseIp4(server, 53) catch return error.NetworkError;
        const addr = zio.net.Address{ .ip = ip_addr };

        // Create UDP socket via zio (fiber-aware, io_uring backed)
        const sock = zio.net.Socket.open(.dgram, .ipv4, .ip) catch return error.NetworkError;
        defer sock.close();

        // Convert timeout
        const timeout: zio.Timeout = if (self.timeout_ms > 0)
            .{ .ns = @as(u64, self.timeout_ms) * 1_000_000 }
        else
            .none;

        // Send — suspends fiber if needed, does not block thread
        _ = sock.sendTo(addr, query_buf[0..query_len], timeout) catch
            return error.NetworkError;

        // Receive — suspends fiber until response arrives or timeout
        var resp_buf: [1024]u8 = undefined;
        const recv_result = sock.receiveFrom(&resp_buf, timeout) catch
            return error.Timeout;

        // Parse response
        return packet.parseResponse(resp_buf[0..recv_result.len], txid) orelse error.FormatError;
    }
};
