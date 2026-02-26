const std = @import("std");
const builtin = @import("builtin");
const cache_mod = @import("cache.zig");
const config_mod = @import("../core/config.zig");
const log = @import("../core/log.zig");

/// DNS resolver with self-implemented wire format.
/// Each worker owns an independent instance.
pub const Resolver = struct {
    cache: cache_mod.DnsCache,
    upstream_servers: []const []const u8,
    allocator: std.mem.Allocator,
    next_id: u16 = 1,

    pub fn init(
        allocator: std.mem.Allocator,
        servers: []const []const u8,
        cache_size: u32,
        min_ttl: u32,
        max_ttl: u32,
    ) Resolver {
        return .{
            .cache = cache_mod.DnsCache.init(min_ttl, max_ttl, cache_size),
            .upstream_servers = servers,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Resolver) void {
        self.cache.deinit(self.allocator);
    }

    /// Resolve a domain name. Checks cache first, then queries upstream.
    /// Synchronous blocking version for Phase 2. Will be made async with libxev UDP in later phases.
    pub fn resolve(self: *Resolver, domain: []const u8) !ResolveResult {
        // Check cache first
        if (self.cache.lookup(domain)) |entry| {
            if (entry.is_negative) return error.DnsNxDomain;
            return cachedToResult(entry);
        }

        // Query upstream DNS server
        const result = try self.queryUpstream(domain);

        // Cache the result
        var cache_entry = cache_mod.DnsCache.CachedEntry{};
        if (result.ip4) |ip4| {
            cache_entry.addresses[cache_entry.addr_count] = .{ .ip4 = ip4 };
            cache_entry.addr_count += 1;
        }
        if (result.ip6) |ip6| {
            cache_entry.addresses[cache_entry.addr_count] = .{ .ip6 = ip6 };
            cache_entry.addr_count += 1;
        }
        self.cache.insert(self.allocator, domain, cache_entry, result.ttl) catch {};

        return result;
    }

    pub fn cachedToResult(entry: cache_mod.DnsCache.CachedEntry) ResolveResult {
        var result = ResolveResult{};
        for (entry.getAddresses()) |addr| {
            if (addr.ip4 != null and result.ip4 == null) {
                result.ip4 = addr.ip4;
            }
            if (addr.ip6 != null and result.ip6 == null) {
                result.ip6 = addr.ip6;
            }
        }
        return result;
    }

    fn queryUpstream(self: *Resolver, domain: []const u8) !ResolveResult {
        if (self.upstream_servers.len == 0) return error.DnsNoUpstreamServers;

        // Try each upstream server
        var last_err: anyerror = error.DnsResolutionFailed;
        for (self.upstream_servers) |server| {
            const result = self.querySingleServer(domain, server) catch |e| {
                last_err = e;
                continue;
            };
            return result;
        }
        return last_err;
    }

    pub fn querySingleServer(self: *Resolver, domain: []const u8, server: []const u8) !ResolveResult {
        // Build DNS query packet
        var query_buf: [512]u8 = undefined;
        const query_len = try buildQuery(&query_buf, domain, self.nextId());

        // Send via UDP (blocking, using std.posix)
        const addr = std.net.Address.parseIp4(server, 53) catch
            return error.DnsInvalidServer;

        const sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch
            return error.DnsSocketFailed;
        defer std.posix.close(sock);

        // Set timeout (2 seconds)
        const timeout = std.posix.timeval{ .sec = 2, .usec = 0 };
        std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

        _ = std.posix.sendto(sock, query_buf[0..query_len], 0, &addr.any, addr.getOsSockLen()) catch
            return error.DnsSendFailed;

        var resp_buf: [512]u8 = undefined;
        const resp_len = std.posix.recvfrom(sock, &resp_buf, 0, null, null) catch
            return error.DnsTimeout;

        return parseResponse(resp_buf[0..resp_len]);
    }

    fn nextId(self: *Resolver) u16 {
        const id = self.next_id;
        self.next_id +%= 1;
        if (self.next_id == 0) self.next_id = 1;
        return id;
    }
};

pub const ResolveResult = struct {
    ip4: ?[4]u8 = null,
    ip6: ?[16]u8 = null,
    ttl: u32 = 300,

    pub fn toAddress(self: ResolveResult, port: u16) ?std.net.Address {
        if (self.ip4) |ip4| {
            return std.net.Address.initIp4(ip4, port);
        }
        if (self.ip6) |ip6| {
            return std.net.Address.initIp6(ip6, port, 0, 0);
        }
        return null;
    }
};

// ── DNS Wire Format ──

/// Build a DNS A query packet.
fn buildQuery(buf: []u8, domain: []const u8, id: u16) !usize {
    if (buf.len < 512) return error.BufferTooSmall;
    var pos: usize = 0;

    // Header (12 bytes)
    // ID
    buf[pos] = @intCast(id >> 8);
    buf[pos + 1] = @intCast(id & 0xFF);
    pos += 2;
    // Flags: RD=1 (recursion desired)
    buf[pos] = 0x01;
    buf[pos + 1] = 0x00;
    pos += 2;
    // QDCOUNT = 1
    buf[pos] = 0x00;
    buf[pos + 1] = 0x01;
    pos += 2;
    // ANCOUNT, NSCOUNT, ARCOUNT = 0
    @memset(buf[pos .. pos + 6], 0);
    pos += 6;

    // Question section: encode domain name
    pos = try encodeDomainName(buf, pos, domain);

    // QTYPE = A (1)
    buf[pos] = 0x00;
    buf[pos + 1] = 0x01;
    pos += 2;
    // QCLASS = IN (1)
    buf[pos] = 0x00;
    buf[pos + 1] = 0x01;
    pos += 2;

    return pos;
}

/// Encode a domain name in DNS wire format (labels).
fn encodeDomainName(buf: []u8, start: usize, domain: []const u8) !usize {
    var pos = start;
    var i: usize = 0;

    while (i < domain.len) {
        // Find next dot
        var end = i;
        while (end < domain.len and domain[end] != '.') : (end += 1) {}

        const label_len = end - i;
        if (label_len == 0 or label_len > 63) return error.InvalidDomain;
        if (pos + 1 + label_len >= buf.len) return error.BufferTooSmall;

        buf[pos] = @intCast(label_len);
        pos += 1;
        @memcpy(buf[pos .. pos + label_len], domain[i .. i + label_len]);
        pos += label_len;

        i = end;
        if (i < domain.len and domain[i] == '.') i += 1;
    }

    // Null terminator
    buf[pos] = 0;
    pos += 1;
    return pos;
}

/// Parse a DNS response and extract A records.
fn parseResponse(data: []const u8) !ResolveResult {
    if (data.len < 12) return error.InvalidResponse;

    // Check response code (RCODE in lower 4 bits of byte 3)
    const rcode = data[3] & 0x0F;
    if (rcode == 3) return error.DnsNxDomain; // NXDOMAIN
    if (rcode != 0) return error.DnsResolutionFailed;

    const ancount = (@as(u16, data[6]) << 8) | data[7];
    if (ancount == 0) return error.DnsResolutionFailed;

    // Skip question section
    var pos: usize = 12;
    pos = try skipDomainName(data, pos);
    pos += 4; // QTYPE + QCLASS

    // Parse answer records
    var result = ResolveResult{};
    for (0..ancount) |_| {
        if (pos >= data.len) break;

        // Skip name (may be compressed)
        pos = try skipDomainName(data, pos);
        if (pos + 10 > data.len) break;

        const rtype = (@as(u16, data[pos]) << 8) | data[pos + 1];
        pos += 2;
        // Skip class
        pos += 2;
        // TTL
        const ttl = (@as(u32, data[pos]) << 24) | (@as(u32, data[pos + 1]) << 16) |
            (@as(u32, data[pos + 2]) << 8) | data[pos + 3];
        pos += 4;
        // RDLENGTH
        const rdlen = (@as(u16, data[pos]) << 8) | data[pos + 1];
        pos += 2;

        if (pos + rdlen > data.len) break;

        if (rtype == 1 and rdlen == 4 and result.ip4 == null) {
            // A record
            result.ip4 = data[pos..][0..4].*;
            result.ttl = ttl;
        } else if (rtype == 28 and rdlen == 16 and result.ip6 == null) {
            // AAAA record
            result.ip6 = data[pos..][0..16].*;
            if (result.ttl == 300) result.ttl = ttl;
        }

        pos += rdlen;
    }

    if (result.ip4 == null and result.ip6 == null) {
        return error.DnsResolutionFailed;
    }
    return result;
}

/// Skip a DNS domain name (handles compression pointers).
fn skipDomainName(data: []const u8, start: usize) !usize {
    var pos = start;
    while (pos < data.len) {
        const len = data[pos];
        if (len == 0) {
            pos += 1;
            break;
        }
        if ((len & 0xC0) == 0xC0) {
            // Compression pointer (2 bytes)
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    return pos;
}

test "encodeDomainName" {
    var buf: [256]u8 = undefined;
    const len = try encodeDomainName(&buf, 0, "www.example.com");
    // Expected: \x03www\x07example\x03com\x00
    try std.testing.expectEqual(@as(usize, 17), len);
    try std.testing.expectEqual(@as(u8, 3), buf[0]);
    try std.testing.expectEqualStrings("www", buf[1..4]);
    try std.testing.expectEqual(@as(u8, 7), buf[4]);
    try std.testing.expectEqualStrings("example", buf[5..12]);
    try std.testing.expectEqual(@as(u8, 3), buf[12]);
    try std.testing.expectEqualStrings("com", buf[13..16]);
    try std.testing.expectEqual(@as(u8, 0), buf[16]);
}

test "buildQuery produces valid packet" {
    var buf: [512]u8 = undefined;
    const len = try buildQuery(&buf, "example.com", 0x1234);
    try std.testing.expect(len > 12);
    // Check ID
    try std.testing.expectEqual(@as(u8, 0x12), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x34), buf[1]);
    // Check RD flag
    try std.testing.expectEqual(@as(u8, 0x01), buf[2]);
    // Check QDCOUNT = 1
    try std.testing.expectEqual(@as(u8, 0x01), buf[5]);
}

// ── Async DNS Resolver ──
//
// Wraps the synchronous Resolver in a dedicated thread to avoid blocking
// worker event loops. Requests are submitted via a mutex-protected queue.
// Results are delivered via a callback stored in the request.

/// A pending DNS resolution request.
pub const DnsRequest = struct {
    domain: [256]u8 = [_]u8{0} ** 256,
    domain_len: u8 = 0,
    result: ?ResolveResult = null,
    err: bool = false,
    cache_hit: bool = false,
    callback: ?*const fn (req: *DnsRequest) void = null,
    user_data: ?*anyopaque = null,

    pub fn getDomain(self: *const DnsRequest) []const u8 {
        return self.domain[0..self.domain_len];
    }

    pub fn setDomain(self: *DnsRequest, d: []const u8) void {
        const n: u8 = @intCast(@min(d.len, self.domain.len));
        @memcpy(self.domain[0..n], d[0..n]);
        self.domain_len = n;
    }
};

/// Thread-safe request queue for async DNS.
pub const DnsRequestQueue = struct {
    allocator: std.mem.Allocator,
    inline_items: [initial_capacity]DnsRequest = undefined,
    items: []DnsRequest = &.{},
    heap_backed: bool = false,
    head: usize = 0,
    tail: usize = 0,
    len: usize = 0,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},

    const initial_capacity = 256;

    pub fn init(allocator: std.mem.Allocator) DnsRequestQueue {
        var q = DnsRequestQueue{
            .allocator = allocator,
        };
        q.items = q.inline_items[0..];
        return q;
    }

    pub fn deinit(self: *DnsRequestQueue) void {
        if (self.heap_backed and self.items.len > 0) {
            self.allocator.free(self.items);
        }
        self.items = &.{};
        self.heap_backed = false;
        self.head = 0;
        self.tail = 0;
        self.len = 0;
    }

    /// Submit a request. Auto-grows when full.
    pub fn push(self: *DnsRequestQueue, req: DnsRequest) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.len >= self.items.len) {
            if (!self.growLocked()) return false;
        }

        self.items[self.tail] = req;
        self.tail = (self.tail + 1) % self.items.len;
        self.len += 1;
        self.cond.signal();
        return true;
    }

    /// Pop a request (blocks until available or woken).
    pub fn pop(self: *DnsRequestQueue, running: *std.atomic.Value(bool)) ?DnsRequest {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.len == 0) {
            if (!running.load(.acquire)) return null;
            self.cond.timedWait(&self.mutex, 500 * std.time.ns_per_ms) catch {};
            if (!running.load(.acquire) and self.len == 0) return null;
        }
        const item = self.items[self.head];
        self.head = (self.head + 1) % self.items.len;
        self.len -= 1;
        return item;
    }

    fn growLocked(self: *DnsRequestQueue) bool {
        if (self.items.len >= std.math.maxInt(usize) / 2) return false;
        const old = self.items;
        const new_cap = if (old.len == 0) initial_capacity else old.len * 2;
        const grown = self.allocator.alloc(DnsRequest, new_cap) catch return false;

        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            grown[i] = old[(self.head + i) % old.len];
        }

        if (self.heap_backed and old.len > 0) {
            self.allocator.free(old);
        }
        self.items = grown;
        self.heap_backed = true;
        self.head = 0;
        self.tail = self.len;
        return true;
    }
};

/// Async DNS resolver that runs blocking queries on a dedicated thread.
/// Worker threads submit requests without blocking their event loops.
/// Supports DNS routing: domain-specific DNS servers (split DNS).
pub const AsyncResolver = struct {
    resolver: Resolver,
    queue: DnsRequestQueue = undefined,
    thread: ?std.Thread = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    logger: log.ScopedLogger,

    // DNS routing rules (split DNS)
    dns_routes: []const config_mod.DnsRoute = &.{},

    // Stats
    queries_total: u64 = 0,
    queries_failed: u64 = 0,
    queries_cached: u64 = 0,
    queries_routed: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        servers: []const []const u8,
        cache_size: u32,
        min_ttl: u32,
        max_ttl: u32,
    ) AsyncResolver {
        return .{
            .resolver = Resolver.init(allocator, servers, cache_size, min_ttl, max_ttl),
            .queue = DnsRequestQueue.init(allocator),
            .logger = log.ScopedLogger.init(0, "dns"),
        };
    }

    pub fn deinit(self: *AsyncResolver) void {
        self.queue.deinit();
        self.resolver.deinit();
    }

    /// Start the DNS worker thread.
    pub fn start(self: *AsyncResolver) !void {
        self.running.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, AsyncResolver.run, .{self});
    }

    /// Signal the DNS thread to stop.
    pub fn stop(self: *AsyncResolver) void {
        self.running.store(false, .release);
        // Wake the thread in case it's waiting on the condition
        self.queue.mutex.lock();
        self.queue.cond.signal();
        self.queue.mutex.unlock();
    }

    /// Wait for the DNS thread to finish.
    pub fn join(self: *AsyncResolver) void {
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    /// Submit a DNS query for asynchronous resolution.
    /// The callback will be invoked on the DNS thread when the result is ready.
    /// Returns false if the queue is full.
    pub fn submitQuery(self: *AsyncResolver, domain: []const u8, callback: ?*const fn (*DnsRequest) void, user_data: ?*anyopaque) bool {
        var req = DnsRequest{};
        req.setDomain(domain);
        req.callback = callback;
        req.user_data = user_data;
        return self.queue.push(req);
    }

    /// Synchronous resolve with cache (convenience for callers that can block).
    pub fn resolveSync(self: *AsyncResolver, domain: []const u8) !ResolveResult {
        return self.resolver.resolve(domain);
    }

    // ── DNS thread entry point ──

    fn run(self: *AsyncResolver) void {
        self.logger.info("async DNS resolver started", .{});

        while (self.running.load(.acquire)) {
            const maybe_req = self.queue.pop(&self.running);
            if (maybe_req) |*req_const| {
                var req = req_const.*;
                const domain = req.getDomain();
                if (domain.len == 0) continue;

                self.queries_total += 1;

                // 1. Check DNS cache first (fast path)
                if (self.resolver.cache.lookup(domain)) |entry| {
                    if (entry.is_negative) {
                        req.err = true;
                        self.queries_failed += 1;
                    } else {
                        req.result = Resolver.cachedToResult(entry);
                        req.cache_hit = true;
                        self.queries_cached += 1;
                    }
                } else {
                    // 2. Cache miss — check DNS routing rules first, then upstream, then system
                    const routed_result = self.resolveRouted(domain);
                    const resolve_result = routed_result orelse
                        self.resolver.queryUpstream(domain) catch
                        resolveSystem(domain) catch null;

                    if (resolve_result) |result| {
                        req.result = result;
                        // Cache the result for future lookups
                        var cache_entry = cache_mod.DnsCache.CachedEntry{};
                        if (result.ip4) |ip4| {
                            cache_entry.addresses[cache_entry.addr_count] = .{ .ip4 = ip4 };
                            cache_entry.addr_count += 1;
                        }
                        if (result.ip6) |ip6| {
                            cache_entry.addresses[cache_entry.addr_count] = .{ .ip6 = ip6 };
                            cache_entry.addr_count += 1;
                        }
                        self.resolver.cache.insert(self.resolver.allocator, domain, cache_entry, result.ttl) catch {};
                    } else {
                        req.err = true;
                        self.queries_failed += 1;
                    }
                }

                // Invoke callback if set
                if (req.callback) |cb| cb(&req);
            }
        }

        self.logger.info("async DNS resolver stopped (total={d}, failed={d}, cached={d}, routed={d})", .{
            self.queries_total,
            self.queries_failed,
            self.queries_cached,
            self.queries_routed,
        });
    }

    /// Try to resolve using DNS routing rules (split DNS).
    /// Returns null if no route matches — caller falls back to system DNS.
    fn resolveRouted(self: *AsyncResolver, domain: []const u8) ?ResolveResult {
        for (self.dns_routes) |*route| {
            if (route.matchesDomain(domain)) {
                const server = route.getServer();
                if (server.len == 0) continue;
                self.queries_routed += 1;
                return self.resolver.querySingleServer(domain, server) catch null;
            }
        }
        return null;
    }
};

// ══════════════════════════════════════════════════════════════
//  Cross-platform System DNS (getaddrinfo)
// ══════════════════════════════════════════════════════════════

/// Platform-specific C bindings for getaddrinfo.
/// Windows: ws2_32.dll, Linux/macOS: libc.
const c_dns = if (builtin.os.tag == .windows) struct {
    pub const AF_UNSPEC: c_int = 0;
    pub const AF_INET: u16 = 2;
    pub const AF_INET6: u16 = 23;
    pub const SOCK_STREAM: c_int = 1;

    // Windows ADDRINFOA layout: ai_addrlen is size_t, canonname before addr
    pub const addrinfo_t = extern struct {
        ai_flags: c_int = 0,
        ai_family: c_int = 0,
        ai_socktype: c_int = 0,
        ai_protocol: c_int = 0,
        ai_addrlen: usize = 0,
        ai_canonname: ?[*:0]u8 = null,
        ai_addr: ?*sockaddr_t = null,
        ai_next: ?*addrinfo_t = null,
    };

    pub const sockaddr_t = extern struct {
        family: u16 = 0,
        data: [14]u8 = [_]u8{0} ** 14,
    };

    pub extern "ws2_32" fn getaddrinfo(
        node: ?[*:0]const u8,
        service: ?[*:0]const u8,
        hints: ?*const addrinfo_t,
        res: *?*addrinfo_t,
    ) c_int;

    pub extern "ws2_32" fn freeaddrinfo(res: ?*addrinfo_t) void;
} else struct {
    pub const AF_UNSPEC: c_int = 0;
    pub const AF_INET: u16 = 2;
    pub const AF_INET6: u16 = if (builtin.os.tag == .macos) 30 else 10;
    pub const SOCK_STREAM: c_int = 1;

    // POSIX addrinfo layout: ai_addrlen is socklen_t(u32), addr before canonname
    pub const addrinfo_t = extern struct {
        ai_flags: c_int = 0,
        ai_family: c_int = 0,
        ai_socktype: c_int = 0,
        ai_protocol: c_int = 0,
        ai_addrlen: u32 = 0,
        ai_addr: ?*sockaddr_t = null,
        ai_canonname: ?[*:0]u8 = null,
        ai_next: ?*addrinfo_t = null,
    };

    pub const sockaddr_t = extern struct {
        family: u16 = 0,
        data: [14]u8 = [_]u8{0} ** 14,
    };

    pub extern "c" fn getaddrinfo(
        node: ?[*:0]const u8,
        service: ?[*:0]const u8,
        hints: ?*const addrinfo_t,
        res: *?*addrinfo_t,
    ) c_int;

    pub extern "c" fn freeaddrinfo(res: ?*addrinfo_t) void;
};

/// Resolve a domain name using the operating system's DNS resolver (getaddrinfo).
/// Cross-platform: uses system DNS settings on Windows, Linux, and macOS.
pub fn resolveSystem(domain: []const u8) !ResolveResult {
    // Null-terminate the domain
    var domain_z: [256:0]u8 = [_:0]u8{0} ** 256;
    const len = @min(domain.len, 255);
    @memcpy(domain_z[0..len], domain[0..len]);

    const hints = c_dns.addrinfo_t{
        .ai_family = c_dns.AF_UNSPEC,
        .ai_socktype = c_dns.SOCK_STREAM,
    };

    var result: ?*c_dns.addrinfo_t = null;
    const rc = c_dns.getaddrinfo(@ptrCast(&domain_z), null, &hints, &result);
    if (rc != 0) return error.DnsResolveFailed;
    defer c_dns.freeaddrinfo(result.?);

    var out = ResolveResult{};
    var it = result;
    while (it) |info| {
        if (info.ai_addr) |addr_ptr| {
            const family = addr_ptr.family;
            const raw: [*]const u8 = @ptrCast(addr_ptr);
            if (family == c_dns.AF_INET and out.ip4 == null) {
                // sockaddr_in: family(2) + port(2) + addr(4)
                out.ip4 = raw[4..8].*;
            } else if (family == c_dns.AF_INET6 and out.ip6 == null) {
                // sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16)
                out.ip6 = raw[8..24].*;
            }
        }
        it = info.ai_next;
    }

    if (out.ip4 == null and out.ip6 == null) return error.DnsNoResult;
    return out;
}

test "DnsRequestQueue push pop" {
    var q = DnsRequestQueue.init(std.testing.allocator);
    defer q.deinit();
    var running = std.atomic.Value(bool).init(true);

    var req1 = DnsRequest{};
    req1.setDomain("example.com");
    try std.testing.expect(q.push(req1));

    var req2 = DnsRequest{};
    req2.setDomain("test.org");
    try std.testing.expect(q.push(req2));

    const r1 = q.pop(&running).?;
    try std.testing.expectEqualStrings("example.com", r1.getDomain());

    const r2 = q.pop(&running).?;
    try std.testing.expectEqualStrings("test.org", r2.getDomain());

    // Queue empty, non-blocking check with running=false
    running.store(false, .release);
    try std.testing.expect(q.pop(&running) == null);
}

test "DnsRequestQueue auto growth" {
    var q = DnsRequestQueue.init(std.testing.allocator);
    defer q.deinit();

    const n = DnsRequestQueue.initial_capacity + 64;
    for (0..n) |_| {
        try std.testing.expect(q.push(.{}));
    }
    try std.testing.expect(q.items.len >= n);

    var running = std.atomic.Value(bool).init(true);
    for (0..n) |_| {
        try std.testing.expect(q.pop(&running) != null);
    }
    running.store(false, .release);
    try std.testing.expect(q.pop(&running) == null);
}

test "DnsRequest domain roundtrip" {
    var req = DnsRequest{};
    req.setDomain("www.example.com");
    try std.testing.expectEqualStrings("www.example.com", req.getDomain());
}

test "AsyncResolver init and deinit" {
    const servers = [_][]const u8{"8.8.8.8"};
    var resolver = AsyncResolver.init(std.testing.allocator, &servers, 4096, 60, 3600);
    defer resolver.deinit();
    try std.testing.expectEqual(@as(u64, 0), resolver.queries_total);
}
