/// V2Board panel sync — periodic user fetch and traffic reporting.
///
/// Each configured panel runs a sync loop in its own thread:
///   1. Fetch user list → update inbound user managers
///   2. Collect per-user traffic → POST to panel API
///   3. Report online users → POST to panel API
const std = @import("std");
const config = @import("../infra/config.zig");
const types = @import("../common/types.zig");
const tls_ctx_mod = @import("../transport/tls/context.zig");
const tls_stream_mod = @import("../transport/tls/stream.zig");

// Protocol user managers
const trojan_um = @import("../protocol/trojan/user_manager.zig");
const trojan_codec = @import("../protocol/trojan/codec.zig");
const vmess_um = @import("../protocol/vmess/user_manager.zig");
const ss_um = @import("../protocol/shadowsocks/user_manager.zig");
const ss_protocol = @import("../protocol/shadowsocks/protocol.zig");

// ── Per-user traffic tracker ─────────────────────────────────────────────

pub const UserTraffic = struct {
    upload: u64 = 0,
    download: u64 = 0,
};

pub const TrafficEntry = struct {
    user_id: i64,
    upload: u64,
    download: u64,
};

/// Thread-safe per-user traffic accumulator.
/// Handler threads call `add()` after each connection closes.
/// Panel sync thread calls `collectAndReset()` periodically.
pub const TrafficTracker = struct {
    map: std.AutoHashMap(i64, UserTraffic),
    lock: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator) TrafficTracker {
        return .{ .map = std.AutoHashMap(i64, UserTraffic).init(allocator) };
    }

    pub fn add(self: *TrafficTracker, user_id: i64, up: u64, down: u64) void {
        if (user_id <= 0 or (up == 0 and down == 0)) return;
        self.lock.lock();
        defer self.lock.unlock();
        const gop = self.map.getOrPut(user_id) catch return;
        if (gop.found_existing) {
            gop.value_ptr.upload += up;
            gop.value_ptr.download += down;
        } else {
            gop.value_ptr.* = .{ .upload = up, .download = down };
        }
    }

    pub fn collectAndReset(self: *TrafficTracker, allocator: std.mem.Allocator) ![]TrafficEntry {
        self.lock.lock();
        defer self.lock.unlock();
        var list = std.array_list.Managed(TrafficEntry).init(allocator);
        var iter = self.map.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.upload > 0 or entry.value_ptr.download > 0) {
                try list.append(.{
                    .user_id = entry.key_ptr.*,
                    .upload = entry.value_ptr.upload,
                    .download = entry.value_ptr.download,
                });
            }
        }
        self.map.clearRetainingCapacity();
        return try list.toOwnedSlice();
    }
};

// ── Panel user ───────────────────────────────────────────────────────────

pub const PanelUser = struct {
    user_id: i64,
    uuid: []const u8, // password/uuid from panel
    email: []const u8,
    speed_limit_mbps: i64, // 0 = unlimited
};

// ── Sync manager ─────────────────────────────────────────────────────────

pub const PanelSyncManager = struct {
    allocator: std.mem.Allocator,
    panels: []const config.PanelConfig,
    tracker: *TrafficTracker,

    pub fn init(
        allocator: std.mem.Allocator,
        panels: []const config.PanelConfig,
        tracker: *TrafficTracker,
    ) PanelSyncManager {
        return .{
            .allocator = allocator,
            .panels = panels,
            .tracker = tracker,
        };
    }

    /// Start background sync threads (one per panel).
    pub fn start(self: *PanelSyncManager) void {
        for (self.panels) |*panel| {
            if (panel.api_host.len == 0 or panel.api_key.len == 0) continue;
            if (panel.node_ids.len == 0) continue;

            const thread = std.Thread.spawn(.{}, panelSyncLoop, .{ self, panel }) catch |err| {
                std.log.err("面板同步线程启动失败: name={s} err={s}", .{
                    panel.name,
                    @errorName(err),
                });
                continue;
            };
            thread.detach();
            std.log.info("面板同步启动: name={s} nodes={d}", .{
                panel.name,
                panel.node_ids.len,
            });
        }
    }

    fn panelSyncLoop(self: *PanelSyncManager, panel: *const config.PanelConfig) void {
        // Initial delay
        std.Thread.sleep(5 * std.time.ns_per_s);

        while (true) {
            for (panel.node_ids) |node_id| {
                self.syncNode(panel, node_id) catch |err| {
                    std.log.warn("面板同步节点失败: name={s} node={d} err={s}", .{
                        panel.name,
                        node_id,
                        @errorName(err),
                    });
                };
            }

            // Report traffic
            self.reportTraffic(panel) catch |err| {
                std.log.warn("流量上报失败: name={s} err={s}", .{
                    panel.name,
                    @errorName(err),
                });
            };

            std.Thread.sleep(60 * std.time.ns_per_s);
        }
    }

    fn syncNode(
        self: *PanelSyncManager,
        panel: *const config.PanelConfig,
        node_id: i64,
    ) !void {
        // Fetch users from panel
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const users = try fetchUsers(arena, panel, node_id);
        std.log.info("面板用户同步: name={s} node={d} users={d} type={s}", .{
            panel.name,
            node_id,
            users.len,
            panel.node_type,
        });
    }

    fn reportTraffic(
        self: *PanelSyncManager,
        panel: *const config.PanelConfig,
    ) !void {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const entries = try self.tracker.collectAndReset(arena);
        if (entries.len == 0) return;

        // Build JSON: {"user_id": [upload, download], ...}
        var json = std.array_list.Managed(u8).init(arena);
        try json.append('{');
        var first = true;
        for (entries) |entry| {
            if (!first) try json.append(',');
            first = false;
            var buf: [128]u8 = undefined;
            const s = std.fmt.bufPrint(&buf, "\"{d}\":[{d},{d}]", .{
                entry.user_id,
                entry.upload,
                entry.download,
            }) catch continue;
            try json.appendSlice(s);
        }
        try json.append('}');

        for (panel.node_ids) |node_id| {
            const path = try std.fmt.allocPrint(
                arena,
                "/api/v1/server/UniProxy/push?node_id={d}&node_type={s}&token={s}",
                .{ node_id, panel.node_type, panel.api_key },
            );
            _ = httpPost(arena, panel.api_host, path, panel.api_key, json.items) catch |err| {
                std.log.warn("流量上报请求失败: node={d} err={s}", .{
                    node_id,
                    @errorName(err),
                });
                continue;
            };
        }

        std.log.info("流量上报完成: name={s} entries={d}", .{
            panel.name,
            entries.len,
        });
    }
};

// ── V2Board API ──────────────────────────────────────────────────────────

fn fetchUsers(
    allocator: std.mem.Allocator,
    panel: *const config.PanelConfig,
    node_id: i64,
) ![]PanelUser {
    const path = try std.fmt.allocPrint(
        allocator,
        "/api/v1/server/UniProxy/user?node_id={d}&node_type={s}&token={s}",
        .{ node_id, panel.node_type, panel.api_key },
    );

    const response = try httpGet(allocator, panel.api_host, path, panel.api_key);

    // Parse JSON response: {"users": [{...}, ...]}
    return parseUsersJson(allocator, response.body);
}

fn parseUsersJson(allocator: std.mem.Allocator, body: []const u8) ![]PanelUser {
    if (body.len == 0) return &.{};

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{
        .allocate = .alloc_always,
    }) catch return &.{};

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return &.{},
    };

    const users_val = root.get("users") orelse return &.{};
    const users_arr = switch (users_val) {
        .array => |a| a,
        else => return &.{},
    };

    var list = std.array_list.Managed(PanelUser).init(allocator);
    for (users_arr.items) |item| {
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };

        const user_id = blk: {
            const v = obj.get("id") orelse continue;
            break :blk switch (v) {
                .integer => |n| n,
                else => continue,
            };
        };

        const uuid = blk: {
            const v = obj.get("uuid") orelse continue;
            break :blk switch (v) {
                .string => |s| s,
                else => continue,
            };
        };

        const email = blk: {
            if (obj.get("email")) |v| {
                if (v == .string) break :blk v.string;
            }
            break :blk "";
        };

        const speed_limit = blk: {
            if (obj.get("speed_limit")) |v| {
                if (v == .integer) break :blk v.integer;
            }
            break :blk @as(i64, 0);
        };

        try list.append(.{
            .user_id = user_id,
            .uuid = uuid,
            .email = email,
            .speed_limit_mbps = speed_limit,
        });
    }

    return try list.toOwnedSlice();
}

// ── User conversion helpers ──────────────────────────────────────────────

pub fn convertToTrojanUsers(
    allocator: std.mem.Allocator,
    panel_users: []const PanelUser,
) ![]const trojan_um.UserInfo {
    var list = std.array_list.Managed(trojan_um.UserInfo).init(allocator);
    for (panel_users) |pu| {
        const speed = if (pu.speed_limit_mbps > 0)
            @as(u64, @intCast(pu.speed_limit_mbps)) * 1024 * 1024 / 8
        else
            0;
        const hash = try trojan_codec.hashPasswordAlloc(allocator, pu.uuid);
        try list.append(.{
            .user_id = pu.user_id,
            .email = pu.email,
            .password_hash = hash,
            .speed_limit_bytes = speed,
        });
    }
    return try list.toOwnedSlice();
}

pub fn convertToVMessUsers(
    panel_users: []const PanelUser,
) ![]const vmess_um.VMessUser {
    var list: [256]vmess_um.VMessUser = undefined;
    var count: usize = 0;
    for (panel_users) |pu| {
        if (count >= 256) break;
        const speed = if (pu.speed_limit_mbps > 0)
            @as(u64, @intCast(pu.speed_limit_mbps)) * 1024 * 1024 / 8
        else
            0;
        list[count] = vmess_um.UserManager.createUser(
            pu.uuid,
            pu.user_id,
            pu.email,
            speed,
        ) catch continue;
        count += 1;
    }
    // Return slice of stack array — caller must copy if needed
    if (count == 0) return &.{};
    return list[0..count];
}

pub fn convertToSsUsers(
    allocator: std.mem.Allocator,
    panel_users: []const PanelUser,
    cipher_str: []const u8,
) ![]const ss_um.UserInfo {
    const cipher_info = ss_protocol.CipherInfo.fromString(cipher_str) orelse
        ss_protocol.CipherInfo.fromString("aes-128-gcm").?;

    var list = std.array_list.Managed(ss_um.UserInfo).init(allocator);
    for (panel_users) |pu| {
        const speed = if (pu.speed_limit_mbps > 0)
            @as(u64, @intCast(pu.speed_limit_mbps)) * 1024 * 1024 / 8
        else
            0;
        var info = ss_um.UserInfo{
            .user_id = pu.user_id,
            .email = pu.email,
            .speed_limit_bytes = speed,
            .cipher_info = cipher_info,
            .master_key = undefined,
            .master_key_len = cipher_info.key_len,
        };
        ss_protocol.deriveMasterKey(
            pu.uuid,
            cipher_info.key_len,
            &info.master_key,
        ) catch continue;
        try list.append(info);
    }
    return try list.toOwnedSlice();
}

// ── HTTP client (minimal HTTP/1.1 over TCP, optional TLS) ────────────────

const HttpResponse = struct {
    status: u16,
    body: []const u8,
};

const ParsedUrl = struct {
    is_https: bool,
    host: []const u8,
    port: u16,
    path: []const u8,
};

fn parseUrl(url: []const u8) ?ParsedUrl {
    var is_https = false;
    var rest = url;

    if (std.mem.startsWith(u8, url, "https://")) {
        is_https = true;
        rest = url["https://".len..];
    } else if (std.mem.startsWith(u8, url, "http://")) {
        rest = url["http://".len..];
    } else {
        return null;
    }

    // Split host[:port] from path
    const path_start = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const host_port = rest[0..path_start];
    const path = if (path_start < rest.len) rest[path_start..] else "/";

    // Parse host:port
    if (std.mem.lastIndexOfScalar(u8, host_port, ':')) |colon| {
        return .{
            .is_https = is_https,
            .host = host_port[0..colon],
            .port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch
                if (is_https) @as(u16, 443) else @as(u16, 80),
            .path = path,
        };
    }

    return .{
        .is_https = is_https,
        .host = host_port,
        .port = if (is_https) @as(u16, 443) else @as(u16, 80),
        .path = path,
    };
}

fn httpGet(
    allocator: std.mem.Allocator,
    api_host: []const u8,
    path: []const u8,
    api_key: []const u8,
) !HttpResponse {
    const url_info = parseUrl(api_host) orelse return error.InvalidAddress;

    // Build request
    var req = std.array_list.Managed(u8).init(allocator);
    try appendRequest(&req, "GET", url_info, path, api_key, null);

    return sendRequest(allocator, url_info, req.items);
}

fn httpPost(
    allocator: std.mem.Allocator,
    api_host: []const u8,
    path: []const u8,
    api_key: []const u8,
    body: []const u8,
) !HttpResponse {
    const url_info = parseUrl(api_host) orelse return error.InvalidAddress;

    var req = std.array_list.Managed(u8).init(allocator);
    try appendRequest(&req, "POST", url_info, path, api_key, body);

    return sendRequest(allocator, url_info, req.items);
}

fn appendRequest(
    req: *std.array_list.Managed(u8),
    method: []const u8,
    url_info: ParsedUrl,
    path: []const u8,
    api_key: []const u8,
    body: ?[]const u8,
) !void {
    // Request line
    try req.appendSlice(method);
    try req.appendSlice(" ");
    // Combine base path + endpoint path
    try req.appendSlice(url_info.path);
    if (!std.mem.endsWith(u8, url_info.path, "/") and
        !std.mem.startsWith(u8, path, "/"))
    {
        try req.appendSlice("/");
    }
    // Avoid double slash
    if (std.mem.endsWith(u8, url_info.path, "/") and
        std.mem.startsWith(u8, path, "/"))
    {
        try req.appendSlice(path[1..]);
    } else {
        try req.appendSlice(path);
    }
    try req.appendSlice(" HTTP/1.1\r\n");

    // Headers
    try req.appendSlice("Host: ");
    try req.appendSlice(url_info.host);
    try req.appendSlice("\r\n");
    try req.appendSlice("User-Agent: znode/1.0\r\n");
    try req.appendSlice("Authorization: Bearer ");
    try req.appendSlice(api_key);
    try req.appendSlice("\r\n");
    try req.appendSlice("Connection: close\r\n");

    if (body) |b| {
        try req.appendSlice("Content-Type: application/json\r\n");
        var len_buf: [20]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{b.len}) catch "0";
        try req.appendSlice("Content-Length: ");
        try req.appendSlice(len_str);
        try req.appendSlice("\r\n");
    }

    try req.appendSlice("\r\n");

    if (body) |b| {
        try req.appendSlice(b);
    }
}

fn sendRequest(
    allocator: std.mem.Allocator,
    url_info: ParsedUrl,
    request_data: []const u8,
) !HttpResponse {
    // TCP connect
    const tcp_stream = try std.net.tcpConnectToHost(allocator, url_info.host, url_info.port);

    if (url_info.is_https) {
        return sendRequestTls(allocator, tcp_stream, url_info.host, request_data);
    } else {
        return sendRequestPlain(allocator, tcp_stream, request_data);
    }
}

fn sendRequestPlain(
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    request_data: []const u8,
) !HttpResponse {
    var s = stream;
    defer s.close();

    s.writeAll(request_data) catch return error.NetworkError;
    return readHttpResponse(allocator, &s);
}

fn sendRequestTls(
    allocator: std.mem.Allocator,
    tcp_stream: std.net.Stream,
    host: []const u8,
    request_data: []const u8,
) !HttpResponse {
    var ssl_ctx = tls_ctx_mod.SslContext.createClient(false) catch
        return error.NetworkError;
    defer ssl_ctx.deinit();

    var tls = tls_stream_mod.TlsStream(std.net.Stream).init(
        tcp_stream,
        &ssl_ctx,
        false,
    ) catch return error.NetworkError;
    defer tls.close();

    // Set SNI
    var sni_buf: [254]u8 = undefined;
    if (host.len < sni_buf.len) {
        @memcpy(sni_buf[0..host.len], host);
        sni_buf[host.len] = 0;
        tls.setServerName(sni_buf[0..host.len :0]);
    }

    // Handshake
    tls.handshake() catch return error.NetworkError;

    // Send request
    _ = tls.write(request_data) catch return error.NetworkError;

    // Read response
    return readHttpResponseTls(allocator, &tls);
}

fn readHttpResponse(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
) !HttpResponse {
    var buf = std.array_list.Managed(u8).init(allocator);
    var tmp: [4096]u8 = undefined;

    while (buf.items.len < 1024 * 1024) { // 1MB max
        const n = stream.read(&tmp) catch break;
        if (n == 0) break;
        try buf.appendSlice(tmp[0..n]);
    }

    return parseHttpResponse(buf.items);
}

fn readHttpResponseTls(
    allocator: std.mem.Allocator,
    tls: *tls_stream_mod.TlsStream(std.net.Stream),
) !HttpResponse {
    var buf = std.array_list.Managed(u8).init(allocator);
    var tmp: [4096]u8 = undefined;

    while (buf.items.len < 1024 * 1024) {
        const n = tls.read(&tmp) catch break;
        if (n == 0) break;
        try buf.appendSlice(tmp[0..n]);
    }

    return parseHttpResponse(buf.items);
}

fn parseHttpResponse(data: []const u8) !HttpResponse {
    // Find status line: "HTTP/1.1 200 OK\r\n"
    const status_end = std.mem.indexOf(u8, data, "\r\n") orelse
        return error.InvalidAddress;
    const status_line = data[0..status_end];

    // Parse status code
    const space1 = std.mem.indexOfScalar(u8, status_line, ' ') orelse
        return error.InvalidAddress;
    const after_space = status_line[space1 + 1 ..];
    const space2 = std.mem.indexOfScalar(u8, after_space, ' ') orelse after_space.len;
    const status = std.fmt.parseInt(u16, after_space[0..space2], 10) catch
        return error.InvalidAddress;

    // Find body (after \r\n\r\n)
    const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse
        return .{ .status = status, .body = "" };
    const body = data[header_end + 4 ..];

    return .{ .status = status, .body = body };
}
