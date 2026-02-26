const std = @import("std");
const log = @import("../core/log.zig");
const config_mod = @import("../core/config.zig");

// ── Data types ──

/// A user record from the V2Board panel API.
pub const PanelUser = struct {
    id: i64 = -1,
    uuid: [16]u8 = [_]u8{0} ** 16,
    uuid_valid: bool = false,
    speed_limit: u64 = 0, // bytes/sec, 0 = unlimited
    device_limit: u32 = 0, // 0 = unlimited
    email: [128]u8 = [_]u8{0} ** 128,
    email_len: u8 = 0,

    pub fn getEmail(self: *const PanelUser) []const u8 {
        return self.email[0..self.email_len];
    }

    pub fn setEmail(self: *PanelUser, em: []const u8) void {
        const len = @min(em.len, self.email.len);
        @memcpy(self.email[0..len], em[0..len]);
        self.email_len = @intCast(len);
    }
};

/// Per-user traffic data for reporting.
pub const TrafficData = struct {
    user_id: i64,
    bytes_up: u64,
    bytes_down: u64,
};

/// Server node info fetched from panel API (GET /api/v1/server/UniProxy/config).
/// Contains protocol-specific settings that are NOT in local config.
pub const ServerNodeInfo = struct {
    server_port: u16 = 443,
    transport: config_mod.Transport = .tcp,

    // Intervals (from panel API)
    sync_interval: u32 = 60, // seconds, user/config sync
    report_interval: u32 = 60, // seconds, traffic report

    // WebSocket settings
    ws_path_buf: [128]u8 = [_]u8{0} ** 128,
    ws_path_len: u8 = 0,
    ws_host_buf: [128]u8 = [_]u8{0} ** 128,
    ws_host_len: u8 = 0,

    // TLS server name (Trojan / VMess)
    server_name_buf: [128]u8 = [_]u8{0} ** 128,
    server_name_len: u8 = 0,

    pub fn getWsPath(self: *const ServerNodeInfo) []const u8 { return self.ws_path_buf[0..self.ws_path_len]; }
    pub fn getWsHost(self: *const ServerNodeInfo) []const u8 { return self.ws_host_buf[0..self.ws_host_len]; }
    pub fn getServerName(self: *const ServerNodeInfo) []const u8 { return self.server_name_buf[0..self.server_name_len]; }

    fn setWsPath(self: *ServerNodeInfo, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.ws_path_buf.len));
        @memcpy(self.ws_path_buf[0..n], v[0..n]);
        self.ws_path_len = n;
    }
    fn setWsHost(self: *ServerNodeInfo, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.ws_host_buf.len));
        @memcpy(self.ws_host_buf[0..n], v[0..n]);
        self.ws_host_len = n;
    }
    fn setServerName(self: *ServerNodeInfo, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.server_name_buf.len));
        @memcpy(self.server_name_buf[0..n], v[0..n]);
        self.server_name_len = n;
    }
};

// ── API Client ──

/// V2Board UniProxy API client.
/// Handles HTTP requests to the panel server and JSON parsing.
pub const ApiClient = struct {
    allocator: std.mem.Allocator,
    // Fixed buffers to own string data (avoid dangling slice from stack copies)
    base_url_buf: [256]u8 = [_]u8{0} ** 256,
    base_url_len: u16 = 0,
    api_key_buf: [128]u8 = [_]u8{0} ** 128,
    api_key_len: u8 = 0,
    node_id: u32 = 0,
    node_type_buf: [32]u8 = [_]u8{0} ** 32,
    node_type_len: u8 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        base_url: []const u8,
        api_key: []const u8,
        node_id: u32,
        node_type: []const u8,
    ) ApiClient {
        var c = ApiClient{ .allocator = allocator, .node_id = node_id };
        const url_len: u16 = @intCast(@min(base_url.len, c.base_url_buf.len));
        @memcpy(c.base_url_buf[0..url_len], base_url[0..url_len]);
        c.base_url_len = url_len;
        const key_len: u8 = @intCast(@min(api_key.len, c.api_key_buf.len));
        @memcpy(c.api_key_buf[0..key_len], api_key[0..key_len]);
        c.api_key_len = key_len;
        const type_len: u8 = @intCast(@min(node_type.len, c.node_type_buf.len));
        @memcpy(c.node_type_buf[0..type_len], node_type[0..type_len]);
        c.node_type_len = type_len;
        return c;
    }

    fn getBaseUrl(self: *const ApiClient) []const u8 { return self.base_url_buf[0..self.base_url_len]; }
    fn getApiKey(self: *const ApiClient) []const u8 { return self.api_key_buf[0..self.api_key_len]; }
    fn getNodeType(self: *const ApiClient) []const u8 { return self.node_type_buf[0..self.node_type_len]; }

    pub fn deinit(self: *ApiClient) void {
        _ = self;
    }

    /// Build a full API URL with authentication query parameters.
    pub fn buildUrl(self: *const ApiClient, path: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}{s}?node_id={d}&node_type={s}&token={s}", .{
            self.getBaseUrl(),
            path,
            self.node_id,
            self.getNodeType(),
            self.getApiKey(),
        });
    }

    /// GET /api/v1/server/UniProxy/config - Fetch node config from panel.
    pub fn fetchNodeConfig(self: *ApiClient, protocol: config_mod.Protocol) !ServerNodeInfo {
        const url = try self.buildUrl("/api/v1/server/UniProxy/config");
        defer self.allocator.free(url);

        const body = try self.doGet(url);
        defer self.allocator.free(body);

        return parseNodeConfigResponseAlloc(self.allocator, body, protocol);
    }

    /// GET /api/v1/server/UniProxy/user - Fetch user list from panel.
    pub fn fetchUsers(self: *ApiClient) ![]PanelUser {
        const url = try self.buildUrl("/api/v1/server/UniProxy/user");
        defer self.allocator.free(url);

        const body = try self.doGet(url);
        defer self.allocator.free(body);

        return parseUsersResponse(self.allocator, body);
    }

    /// POST /api/v1/server/UniProxy/push - Report traffic data.
    pub fn pushTraffic(self: *ApiClient, traffic: []const TrafficData) !void {
        const url = try self.buildUrl("/api/v1/server/UniProxy/push");
        defer self.allocator.free(url);

        const payload = try encodeTrafficPayload(self.allocator, traffic);
        defer self.allocator.free(payload);

        try self.doPost(url, payload);
    }

    /// POST /api/v1/server/UniProxy/alive - Send heartbeat.
    pub fn sendHeartbeat(self: *ApiClient) !void {
        const url = try self.buildUrl("/api/v1/server/UniProxy/alive");
        defer self.allocator.free(url);
        try self.doPost(url, "{}");
    }

    // ── HTTP transport ──

    fn doGet(self: *ApiClient, url: []const u8) ![]u8 {
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(self.allocator);

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .response_writer = &aw.writer,
        }) catch |e| {
            var err_list = aw.toArrayList();
            const partial = err_list.items;
            if (partial.len > 0) {
                log.err("HTTP GET {s} error={s} partial({d}B)={s}", .{ url, @errorName(e), partial.len, partial[0..@min(partial.len, 500)] });
            } else {
                log.err("HTTP GET {s} error={s}", .{ url, @errorName(e) });
            }
            err_list.deinit(self.allocator);
            return e; // propagate actual error (not wrapped)
        };

        var list = aw.toArrayList();
        const body_items = list.items;
        if (result.status != .ok) {
            const preview = if (body_items.len > 0) body_items[0..@min(body_items.len, 500)] else "";
            log.err("HTTP GET {s} status={d} body={s}", .{ url, @intFromEnum(result.status), preview });
            list.deinit(self.allocator);
            return error.HttpNon200;
        }

        return list.toOwnedSlice(self.allocator) catch {
            list.deinit(self.allocator);
            return error.PanelApiError;
        };
    }

    fn doPost(self: *ApiClient, url: []const u8, body: []const u8) !void {
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        // No response_writer — response body is discarded (POST endpoints
        // only need status code; avoids unnecessary heap allocation).
        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json" },
            },
        }) catch |e| {
            log.err("HTTP POST {s} error={s}", .{ url, @errorName(e) });
            return e;
        };

        if (result.status != .ok) {
            log.err("HTTP POST {s} status={d}", .{ url, @intFromEnum(result.status) });
            return error.PanelApiError;
        }
    }

    const Error = error{PanelApiError} || std.mem.Allocator.Error;
};

// ── JSON parsing/encoding (pure functions, independently testable) ──

/// Parse V2Board UniProxy /config response with a caller-supplied allocator.
fn parseNodeConfigResponseAlloc(allocator: std.mem.Allocator, json_str: []const u8, protocol: config_mod.Protocol) !ServerNodeInfo {
    var info = ServerNodeInfo{};

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch {
        log.err("parseNodeConfig: invalid JSON ({d}B): {s}", .{
            json_str.len,
            if (json_str.len > 0) json_str[0..@min(json_str.len, 500)] else "",
        });
        return error.PanelApiError;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) {
        log.err("parseNodeConfig: root is not object", .{});
        return error.PanelApiError;
    }

    // Support {"data": {...}} wrapper (some V2Board versions)
    const obj = blk: {
        if (root.object.get("data")) |data| {
            if (data == .object) break :blk data.object;
        }
        break :blk root.object;
    };

    // server_port (common)
    if (obj.get("server_port")) |v| {
        if (v == .integer) info.server_port = @intCast(@max(1, @min(v.integer, 65535)));
    }

    // base_config: intervals from panel (common to all protocols)
    // V2Board returns: {"base_config":{"push_interval":60,"pull_interval":60}}
    if (obj.get("base_config")) |bc| {
        if (bc == .object) {
            const bc_obj = bc.object;
            if (bc_obj.get("push_interval")) |v| {
                if (v == .integer) info.report_interval = @intCast(@max(10, @min(v.integer, 3600)));
            }
            if (bc_obj.get("pull_interval")) |v| {
                if (v == .integer) info.sync_interval = @intCast(@max(10, @min(v.integer, 3600)));
            }
        }
    }

    switch (protocol) {
        .vmess => {
            // network: "ws", "tcp", "grpc"
            var network: []const u8 = "tcp";
            if (obj.get("network")) |v| {
                if (v == .string) network = v.string;
            }

            // tls: 0=none, 1=tls, 2=reality
            var tls_enabled = false;
            if (obj.get("tls")) |v| {
                if (v == .integer) tls_enabled = v.integer >= 1;
            }

            // Derive transport from network + tls
            if (std.mem.eql(u8, network, "ws")) {
                info.transport = if (tls_enabled) .wss else .ws;
            } else {
                info.transport = if (tls_enabled) .tls else .tcp;
            }

            // networkSettings (camelCase for VMess)
            const ns_val = obj.get("networkSettings") orelse obj.get("network_settings");
            if (ns_val) |ns| {
                if (ns == .object) {
                    const nsobj = ns.object;
                    if (nsobj.get("path")) |v| {
                        if (v == .string) info.setWsPath(v.string);
                    }
                    if (nsobj.get("host")) |v| {
                        if (v == .string) info.setWsHost(v.string);
                    }
                }
            }

            // server_name (optional for VMess TLS)
            if (obj.get("server_name")) |v| {
                if (v == .string) info.setServerName(v.string);
            }
        },
        .trojan => {
            // Trojan always uses TLS
            info.transport = .tls;

            if (obj.get("server_name")) |v| {
                if (v == .string) info.setServerName(v.string);
            }
        },
        else => {},
    }

    return info;
}

/// Typed JSON entry — parsed directly without building a generic Value AST.
const UserJsonEntry = struct {
    id: ?i64 = null,
    uuid: ?[]const u8 = null,
    speed_limit: ?i64 = null,
    device_limit: ?i64 = null,
    email: ?[]const u8 = null,
};

/// Convert typed entries to PanelUser slice.
fn convertJsonEntries(allocator: std.mem.Allocator, entries: []const UserJsonEntry) ![]PanelUser {
    var result: std.ArrayList(PanelUser) = .{};
    errdefer result.deinit(allocator);

    for (entries) |entry| {
        var user = PanelUser{};

        if (entry.id) |id| user.id = id;
        if (entry.uuid) |uuid_str| {
            if (parseUuid(uuid_str)) |uuid| {
                user.uuid = uuid;
                user.uuid_valid = true;
            }
        }
        if (entry.speed_limit) |sl| {
            const mbps = @max(0, sl);
            user.speed_limit = @as(u64, @intCast(mbps)) * 1000000 / 8;
        }
        if (entry.device_limit) |dl| {
            user.device_limit = @intCast(@max(0, dl));
        }
        if (entry.email) |em| {
            user.setEmail(em);
        }

        if (user.id >= 0 and user.uuid_valid) {
            try result.append(allocator, user);
        }
    }

    return try result.toOwnedSlice(allocator);
}

/// Parse V2Board user list JSON response.
/// Expected format: {"users": [{"id":1, "uuid":"...", ...}, ...]}
/// Also handles flat array format: [{"id":1, "uuid":"...", ...}, ...]
///
/// Uses typed JSON parsing for common formats to avoid building a generic
/// Value AST tree — reduces memory usage by ~50-70% for large user lists.
pub fn parseUsersResponse(allocator: std.mem.Allocator, json_str: []const u8) ![]PanelUser {
    const json_opts: std.json.ParseOptions = .{ .ignore_unknown_fields = true };

    // Fast path: {"users": [...]} — most common V2Board format
    if (std.json.parseFromSlice(struct { users: []UserJsonEntry }, allocator, json_str, json_opts)) |parsed| {
        defer parsed.deinit();
        return convertJsonEntries(allocator, parsed.value.users);
    } else |_| {}

    // Fast path: flat array [...]
    if (std.json.parseFromSlice([]UserJsonEntry, allocator, json_str, json_opts)) |parsed| {
        defer parsed.deinit();
        return convertJsonEntries(allocator, parsed.value);
    } else |_| {}

    // Fast path: {"data": {"users": [...]}}
    if (std.json.parseFromSlice(struct { data: struct { users: []UserJsonEntry } }, allocator, json_str, json_opts)) |parsed| {
        defer parsed.deinit();
        return convertJsonEntries(allocator, parsed.value.data.users);
    } else |_| {}

    // Fast path: {"data": [...]}
    if (std.json.parseFromSlice(struct { data: []UserJsonEntry }, allocator, json_str, json_opts)) |parsed| {
        defer parsed.deinit();
        return convertJsonEntries(allocator, parsed.value.data);
    } else |_| {}

    return error.PanelApiError;
}

/// Encode traffic report as V2Board JSON payload.
/// Output format: {"1":[upload,download],"2":[upload,download]}
pub fn encodeTrafficPayload(allocator: std.mem.Allocator, traffic: []const TrafficData) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);

    // Pre-allocate: ~48 bytes per entry avoids repeated reallocation
    try buf.ensureTotalCapacity(allocator, traffic.len * 48 + 2);

    const writer = buf.writer(allocator);
    try writer.writeByte('{');
    var first = true;
    for (traffic) |t| {
        if (t.bytes_up == 0 and t.bytes_down == 0) continue;
        if (!first) try writer.writeByte(',');
        try std.fmt.format(writer, "\"{d}\":[{d},{d}]", .{ t.user_id, t.bytes_up, t.bytes_down });
        first = false;
    }
    try writer.writeByte('}');

    return try buf.toOwnedSlice(allocator);
}

/// Parse a UUID string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" to [16]u8.
/// Also accepts UUID without dashes (32 hex chars).
pub fn parseUuid(s: []const u8) ?[16]u8 {
    var result: [16]u8 = undefined;
    var out_idx: usize = 0;

    var i: usize = 0;
    while (i < s.len and out_idx < 16) {
        if (s[i] == '-') {
            i += 1;
            continue;
        }
        if (i + 1 >= s.len) return null;

        const hi = hexVal(s[i]) orelse return null;
        const lo = hexVal(s[i + 1]) orelse return null;
        result[out_idx] = (@as(u8, hi) << 4) | @as(u8, lo);
        out_idx += 1;
        i += 2;
    }

    if (out_idx != 16) return null;
    return result;
}

/// Format a [16]u8 UUID as "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
pub fn formatUuid(uuid: [16]u8) [36]u8 {
    const hex = "0123456789abcdef";
    var result: [36]u8 = undefined;
    var pos: usize = 0;

    for (uuid, 0..) |byte, i| {
        if (i == 4 or i == 6 or i == 8 or i == 10) {
            result[pos] = '-';
            pos += 1;
        }
        result[pos] = hex[byte >> 4];
        result[pos + 1] = hex[byte & 0x0f];
        pos += 2;
    }

    return result;
}

fn hexVal(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

