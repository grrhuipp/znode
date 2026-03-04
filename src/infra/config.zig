const std = @import("std");

pub const ConfigError = error{
    InvalidConfig,
};

// ============================================================================
// TLS / WebSocket / Transport
// ============================================================================

pub const TlsConfig = struct {
    cert_file: []const u8 = "",
    key_file: []const u8 = "",
    ca_file: []const u8 = "",
    server_name: []const u8 = "",
    allow_insecure: bool = false,
    alpn: []const []const u8 = &.{},
    min_version: []const u8 = "1.2",
    max_version: []const u8 = "1.3",

    pub fn isServer(self: *const TlsConfig) bool {
        return self.cert_file.len > 0 and self.key_file.len > 0;
    }
};

pub const WsConfig = struct {
    path: []const u8 = "/",
    real_ip_header: []const u8 = "",
};

pub const StreamSettings = struct {
    network: []const u8 = "tcp",
    security: []const u8 = "none",
    tls: TlsConfig = .{},
    ws: WsConfig = .{},

    pub fn isTls(self: *const StreamSettings) bool {
        return std.ascii.eqlIgnoreCase(self.security, "tls");
    }

    pub fn isWs(self: *const StreamSettings) bool {
        return std.ascii.eqlIgnoreCase(self.network, "ws");
    }
};

pub const SniffConfig = struct {
    enabled: bool = false,
    override_dest: bool = false,
};

// ============================================================================
// Log / DNS / Timeouts / Limits / Panel
// ============================================================================

pub const LogConfig = struct {
    level: []const u8 = "info",
    log_dir: []const u8 = "/var/log/znode",
    max_days: u16 = 15,
};

pub const DnsConfig = struct {
    servers: []const []const u8 = &.{},
    timeout: u32 = 5,
    cache_size: u32 = 10000,
    min_ttl: u32 = 60,
    max_ttl: u32 = 3600,
};

pub const TimeoutsConfig = struct {
    handshake: u32 = 4,
    dial: u32 = 10,
    read: u32 = 15,
    write: u32 = 30,
    idle: u32 = 300,
    uplink_only: u32 = 2,
    downlink_only: u32 = 5,
};

pub const LimitsConfig = struct {
    max_connections: u32 = 0,
    max_connections_per_ip: u32 = 0,
    max_rate_per_ip: u32 = 0,
    auth_fail_limit: u32 = 10,
    auth_fail_window: u32 = 60,
    auth_ban_seconds: u32 = 180,
    buffer_size: usize = 24 * 1024,
};

pub const PanelConfig = struct {
    name: []const u8 = "",
    panel_type: []const u8 = "V2Board",
    api_host: []const u8 = "",
    api_key: []const u8 = "",
    node_ids: []const i64 = &.{},
    node_type: []const u8 = "vmess",
    tls_enable: bool = false,
    tls_cert: []const u8 = "",
    tls_key: []const u8 = "",
};

// ============================================================================
// Client / Inbound / Outbound / Routing (existing)
// ============================================================================

pub const ClientConfig = struct {
    password: []const u8,
    email: []const u8,
    user_id: i64,
    speed_limit_mbps: i64,
};

pub const InboundConfig = struct {
    tag: []const u8,
    protocol: []const u8,
    listen: []const u8,
    port: u16,
    outbound_tag: ?[]const u8,
    clients: []const ClientConfig,
    stream_settings: StreamSettings = .{},
    sniff: SniffConfig = .{},
};

pub const OutboundConfig = struct {
    tag: []const u8,
    protocol: []const u8,
    address: []const u8 = "",
    port: u16 = 0,
    password: []const u8 = "",
    uuid: []const u8 = "",
    method: []const u8 = "",
    security: []const u8 = "auto",
    domain_strategy: []const u8 = "AsIs",
    send_through: []const u8 = "",
    stream_settings: StreamSettings = .{},
};

pub const RouteRuleConfig = struct {
    domain_suffix: []const []const u8,
    ip_cidrs: []const []const u8,
    outbound_tag: []const u8,
};

pub const RoutingConfig = struct {
    default_outbound: []const u8,
    rules: []const RouteRuleConfig,
};

pub const Config = struct {
    workers: usize,
    inbounds: []const InboundConfig,
    outbounds: []const OutboundConfig,
    routing: RoutingConfig,
    config_dir: []const u8,
    log: LogConfig = .{},
    dns: DnsConfig = .{},
    timeouts: TimeoutsConfig = .{},
    limits: LimitsConfig = .{},
    panels: []const PanelConfig = &.{},
};

const ParsedValue = std.json.Parsed(std.json.Value);

pub fn loadFromPath(allocator: std.mem.Allocator, path: []const u8) !Config {
    var workers: usize = std.Thread.getCpuCount() catch 1;
    var config_dir: []const u8 = try dupString(allocator, ".");

    var inbounds = std.array_list.Managed(InboundConfig).init(allocator);
    var outbounds = std.array_list.Managed(OutboundConfig).init(allocator);
    var routing = RoutingConfig{
        .default_outbound = try dupString(allocator, "direct"),
        .rules = &[_]RouteRuleConfig{},
    };
    var log_cfg = LogConfig{};
    var dns_cfg = DnsConfig{};
    var timeouts_cfg = TimeoutsConfig{};
    var limits_cfg = LimitsConfig{};
    var panels_cfg: []const PanelConfig = &.{};

    var main_config_path: ?[]const u8 = null;
    if (std.fs.cwd().openDir(path, .{})) |opened_dir| {
        var dir = opened_dir;
        dir.close();
        config_dir = try dupString(allocator, path);
        main_config_path = try std.fs.path.join(allocator, &.{ path, "config.json" });
    } else |err| switch (err) {
        error.NotDir => {
            config_dir = try dupString(allocator, std.fs.path.dirname(path) orelse ".");
            main_config_path = try dupString(allocator, path);
        },
        else => return err,
    }

    if (main_config_path) |p| {
        if (try readParsedFileIfExists(allocator, p)) |parsed| {
            defer parsed.deinit();
            const root = switch (parsed.value) {
                .object => |o| o,
                else => return ConfigError.InvalidConfig,
            };

            if (getFieldAny(root, &.{ "Workers", "workers" })) |v| {
                if (valueToInt(v)) |n| {
                    if (n > 0) workers = @as(usize, @intCast(n));
                }
            }

            if (getFieldAny(root, &.{ "Inbounds", "inbounds" })) |v| {
                try parseInboundsValue(allocator, v, &inbounds);
            }

            if (getFieldAny(root, &.{ "Outbounds", "outbounds" })) |v| {
                try parseOutboundsValue(allocator, v, &outbounds);
            }

            if (getFieldAny(root, &.{ "Routing", "routing" })) |v| {
                if (v == .object) {
                    routing = try parseRoutingObject(allocator, v.object);
                }
            }

            if (getFieldAny(root, &.{ "Log", "log" })) |v| {
                if (v == .object) log_cfg = try parseLogConfig(allocator, v.object);
            }
            if (getFieldAny(root, &.{ "Dns", "dns", "DNS" })) |v| {
                if (v == .object) dns_cfg = try parseDnsConfig(allocator, v.object);
            }
            if (getFieldAny(root, &.{ "Timeouts", "timeouts" })) |v| {
                if (v == .object) timeouts_cfg = parseTimeoutsConfig(v.object);
            }
            if (getFieldAny(root, &.{ "Limits", "limits" })) |v| {
                if (v == .object) limits_cfg = parseLimitsConfig(v.object);
            }
            if (getFieldAny(root, &.{ "Panels", "panels" })) |v| {
                panels_cfg = try parsePanelsConfig(allocator, v);
            }
        }
    }

    const inbound_path = try std.fs.path.join(allocator, &.{ config_dir, "inbound.json" });
    if (try readParsedFileIfExists(allocator, inbound_path)) |parsed| {
        defer parsed.deinit();
        try parseInboundsValue(allocator, parsed.value, &inbounds);
    }

    const outbound_path = try std.fs.path.join(allocator, &.{ config_dir, "outbound.json" });
    if (try readParsedFileIfExists(allocator, outbound_path)) |parsed| {
        defer parsed.deinit();
        try parseOutboundsValue(allocator, parsed.value, &outbounds);
    }

    const route_path = try std.fs.path.join(allocator, &.{ config_dir, "route.json" });
    if (try readParsedFileIfExists(allocator, route_path)) |parsed| {
        defer parsed.deinit();
        if (parsed.value == .object) {
            routing = try parseRoutingObject(allocator, parsed.value.object);
        }
    }

    try ensureBuiltinOutbounds(allocator, &outbounds);

    if (workers == 0) workers = 1;

    return Config{
        .workers = workers,
        .inbounds = try inbounds.toOwnedSlice(),
        .outbounds = try outbounds.toOwnedSlice(),
        .routing = routing,
        .config_dir = config_dir,
        .log = log_cfg,
        .dns = dns_cfg,
        .timeouts = timeouts_cfg,
        .limits = limits_cfg,
        .panels = panels_cfg,
    };
}

fn readParsedFileIfExists(allocator: std.mem.Allocator, path: []const u8) !?ParsedValue {
    const raw = std.fs.cwd().readFileAlloc(allocator, path, 8 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    return try std.json.parseFromSlice(std.json.Value, allocator, raw, .{
        .allocate = .alloc_always,
    });
}

fn parseInboundsValue(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    list: *std.array_list.Managed(InboundConfig),
) !void {
    switch (value) {
        .array => |arr| {
            for (arr.items) |item| {
                if (item != .object) continue;
                try list.append(try parseInboundObject(allocator, item.object));
            }
        },
        .object => |obj| {
            try list.append(try parseInboundObject(allocator, obj));
        },
        else => {},
    }
}

fn parseOutboundsValue(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    list: *std.array_list.Managed(OutboundConfig),
) !void {
    switch (value) {
        .array => |arr| {
            for (arr.items) |item| {
                if (item != .object) continue;
                try list.append(try parseOutboundObject(allocator, item.object));
            }
        },
        .object => |obj| {
            try list.append(try parseOutboundObject(allocator, obj));
        },
        else => {},
    }
}

fn parseInboundObject(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !InboundConfig {
    const protocol_raw = getFieldString(obj, &.{ "protocol", "Protocol" }) orelse "trojan";
    const listen_raw = getFieldString(obj, &.{ "listen", "Listen" }) orelse "0.0.0.0";
    const port_num = getFieldInt(obj, &.{ "port", "Port" }) orelse 0;
    const outbound_tag = getFieldString(obj, &.{ "outbound", "outboundTag", "OutboundTag" });

    const settings_obj: ?std.json.ObjectMap = blk: {
        if (getFieldAny(obj, &.{ "settings", "Settings" })) |v| {
            if (v == .object) break :blk v.object;
        }
        break :blk null;
    };

    const tag = if (getFieldString(obj, &.{ "tag", "Tag" })) |t|
        try dupString(allocator, t)
    else
        try std.fmt.allocPrint(allocator, "{s}-{d}", .{ protocol_raw, port_num });

    const stream_settings = if (getFieldAny(obj, &.{ "streamSettings", "StreamSettings" })) |v|
        (if (v == .object) try parseStreamSettings(allocator, v.object) else StreamSettings{})
    else
        StreamSettings{};

    const sniff = if (getFieldAny(obj, &.{ "sniffing", "Sniffing", "sniff" })) |v|
        (if (v == .object) parseSniffConfig(v.object) else SniffConfig{})
    else
        SniffConfig{};

    return InboundConfig{
        .tag = tag,
        .protocol = try dupString(allocator, protocol_raw),
        .listen = try dupString(allocator, listen_raw),
        .port = @as(u16, @intCast(@max(port_num, 0))),
        .outbound_tag = if (outbound_tag) |v| try dupString(allocator, v) else null,
        .clients = try parseClients(allocator, settings_obj),
        .stream_settings = stream_settings,
        .sniff = sniff,
    };
}

fn parseClients(
    allocator: std.mem.Allocator,
    settings_obj: ?std.json.ObjectMap,
) ![]const ClientConfig {
    if (settings_obj == null) return &[_]ClientConfig{};

    const settings = settings_obj.?;
    const clients_value = settings.get("clients") orelse return &[_]ClientConfig{};
    if (clients_value != .array) return &[_]ClientConfig{};

    var list = std.array_list.Managed(ClientConfig).init(allocator);
    for (clients_value.array.items) |item| {
        if (item != .object) continue;
        const c = item.object;
        const password = getFieldString(c, &.{ "password", "Password", "id", "uuid", "UUID" }) orelse "";
        if (password.len == 0) continue;
        try list.append(.{
            .password = try dupString(allocator, password),
            .email = try dupString(allocator, getFieldString(c, &.{ "email", "Email" }) orelse ""),
            .user_id = getFieldInt(c, &.{ "user_id", "id", "ID" }) orelse 0,
            .speed_limit_mbps = getFieldInt(c, &.{ "speed_limit", "SpeedLimit" }) orelse 0,
        });
    }

    return try list.toOwnedSlice();
}

fn parseOutboundObject(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !OutboundConfig {
    const tag = getFieldString(obj, &.{ "tag", "Tag" }) orelse return ConfigError.InvalidConfig;
    const protocol = getFieldString(obj, &.{ "protocol", "Protocol" }) orelse return ConfigError.InvalidConfig;

    const stream_settings = if (getFieldAny(obj, &.{ "streamSettings", "StreamSettings" })) |v|
        (if (v == .object) try parseStreamSettings(allocator, v.object) else StreamSettings{})
    else
        StreamSettings{};

    // Parse outbound-specific fields from settings sub-object or flat format
    var address: []const u8 = "";
    var port: u16 = 0;
    var password: []const u8 = "";
    var uuid: []const u8 = "";
    var method: []const u8 = "";
    var security: []const u8 = "auto";

    // Try flat format first
    if (getFieldString(obj, &.{ "address", "Address" })) |v| address = v;
    if (getFieldInt(obj, &.{ "port", "Port" })) |v| port = @intCast(@max(v, 0));
    if (getFieldString(obj, &.{ "password", "Password" })) |v| password = v;
    if (getFieldString(obj, &.{ "uuid", "UUID", "id" })) |v| uuid = v;
    if (getFieldString(obj, &.{ "method", "Method", "cipher" })) |v| method = v;
    if (getFieldString(obj, &.{ "security", "Security" })) |v| security = v;

    // Try V2Ray nested format: settings.vnext[0] or settings.servers[0]
    if (getFieldAny(obj, &.{ "settings", "Settings" })) |settings_val| {
        if (settings_val == .object) {
            const settings = settings_val.object;
            // VMess: vnext[0]
            if (getFieldAny(settings, &.{"vnext"})) |vnext_val| {
                if (vnext_val == .array and vnext_val.array.items.len > 0) {
                    if (vnext_val.array.items[0] == .object) {
                        const srv = vnext_val.array.items[0].object;
                        if (address.len == 0) if (getFieldString(srv, &.{ "address", "Address" })) |v| {
                            address = v;
                        };
                        if (port == 0) if (getFieldInt(srv, &.{ "port", "Port" })) |v| {
                            port = @intCast(@max(v, 0));
                        };
                        // users[0].id
                        if (getFieldAny(srv, &.{"users"})) |users_val| {
                            if (users_val == .array and users_val.array.items.len > 0) {
                                if (users_val.array.items[0] == .object) {
                                    const u = users_val.array.items[0].object;
                                    if (uuid.len == 0) if (getFieldString(u, &.{ "id", "uuid", "UUID" })) |v| {
                                        uuid = v;
                                    };
                                    if (getFieldString(u, &.{ "security", "Security" })) |v| security = v;
                                }
                            }
                        }
                    }
                }
            }
            // Trojan/SS: servers[0]
            if (getFieldAny(settings, &.{"servers"})) |servers_val| {
                if (servers_val == .array and servers_val.array.items.len > 0) {
                    if (servers_val.array.items[0] == .object) {
                        const srv = servers_val.array.items[0].object;
                        if (address.len == 0) if (getFieldString(srv, &.{ "address", "Address" })) |v| {
                            address = v;
                        };
                        if (port == 0) if (getFieldInt(srv, &.{ "port", "Port" })) |v| {
                            port = @intCast(@max(v, 0));
                        };
                        if (password.len == 0) if (getFieldString(srv, &.{ "password", "Password" })) |v| {
                            password = v;
                        };
                        if (method.len == 0) if (getFieldString(srv, &.{ "method", "Method", "cipher" })) |v| {
                            method = v;
                        };
                    }
                }
            }
        }
    }

    return .{
        .tag = try dupString(allocator, tag),
        .protocol = try dupString(allocator, protocol),
        .address = try dupString(allocator, address),
        .port = port,
        .password = try dupString(allocator, password),
        .uuid = try dupString(allocator, uuid),
        .method = try dupString(allocator, method),
        .security = try dupString(allocator, security),
        .domain_strategy = try dupString(allocator, getFieldString(obj, &.{ "domainStrategy", "DomainStrategy" }) orelse "AsIs"),
        .send_through = try dupString(allocator, getFieldString(obj, &.{ "sendThrough", "SendThrough" }) orelse ""),
        .stream_settings = stream_settings,
    };
}

fn parseRoutingObject(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !RoutingConfig {
    const default_outbound = try dupString(
        allocator,
        getFieldString(obj, &.{ "defaultOutbound", "DefaultOutbound" }) orelse "direct",
    );

    var rules = std.array_list.Managed(RouteRuleConfig).init(allocator);

    if (getFieldAny(obj, &.{ "rules", "Rules" })) |v| {
        if (v == .array) {
            for (v.array.items) |item| {
                if (item != .object) continue;
                try rules.append(try parseRouteRuleObject(allocator, item.object));
            }
        }
    }

    return RoutingConfig{
        .default_outbound = default_outbound,
        .rules = try rules.toOwnedSlice(),
    };
}

fn parseRouteRuleObject(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !RouteRuleConfig {
    var domains = std.array_list.Managed([]const u8).init(allocator);
    var ips = std.array_list.Managed([]const u8).init(allocator);

    if (obj.get("domain")) |domain_value| {
        if (domain_value == .array) {
            for (domain_value.array.items) |item| {
                if (item != .string) continue;
                const val = item.string;
                if (std.mem.startsWith(u8, val, "domain:")) {
                    try domains.append(try dupString(allocator, val["domain:".len..]));
                } else if (std.mem.startsWith(u8, val, "full:")) {
                    try domains.append(try dupString(allocator, val["full:".len..]));
                } else if (std.mem.startsWith(u8, val, "geosite:")) {
                    continue;
                } else if (std.mem.startsWith(u8, val, "keyword:")) {
                    continue;
                } else if (std.mem.startsWith(u8, val, "regexp:")) {
                    continue;
                } else {
                    try domains.append(try dupString(allocator, val));
                }
            }
        }
    }

    if (getFieldAny(obj, &.{ "domainSuffix", "domain_suffix" })) |v| {
        if (v == .array) {
            for (v.array.items) |item| {
                if (item != .string) continue;
                try domains.append(try dupString(allocator, item.string));
            }
        }
    }

    if (obj.get("ip")) |ip_value| {
        if (ip_value == .array) {
            for (ip_value.array.items) |item| {
                if (item != .string) continue;
                const val = item.string;
                if (std.mem.startsWith(u8, val, "geoip:")) continue;
                try ips.append(try dupString(allocator, val));
            }
        }
    }

    const outbound_tag = try dupString(
        allocator,
        getFieldString(obj, &.{ "outboundTag", "OutboundTag" }) orelse "direct",
    );

    return RouteRuleConfig{
        .domain_suffix = try domains.toOwnedSlice(),
        .ip_cidrs = try ips.toOwnedSlice(),
        .outbound_tag = outbound_tag,
    };
}

fn parseStreamSettings(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !StreamSettings {
    const tls_cfg = if (getFieldAny(obj, &.{ "tlsSettings", "TlsSettings", "tls" })) |v|
        (if (v == .object) try parseTlsConfig(allocator, v.object) else TlsConfig{})
    else
        TlsConfig{};

    const ws_cfg = if (getFieldAny(obj, &.{ "wsSettings", "WsSettings", "ws" })) |v|
        (if (v == .object) try parseWsConfig(allocator, v.object) else WsConfig{})
    else
        WsConfig{};

    return StreamSettings{
        .network = try dupString(allocator, getFieldString(obj, &.{ "network", "Network" }) orelse "tcp"),
        .security = try dupString(allocator, getFieldString(obj, &.{ "security", "Security" }) orelse "none"),
        .tls = tls_cfg,
        .ws = ws_cfg,
    };
}

fn parseTlsConfig(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !TlsConfig {
    var alpn_list = std.array_list.Managed([]const u8).init(allocator);
    if (getFieldAny(obj, &.{ "alpn", "ALPN" })) |v| {
        if (v == .array) {
            for (v.array.items) |item| {
                if (item != .string) continue;
                try alpn_list.append(try dupString(allocator, item.string));
            }
        }
    }

    return TlsConfig{
        .cert_file = try dupString(allocator, getFieldString(obj, &.{ "certificateFile", "certFile", "cert" }) orelse ""),
        .key_file = try dupString(allocator, getFieldString(obj, &.{ "keyFile", "key" }) orelse ""),
        .ca_file = try dupString(allocator, getFieldString(obj, &.{ "caFile", "ca" }) orelse ""),
        .server_name = try dupString(allocator, getFieldString(obj, &.{ "serverName", "ServerName", "sni" }) orelse ""),
        .allow_insecure = getFieldBool(obj, &.{ "allowInsecure", "AllowInsecure" }) orelse false,
        .alpn = try alpn_list.toOwnedSlice(),
        .min_version = try dupString(allocator, getFieldString(obj, &.{ "minVersion", "MinVersion" }) orelse "1.2"),
        .max_version = try dupString(allocator, getFieldString(obj, &.{ "maxVersion", "MaxVersion" }) orelse "1.3"),
    };
}

fn parseWsConfig(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !WsConfig {
    return WsConfig{
        .path = try dupString(allocator, getFieldString(obj, &.{ "path", "Path" }) orelse "/"),
        .real_ip_header = try dupString(allocator, getFieldString(obj, &.{ "realIpHeader", "RealIpHeader" }) orelse ""),
    };
}

fn parseSniffConfig(obj: std.json.ObjectMap) SniffConfig {
    return SniffConfig{
        .enabled = getFieldBool(obj, &.{ "enabled", "Enabled" }) orelse false,
        .override_dest = getFieldBool(obj, &.{ "destOverride", "DestOverride", "overrideDest" }) orelse false,
    };
}

fn parseLogConfig(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !LogConfig {
    return LogConfig{
        .level = try dupString(allocator, getFieldString(obj, &.{ "level", "Level" }) orelse "info"),
        .log_dir = try dupString(allocator, getFieldString(obj, &.{ "logDir", "LogDir", "log_dir" }) orelse "/var/log/znode"),
        .max_days = @intCast(@max(getFieldInt(obj, &.{ "maxDays", "MaxDays", "max_days" }) orelse 15, 0)),
    };
}

fn parseDnsConfig(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !DnsConfig {
    var servers = std.array_list.Managed([]const u8).init(allocator);
    if (getFieldAny(obj, &.{ "servers", "Servers" })) |v| {
        if (v == .array) {
            for (v.array.items) |item| {
                if (item != .string) continue;
                try servers.append(try dupString(allocator, item.string));
            }
        }
    }

    return DnsConfig{
        .servers = try servers.toOwnedSlice(),
        .timeout = @intCast(@max(getFieldInt(obj, &.{ "timeout", "Timeout" }) orelse 5, 0)),
        .cache_size = @intCast(@max(getFieldInt(obj, &.{ "cacheSize", "CacheSize" }) orelse 10000, 0)),
        .min_ttl = @intCast(@max(getFieldInt(obj, &.{ "minTTL", "MinTTL" }) orelse 60, 0)),
        .max_ttl = @intCast(@max(getFieldInt(obj, &.{ "maxTTL", "MaxTTL" }) orelse 3600, 0)),
    };
}

fn parseTimeoutsConfig(obj: std.json.ObjectMap) TimeoutsConfig {
    return TimeoutsConfig{
        .handshake = @intCast(@max(getFieldInt(obj, &.{ "handshake", "Handshake" }) orelse 4, 0)),
        .dial = @intCast(@max(getFieldInt(obj, &.{ "dial", "Dial" }) orelse 10, 0)),
        .read = @intCast(@max(getFieldInt(obj, &.{ "read", "Read" }) orelse 15, 0)),
        .write = @intCast(@max(getFieldInt(obj, &.{ "write", "Write" }) orelse 30, 0)),
        .idle = @intCast(@max(getFieldInt(obj, &.{ "idle", "Idle" }) orelse 300, 0)),
        .uplink_only = @intCast(@max(getFieldInt(obj, &.{ "uplinkOnly", "UplinkOnly" }) orelse 2, 0)),
        .downlink_only = @intCast(@max(getFieldInt(obj, &.{ "downlinkOnly", "DownlinkOnly" }) orelse 5, 0)),
    };
}

fn parseLimitsConfig(obj: std.json.ObjectMap) LimitsConfig {
    return LimitsConfig{
        .max_connections = @intCast(@max(getFieldInt(obj, &.{ "maxConnections", "MaxConnections" }) orelse 0, 0)),
        .max_connections_per_ip = @intCast(@max(getFieldInt(obj, &.{ "maxConnectionsPerIP", "MaxConnectionsPerIP" }) orelse 0, 0)),
        .max_rate_per_ip = @intCast(@max(getFieldInt(obj, &.{ "maxRatePerIP", "MaxRatePerIP" }) orelse 0, 0)),
        .auth_fail_limit = @intCast(@max(getFieldInt(obj, &.{ "authFailLimit", "AuthFailLimit" }) orelse 10, 0)),
        .auth_fail_window = @intCast(@max(getFieldInt(obj, &.{ "authFailWindow", "AuthFailWindow" }) orelse 60, 0)),
        .auth_ban_seconds = @intCast(@max(getFieldInt(obj, &.{ "authBanSeconds", "AuthBanSeconds" }) orelse 180, 0)),
        .buffer_size = @intCast(@max(getFieldInt(obj, &.{ "bufferSize", "BufferSize" }) orelse 24 * 1024, 0)),
    };
}

fn parsePanelsConfig(allocator: std.mem.Allocator, value: std.json.Value) ![]const PanelConfig {
    var list = std.array_list.Managed(PanelConfig).init(allocator);
    switch (value) {
        .array => |arr| {
            for (arr.items) |item| {
                if (item != .object) continue;
                try list.append(try parsePanelObject(allocator, item.object));
            }
        },
        .object => |obj| {
            try list.append(try parsePanelObject(allocator, obj));
        },
        else => {},
    }
    return try list.toOwnedSlice();
}

fn parsePanelObject(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !PanelConfig {
    var node_ids = std.array_list.Managed(i64).init(allocator);
    if (getFieldAny(obj, &.{ "NodeID", "nodeIds", "NodeIds", "node_ids" })) |v| {
        if (v == .array) {
            for (v.array.items) |item| {
                if (valueToInt(item)) |n| {
                    try node_ids.append(n);
                }
            }
        }
    }

    return PanelConfig{
        .name = try dupString(allocator, getFieldString(obj, &.{ "name", "Name" }) orelse ""),
        .panel_type = try dupString(allocator, getFieldString(obj, &.{ "type", "Type" }) orelse "V2Board"),
        .api_host = try dupString(allocator, getFieldString(obj, &.{ "apiHost", "ApiHost", "api_host" }) orelse ""),
        .api_key = try dupString(allocator, getFieldString(obj, &.{ "apiKey", "ApiKey", "api_key" }) orelse ""),
        .node_ids = try node_ids.toOwnedSlice(),
        .node_type = try dupString(allocator, getFieldString(obj, &.{ "nodeType", "NodeType", "node_type" }) orelse "vmess"),
        .tls_enable = getFieldBool(obj, &.{ "tlsEnable", "TlsEnable", "tls_enable" }) orelse false,
        .tls_cert = try dupString(allocator, getFieldString(obj, &.{ "tlsCert", "TlsCert", "tls_cert" }) orelse ""),
        .tls_key = try dupString(allocator, getFieldString(obj, &.{ "tlsKey", "TlsKey", "tls_key" }) orelse ""),
    };
}

fn ensureBuiltinOutbounds(
    allocator: std.mem.Allocator,
    outbounds: *std.array_list.Managed(OutboundConfig),
) !void {
    if (!hasOutboundTag(outbounds.items, "direct")) {
        try outbounds.append(.{
            .tag = try dupString(allocator, "direct"),
            .protocol = try dupString(allocator, "freedom"),
        });
    }
    if (!hasOutboundTag(outbounds.items, "blackhole")) {
        try outbounds.append(.{
            .tag = try dupString(allocator, "blackhole"),
            .protocol = try dupString(allocator, "blackhole"),
        });
    }
}

fn hasOutboundTag(outbounds: []const OutboundConfig, tag: []const u8) bool {
    for (outbounds) |ob| {
        if (std.mem.eql(u8, ob.tag, tag)) return true;
    }
    return false;
}

fn getFieldAny(obj: std.json.ObjectMap, keys: []const []const u8) ?std.json.Value {
    for (keys) |key| {
        if (obj.get(key)) |v| return v;
    }
    return null;
}

fn getFieldString(obj: std.json.ObjectMap, keys: []const []const u8) ?[]const u8 {
    const v = getFieldAny(obj, keys) orelse return null;
    return valueToString(v);
}

fn getFieldBool(obj: std.json.ObjectMap, keys: []const []const u8) ?bool {
    const v = getFieldAny(obj, keys) orelse return null;
    return switch (v) {
        .bool => |b| b,
        else => null,
    };
}

fn getFieldInt(obj: std.json.ObjectMap, keys: []const []const u8) ?i64 {
    const v = getFieldAny(obj, keys) orelse return null;
    return valueToInt(v);
}

fn valueToString(v: std.json.Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn valueToInt(v: std.json.Value) ?i64 {
    return switch (v) {
        .integer => |n| n,
        .float => |n| @as(i64, @intFromFloat(n)),
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        else => null,
    };
}

fn dupString(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    return try allocator.dupe(u8, value);
}
