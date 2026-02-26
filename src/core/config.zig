const std = @import("std");
const log = @import("log.zig");
const trojan = @import("../protocol/trojan/trojan_protocol.zig");
const ss_crypto = @import("../protocol/shadowsocks/ss_crypto.zig");

// ── Defaults ──

pub const default_geoip_url = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat";
pub const default_geosite_url = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat";

// ── Enums ──

pub const Protocol = enum {
    vmess,
    trojan,
    shadowsocks,
    freedom,
    blackhole,
};

pub const Transport = enum {
    tcp,
    tls,
    ws,
    wss,
    udp,
};

// ── NodeConfig ──

/// Each panel entry = one panel connection + local controller config.
/// Protocol details (port, transport, ws, server_name) come from panel API.
/// Fixed-buffer pattern for safe memory ownership.
pub const NodeConfig = struct {
    // ── Name (for inbound tag: name-protocol-port) ──
    name_buf: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,

    // ── Panel connection ──
    panel_type_buf: [32]u8 = [_]u8{0} ** 32,
    panel_type_len: u8 = 0,
    api_url_buf: [256]u8 = [_]u8{0} ** 256,
    api_url_len: u16 = 0,
    api_key_buf: [128]u8 = [_]u8{0} ** 128,
    api_key_len: u8 = 0,
    node_id: u32 = 0,
    // Multi-node support: "node_id = [2011, 1011]" expands to separate entries
    node_ids: [16]u32 = [_]u32{0} ** 16,
    node_id_count: u8 = 0,

    // ── Sniff ──
    sniff_enabled: bool = true,
    sniff_redirect: bool = true,

    // ── Local controller ──
    protocol: Protocol = .vmess,
    listen_buf: [64]u8 = [_]u8{0} ** 64,
    listen_len: u8 = 0,

    // ── Fallback (auth failure → forward to fallback server) ──
    fallback_addr_buf: [64]u8 = [_]u8{0} ** 64,
    fallback_addr_len: u8 = 0,
    fallback_port: u16 = 0,

    // ── Shadowsocks inbound (panel mode) ──
    ss_password_buf: [64]u8 = [_]u8{0} ** 64,
    ss_password_len: u8 = 0,
    ss_method_buf: [32]u8 = [_]u8{0} ** 32,
    ss_method_len: u8 = 0,

    // ── SendThrough: bind outbound to specific local IP (per-panel) ──
    send_through_buf: [45]u8 = [_]u8{0} ** 45,
    send_through_len: u8 = 0,

    // ── TLS ──
    tls_enabled: bool = false, // true = terminate TLS locally
    cert_file_buf: [256]u8 = [_]u8{0} ** 256,
    cert_file_len: u16 = 0,
    key_file_buf: [256]u8 = [_]u8{0} ** 256,
    key_file_len: u16 = 0,

    // ── Getters ──

    pub fn getSendThrough(self: *const NodeConfig) []const u8 {
        return self.send_through_buf[0..self.send_through_len];
    }

    pub fn getName(self: *const NodeConfig) []const u8 {
        return self.name_buf[0..self.name_len];
    }
    pub fn getPanelType(self: *const NodeConfig) []const u8 {
        if (self.panel_type_len == 0) return "v2board";
        return self.panel_type_buf[0..self.panel_type_len];
    }
    pub fn getApiUrl(self: *const NodeConfig) []const u8 { return self.api_url_buf[0..self.api_url_len]; }
    pub fn getApiKey(self: *const NodeConfig) []const u8 { return self.api_key_buf[0..self.api_key_len]; }
    pub fn getListenAddr(self: *const NodeConfig) []const u8 {
        if (self.listen_len == 0) return "0.0.0.0";
        return self.listen_buf[0..self.listen_len];
    }
    pub fn getFallbackAddr(self: *const NodeConfig) []const u8 { return self.fallback_addr_buf[0..self.fallback_addr_len]; }
    pub fn getCertFile(self: *const NodeConfig) []const u8 { return self.cert_file_buf[0..self.cert_file_len]; }
    pub fn getKeyFile(self: *const NodeConfig) []const u8 { return self.key_file_buf[0..self.key_file_len]; }

    /// Get cert/key file path as null-terminated C string (buffer is zero-initialized so [len] == 0).
    pub fn getCertFileZ(self: *const NodeConfig) [*:0]const u8 {
        return @ptrCast(self.cert_file_buf[0 .. self.cert_file_len + 1]);
    }
    pub fn getKeyFileZ(self: *const NodeConfig) [*:0]const u8 {
        return @ptrCast(self.key_file_buf[0 .. self.key_file_len + 1]);
    }

    /// Return the protocol as the V2Board API "node_type" query parameter string.
    pub fn getNodeTypeStr(self: *const NodeConfig) []const u8 {
        return switch (self.protocol) {
            .vmess => "v2ray",
            .trojan => "trojan",
            .shadowsocks => "shadowsocks",
            .freedom => "freedom",
            .blackhole => "blackhole",
        };
    }

    // ── Setters ──

    pub fn setName(self: *NodeConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.name_buf.len));
        @memcpy(self.name_buf[0..n], v[0..n]);
        self.name_len = n;
    }
    pub fn setPanelType(self: *NodeConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.panel_type_buf.len));
        @memcpy(self.panel_type_buf[0..n], v[0..n]);
        self.panel_type_len = n;
    }
    pub fn setApiUrl(self: *NodeConfig, v: []const u8) void {
        if (v.len > self.api_url_buf.len)
            log.warn("config: api_url truncated ({d} > {d})", .{ v.len, self.api_url_buf.len });
        const n: u16 = @intCast(@min(v.len, self.api_url_buf.len));
        @memcpy(self.api_url_buf[0..n], v[0..n]);
        self.api_url_len = n;
    }
    pub fn setApiKey(self: *NodeConfig, v: []const u8) void {
        if (v.len > self.api_key_buf.len)
            log.warn("config: api_key truncated ({d} > {d})", .{ v.len, self.api_key_buf.len });
        const n: u8 = @intCast(@min(v.len, self.api_key_buf.len));
        @memcpy(self.api_key_buf[0..n], v[0..n]);
        self.api_key_len = n;
    }
    pub fn setSendThrough(self: *NodeConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.send_through_buf.len));
        @memcpy(self.send_through_buf[0..n], v[0..n]);
        self.send_through_len = n;
    }
    pub fn setFallbackAddr(self: *NodeConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.fallback_addr_buf.len));
        @memcpy(self.fallback_addr_buf[0..n], v[0..n]);
        self.fallback_addr_len = n;
    }
    pub fn setListen(self: *NodeConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.listen_buf.len));
        @memcpy(self.listen_buf[0..n], v[0..n]);
        self.listen_len = n;
    }
    pub fn setCertFile(self: *NodeConfig, v: []const u8) void {
        if (v.len > self.cert_file_buf.len)
            log.warn("config: cert_file truncated ({d} > {d})", .{ v.len, self.cert_file_buf.len });
        const n: u16 = @intCast(@min(v.len, self.cert_file_buf.len));
        @memcpy(self.cert_file_buf[0..n], v[0..n]);
        self.cert_file_len = n;
    }
    pub fn getSsPassword(self: *const NodeConfig) []const u8 {
        return self.ss_password_buf[0..self.ss_password_len];
    }
    pub fn getSsMethod(self: *const NodeConfig) []const u8 {
        return self.ss_method_buf[0..self.ss_method_len];
    }
    pub fn setSsPassword(self: *NodeConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.ss_password_buf.len));
        @memcpy(self.ss_password_buf[0..n], v[0..n]);
        self.ss_password_len = n;
    }
    pub fn setSsMethod(self: *NodeConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.ss_method_buf.len));
        @memcpy(self.ss_method_buf[0..n], v[0..n]);
        self.ss_method_len = n;
    }
    pub fn setKeyFile(self: *NodeConfig, v: []const u8) void {
        if (v.len > self.key_file_buf.len)
            log.warn("config: key_file truncated ({d} > {d})", .{ v.len, self.key_file_buf.len });
        const n: u16 = @intCast(@min(v.len, self.key_file_buf.len));
        @memcpy(self.key_file_buf[0..n], v[0..n]);
        self.key_file_len = n;
    }
};

// ── ListenerConfig ──

/// Per-listener configuration for multi-port listening.
/// Fallback entry: conditional routing on auth failure (Xray-compatible).
/// Matches by ALPN and/or HTTP path prefix, routes to a specific dest.
pub const FallbackEntry = struct {
    alpn_buf: [16]u8 = [_]u8{0} ** 16, // e.g. "h2", "http/1.1"
    alpn_len: u8 = 0,
    path_buf: [64]u8 = [_]u8{0} ** 64, // e.g. "/ws", "/vmess"
    path_len: u8 = 0,
    dest_addr: ?std.net.Address = null,

    pub fn getAlpn(self: *const FallbackEntry) []const u8 {
        return self.alpn_buf[0..self.alpn_len];
    }
    pub fn getPath(self: *const FallbackEntry) []const u8 {
        return self.path_buf[0..self.path_len];
    }
    pub fn setAlpn(self: *FallbackEntry, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.alpn_buf.len));
        @memcpy(self.alpn_buf[0..n], v[0..n]);
        self.alpn_len = n;
    }
    pub fn setPath(self: *FallbackEntry, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.path_buf.len));
        @memcpy(self.path_buf[0..n], v[0..n]);
        self.path_len = n;
    }
    /// Match this entry against ALPN and path. Empty fields match anything.
    pub fn matches(self: *const FallbackEntry, alpn: ?[]const u8, path: ?[]const u8) bool {
        // If alpn is specified in entry, it must match
        if (self.alpn_len > 0) {
            const entry_alpn = self.getAlpn();
            if (alpn) |a| {
                if (!std.ascii.eqlIgnoreCase(a, entry_alpn)) return false;
            } else return false;
        }
        // If path is specified in entry, the request path must start with it
        if (self.path_len > 0) {
            const entry_path = self.getPath();
            if (path) |p| {
                if (p.len < entry_path.len) return false;
                if (!std.mem.eql(u8, p[0..entry_path.len], entry_path)) return false;
            } else return false;
        }
        return true;
    }
};

pub const max_fallbacks = 4;

/// Each listener can have its own protocol, TLS, and fallback settings.
pub const ListenerConfig = struct {
    name_buf: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    port: u16 = 0,
    protocol: Protocol = .vmess,
    tls_enabled: bool = false,
    listen_buf: [64]u8 = [_]u8{0} ** 64,
    listen_len: u8 = 0,
    fallback_addr_buf: [64]u8 = [_]u8{0} ** 64,
    fallback_addr_len: u8 = 0,
    fallback_port: u16 = 0,
    // Multi-level fallbacks (path/ALPN-based, Xray-compatible)
    fallbacks: [max_fallbacks]FallbackEntry = [_]FallbackEntry{.{}} ** max_fallbacks,
    fallback_count: u8 = 0,
    // TLS certificate files (only used when tls_enabled == true)
    cert_file_buf: [256]u8 = [_]u8{0} ** 256,
    cert_file_len: u16 = 0,
    key_file_buf: [256]u8 = [_]u8{0} ** 256,
    key_file_len: u16 = 0,
    // SendThrough: bind outbound to specific local IP (per-listener)
    send_through_buf: [45]u8 = [_]u8{0} ** 45,
    send_through_len: u8 = 0,
    // Shadowsocks inbound: password + method (only used when protocol == .shadowsocks)
    ss_password_buf: [64]u8 = [_]u8{0} ** 64,
    ss_password_len: u8 = 0,
    ss_method_buf: [32]u8 = [_]u8{0} ** 32,
    ss_method_len: u8 = 0,
    // Sniff: detect TLS SNI / HTTP Host from initial payload
    sniff_enabled: bool = true,
    sniff_redirect: bool = true,
    // Transport: tcp (default), ws, wss
    transport: Transport = .tcp,
    // WebSocket path (only used when transport == .ws or .wss)
    ws_path_buf: [128]u8 = [_]u8{0} ** 128,
    ws_path_len: u8 = 0,
    // VMess UUID for standalone mode (without panel)
    uuid_buf: [36]u8 = [_]u8{0} ** 36,
    uuid_len: u8 = 0,
    // Routing: whether to use route rules for this listener (default: false = direct)
    enable_routing: bool = false,

    pub fn getSendThrough(self: *const ListenerConfig) []const u8 {
        return self.send_through_buf[0..self.send_through_len];
    }
    pub fn setSendThrough(self: *ListenerConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.send_through_buf.len));
        @memcpy(self.send_through_buf[0..n], v[0..n]);
        self.send_through_len = n;
    }

    pub fn getName(self: *const ListenerConfig) []const u8 {
        return self.name_buf[0..self.name_len];
    }
    pub fn setName(self: *ListenerConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.name_buf.len));
        @memcpy(self.name_buf[0..n], v[0..n]);
        self.name_len = n;
    }
    pub fn getListenAddr(self: *const ListenerConfig) []const u8 {
        if (self.listen_len == 0) return "0.0.0.0";
        return self.listen_buf[0..self.listen_len];
    }
    pub fn getFallbackAddr(self: *const ListenerConfig) []const u8 {
        return self.fallback_addr_buf[0..self.fallback_addr_len];
    }
    pub fn setListen(self: *ListenerConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.listen_buf.len));
        @memcpy(self.listen_buf[0..n], v[0..n]);
        self.listen_len = n;
    }
    pub fn setFallbackAddr(self: *ListenerConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.fallback_addr_buf.len));
        @memcpy(self.fallback_addr_buf[0..n], v[0..n]);
        self.fallback_addr_len = n;
    }
    pub fn getSsPassword(self: *const ListenerConfig) []const u8 {
        return self.ss_password_buf[0..self.ss_password_len];
    }
    pub fn getSsMethod(self: *const ListenerConfig) []const u8 {
        return self.ss_method_buf[0..self.ss_method_len];
    }
    pub fn setSsPassword(self: *ListenerConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.ss_password_buf.len));
        @memcpy(self.ss_password_buf[0..n], v[0..n]);
        self.ss_password_len = n;
    }
    pub fn setSsMethod(self: *ListenerConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.ss_method_buf.len));
        @memcpy(self.ss_method_buf[0..n], v[0..n]);
        self.ss_method_len = n;
    }
    pub fn getCertFile(self: *const ListenerConfig) []const u8 { return self.cert_file_buf[0..self.cert_file_len]; }
    pub fn getKeyFile(self: *const ListenerConfig) []const u8 { return self.key_file_buf[0..self.key_file_len]; }
    /// Get cert file path as null-terminated C string (buffer is zero-initialized so [len] == 0).
    pub fn getCertFileZ(self: *const ListenerConfig) [*:0]const u8 {
        return @ptrCast(self.cert_file_buf[0 .. self.cert_file_len + 1]);
    }
    pub fn getKeyFileZ(self: *const ListenerConfig) [*:0]const u8 {
        return @ptrCast(self.key_file_buf[0 .. self.key_file_len + 1]);
    }
    pub fn setCertFile(self: *ListenerConfig, v: []const u8) void {
        if (v.len > self.cert_file_buf.len)
            log.warn("config: cert_file truncated ({d} > {d})", .{ v.len, self.cert_file_buf.len });
        const n: u16 = @intCast(@min(v.len, self.cert_file_buf.len));
        @memcpy(self.cert_file_buf[0..n], v[0..n]);
        self.cert_file_len = n;
    }
    pub fn setKeyFile(self: *ListenerConfig, v: []const u8) void {
        if (v.len > self.key_file_buf.len)
            log.warn("config: key_file truncated ({d} > {d})", .{ v.len, self.key_file_buf.len });
        const n: u16 = @intCast(@min(v.len, self.key_file_buf.len));
        @memcpy(self.key_file_buf[0..n], v[0..n]);
        self.key_file_len = n;
    }
    pub fn getWsPath(self: *const ListenerConfig) []const u8 {
        if (self.ws_path_len == 0) return "/";
        return self.ws_path_buf[0..self.ws_path_len];
    }
    pub fn setWsPath(self: *ListenerConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.ws_path_buf.len));
        @memcpy(self.ws_path_buf[0..n], v[0..n]);
        self.ws_path_len = n;
    }
    pub fn getUuid(self: *const ListenerConfig) []const u8 {
        return self.uuid_buf[0..self.uuid_len];
    }
    pub fn setUuid(self: *ListenerConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.uuid_buf.len));
        @memcpy(self.uuid_buf[0..n], v[0..n]);
        self.uuid_len = n;
    }
};

/// Max local [[listeners]] in config file.
pub const max_config_listeners = 16;
/// Max runtime listeners (config + panel combined).
pub const max_listeners = 256;

// ── OutboundConfig (legacy, kept for parseUuid) ──

pub const OutboundConfig = struct {
    tag: []const u8 = "",
    protocol: Protocol = .freedom,
    address: []const u8 = "",
    port: u16 = 0,
    transport: Transport = .tcp,
    send_through: []const u8 = "",
    vmess_uuid: [16]u8 = [_]u8{0} ** 16,
    vmess_security: u8 = 3,
    has_vmess_config: bool = false,
    trojan_password: []const u8 = "",
    has_trojan_config: bool = false,
    ss_password: []const u8 = "",
    ss_method: []const u8 = "",
    has_ss_config: bool = false,

    /// Parse a UUID string like "550e8400-e29b-41d4-a716-446655440000" into 16 bytes.
    pub fn parseUuid(s: []const u8) ?[16]u8 {
        if (s.len != 36) return null;
        if (s[8] != '-' or s[13] != '-' or s[18] != '-' or s[23] != '-') return null;
        var result: [16]u8 = undefined;
        var out_idx: usize = 0;
        var i: usize = 0;
        while (i < s.len) : (i += 1) {
            if (s[i] == '-') continue;
            if (i + 1 >= s.len) return null;
            const hi = hexVal(s[i]) orelse return null;
            const lo = hexVal(s[i + 1]) orelse return null;
            if (out_idx >= 16) return null;
            result[out_idx] = @as(u8, hi) << 4 | lo;
            out_idx += 1;
            i += 1;
        }
        if (out_idx != 16) return null;
        return result;
    }

    fn hexVal(c: u8) ?u4 {
        if (c >= '0' and c <= '9') return @intCast(c - '0');
        if (c >= 'a' and c <= 'f') return @intCast(c - 'a' + 10);
        if (c >= 'A' and c <= 'F') return @intCast(c - 'A' + 10);
        return null;
    }
};

// ── Unified Route Config (soga-style) ──

/// Pre-processed outbound endpoint. All credentials are derived at parse time.
pub const OutConfig = struct {
    protocol: Protocol = .freedom,
    transport: Transport = .tcp,
    server_addr: ?std.net.Address = null, // resolved at parse time (IP only)
    server_host_buf: [128]u8 = [_]u8{0} ** 128, // hostname for DNS resolution
    server_host_len: u8 = 0,
    server_port: u16 = 0, // port (used when server is hostname)
    // TLS
    tls: bool = false,
    sni_buf: [128]u8 = [_]u8{0} ** 128,
    sni_len: u8 = 0,
    skip_cert_verify: bool = false,
    // WebSocket
    ws_path_buf: [128]u8 = [_]u8{0} ** 128,
    ws_path_len: u8 = 0,
    ws_host_buf: [128]u8 = [_]u8{0} ** 128,
    ws_host_len: u8 = 0,
    // VMess (uuid parsed, security resolved)
    vmess_uuid: [16]u8 = [_]u8{0} ** 16,
    vmess_security: u8 = 3,
    // Trojan (password hashed via SHA224)
    trojan_password_hash: [56]u8 = [_]u8{0} ** 56,
    // Shadowsocks (password → PSK via EVP_BytesToKey)
    ss_psk: [32]u8 = [_]u8{0} ** 32,
    ss_method: u8 = 0,
    ss_key_len: u8 = 0,
    // Bind IP (listen/send_through)
    bind_addr: ?std.net.Address = null,

    pub fn getSni(self: *const OutConfig) []const u8 {
        return self.sni_buf[0..self.sni_len];
    }

    pub fn setSni(self: *OutConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.sni_buf.len));
        @memcpy(self.sni_buf[0..n], v[0..n]);
        self.sni_len = n;
    }

    pub fn getServerHost(self: *const OutConfig) []const u8 {
        return self.server_host_buf[0..self.server_host_len];
    }

    pub fn setServerHost(self: *OutConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.server_host_buf.len));
        @memcpy(self.server_host_buf[0..n], v[0..n]);
        self.server_host_len = n;
    }

    pub fn getWsPath(self: *const OutConfig) []const u8 {
        if (self.ws_path_len == 0) return "/";
        return self.ws_path_buf[0..self.ws_path_len];
    }

    pub fn setWsPath(self: *OutConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.ws_path_buf.len));
        @memcpy(self.ws_path_buf[0..n], v[0..n]);
        self.ws_path_len = n;
    }

    pub fn getWsHost(self: *const OutConfig) []const u8 {
        return self.ws_host_buf[0..self.ws_host_len];
    }

    pub fn setWsHost(self: *OutConfig, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.ws_host_buf.len));
        @memcpy(self.ws_host_buf[0..n], v[0..n]);
        self.ws_host_len = n;
    }
};

/// A route entry: rules (OR'd) + outbound endpoints (random LB).
pub const RouteEntry = struct {
    rules: []const []const u8, // rule strings like "geosite:netflix" (reference file content memory)
    outs: []const OutConfig, // outbound endpoints (pre-processed)
};

// ── Sub-configs ──

pub const DnsConfig = struct {
    servers: []const []const u8 = &.{"8.8.8.8"},
    routes: [max_dns_routes]DnsRoute = [_]DnsRoute{.{}} ** max_dns_routes,
    route_count: u8 = 0,
    cache_size: u32 = 4096,
    min_ttl: u32 = 60,
    max_ttl: u32 = 3600,

    pub const max_dns_routes = 8;
};

/// DNS routing rule: maps domain suffixes to a specific DNS server.
pub const DnsRoute = struct {
    server_buf: [64]u8 = [_]u8{0} ** 64,
    server_len: u8 = 0,
    suffixes: [max_suffixes][64]u8 = undefined,
    suffix_lens: [max_suffixes]u8 = [_]u8{0} ** max_suffixes,
    suffix_count: u8 = 0,

    const max_suffixes = 16;

    pub fn getServer(self: *const DnsRoute) []const u8 {
        return self.server_buf[0..self.server_len];
    }

    pub fn setServer(self: *DnsRoute, v: []const u8) void {
        const n: u8 = @intCast(@min(v.len, self.server_buf.len));
        @memcpy(self.server_buf[0..n], v[0..n]);
        self.server_len = n;
    }

    pub fn addSuffix(self: *DnsRoute, s: []const u8) void {
        if (self.suffix_count >= max_suffixes) return;
        const n: u8 = @intCast(@min(s.len, 64));
        @memcpy(self.suffixes[self.suffix_count][0..n], s[0..n]);
        self.suffix_lens[self.suffix_count] = n;
        self.suffix_count += 1;
    }

    /// Check if a domain matches any of this route's suffixes.
    pub fn matchesDomain(self: *const DnsRoute, domain: []const u8) bool {
        for (0..self.suffix_count) |i| {
            const suffix = self.suffixes[i][0..self.suffix_lens[i]];
            if (suffix.len == 0) continue;
            if (std.mem.eql(u8, domain, suffix)) return true;
            if (domain.len > suffix.len + 1) {
                const tail = domain[domain.len - suffix.len ..];
                if (std.mem.eql(u8, tail, suffix) and domain[domain.len - suffix.len - 1] == '.') {
                    return true;
                }
            }
        }
        return false;
    }
};

pub const DispatchStrategy = enum {
    least_connections,
    round_robin,
    random,
    ip_hash,
};

pub const LimitsConfig = struct {
    max_connections: u32 = 0,
    max_conn_per_ip: u32 = 0,
    handshake_timeout_ms: u32 = 30_000, // 30s default — prevents half-open connections hanging forever
    relay_idle_timeout_ms: u32 = 15_000, // 15s default — reclaims idle connections promptly
    half_close_grace_ms: u32 = 5_000, // 5s hard cap on half-close duration
    buffer_pool_max_mb: u32 = 0,
    vmess_hot_cache_ttl: u32 = 300, // seconds, 0 = disabled
    dispatch_strategy: DispatchStrategy = .least_connections,
};

// ── Main Config ──

pub const Config = struct {
    log_level: log.Level = .info,
    workers: u16 = 0, // 0 = auto-detect CPU count

    // Panel entries (each connects to a panel + listens locally)
    panel: []const NodeConfig = &.{},

    // Unified routes (rules + inline outbounds, soga-style)
    routes: []const RouteEntry = &.{},

    // Multi-port listeners (local config, independent of panel)
    listeners: [max_config_listeners]ListenerConfig = [_]ListenerConfig{.{}} ** max_config_listeners,
    listener_count: u8 = 0,

    // Sub-configs
    dns: DnsConfig = .{},
    limits: LimitsConfig = .{},

    // Log settings
    log_dir: [256]u8 = [_]u8{0} ** 256,
    log_dir_len: u16 = 0,
    log_max_days: u16 = 7,
    log_clean_on_start: bool = false,

    // Geo database paths (relative to config dir, or absolute; default: geoip.dat / geosite.dat)
    geoip_path: [256]u8 = [_]u8{0} ** 256,
    geoip_path_len: u16 = 0,
    geosite_path: [256]u8 = [_]u8{0} ** 256,
    geosite_path_len: u16 = 0,

    // Geo download URLs (configurable, default Loyalsoldier)
    geoip_url: [512]u8 = [_]u8{0} ** 512,
    geoip_url_len: u16 = 0,
    geosite_url: [512]u8 = [_]u8{0} ** 512,
    geosite_url_len: u16 = 0,

    // Auto-update interval in hours (0 = disabled, default 24)
    geo_update_interval: u16 = 24,

    // Config directory (derived from config file path)
    config_dir: [256]u8 = [_]u8{0} ** 256,
    config_dir_len: u16 = 0,

    // Internal: owned file data kept alive for string references
    _file_data: [4]?[]u8 = .{ null, null, null, null },

    pub fn getWorkerCount(self: *const Config) u16 {
        if (self.workers > 0) return self.workers;
        const cpus = std.Thread.getCpuCount() catch 1;
        return @intCast(@min(cpus, 64));
    }

    pub fn getConfigDir(self: *const Config) []const u8 {
        return self.config_dir[0..self.config_dir_len];
    }
    pub fn getGeoipPath(self: *const Config) []const u8 {
        if (self.geoip_path_len == 0) return "geoip.dat";
        return self.geoip_path[0..self.geoip_path_len];
    }
    pub fn getGeositePath(self: *const Config) []const u8 {
        if (self.geosite_path_len == 0) return "geosite.dat";
        return self.geosite_path[0..self.geosite_path_len];
    }
    pub fn getGeoipUrl(self: *const Config) []const u8 {
        if (self.geoip_url_len == 0) return default_geoip_url;
        return self.geoip_url[0..self.geoip_url_len];
    }
    pub fn getGeositeUrl(self: *const Config) []const u8 {
        if (self.geosite_url_len == 0) return default_geosite_url;
        return self.geosite_url[0..self.geosite_url_len];
    }

    fn setConfigDir(self: *Config, dir: []const u8) void {
        const len: u16 = @intCast(@min(dir.len, self.config_dir.len));
        @memcpy(self.config_dir[0..len], dir[0..len]);
        self.config_dir_len = len;
    }

    fn setPathField(buf: []u8, len_ptr: *u16, val: []const u8) void {
        const n: u16 = @intCast(@min(val.len, buf.len));
        @memcpy(buf[0..n], val[0..n]);
        len_ptr.* = n;
    }

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        if (self.panel.len > 0) allocator.free(self.panel);
        for (self.routes) |entry| {
            if (entry.rules.len > 0) allocator.free(entry.rules);
            if (entry.outs.len > 0) allocator.free(entry.outs);
        }
        if (self.routes.len > 0) allocator.free(self.routes);
        for (&self._file_data) |*d| {
            if (d.*) |data| {
                allocator.free(data);
                d.* = null;
            }
        }
    }
};

// ── File Loading ──

/// Load configuration from a TOML file, resolving external file references.
pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !Config {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024 * 1024);

    var config = try parseToml(allocator, content);
    config._file_data[0] = content;

    // Extract config directory from file path
    const dir = std.fs.path.dirname(path) orelse ".";
    config.setConfigDir(dir);

    // Auto-load routes.toml from config directory (silently skip if not present)
    if (loadRelativeFile(allocator, config.getConfigDir(), "routes.toml")) |data| {
        config._file_data[1] = data;
        parseRouteToml(&config, allocator, data);
        log.info("auto-loaded routes.toml ({d} bytes)", .{data.len});
    } else |_| {}

    return config;
}

fn loadRelativeFile(allocator: std.mem.Allocator, config_dir: []const u8, relative_path: []const u8) ![]u8 {
    var path_buf: [512]u8 = undefined;
    const full_path = if (std.fs.path.isAbsolute(relative_path))
        relative_path
    else if (config_dir.len == 0)
        relative_path
    else
        std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ config_dir, relative_path }) catch return error.InvalidPath;

    const file = try std.fs.cwd().openFile(full_path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, 1024 * 1024);
}

// ── TOML Parsing ──

const eql = std.mem.eql;

/// Case-insensitive ASCII string comparison for TOML section names.
fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

const Section = enum {
    root,
    panel,
    routes,
    routes_outs,
    limits,
    dns,
    dns_routes,
    listeners,
};

/// Builder for accumulating route entries during TOML parsing.
const RouteBuilder = struct {
    rules: std.ArrayList([]const u8) = .{},
    outs: std.ArrayList(OutConfig) = .{},
};

/// Parse main config TOML string.
pub fn parseToml(allocator: std.mem.Allocator, content: []const u8) !Config {
    var config = Config{};
    var panel_list: std.ArrayList(NodeConfig) = .{};
    var route_list: std.ArrayList(RouteBuilder) = .{};
    var section: Section = .root;

    // Temp storage for OutConfig credential derivation (password/cipher come on separate lines)
    var pending_password: []const u8 = "";
    var pending_cipher: []const u8 = "";

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, " \t\r");
        const trimmed = std.mem.trimLeft(u8, line, " \t");

        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        // Array of tables: [[name]]
        if (trimmed.len > 4 and trimmed[0] == '[' and trimmed[1] == '[') {
            // Finalize previous routes_outs section
            if (section == .routes_outs) {
                finalizeOutConfig(&route_list, pending_password, pending_cipher);
            }

            const name = parseArrayTableName(trimmed);
            if (eqlIgnoreCase(name, "panel")) {
                section = .panel;
                try panel_list.append(allocator, NodeConfig{});
            } else if (eqlIgnoreCase(name, "routes")) {
                section = .routes;
                try route_list.append(allocator, RouteBuilder{});
            } else if (eqlIgnoreCase(name, "routes.outs")) {
                section = .routes_outs;
                if (route_list.items.len > 0) {
                    try route_list.items[route_list.items.len - 1].outs.append(allocator, OutConfig{});
                }
                pending_password = "";
                pending_cipher = "";
            } else if (eqlIgnoreCase(name, "dns.routes")) {
                section = .dns_routes;
                if (config.dns.route_count < DnsConfig.max_dns_routes) {
                    config.dns.route_count += 1;
                }
            } else if (eqlIgnoreCase(name, "listeners")) {
                section = .listeners;
                if (config.listener_count < max_config_listeners) {
                    config.listener_count += 1;
                }
            }
            continue;
        }

        // Table: [name]
        if (trimmed[0] == '[') {
            if (section == .routes_outs) {
                finalizeOutConfig(&route_list, pending_password, pending_cipher);
            }
            const name = parseSectionName(trimmed);
            if (eqlIgnoreCase(name, "limits")) {
                section = .limits;
            } else if (eqlIgnoreCase(name, "dns")) {
                section = .dns;
            }
            continue;
        }

        // Key = value
        const kv = parseKeyValue(trimmed) orelse continue;

        switch (section) {
            .root => applyRootKV(&config, kv.key, kv.value),
            .panel => {
                if (panel_list.items.len > 0)
                    applyPanelKV(&panel_list.items[panel_list.items.len - 1], kv.key, kv.value);
            },
            .routes => {
                if (route_list.items.len > 0)
                    applyRouteKV(allocator, &route_list.items[route_list.items.len - 1], kv.key, kv.value);
            },
            .routes_outs => {
                if (route_list.items.len > 0) {
                    const rb = &route_list.items[route_list.items.len - 1];
                    if (rb.outs.items.len > 0) {
                        applyOutKV(&rb.outs.items[rb.outs.items.len - 1], kv.key, kv.value, &pending_password, &pending_cipher);
                    }
                }
            },
            .limits => applyLimitsKV(&config.limits, kv.key, kv.value),
            .dns => applyDnsKV(&config.dns, kv.key, kv.value),
            .dns_routes => {
                if (config.dns.route_count > 0)
                    applyDnsRouteKV(&config.dns.routes[config.dns.route_count - 1], kv.key, kv.value);
            },
            .listeners => {
                if (config.listener_count > 0)
                    applyListenerKV(&config.listeners[config.listener_count - 1], kv.key, kv.value);
            },
        }
    }

    // Finalize last section if it was routes_outs
    if (section == .routes_outs) {
        finalizeOutConfig(&route_list, pending_password, pending_cipher);
    }

    // Expand multi-node-id panel entries: "node_id = 2011,1011" → 2 entries
    var expanded: std.ArrayList(NodeConfig) = .{};
    for (panel_list.items) |entry| {
        if (entry.node_id_count <= 1) {
            try expanded.append(allocator, entry);
        } else {
            for (0..entry.node_id_count) |i| {
                var clone = entry;
                clone.node_id = entry.node_ids[i];
                clone.node_id_count = 1;
                clone.node_ids[0] = entry.node_ids[i];
                try expanded.append(allocator, clone);
            }
        }
    }
    panel_list.deinit(allocator);

    // Convert builders to owned slices
    config.panel = try expanded.toOwnedSlice(allocator);

    var route_entries: std.ArrayList(RouteEntry) = .{};
    for (route_list.items) |*rb| {
        try route_entries.append(allocator, .{
            .rules = try rb.rules.toOwnedSlice(allocator),
            .outs = try rb.outs.toOwnedSlice(allocator),
        });
    }
    config.routes = try route_entries.toOwnedSlice(allocator);
    route_list.deinit(allocator);

    return config;
}

// ── TOML Line Helpers ──

const KV = struct { key: []const u8, value: []const u8 };

fn parseKeyValue(line: []const u8) ?KV {
    const eq_pos = std.mem.indexOfScalar(u8, line, '=') orelse return null;
    const key = std.mem.trimRight(u8, line[0..eq_pos], " \t");
    if (key.len == 0) return null;
    const value = std.mem.trim(u8, line[eq_pos + 1 ..], " \t\r\n");
    return .{ .key = key, .value = value };
}

/// Extract section name from "[name]" → "name"
fn parseSectionName(line: []const u8) []const u8 {
    if (line.len < 3 or line[0] != '[') return "";
    const end = std.mem.indexOfScalar(u8, line[1..], ']') orelse return "";
    return std.mem.trim(u8, line[1 .. 1 + end], " \t");
}

/// Extract section name from "[[name]]" → "name"
fn parseArrayTableName(line: []const u8) []const u8 {
    if (line.len < 5 or line[0] != '[' or line[1] != '[') return "";
    // Find closing ]]
    if (std.mem.indexOf(u8, line[2..], "]]")) |end| {
        return std.mem.trim(u8, line[2 .. 2 + end], " \t");
    }
    return "";
}

fn parseTomlString(val: []const u8) []const u8 {
    if (val.len >= 2 and val[0] == '"') {
        // Find matching closing quote (handles trailing comments: "value" # comment)
        if (std.mem.indexOfScalar(u8, val[1..], '"')) |end| {
            return val[1 .. 1 + end];
        }
    }
    // Bare value: strip inline comment
    if (std.mem.indexOfScalar(u8, val, '#')) |pos| {
        return std.mem.trimRight(u8, val[0..pos], " \t");
    }
    return val;
}

fn parseTomlInt(val: []const u8) ?i64 {
    // Strip inline comment for bare values
    var clean = val;
    if (std.mem.indexOfScalar(u8, clean, '#')) |pos| {
        clean = std.mem.trimRight(u8, clean[0..pos], " \t");
    }
    return std.fmt.parseInt(i64, clean, 10) catch null;
}

fn parseTomlBool(val: []const u8) ?bool {
    var clean = val;
    if (std.mem.indexOfScalar(u8, clean, '#')) |pos| {
        clean = std.mem.trimRight(u8, clean[0..pos], " \t");
    }
    if (eql(u8, clean, "true")) return true;
    if (eql(u8, clean, "false")) return false;
    return null;
}

/// Parse inline string array: ["a", "b"] → allocated slice of string slices.
/// Strings are slices into the original content (zero-copy).
fn parseTomlStringArray(allocator: std.mem.Allocator, val: []const u8) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .{};
    if (val.len < 2 or val[0] != '[') return try list.toOwnedSlice(allocator);

    var i: usize = 1; // skip '['
    while (i < val.len) {
        // Skip whitespace and commas
        while (i < val.len and (val[i] == ' ' or val[i] == '\t' or val[i] == ',')) : (i += 1) {}
        if (i >= val.len or val[i] == ']') break;

        if (val[i] == '"') {
            const start = i + 1;
            i += 1;
            while (i < val.len and val[i] != '"') : (i += 1) {}
            if (i < val.len) {
                try list.append(allocator, val[start..i]);
                i += 1; // skip closing quote
            }
        } else {
            i += 1;
        }
    }
    return try list.toOwnedSlice(allocator);
}

// ── Section Apply Functions ──

fn applyRootKV(config: *Config, key: []const u8, val: []const u8) void {
    if (eql(u8, key, "log_level")) {
        config.log_level = log.Level.fromString(parseTomlString(val));
    } else if (eql(u8, key, "log_dir")) {
        Config.setPathField(&config.log_dir, &config.log_dir_len, parseTomlString(val));
    } else if (eql(u8, key, "log_max_days")) {
        if (parseTomlInt(val)) |v| config.log_max_days = @intCast(@max(1, @min(v, 365)));
    } else if (eql(u8, key, "log_clean_on_start")) {
        if (parseTomlBool(val)) |v| config.log_clean_on_start = v;
    } else if (eql(u8, key, "workers")) {
        if (parseTomlInt(val)) |v| config.workers = @intCast(@max(0, @min(v, 64)));
    } else if (eql(u8, key, "geoip_path")) {
        Config.setPathField(&config.geoip_path, &config.geoip_path_len, parseTomlString(val));
    } else if (eql(u8, key, "geosite_path")) {
        Config.setPathField(&config.geosite_path, &config.geosite_path_len, parseTomlString(val));
    } else if (eql(u8, key, "geoip_url")) {
        Config.setPathField(&config.geoip_url, &config.geoip_url_len, parseTomlString(val));
    } else if (eql(u8, key, "geosite_url")) {
        Config.setPathField(&config.geosite_url, &config.geosite_url_len, parseTomlString(val));
    } else if (eql(u8, key, "geo_update_interval")) {
        if (parseTomlInt(val)) |v| config.geo_update_interval = @intCast(@max(0, @min(v, 8760)));
    }
}

fn applyPanelKV(node: *NodeConfig, key: []const u8, val: []const u8) void {
    if (eql(u8, key, "name")) {
        node.setName(parseTomlString(val));
    } else if (eql(u8, key, "panel_type")) {
        node.setPanelType(parseTomlString(val));
    } else if (eql(u8, key, "api_url")) {
        node.setApiUrl(parseTomlString(val));
    } else if (eql(u8, key, "api_key")) {
        node.setApiKey(parseTomlString(val));
    } else if (eql(u8, key, "node_id")) {
        // TOML array: node_id = [2011, 1011]  or single: node_id = 2011
        const trimmed_val = std.mem.trim(u8, val, " \t");
        if (trimmed_val.len > 0 and trimmed_val[0] == '[') {
            var count: u8 = 0;
            // Strip [ and ]
            const inner = blk: {
                const start: usize = 1;
                var end = trimmed_val.len;
                if (std.mem.indexOfScalar(u8, trimmed_val, ']')) |p| end = p;
                break :blk trimmed_val[start..end];
            };
            var iter = std.mem.splitScalar(u8, inner, ',');
            while (iter.next()) |part| {
                const num = std.mem.trim(u8, part, " \t");
                if (std.fmt.parseInt(u32, num, 10) catch null) |id| {
                    if (count < node.node_ids.len) {
                        node.node_ids[count] = id;
                        count += 1;
                    }
                }
            }
            node.node_id_count = count;
            if (count > 0) node.node_id = node.node_ids[0];
        } else {
            if (parseTomlInt(val)) |v| {
                node.node_id = @intCast(@max(0, v));
                node.node_ids[0] = node.node_id;
                node.node_id_count = 1;
            }
        }
    } else if (eql(u8, key, "node_type") or eql(u8, key, "protocol")) {
        node.protocol = parseProtocol(parseTomlString(val));
    } else if (eql(u8, key, "listen")) {
        node.setListen(parseTomlString(val));
    } else if (eql(u8, key, "fallback_addr")) {
        node.setFallbackAddr(parseTomlString(val));
    } else if (eql(u8, key, "fallback_port")) {
        if (parseTomlInt(val)) |v| node.fallback_port = @intCast(@max(0, @min(v, 65535)));
    } else if (eql(u8, key, "tls")) {
        if (parseTomlBool(val)) |v| node.tls_enabled = v;
    } else if (eql(u8, key, "cert_file")) {
        node.setCertFile(parseTomlString(val));
    } else if (eql(u8, key, "key_file")) {
        node.setKeyFile(parseTomlString(val));
    } else if (eql(u8, key, "send_through")) {
        node.setSendThrough(parseTomlString(val));
    } else if (eql(u8, key, "password") or eql(u8, key, "ss_password")) {
        node.setSsPassword(parseTomlString(val));
    } else if (eql(u8, key, "method") or eql(u8, key, "ss_method")) {
        node.setSsMethod(parseTomlString(val));
    } else if (eql(u8, key, "sniff")) {
        if (parseTomlBool(val)) |v| node.sniff_enabled = v;
    } else if (eql(u8, key, "sniff_redirect")) {
        if (parseTomlBool(val)) |v| node.sniff_redirect = v;
    }
}

fn applyRouteKV(allocator: std.mem.Allocator, rb: *RouteBuilder, key: []const u8, val: []const u8) void {
    if (eql(u8, key, "rules")) {
        const arr = parseTomlStringArray(allocator, val) catch return;
        for (arr) |s| {
            rb.rules.append(allocator, s) catch {};
        }
        allocator.free(arr);
    }
}

fn applyOutKV(out: *OutConfig, key: []const u8, val: []const u8, pending_password: *[]const u8, pending_cipher: *[]const u8) void {
    if (eql(u8, key, "type")) {
        out.protocol = parseProtocol(parseTomlString(val));
    } else if (eql(u8, key, "server")) {
        const server_str = parseTomlString(val);
        // Try IP first; if it fails, treat as hostname for DNS resolution
        if (std.net.Address.parseIp4(server_str, out.server_port)) |addr| {
            out.server_addr = addr;
            out.server_host_len = 0; // clear hostname since we have IP
        } else |_| {
            // Domain name — store for DNS resolution at connect time
            out.setServerHost(server_str);
            out.server_addr = null;
        }
    } else if (eql(u8, key, "port")) {
        if (parseTomlInt(val)) |v| {
            const port: u16 = @intCast(@max(0, @min(v, 65535)));
            out.server_port = port;
            if (out.server_addr) |existing| {
                // IP already set, update port
                const ip_bytes: [4]u8 = @bitCast(existing.in.sa.addr);
                out.server_addr = std.net.Address.initIp4(ip_bytes, port);
            }
            // If server is hostname (server_addr=null), port is stored in server_port
        }
    } else if (eql(u8, key, "network") or eql(u8, key, "transport")) {
        const s = parseTomlString(val);
        out.transport = parseTransport(s);
        // "ws" implies no TLS, "wss" implies TLS
        if (out.transport == .wss) out.tls = true;
    } else if (eql(u8, key, "ws_path") or eql(u8, key, "path")) {
        out.setWsPath(parseTomlString(val));
    } else if (eql(u8, key, "ws_host") or eql(u8, key, "host")) {
        out.setWsHost(parseTomlString(val));
    } else if (eql(u8, key, "tls")) {
        if (parseTomlBool(val)) |v| out.tls = v;
    } else if (eql(u8, key, "sni")) {
        out.setSni(parseTomlString(val));
    } else if (eql(u8, key, "skip_cert_verify")) {
        if (parseTomlBool(val)) |v| out.skip_cert_verify = v;
    } else if (eql(u8, key, "uuid")) {
        if (OutboundConfig.parseUuid(parseTomlString(val))) |uuid| {
            out.vmess_uuid = uuid;
        }
    } else if (eql(u8, key, "security")) {
        out.vmess_security = parseSecurityMethod(parseTomlString(val));
    } else if (eql(u8, key, "alterid") or eql(u8, key, "alter_id") or eql(u8, key, "alterId")) {
        // AEAD VMess requires alterId=0; warn if non-zero
        if (parseTomlInt(val)) |v| {
            if (v != 0) log.warn("VMess alterId={d} ignored — only AEAD (alterId=0) is supported", .{v});
        }
    } else if (eql(u8, key, "password")) {
        pending_password.* = parseTomlString(val);
    } else if (eql(u8, key, "cipher") or eql(u8, key, "method")) {
        pending_cipher.* = parseTomlString(val);
    } else if (eql(u8, key, "listen")) {
        const s = parseTomlString(val);
        if (s.len > 0) {
            out.bind_addr = std.net.Address.parseIp4(s, 0) catch null;
        }
    }
}

fn applyLimitsKV(limits: *LimitsConfig, key: []const u8, val: []const u8) void {
    if (eql(u8, key, "max_connections")) {
        if (parseTomlInt(val)) |v| limits.max_connections = @intCast(@max(0, v));
    } else if (eql(u8, key, "max_conn_per_ip")) {
        if (parseTomlInt(val)) |v| limits.max_conn_per_ip = @intCast(@max(0, v));
    } else if (eql(u8, key, "handshake_timeout_ms")) {
        if (parseTomlInt(val)) |v| limits.handshake_timeout_ms = @intCast(@max(0, v));
    } else if (eql(u8, key, "relay_idle_timeout_ms")) {
        if (parseTomlInt(val)) |v| limits.relay_idle_timeout_ms = @intCast(@max(0, v));
    } else if (eql(u8, key, "half_close_grace_ms")) {
        if (parseTomlInt(val)) |v| limits.half_close_grace_ms = @intCast(@max(0, v));
    } else if (eql(u8, key, "buffer_pool_max_mb")) {
        if (parseTomlInt(val)) |v| limits.buffer_pool_max_mb = @intCast(@max(0, v));
    } else if (eql(u8, key, "vmess_hot_cache_ttl")) {
        if (parseTomlInt(val)) |v| limits.vmess_hot_cache_ttl = @intCast(@max(0, v));
    } else if (eql(u8, key, "dispatch_strategy")) {
        const s = parseTomlString(val);
        if (eql(u8, s, "round_robin")) {
            limits.dispatch_strategy = .round_robin;
        } else if (eql(u8, s, "random")) {
            limits.dispatch_strategy = .random;
        } else if (eql(u8, s, "ip_hash")) {
            limits.dispatch_strategy = .ip_hash;
        } else {
            limits.dispatch_strategy = .least_connections;
        }
    }
}

fn applyDnsKV(dns: *DnsConfig, key: []const u8, val: []const u8) void {
    if (eql(u8, key, "cache_size")) {
        if (parseTomlInt(val)) |v| dns.cache_size = @intCast(@max(0, v));
    } else if (eql(u8, key, "min_ttl")) {
        if (parseTomlInt(val)) |v| dns.min_ttl = @intCast(@max(0, v));
    } else if (eql(u8, key, "max_ttl")) {
        if (parseTomlInt(val)) |v| dns.max_ttl = @intCast(@max(0, v));
    }
}

fn applyDnsRouteKV(route: *DnsRoute, key: []const u8, val: []const u8) void {
    if (eql(u8, key, "server")) {
        route.setServer(parseTomlString(val));
    } else if (eql(u8, key, "domains")) {
        // Parse inline array; copy into fixed buffers via addSuffix
        const arr = parseTomlStringArray(std.heap.page_allocator, val) catch return;
        defer std.heap.page_allocator.free(arr);
        for (arr) |s| {
            route.addSuffix(s);
        }
    }
}

fn applyListenerKV(lc: *ListenerConfig, key: []const u8, val: []const u8) void {
    if (eql(u8, key, "name")) {
        lc.setName(parseTomlString(val));
    } else if (eql(u8, key, "port")) {
        if (parseTomlInt(val)) |v| lc.port = @intCast(@max(0, @min(v, 65535)));
    } else if (eql(u8, key, "protocol")) {
        lc.protocol = parseProtocol(parseTomlString(val));
    } else if (eql(u8, key, "tls")) {
        if (parseTomlBool(val)) |v| lc.tls_enabled = v;
    } else if (eql(u8, key, "listen")) {
        lc.setListen(parseTomlString(val));
    } else if (eql(u8, key, "fallback_addr")) {
        lc.setFallbackAddr(parseTomlString(val));
    } else if (eql(u8, key, "fallback_port")) {
        if (parseTomlInt(val)) |v| lc.fallback_port = @intCast(@max(0, @min(v, 65535)));
    } else if (eql(u8, key, "password")) {
        lc.setSsPassword(parseTomlString(val));
    } else if (eql(u8, key, "method")) {
        lc.setSsMethod(parseTomlString(val));
    } else if (eql(u8, key, "send_through")) {
        lc.setSendThrough(parseTomlString(val));
    } else if (eql(u8, key, "cert_file")) {
        lc.setCertFile(parseTomlString(val));
    } else if (eql(u8, key, "key_file")) {
        lc.setKeyFile(parseTomlString(val));
    } else if (eql(u8, key, "sniff")) {
        if (parseTomlBool(val)) |v| lc.sniff_enabled = v;
    } else if (eql(u8, key, "sniff_redirect")) {
        if (parseTomlBool(val)) |v| lc.sniff_redirect = v;
    } else if (eql(u8, key, "transport") or eql(u8, key, "network")) {
        lc.transport = parseTransport(parseTomlString(val));
    } else if (eql(u8, key, "ws_path") or eql(u8, key, "path")) {
        lc.setWsPath(parseTomlString(val));
    } else if (eql(u8, key, "uuid")) {
        lc.setUuid(parseTomlString(val));
    } else if (eql(u8, key, "routing")) {
        if (parseTomlBool(val)) |v| lc.enable_routing = v;
    }
}

/// Finalize the current OutConfig with credential derivation (Trojan hash, SS PSK).
fn finalizeOutConfig(route_list: *std.ArrayList(RouteBuilder), password: []const u8, cipher: []const u8) void {
    if (route_list.items.len == 0) return;
    const rb = &route_list.items[route_list.items.len - 1];
    if (rb.outs.items.len == 0) return;
    const out = &rb.outs.items[rb.outs.items.len - 1];

    if (password.len == 0) return;

    if (out.protocol == .trojan) {
        out.trojan_password_hash = trojan.hashPassword(password);
    }
    if (out.protocol == .shadowsocks) {
        const method_str = if (cipher.len > 0) cipher else "aes-128-gcm";
        if (ss_crypto.Method.fromString(method_str)) |method| {
            out.ss_psk = ss_crypto.evpBytesToKey(password, method.keySize());
            out.ss_method = @intFromEnum(method);
            out.ss_key_len = @intCast(method.keySize());
        }
        // Shadowsocks has its own AEAD encryption — TLS/WS transport is not supported.
        // Force transport=tcp to prevent data path bypassing transport layers.
        if (out.transport != .tcp) {
            log.warn("Shadowsocks outbound: transport={s} not supported, forcing tcp", .{@tagName(out.transport)});
            out.transport = .tcp;
            out.tls = false;
        }
    }
}

// ── External File Parsers ──

fn parseRouteToml(config: *Config, allocator: std.mem.Allocator, content: []const u8) void {
    // External route file uses same TOML format: [[routes]] + [[routes.outs]]
    var route_list: std.ArrayList(RouteBuilder) = .{};
    var section: Section = .root;
    var pending_password: []const u8 = "";
    var pending_cipher: []const u8 = "";

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, " \t\r");
        const trimmed = std.mem.trimLeft(u8, line, " \t");

        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        if (trimmed.len > 4 and trimmed[0] == '[' and trimmed[1] == '[') {
            if (section == .routes_outs) {
                finalizeOutConfig(&route_list, pending_password, pending_cipher);
            }
            const name = parseArrayTableName(trimmed);
            if (eqlIgnoreCase(name, "routes")) {
                section = .routes;
                route_list.append(allocator, RouteBuilder{}) catch return;
            } else if (eqlIgnoreCase(name, "routes.outs")) {
                section = .routes_outs;
                if (route_list.items.len > 0) {
                    route_list.items[route_list.items.len - 1].outs.append(allocator, OutConfig{}) catch return;
                }
                pending_password = "";
                pending_cipher = "";
            }
            continue;
        }

        if (trimmed[0] == '[') continue; // skip other table headers

        const kv = parseKeyValue(trimmed) orelse continue;
        switch (section) {
            .routes => {
                if (route_list.items.len > 0)
                    applyRouteKV(allocator, &route_list.items[route_list.items.len - 1], kv.key, kv.value);
            },
            .routes_outs => {
                if (route_list.items.len > 0) {
                    const rb = &route_list.items[route_list.items.len - 1];
                    if (rb.outs.items.len > 0) {
                        applyOutKV(&rb.outs.items[rb.outs.items.len - 1], kv.key, kv.value, &pending_password, &pending_cipher);
                    }
                }
            },
            else => {},
        }
    }

    if (section == .routes_outs) {
        finalizeOutConfig(&route_list, pending_password, pending_cipher);
    }

    // Convert to RouteEntry slice
    var route_entries: std.ArrayList(RouteEntry) = .{};
    for (route_list.items) |*rb| {
        route_entries.append(allocator, .{
            .rules = rb.rules.toOwnedSlice(allocator) catch &.{},
            .outs = rb.outs.toOwnedSlice(allocator) catch &.{},
        }) catch {};
    }
    config.routes = route_entries.toOwnedSlice(allocator) catch &.{};
    route_list.deinit(allocator);
}

fn parseDnsToml(config: *Config, content: []const u8) void {
    var section: Section = .root;

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, " \t\r");
        const trimmed = std.mem.trimLeft(u8, line, " \t");

        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        if (trimmed.len > 4 and trimmed[0] == '[' and trimmed[1] == '[') {
            const name = parseArrayTableName(trimmed);
            if (eqlIgnoreCase(name, "dns.routes") or eqlIgnoreCase(name, "routes")) {
                section = .dns_routes;
                if (config.dns.route_count < DnsConfig.max_dns_routes) {
                    config.dns.route_count += 1;
                }
            }
            continue;
        }

        if (trimmed[0] == '[') {
            const name = parseSectionName(trimmed);
            if (eqlIgnoreCase(name, "dns")) section = .dns;
            continue;
        }

        const kv = parseKeyValue(trimmed) orelse continue;
        switch (section) {
            .root, .dns => applyDnsKV(&config.dns, kv.key, kv.value),
            .dns_routes => {
                if (config.dns.route_count > 0)
                    applyDnsRouteKV(&config.dns.routes[config.dns.route_count - 1], kv.key, kv.value);
            },
            else => {},
        }
    }
}

// ── Helpers ──

pub fn parseProtocol(s: []const u8) Protocol {
    if (eql(u8, s, "vmess")) return .vmess;
    if (eql(u8, s, "trojan")) return .trojan;
    if (eql(u8, s, "shadowsocks") or eql(u8, s, "ss")) return .shadowsocks;
    if (eql(u8, s, "freedom") or eql(u8, s, "direct")) return .freedom;
    if (eql(u8, s, "blackhole") or eql(u8, s, "block")) return .blackhole;
    return .freedom;
}

pub fn parseTransport(s: []const u8) Transport {
    if (eql(u8, s, "tcp")) return .tcp;
    if (eql(u8, s, "tls")) return .tls;
    if (eql(u8, s, "ws")) return .ws;
    if (eql(u8, s, "wss")) return .wss;
    return .tcp;
}

pub fn parseSecurityMethod(s: []const u8) u8 {
    if (eql(u8, s, "aes-128-gcm")) return 3;
    if (eql(u8, s, "chacha20-poly1305")) return 4;
    if (eql(u8, s, "none")) return 5;
    if (eql(u8, s, "aes-256-gcm")) return 6;
    if (eql(u8, s, "auto") or eql(u8, s, "")) return 3; // auto resolves to aes-128-gcm (same as Xray-core on x86_64)
    return 3; // default: aes-128-gcm
}

// ── Tests ──

test "parseToml default config" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator, "");
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 0), config.workers);
    try std.testing.expectEqual(log.Level.info, config.log_level);
}

test "parseToml with workers" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\workers = 4
        \\log_level = "debug"
    );
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 4), config.workers);
    try std.testing.expectEqual(log.Level.debug, config.log_level);
}

test "parseToml with log config" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\log_dir = "logs"
        \\log_max_days = 30
    );
    defer config.deinit(allocator);
    try std.testing.expectEqualStrings("logs", config.log_dir[0..config.log_dir_len]);
    try std.testing.expectEqual(@as(u16, 30), config.log_max_days);
}

test "parseToml default log config" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator, "");
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 0), config.log_dir_len);
    try std.testing.expectEqual(@as(u16, 7), config.log_max_days);
}

test "parseToml with limits config" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\[limits]
        \\max_connections = 5000
        \\max_conn_per_ip = 100
        \\buffer_pool_max_mb = 512
    );
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 5000), config.limits.max_connections);
    try std.testing.expectEqual(@as(u32, 100), config.limits.max_conn_per_ip);
    try std.testing.expectEqual(@as(u32, 512), config.limits.buffer_pool_max_mb);
    try std.testing.expectEqual(@as(u32, 30_000), config.limits.handshake_timeout_ms);
    try std.testing.expectEqual(@as(u32, 15_000), config.limits.relay_idle_timeout_ms);
}

test "parseToml with panel" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\[[panel]]
        \\panel_type = "v2board"
        \\api_url = "https://panel.com"
        \\api_key = "key1"
        \\node_id = 1
        \\node_type = "vmess"
        \\listen = "0.0.0.0"
        \\cert_file = "cert/s.crt"
        \\key_file = "cert/s.key"
        \\
        \\[[panel]]
        \\api_url = "https://panel2.com"
        \\api_key = "key2"
        \\node_id = 5
        \\node_type = "trojan"
    );
    defer config.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), config.panel.len);

    const n0 = &config.panel[0];
    try std.testing.expectEqualStrings("v2board", n0.getPanelType());
    try std.testing.expectEqualStrings("https://panel.com", n0.getApiUrl());
    try std.testing.expectEqualStrings("key1", n0.getApiKey());
    try std.testing.expectEqual(@as(u32, 1), n0.node_id);
    try std.testing.expectEqual(Protocol.vmess, n0.protocol);
    try std.testing.expectEqualStrings("0.0.0.0", n0.getListenAddr());
    try std.testing.expectEqualStrings("cert/s.crt", n0.getCertFile());
    try std.testing.expectEqualStrings("cert/s.key", n0.getKeyFile());

    const n1 = &config.panel[1];
    try std.testing.expectEqualStrings("v2board", n1.getPanelType()); // default
    try std.testing.expectEqual(@as(u32, 5), n1.node_id);
    try std.testing.expectEqual(Protocol.trojan, n1.protocol);
}

test "parseToml with comma-separated node_id" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\[[panel]]
        \\name = "multi"
        \\api_url = "https://panel.com"
        \\api_key = "key1"
        \\node_id = [2011, 1011]
        \\node_type = "trojan"
        \\
        \\[[panel]]
        \\name = "single"
        \\api_url = "https://panel2.com"
        \\api_key = "key2"
        \\node_id = 99
        \\node_type = "vmess"
    );
    defer config.deinit(allocator);

    // "2011,1011" expands to 2 entries + 1 single = 3 total
    try std.testing.expectEqual(@as(usize, 3), config.panel.len);

    // First expanded entry: node_id=2011, inherits all other fields
    try std.testing.expectEqualStrings("multi", config.panel[0].getName());
    try std.testing.expectEqual(@as(u32, 2011), config.panel[0].node_id);
    try std.testing.expectEqualStrings("https://panel.com", config.panel[0].getApiUrl());
    try std.testing.expectEqual(Protocol.trojan, config.panel[0].protocol);

    // Second expanded entry: node_id=1011, same config
    try std.testing.expectEqualStrings("multi", config.panel[1].getName());
    try std.testing.expectEqual(@as(u32, 1011), config.panel[1].node_id);
    try std.testing.expectEqualStrings("https://panel.com", config.panel[1].getApiUrl());
    try std.testing.expectEqual(Protocol.trojan, config.panel[1].protocol);

    // Third entry: single node_id=99
    try std.testing.expectEqualStrings("single", config.panel[2].getName());
    try std.testing.expectEqual(@as(u32, 99), config.panel[2].node_id);
}

test "parseToml without panel" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator, "");
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), config.panel.len);
}

test "parseToml with geo config" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\geoip_path = "data/geoip.dat"
        \\geosite_path = "data/geosite.dat"
        \\geoip_url = "https://example.com/geoip.dat"
        \\geo_update_interval = 12
    );
    defer config.deinit(allocator);
    try std.testing.expectEqualStrings("data/geoip.dat", config.getGeoipPath());
    try std.testing.expectEqualStrings("data/geosite.dat", config.getGeositePath());
    try std.testing.expectEqualStrings("https://example.com/geoip.dat", config.getGeoipUrl());
    // geosite_url not set → default
    try std.testing.expectEqualStrings(default_geosite_url, config.getGeositeUrl());
    try std.testing.expectEqual(@as(u16, 12), config.geo_update_interval);
}

test "parseToml with routes" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\[[routes]]
        \\rules = ["geosite:netflix", "domain:google.com"]
        \\
        \\[[routes.outs]]
        \\type = "vmess"
        \\server = "1.2.3.4"
        \\port = 443
        \\uuid = "550e8400-e29b-41d4-a716-446655440000"
        \\
        \\[[routes]]
        \\rules = ["*"]
        \\
        \\[[routes.outs]]
        \\type = "direct"
    );
    defer config.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), config.routes.len);
    // Route 0: 2 rules, 1 out
    try std.testing.expectEqual(@as(usize, 2), config.routes[0].rules.len);
    try std.testing.expectEqualStrings("geosite:netflix", config.routes[0].rules[0]);
    try std.testing.expectEqualStrings("domain:google.com", config.routes[0].rules[1]);
    try std.testing.expectEqual(@as(usize, 1), config.routes[0].outs.len);
    try std.testing.expectEqual(Protocol.vmess, config.routes[0].outs[0].protocol);
    // Route 1: catch-all direct
    try std.testing.expectEqual(@as(usize, 1), config.routes[1].rules.len);
    try std.testing.expectEqualStrings("*", config.routes[1].rules[0]);
    try std.testing.expectEqual(Protocol.freedom, config.routes[1].outs[0].protocol);
}

test "parseToml routes with trojan outbound" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\[[routes]]
        \\rules = ["*"]
        \\
        \\[[routes.outs]]
        \\type = "trojan"
        \\server = "5.6.7.8"
        \\port = 443
        \\password = "mypass"
        \\tls = true
        \\sni = "example.com"
    );
    defer config.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), config.routes.len);
    const out = &config.routes[0].outs[0];
    try std.testing.expectEqual(Protocol.trojan, out.protocol);
    try std.testing.expect(out.tls);
    try std.testing.expectEqualStrings("example.com", out.getSni());
    // Trojan password should be hashed
    try std.testing.expect(out.trojan_password_hash[0] != 0 or out.trojan_password_hash[1] != 0);
}

test "parseToml routes with ss outbound" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\[[routes]]
        \\rules = ["*"]
        \\
        \\[[routes.outs]]
        \\type = "ss"
        \\server = "1.2.3.4"
        \\port = 8388
        \\password = "test123"
        \\cipher = "aes-128-gcm"
    );
    defer config.deinit(allocator);

    const out = &config.routes[0].outs[0];
    try std.testing.expectEqual(Protocol.shadowsocks, out.protocol);
    try std.testing.expect(out.ss_key_len > 0);
}

test "NodeConfig getter defaults" {
    const node = NodeConfig{};
    try std.testing.expectEqualStrings("v2board", node.getPanelType());
    try std.testing.expectEqualStrings("0.0.0.0", node.getListenAddr());
    try std.testing.expectEqualStrings("", node.getApiUrl());
    try std.testing.expectEqualStrings("", node.getCertFile());
    try std.testing.expectEqualStrings("v2ray", node.getNodeTypeStr());
}

test "NodeConfig setter and getter roundtrip" {
    var node = NodeConfig{};
    node.setApiUrl("https://panel.example.com");
    node.setApiKey("my-secret-key");
    node.setListen("127.0.0.1");
    node.setCertFile("/etc/ssl/cert.pem");

    try std.testing.expectEqualStrings("https://panel.example.com", node.getApiUrl());
    try std.testing.expectEqualStrings("my-secret-key", node.getApiKey());
    try std.testing.expectEqualStrings("127.0.0.1", node.getListenAddr());
    try std.testing.expectEqualStrings("/etc/ssl/cert.pem", node.getCertFile());
}

test "NodeConfig getNodeTypeStr" {
    var node = NodeConfig{};
    try std.testing.expectEqualStrings("v2ray", node.getNodeTypeStr());
    node.protocol = .trojan;
    try std.testing.expectEqualStrings("trojan", node.getNodeTypeStr());
}

test "parseProtocol" {
    try std.testing.expectEqual(Protocol.vmess, parseProtocol("vmess"));
    try std.testing.expectEqual(Protocol.trojan, parseProtocol("trojan"));
    try std.testing.expectEqual(Protocol.freedom, parseProtocol("freedom"));
    try std.testing.expectEqual(Protocol.freedom, parseProtocol("direct"));
    try std.testing.expectEqual(Protocol.blackhole, parseProtocol("blackhole"));
    try std.testing.expectEqual(Protocol.blackhole, parseProtocol("block"));
    try std.testing.expectEqual(Protocol.freedom, parseProtocol("unknown"));
}

test "parseTransport" {
    try std.testing.expectEqual(Transport.tcp, parseTransport("tcp"));
    try std.testing.expectEqual(Transport.tls, parseTransport("tls"));
    try std.testing.expectEqual(Transport.ws, parseTransport("ws"));
    try std.testing.expectEqual(Transport.wss, parseTransport("wss"));
    try std.testing.expectEqual(Transport.tcp, parseTransport("unknown"));
}

test "Config deinit with panel and routes" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\[[panel]]
        \\node_id = 1
        \\
        \\[[routes]]
        \\rules = ["*"]
        \\
        \\[[routes.outs]]
        \\type = "direct"
    );
    config.deinit(allocator);
}

test "DnsRoute matchesDomain suffix" {
    var route = DnsRoute{};
    route.addSuffix("cn");
    route.addSuffix("baidu.com");

    try std.testing.expect(route.matchesDomain("google.cn"));
    try std.testing.expect(route.matchesDomain("test.baidu.com"));
    try std.testing.expect(route.matchesDomain("baidu.com"));
    try std.testing.expect(!route.matchesDomain("example.org"));
    try std.testing.expect(!route.matchesDomain("notcn"));
}

test "parseToml with dns routes" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\[dns]
        \\min_ttl = 120
        \\
        \\[[dns.routes]]
        \\server = "119.29.29.29"
        \\domains = ["cn", "baidu.com"]
        \\
        \\[[dns.routes]]
        \\server = "8.8.4.4"
        \\domains = ["google.com"]
    );
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 2), config.dns.route_count);
    try std.testing.expectEqualStrings("119.29.29.29", config.dns.routes[0].getServer());
    try std.testing.expectEqual(@as(u8, 2), config.dns.routes[0].suffix_count);
    try std.testing.expect(config.dns.routes[0].matchesDomain("test.cn"));
    try std.testing.expectEqualStrings("8.8.4.4", config.dns.routes[1].getServer());
    try std.testing.expectEqual(@as(u32, 120), config.dns.min_ttl);
}

test "parseToml with listeners" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\[[listeners]]
        \\port = 443
        \\protocol = "trojan"
        \\tls = true
        \\fallback_addr = "127.0.0.1"
        \\fallback_port = 80
        \\
        \\[[listeners]]
        \\port = 8080
        \\protocol = "vmess"
    );
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 2), config.listener_count);
    try std.testing.expectEqual(@as(u16, 443), config.listeners[0].port);
    try std.testing.expectEqual(Protocol.trojan, config.listeners[0].protocol);
    try std.testing.expect(config.listeners[0].tls_enabled);
    try std.testing.expectEqual(@as(u16, 80), config.listeners[0].fallback_port);
    try std.testing.expectEqual(@as(u16, 8080), config.listeners[1].port);
    try std.testing.expectEqual(Protocol.vmess, config.listeners[1].protocol);
    try std.testing.expect(!config.listeners[1].tls_enabled);
}

test "OutboundConfig parseUuid" {
    const uuid = OutboundConfig.parseUuid("550e8400-e29b-41d4-a716-446655440000") orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(u8, 0x55), uuid[0]);
    try std.testing.expectEqual(@as(u8, 0x0e), uuid[1]);
    try std.testing.expectEqual(@as(u8, 0x84), uuid[2]);
    try std.testing.expectEqual(@as(u8, 0x00), uuid[3]);
    try std.testing.expectEqual(@as(u8, 0xe2), uuid[4]);
    try std.testing.expectEqual(@as(u8, 0x9b), uuid[5]);
    // Invalid UUID
    try std.testing.expect(OutboundConfig.parseUuid("invalid") == null);
    try std.testing.expect(OutboundConfig.parseUuid("550e8400-e29b-41d4-a716-44665544000") == null); // too short
}

test "parseToml routes with vmess outbound" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\[[routes]]
        \\rules = ["*"]
        \\
        \\[[routes.outs]]
        \\type = "vmess"
        \\server = "1.2.3.4"
        \\port = 443
        \\uuid = "550e8400-e29b-41d4-a716-446655440000"
        \\security = "chacha20-poly1305"
    );
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), config.routes.len);
    const out = &config.routes[0].outs[0];
    try std.testing.expectEqual(Protocol.vmess, out.protocol);
    try std.testing.expectEqual(@as(u8, 0x55), out.vmess_uuid[0]);
    try std.testing.expectEqual(@as(u8, 4), out.vmess_security); // chacha20-poly1305
    try std.testing.expect(out.server_addr != null);
}

test "parseToml comments and blank lines" {
    const allocator = std.testing.allocator;
    var config = try parseToml(allocator,
        \\# This is a comment
        \\workers = 2
        \\
        \\# Another comment
        \\log_level = "warn"
    );
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 2), config.workers);
    try std.testing.expectEqual(log.Level.warn, config.log_level);
}
