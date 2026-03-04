const std = @import("std");

// ============================================================================
// Network / Address
// ============================================================================

pub const Network = enum {
    tcp,
    udp,
    mux,
};

pub const AddressType = enum {
    ipv4,
    domain,
    ipv6,
};

pub const TargetAddress = struct {
    host_buf: [253]u8 = undefined,
    host_len: u8 = 0,
    port: u16 = 0,
    address_type: AddressType = .ipv4,

    pub fn init(h: []const u8, port: u16, atype: AddressType) TargetAddress {
        var self = TargetAddress{
            .port = port,
            .address_type = atype,
        };
        const len: u8 = @intCast(@min(h.len, self.host_buf.len));
        @memcpy(self.host_buf[0..len], h[0..len]);
        self.host_len = len;
        return self;
    }

    pub fn host(self: *const TargetAddress) []const u8 {
        return self.host_buf[0..self.host_len];
    }

    pub fn isEmpty(self: *const TargetAddress) bool {
        return self.host_len == 0;
    }

    pub fn format(self: *const TargetAddress, writer: anytype) !void {
        try writer.print("{s}:{d}", .{ self.host(), self.port });
    }
};

// ============================================================================
// Protocol
// ============================================================================

pub const Protocol = enum {
    unknown,
    trojan,
    vmess,
    shadowsocks,
    freedom,
    blackhole,

    pub fn fromString(s: []const u8) Protocol {
        if (std.ascii.eqlIgnoreCase(s, "trojan")) return .trojan;
        if (std.ascii.eqlIgnoreCase(s, "vmess")) return .vmess;
        if (std.ascii.eqlIgnoreCase(s, "shadowsocks") or std.ascii.eqlIgnoreCase(s, "ss")) return .shadowsocks;
        if (std.ascii.eqlIgnoreCase(s, "freedom") or std.ascii.eqlIgnoreCase(s, "direct")) return .freedom;
        if (std.ascii.eqlIgnoreCase(s, "blackhole")) return .blackhole;
        return .unknown;
    }
};

// ============================================================================
// Connection State
// ============================================================================

pub const ConnState = enum {
    accepted,
    handshaking,
    authenticating,
    sniffing,
    routing,
    dialing,
    relaying,
    closing,
    closed,
};

// ============================================================================
// ErrorCode (mirrors C++ ErrorCode 1:1)
// ============================================================================

pub const ErrorCode = enum(i32) {
    // Success
    ok = 0,

    // Generic (1-99)
    timeout = 1,
    cancelled = 2,
    internal = 3,
    invalid_argument = 4,
    not_found = 5,
    already_exists = 6,
    permission_denied = 7,
    resource_exhausted = 8,
    not_supported = 9,
    connection_closed = 10,

    // Socket/Network (100-199)
    socket_create_failed = 100,
    socket_bind_failed = 101,
    socket_listen_failed = 102,
    socket_connect_failed = 103,
    socket_read_failed = 104,
    socket_write_failed = 105,
    socket_closed = 106,
    socket_eof = 107,
    network_bind_failed = 110,
    network_io_error = 111,

    // Protocol (200-299)
    protocol_invalid_version = 200,
    protocol_invalid_command = 201,
    protocol_invalid_address = 202,
    protocol_auth_failed = 203,
    protocol_decode_failed = 204,
    protocol_encode_failed = 205,
    protocol_unsupported = 206,

    // Router (300-399)
    router_no_match = 300,
    router_outbound_not_found = 301,
    router_invalid_rule = 302,
    blocked = 303,

    // Dial (400-499)
    dial_dns_failed = 400,
    dial_connect_failed = 401,
    dial_timeout = 402,
    dial_refused = 403,
    dial_network_unreachable = 404,
    dial_host_unreachable = 405,
    outbound_connection_failed = 406,

    // Relay (500-549)
    relay_read_failed = 500,
    relay_write_failed = 501,
    relay_timeout = 502,
    relay_client_closed = 503,
    relay_target_closed = 504,

    // Sniff (550-599)
    sniff_failed = 550,
    sniff_timeout = 551,
    sniff_unsupported = 552,
    sniff_incomplete = 553,

    // TLS (600-699)
    tls_handshake_failed = 600,
    tls_cert_invalid = 601,
    tls_version_mismatch = 602,
    tls_verify_failed = 603,
    tls_alert_received = 604,

    // VMess (700-799)
    vmess_invalid_user = 700,
    vmess_invalid_request = 701,
    vmess_timestamp_expired = 702,
    vmess_replay_attack = 703,
    vmess_checksum_mismatch = 704,
    vmess_invalid_response = 705,

    // DNS (800-899)
    dns_resolve_failed = 800,
    dns_timeout = 801,
    dns_no_record = 802,
    dns_server_failed = 803,
    dns_format_error = 804,
    dns_refused = 805,

    // Panel (900-999)
    panel_api_failed = 900,
    panel_auth_failed = 901,
    panel_node_not_found = 902,
    panel_user_not_found = 903,
    panel_user_disabled = 904,
    panel_traffic_exceeded = 905,
    panel_rate_limited = 906,
    panel_invalid_response = 907,
    panel_network_error = 908,

    pub fn isOk(self: ErrorCode) bool {
        return self == .ok;
    }

    pub fn isTimeout(self: ErrorCode) bool {
        return self == .timeout or self == .dial_timeout or
            self == .relay_timeout or self == .sniff_timeout or
            self == .dns_timeout;
    }

    pub fn isClosed(self: ErrorCode) bool {
        return self == .socket_closed or self == .socket_eof or
            self == .relay_client_closed or self == .relay_target_closed;
    }
};

// ============================================================================
// Defaults (from C++ defaults.hpp)
// ============================================================================

pub const defaults = struct {
    // Buffer sizes
    pub const buffer_size: usize = 24 * 1024; // 24KB
    pub const max_header_size: usize = 4 * 1024; // 4KB

    // Timeouts (seconds)
    pub const handshake_timeout: u32 = 4;
    pub const dial_timeout: u32 = 10;
    pub const read_timeout: u32 = 15;
    pub const write_timeout: u32 = 30;
    pub const idle_timeout: u32 = 300;
    pub const uplink_only_timeout: u32 = 2;
    pub const downlink_only_timeout: u32 = 5;

    // Connection pressure
    pub const max_connections_per_worker: u32 = 10000;
    pub const pressure_percent: u32 = 75;
    pub const pressure_idle_timeout: u32 = 60;

    // DNS
    pub const dns_timeout: u32 = 5;
    pub const dns_cache_size: u32 = 10000;
    pub const dns_min_ttl: u32 = 60;
    pub const dns_max_ttl: u32 = 3600;

    // Panel
    pub const panel_pull_interval: u32 = 60;
    pub const panel_push_interval: u32 = 60;
    pub const panel_config_refresh_interval: u32 = 300;

    // Stats
    pub const stats_output_interval: u32 = 10;
};

// ============================================================================
// Utility
// ============================================================================

pub fn formatBytes(value: u64, buf: []u8) []const u8 {
    const units = [_][]const u8{ "B", "KB", "MB", "GB", "TB" };
    var unit_index: usize = 0;
    var scaled = @as(f64, @floatFromInt(value));
    while (scaled >= 1024.0 and unit_index + 1 < units.len) {
        scaled /= 1024.0;
        unit_index += 1;
    }
    if (unit_index == 0) {
        return std.fmt.bufPrint(buf, "{d}{s}", .{ value, units[unit_index] }) catch "0B";
    }
    return std.fmt.bufPrint(buf, "{d:.2}{s}", .{ scaled, units[unit_index] }) catch "0B";
}
