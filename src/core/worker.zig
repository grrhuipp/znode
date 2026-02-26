const std = @import("std");
const config_mod = @import("config.zig");
const tls_mod = @import("../transport/tls_stream.zig");
const user_store_mod = @import("user_store.zig");
const vmess_hot_cache = @import("../protocol/vmess/vmess_hot_cache.zig");

/// Worker namespace — retained for ListenerInfo type definitions used by
/// dispatcher, session_handler, and main.zig.
pub const Worker = struct {
    pub const ListenerInfo = struct {
        protocol: config_mod.Protocol = .vmess,
        tls_enabled: bool = false,
        send_through_addr: ?std.net.Address = null,
        fallback_addr: ?std.net.Address = null,
        // Multi-level fallbacks (path/ALPN conditional)
        fallbacks: [config_mod.max_fallbacks]config_mod.FallbackEntry = [_]config_mod.FallbackEntry{.{}} ** config_mod.max_fallbacks,
        fallback_count: u8 = 0,
        tag_buf: [64]u8 = [_]u8{0} ** 64,
        tag_len: u8 = 0,
        // Per-panel context (set by main.zig for each panel's listener)
        tls_ctx: ?*tls_mod.TlsContext = null,
        user_store: ?*user_store_mod.UserStore = null,
        // VMess hot user cache (per-listener isolation for multi-panel)
        hot_cache: vmess_hot_cache.HotCache = vmess_hot_cache.HotCache.init(vmess_hot_cache.HotCache.default_ttl),
        // Shadowsocks inbound credentials (optional, set when protocol == .shadowsocks)
        ss_inbound: ?SsInbound = null,
        // Sniff: detect TLS SNI / HTTP Host from initial payload
        sniff_enabled: bool = true,
        sniff_redirect: bool = true,
        // Transport: tcp (default), ws, wss
        transport: config_mod.Transport = .tcp,
        // WebSocket path (only used when transport == .ws or .wss)
        ws_path_buf: [128]u8 = [_]u8{0} ** 128,
        ws_path_len: u8 = 0,
        // Routing: whether to use route rules for this listener
        enable_routing: bool = false,

        pub const SsInbound = struct {
            psk: [32]u8,
            method: u8,
            key_len: u8,
        };

        pub fn getTag(self: *const ListenerInfo) []const u8 {
            return self.tag_buf[0..self.tag_len];
        }

        pub fn getWsPath(self: *const ListenerInfo) []const u8 {
            if (self.ws_path_len == 0) return "/";
            return self.ws_path_buf[0..self.ws_path_len];
        }
    };
};
