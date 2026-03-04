const std = @import("std");
const config = @import("infra/config.zig");
const server = @import("app/handler.zig");

// Crypto modules (aws-lc backed) — referenced to force analysis
pub const crypto = struct {
    pub const bindings = @import("infra/crypto/bindings.zig");
    pub const hash = @import("infra/crypto/hash.zig");
    pub const hmac = @import("infra/crypto/hmac.zig");
    pub const aead = @import("infra/crypto/aead.zig");
    pub const kdf = @import("infra/crypto/kdf.zig");
    pub const hkdf = @import("infra/crypto/hkdf.zig");
    pub const evp = @import("infra/crypto/evp_bytes_to_key.zig");
    pub const ecb = @import("infra/crypto/aes_ecb.zig");
    pub const shake = @import("infra/crypto/shake.zig");
    pub const rand = @import("infra/crypto/rand.zig");
};

// Transport modules
pub const transport = struct {
    pub const tls_context = @import("transport/tls/context.zig");
    pub const tls_stream = @import("transport/tls/stream.zig");
    pub const ws_frame = @import("transport/ws/frame.zig");
    pub const ws_stream = @import("transport/ws/stream.zig");
    pub const ws_handshake = @import("transport/ws/handshake.zig");
    pub const proxy_protocol = @import("transport/proxy_protocol.zig");
    pub const stream = @import("transport/stream.zig");
    pub const stack = @import("transport/stack.zig");
};

// Protocol modules
pub const protocol = struct {
    pub const trojan_codec = @import("protocol/trojan/codec.zig");
    pub const trojan_user_manager = @import("protocol/trojan/user_manager.zig");
    pub const trojan_inbound = @import("protocol/trojan/inbound.zig");
    pub const trojan_outbound = @import("protocol/trojan/outbound.zig");
    pub const ss_protocol = @import("protocol/shadowsocks/protocol.zig");
    pub const ss_stream = @import("protocol/shadowsocks/stream.zig");
    pub const ss_user_manager = @import("protocol/shadowsocks/user_manager.zig");
    pub const ss_inbound = @import("protocol/shadowsocks/inbound.zig");
    pub const ss_outbound = @import("protocol/shadowsocks/outbound.zig");
    pub const vmess_crypto = @import("protocol/vmess/crypto.zig");
    pub const vmess_stream = @import("protocol/vmess/stream.zig");
    pub const vmess_user_manager = @import("protocol/vmess/user_manager.zig");
    pub const vmess_inbound = @import("protocol/vmess/inbound.zig");
    pub const vmess_outbound = @import("protocol/vmess/outbound.zig");
    pub const mux_codec = @import("protocol/mux/codec.zig");
};

// Route + Sniff + DNS
pub const route = struct {
    pub const router = @import("route/router.zig");
    pub const geodata = @import("route/geodata.zig");
};
pub const sniff = struct {
    pub const sniffer = @import("sniff/sniffer.zig");
};
pub const dns = struct {
    pub const dns_packet = @import("dns/packet.zig");
    pub const dns_cache = @import("dns/cache.zig");
    pub const dns_service = @import("dns/service.zig");
};

// App modules
pub const app = struct {
    pub const panel_sync = @import("app/panel_sync.zig");
    pub const relay = @import("app/relay.zig");
    pub const stats = @import("app/stats.zig");
    pub const session_ctx = @import("app/session.zig");
    pub const rate_limiter = @import("app/rate_limiter.zig");
    pub const worker = @import("app/worker.zig");
    pub const udp_session = @import("app/udp_session.zig");
    pub const mux_relay = @import("app/mux_relay.zig");
};

// Outbound
pub const outbound = struct {
    pub const registry = @import("outbound/registry.zig");
};

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var args = try std.process.argsWithAllocator(gpa);
    defer args.deinit();

    _ = args.next();
    var config_path: []const u8 = "config";

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printHelp();
            return;
        }
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (args.next()) |v| {
                config_path = v;
            } else {
                printHelp();
                return;
            }
        }
    }

    const cfg = try config.loadFromPath(arena, config_path);
    std.log.info("znode 启动: workers={d} inbounds={d} outbounds={d} default_outbound={s}", .{
        cfg.workers,
        cfg.inbounds.len,
        cfg.outbounds.len,
        cfg.routing.default_outbound,
    });

    try server.run(arena, &cfg);
}

fn printHelp() void {
    std.debug.print(
        \\Usage: znode [options]
        \\  -c, --config <path>   Config file or directory (default: config)
        \\  -h, --help            Show help
        \\
    , .{});
}
