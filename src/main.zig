const std = @import("std");
const zio = @import("zio");
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

const log = @import("infra/log.zig");

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

    // 默认基础目录 = 二进制所在目录
    var exe_dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = std.fs.selfExePath(&exe_dir_buf) catch "znode";
    const exe_dir = std.fs.path.dirname(exe_path) orelse ".";
    var base_dir: []const u8 = exe_dir;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printHelp();
            return;
        }
        if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--dir")) {
            if (args.next()) |v| {
                base_dir = v;
            } else {
                printHelp();
                return;
            }
        }
    }

    const config_path = try std.fs.path.join(arena, &.{ base_dir, "config" });
    std.log.info("znode 启动: base={s} config={s}", .{ base_dir, config_path });

    const cfg = try config.loadFromPath(arena, config_path);

    // 解析日志目录：相对路径基于 base_dir
    const log_dir = if (cfg.log.log_dir.len > 0 and !std.fs.path.isAbsolute(cfg.log.log_dir))
        try std.fs.path.join(arena, &.{ base_dir, cfg.log.log_dir })
    else if (cfg.log.log_dir.len > 0)
        cfg.log.log_dir
    else
        try std.fs.path.join(arena, &.{ base_dir, "log" });

    // 自动创建日志目录
    std.fs.cwd().makePath(log_dir) catch |err| {
        std.log.warn("创建日志目录失败: {s} err={s}", .{ log_dir, @errorName(err) });
    };

    try log.initGlobal(log_dir, log.Level.fromString(cfg.log.level), cfg.log.max_days);

    std.log.info("workers={d} inbounds={d} outbounds={d} log={s}", .{
        cfg.workers,
        cfg.inbounds.len,
        cfg.outbounds.len,
        log_dir,
    });

    // Initialize zio runtime — fiber-per-connection event loop
    var rt = try zio.Runtime.init(gpa, .{
        .executors = .exact(@intCast(cfg.workers)),
    });
    // 注意: 不 defer rt.deinit() — 服务器永久运行，
    // 异常退出时 detached fibers 仍在运行，deinit 会导致 allocator crash。
    // OS 进程退出时自动回收所有资源。

    // Run server inside a zio fiber (all I/O must be fiber-context)
    var handle = try rt.spawn(server.run, .{ arena, &cfg });
    handle.join() catch |err| {
        std.log.err("server.run 异常退出: {s}", .{@errorName(err)});
    };

    // 正常情况下不应到达这里（listener fibers 永久运行）
    std.log.err("server.run 意外返回，程序即将退出", .{});
}

fn printHelp() void {
    std.debug.print(
        \\Usage: znode [options]
        \\  -d, --dir <path>      Base directory (default: binary location)
        \\                        Config loaded from <dir>/config/
        \\  -h, --help            Show help
        \\
    , .{});
}
