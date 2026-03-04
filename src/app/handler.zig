/// Connection handler — multi-protocol inbound/outbound pipeline.
///
/// Supports Trojan, VMess, Shadowsocks inbound protocols.
/// Supports Freedom, Blackhole, Trojan, VMess, Shadowsocks outbound protocols.
/// Pipeline: accept → proxy protocol → protocol parse → sniff → route → dial → outbound handshake → relay.
const std = @import("std");
const zio = @import("zio");

const config = @import("../infra/config.zig");
const types = @import("../common/types.zig");
const log = @import("../infra/log.zig");
const router_mod = @import("../route/router.zig");
const outbound_mod = @import("../outbound/registry.zig");
const stats_mod = @import("stats.zig");
const relay_mod = @import("relay.zig");
const session_mod = @import("session.zig");
const sniffer = @import("../sniff/sniffer.zig");
const panel_sync = @import("panel_sync.zig");
const proxy_protocol = @import("../transport/proxy_protocol.zig");

// Protocol inbound handlers
const trojan_inbound = @import("../protocol/trojan/inbound.zig");
const trojan_um = @import("../protocol/trojan/user_manager.zig");
const vmess_inbound = @import("../protocol/vmess/inbound.zig");
const vmess_um = @import("../protocol/vmess/user_manager.zig");
const ss_inbound = @import("../protocol/shadowsocks/inbound.zig");
const ss_um = @import("../protocol/shadowsocks/user_manager.zig");
const ss_protocol = @import("../protocol/shadowsocks/protocol.zig");

// Protocol outbound handlers
const trojan_outbound = @import("../protocol/trojan/outbound.zig");
const vmess_outbound = @import("../protocol/vmess/outbound.zig");
const ss_outbound = @import("../protocol/shadowsocks/outbound.zig");

// Protocol stream wrappers
const vmess_stream_mod = @import("../protocol/vmess/stream.zig");
const ss_stream_mod = @import("../protocol/shadowsocks/stream.zig");
const vmess_crypto = @import("../protocol/vmess/crypto.zig");
const aead_mod = @import("../infra/crypto/aead.zig");
const TcpStream = @import("../transport/stream.zig").TcpStream;

const StreamAdapter = relay_mod.StreamAdapter;

// ── PrefixedStream: 预读缓冲 + 真实流 ─────────────────────────────────────
/// 把 proxy protocol 检测阶段预读的数据放在前面，读完后透传到底层 stream。
/// 实现 read/write/writeAll 接口，可直接传给 protocol parseStream (comptime Transport)。
pub const PrefixedStream = struct {
    inner: TcpStream,
    pending: [2048]u8 = undefined,
    pending_len: usize = 0,
    pending_pos: usize = 0,

    pub fn init(inner: TcpStream, pending_data: []const u8) PrefixedStream {
        var s = PrefixedStream{ .inner = inner };
        const len = @min(pending_data.len, s.pending.len);
        @memcpy(s.pending[0..len], pending_data[0..len]);
        s.pending_len = len;
        return s;
    }

    pub fn read(self: *PrefixedStream, buf: []u8) !usize {
        // 先从 pending 读
        if (self.pending_pos < self.pending_len) {
            const avail = self.pending_len - self.pending_pos;
            const n = @min(avail, buf.len);
            @memcpy(buf[0..n], self.pending[self.pending_pos..][0..n]);
            self.pending_pos += n;
            return n;
        }
        // pending 读完，转到底层
        return self.inner.read(buf);
    }

    pub fn write(self: *PrefixedStream, data: []const u8) !usize {
        return self.inner.write(data);
    }

    pub fn writeAll(self: *PrefixedStream, data: []const u8) !void {
        return self.inner.writeAll(data);
    }

    pub fn close(self: *PrefixedStream) void {
        self.inner.close();
    }

    /// 是否还有 pending 数据未读
    pub fn hasPending(self: *const PrefixedStream) bool {
        return self.pending_pos < self.pending_len;
    }
};

const ProtocolKind = enum {
    trojan,
    vmess,
    shadowsocks,
    unsupported,
};

/// Per-inbound runtime state built from config.
const InboundRuntime = struct {
    tag: []const u8,
    protocol: ProtocolKind,
    listen: []const u8,
    port: u16,
    fixed_outbound: ?[]const u8,
    sniff_enabled: bool,
    sniff_override: bool,
    handler: InboundHandler,
};

const InboundHandler = union(enum) {
    trojan: TrojanCtx,
    vmess: VMessCtx,
    ss: SsCtx,
    none: void,
};

const TrojanCtx = struct {
    user_manager: trojan_um.UserManager,
};

const VMessCtx = struct {
    user_manager: vmess_um.UserManager,
};

const SsCtx = struct {
    user_manager: ss_um.UserManager,
};

const Runtime = struct {
    allocator: std.mem.Allocator,
    router: router_mod.Router,
    outbounds: outbound_mod.Manager,
    stats: stats_mod.ShardedStats,
    timeouts: config.TimeoutsConfig,
    tracker: panel_sync.TrafficTracker,
};

pub fn run(allocator: std.mem.Allocator, cfg: *const config.Config) !void {
    var runtime = Runtime{
        .allocator = allocator,
        .router = try router_mod.Router.init(allocator, cfg.routing),
        .outbounds = try outbound_mod.Manager.init(allocator, cfg.outbounds),
        .stats = try stats_mod.ShardedStats.init(allocator, cfg.workers),
        .timeouts = cfg.timeouts,
        .tracker = panel_sync.TrafficTracker.init(allocator),
    };

    const logger = log.getLogger();

    // Merge static inbounds with panel-generated inbounds
    var all_inbound_cfgs = std.array_list.Managed(config.InboundConfig).init(allocator);
    for (cfg.inbounds) |item| {
        try all_inbound_cfgs.append(item);
    }

    // Panel initial sync: fetch node configs + users → generate inbounds
    if (cfg.panels.len > 0) {
        var sync = panel_sync.PanelSyncManager.init(allocator, cfg.panels, &runtime.tracker);
        const panel_inbounds = sync.initialSync() catch |err| blk: {
            logger.console("面板初始同步失败: {s}", .{@errorName(err)});
            break :blk &[_]config.InboundConfig{};
        };
        for (panel_inbounds) |item| {
            try all_inbound_cfgs.append(item);
        }
        // Start background sync loop for periodic user/traffic updates
        sync.start();
    }

    const inbounds = try buildInbounds(allocator, try all_inbound_cfgs.toOwnedSlice());

    // Stats fiber
    var stats_handle = zio.spawn(statsLoop, .{&runtime}) catch {
        logger.console("统计 fiber 启动失败", .{});
        return error.FiberSpawnFailed;
    };
    stats_handle.detach();

    if (inbounds.len == 0) {
        logger.console("没有 inbound 监听器，等待面板同步...", .{});
        while (true) {
            zio.sleep(zio.time.Duration.fromSeconds(60)) catch break;
        }
        return;
    }

    // Spawn listener fibers — each inbound × workers个 fiber (SO_REUSEPORT)
    const workers: usize = @intCast(cfg.workers);
    const max_fibers = inbounds.len * workers;
    var handles = try allocator.alloc(zio.JoinHandle(void), max_fibers);
    var handle_count: usize = 0;

    for (inbounds) |*inbound| {
        if (inbound.protocol == .unsupported) continue;
        var w: usize = 0;
        while (w < workers) : (w += 1) {
            handles[handle_count] = zio.spawn(listenerFiber, .{ &runtime, inbound, w }) catch {
                logger.console("监听 fiber 启动失败: tag={s} worker={d}", .{ inbound.tag, w });
                continue;
            };
            handle_count += 1;
        }
        logger.console("监听启动: tag={s} protocol={s} {s}:{d} workers={d}", .{
            inbound.tag,
            @tagName(inbound.protocol),
            inbound.listen,
            inbound.port,
            workers,
        });
    }

    if (handle_count == 0) {
        logger.console("没有可用的 inbound 监听器", .{});
        while (true) {
            zio.sleep(zio.time.Duration.fromSeconds(60)) catch break;
        }
        return;
    }

    for (handles[0..handle_count]) |*h| {
        h.join();
    }
}

// ── Inbound construction ─────────────────────────────────────────────────

fn buildInbounds(
    allocator: std.mem.Allocator,
    inbounds_cfg: []const config.InboundConfig,
) ![]InboundRuntime {
    var list = std.array_list.Managed(InboundRuntime).init(allocator);
    const logger = log.getLogger();

    for (inbounds_cfg) |item| {
        const kind: ProtocolKind = if (std.ascii.eqlIgnoreCase(item.protocol, "trojan"))
            .trojan
        else if (std.ascii.eqlIgnoreCase(item.protocol, "vmess"))
            .vmess
        else if (std.ascii.eqlIgnoreCase(item.protocol, "shadowsocks") or
            std.ascii.eqlIgnoreCase(item.protocol, "ss"))
            .shadowsocks
        else
            .unsupported;

        if (kind == .unsupported) {
            logger.app(.warn, "忽略未实现入站协议: tag={s} protocol={s}", .{
                item.tag,
                item.protocol,
            });
            continue;
        }

        const handler = try buildHandler(allocator, kind, item.clients, item.protocol);

        try list.append(.{
            .tag = item.tag,
            .protocol = kind,
            .listen = item.listen,
            .port = item.port,
            .fixed_outbound = item.outbound_tag,
            .sniff_enabled = item.sniff.enabled,
            .sniff_override = item.sniff.override_dest,
            .handler = handler,
        });
    }

    return try list.toOwnedSlice();
}

fn buildHandler(
    allocator: std.mem.Allocator,
    kind: ProtocolKind,
    clients: []const config.ClientConfig,
    protocol_str: []const u8,
) !InboundHandler {
    const logger = log.getLogger();

    switch (kind) {
        .trojan => {
            var um = trojan_um.UserManager.init(allocator);
            var synthetic_id: i64 = 1;
            for (clients) |client| {
                if (client.password.len == 0) continue;
                const uid = if (client.user_id > 0) client.user_id else synthetic_id;
                if (client.user_id <= 0) synthetic_id += 1;
                const speed = speedLimitBytes(client.speed_limit_mbps);
                try um.addUser(allocator, client.password, uid, client.email, speed);
            }
            logger.app(.info, "Trojan 用户: {d}", .{um.count()});
            return .{ .trojan = .{ .user_manager = um } };
        },
        .vmess => {
            var users = std.array_list.Managed(vmess_um.VMessUser).init(allocator);
            var synthetic_id: i64 = 1;
            for (clients) |client| {
                if (client.password.len == 0) continue;
                const uid = if (client.user_id > 0) client.user_id else synthetic_id;
                if (client.user_id <= 0) synthetic_id += 1;
                const speed = speedLimitBytes(client.speed_limit_mbps);
                const user = vmess_um.UserManager.createUser(
                    client.password,
                    uid,
                    client.email,
                    speed,
                ) catch {
                    logger.app(.warn, "无效 VMess UUID: email={s}", .{client.email});
                    continue;
                };
                try users.append(user);
            }
            const user_slice = try users.toOwnedSlice();
            logger.app(.info, "VMess 用户: {d}", .{user_slice.len});
            return .{ .vmess = .{ .user_manager = vmess_um.UserManager.init(user_slice) } };
        },
        .shadowsocks => {
            const cipher_info = ss_protocol.CipherInfo.fromString(protocol_str) orelse
                ss_protocol.CipherInfo.fromString("aes-128-gcm").?;

            var ss_users = std.array_list.Managed(ss_um.UserInfo).init(allocator);
            var synthetic_id: i64 = 1;
            for (clients) |client| {
                if (client.password.len == 0) continue;
                const uid = if (client.user_id > 0) client.user_id else synthetic_id;
                if (client.user_id <= 0) synthetic_id += 1;
                const speed = speedLimitBytes(client.speed_limit_mbps);
                var info = ss_um.UserInfo{
                    .user_id = uid,
                    .email = client.email,
                    .speed_limit_bytes = speed,
                    .cipher_info = cipher_info,
                    .master_key = undefined,
                    .master_key_len = cipher_info.key_len,
                };
                ss_protocol.deriveMasterKey(
                    client.password,
                    cipher_info.key_len,
                    &info.master_key,
                ) catch {
                    logger.app(.warn, "SS 密钥派生失败: email={s}", .{client.email});
                    continue;
                };
                try ss_users.append(info);
            }
            const user_slice = try ss_users.toOwnedSlice();
            logger.app(.info, "Shadowsocks 用户: {d}", .{user_slice.len});
            return .{ .ss = .{ .user_manager = ss_um.UserManager.init(user_slice) } };
        },
        .unsupported => return .{ .none = {} },
    }
}

fn speedLimitBytes(mbps: i64) u64 {
    if (mbps <= 0) return 0;
    return @as(u64, @intCast(mbps)) * 1024 * 1024 / 8;
}

// ── Listener ─────────────────────────────────────────────────────────────

fn listenerFiber(runtime: *Runtime, inbound: *const InboundRuntime, worker_id: usize) void {
    const logger = log.getLogger();
    listenerLoop(runtime, inbound, worker_id) catch |err| {
        logger.console("监听 fiber 异常退出: tag={s} worker={d} err={s}", .{ inbound.tag, worker_id, @errorName(err) });
    };
}

fn listenerLoop(runtime: *Runtime, inbound: *const InboundRuntime, worker_id: usize) !void {
    const logger = log.getLogger();
    const address = try zio.net.IpAddress.parseIp(inbound.listen, inbound.port);

    // 手动创建 socket: SO_REUSEADDR + SO_REUSEPORT → bind → listen
    // 每个 worker 独立 listener，内核负载均衡分发连接
    var socket = try zio.net.Socket.open(.stream, .fromPosix(address.any.family), .ip);
    errdefer socket.close();
    try socket.setReuseAddress(true);
    try socket.setReusePort(true);
    try socket.bind(.{ .ip = address });
    try socket.listen(1024);
    var server = zio.net.Server{ .socket = socket };
    defer server.close();

    logger.app(.info, "worker 监听就绪: tag={s} worker={d} {s}:{d}", .{
        inbound.tag,
        worker_id,
        inbound.listen,
        inbound.port,
    });

    while (true) {
        const stream = server.accept() catch |err| {
            logger.app(.warn, "accept 失败: tag={s} worker={d} err={s}", .{ inbound.tag, worker_id, @errorName(err) });
            continue;
        };

        const shard = runtime.stats.getShard(@intCast(worker_id));
        shard.onAccepted();
        var handle = zio.spawn(handleConnectionFiber, .{ runtime, inbound, stream }) catch |err| {
            shard.onClosed();
            shard.onError();
            stream.close();
            logger.app(.warn, "fiber 派发失败: tag={s} worker={d} err={s}", .{ inbound.tag, worker_id, @errorName(err) });
            continue;
        };
        handle.detach();
    }
}

// ── Connection dispatch ──────────────────────────────────────────────────

fn handleConnectionFiber(
    runtime: *Runtime,
    inbound: *const InboundRuntime,
    raw: zio.net.Stream,
) void {
    const shard = runtime.stats.getShard(0);
    defer shard.onClosed();

    // Create session context and extract client IP + port
    var session_ctx = session_mod.SessionContext.init();
    session_ctx.setInboundTag(inbound.tag);
    extractClientAddr(&session_ctx, raw.socket.address.toStd());

    const logger = log.getLogger();
    var pfx = connPrefix(&session_ctx);

    logger.access("{s} ACCEPTED protocol={s}", .{ pfx.str(), @tagName(inbound.protocol) });

    // ── Proxy Protocol 自动检测 ─────────────────────────────────────────
    var peek_buf: [2048]u8 = undefined;
    var peek_len: usize = 0;
    var tcp_stream = TcpStream.init(raw);

    // 读第一块数据
    peek_len = tcp_stream.read(&peek_buf) catch |err| {
        logger.access("{s} FIRST_READ_ERROR err={s}", .{ pfx.str(), @errorName(err) });
        tcp_stream.close();
        return;
    };
    if (peek_len == 0) {
        logger.access("{s} EMPTY_CONN (0 bytes received, client closed immediately)", .{pfx.str()});
        tcp_stream.close();
        return;
    }

    // 记录收到的首包数据摘要
    var first_hex_buf: [96]u8 = undefined;
    const first_hex = hexDump(peek_buf[0..@min(peek_len, 32)], &first_hex_buf);
    logger.access("{s} FIRST_READ {d}bytes hex=[{s}]", .{ pfx.str(), peek_len, first_hex });

    const pp_result = proxy_protocol.parse(peek_buf[0..peek_len]);
    var pp_consumed: usize = 0;

    switch (pp_result.status) {
        .success => {
            pp_consumed = pp_result.consumed;
            if (pp_result.src_ip_len > 0) {
                session_ctx.setClientIp(pp_result.srcIp());
                session_ctx.client_port = pp_result.src_port;
                // 更新前缀
                pfx = connPrefix(&session_ctx);
                logger.access("{s} PROXY_PROTOCOL_OK real_ip={s}:{d} consumed={d}bytes", .{
                    pfx.str(),
                    pp_result.srcIp(),
                    pp_result.src_port,
                    pp_consumed,
                });
            } else {
                logger.access("{s} PROXY_PROTOCOL_OK (LOCAL/unknown) consumed={d}bytes", .{ pfx.str(), pp_consumed });
            }
        },
        .not_proxy => {
            // 不是 proxy protocol，所有数据回流
            pp_consumed = 0;
            logger.access("{s} PROXY_PROTOCOL_SKIP (not proxy protocol header)", .{pfx.str()});
        },
        .incomplete => {
            logger.access("{s} PROXY_PROTOCOL_INCOMPLETE (partial match, reading more)", .{pfx.str()});
            // 部分匹配但不完整 — 尝试再读一次
            if (tcp_stream.read(peek_buf[peek_len..])) |n2| {
                peek_len += n2;
                logger.access("{s} PROXY_PROTOCOL_RETRY total={d}bytes", .{ pfx.str(), peek_len });
                const pp2 = proxy_protocol.parse(peek_buf[0..peek_len]);
                if (pp2.status == .success) {
                    pp_consumed = pp2.consumed;
                    if (pp2.src_ip_len > 0) {
                        session_ctx.setClientIp(pp2.srcIp());
                        session_ctx.client_port = pp2.src_port;
                        pfx = connPrefix(&session_ctx);
                        logger.access("{s} PROXY_PROTOCOL_OK real_ip={s}:{d} consumed={d}bytes", .{
                            pfx.str(),
                            pp2.srcIp(),
                            pp2.src_port,
                            pp_consumed,
                        });
                    }
                } else {
                    logger.access("{s} PROXY_PROTOCOL_RETRY_FAILED status={s}", .{ pfx.str(), @tagName(pp2.status) });
                }
                // 其他情况 pp_consumed 保持 0，当做非 proxy protocol
            } else |err| {
                logger.access("{s} PROXY_PROTOCOL_RETRY_READ_ERROR err={s}", .{ pfx.str(), @errorName(err) });
                // 读不到更多，当做非 proxy protocol
            }
        },
        .invalid => {
            logger.access("{s} PROXY_PROTOCOL_INVALID closing", .{pfx.str()});
            tcp_stream.close();
            return;
        },
    }

    // 构建 PrefixedStream（剩余未消费的 peek 数据作为 pending）
    const remaining = peek_buf[pp_consumed..peek_len];
    var client_stream = PrefixedStream.init(tcp_stream, remaining);
    defer client_stream.close();

    // 记录分发到协议层的数据摘要
    var dispatch_hex_buf: [96]u8 = undefined;
    const dispatch_hex = hexDump(remaining[0..@min(remaining.len, 32)], &dispatch_hex_buf);
    logger.access("{s} DISPATCH protocol={s} pending={d}bytes hex=[{s}]", .{
        pfx.str(),
        @tagName(inbound.protocol),
        remaining.len,
        dispatch_hex,
    });

    switch (inbound.handler) {
        .trojan => |*ctx| handleTrojan(runtime, inbound, ctx, &client_stream, shard, &session_ctx, &pfx),
        .vmess => |*ctx| handleVMess(runtime, inbound, ctx, &client_stream, shard, &session_ctx, &pfx),
        .ss => |*ctx| handleSs(runtime, inbound, ctx, &client_stream, shard, &session_ctx, &pfx),
        .none => {
            logger.access("{s} NO_HANDLER (unsupported protocol)", .{pfx.str()});
            shard.onError();
        },
    }
}

// ── 辅助工具 ────────────────────────────────────────────────────────────

/// 将字节数据格式化为 hex 字符串（空格分隔），用于调试日志。
fn hexDump(data: []const u8, buf: []u8) []const u8 {
    const hex = "0123456789abcdef";
    const max_bytes = @min(data.len, buf.len / 3);
    var pos: usize = 0;
    for (data[0..max_bytes], 0..) |b, i| {
        if (i > 0 and pos < buf.len) {
            buf[pos] = ' ';
            pos += 1;
        }
        if (pos + 2 > buf.len) break;
        buf[pos] = hex[b >> 4];
        pos += 1;
        buf[pos] = hex[b & 0x0f];
        pos += 1;
    }
    return buf[0..pos];
}

/// 计算两个微秒时间戳之间的毫秒差。
fn stageDurationMs(start_us: i64, end_us: i64) i64 {
    if (end_us <= 0 or start_us <= 0) return 0;
    return @divTrunc(end_us - start_us, 1000);
}

// ── 统一日志前缀 ─────────────────────────────────────────────────────────

const ConnPrefix = struct {
    buf: [128]u8 = undefined,
    len: usize = 0,

    pub fn str(self: *const ConnPrefix) []const u8 {
        return self.buf[0..self.len];
    }
};

/// 生成统一连接日志前缀: [ip:port][conn=N][tag=T]
fn connPrefix(ctx: *const session_mod.SessionContext) ConnPrefix {
    var p = ConnPrefix{};
    const s = std.fmt.bufPrint(&p.buf, "[{s}:{d}][conn={d}][tag={s}]", .{
        ctx.clientIp(),
        ctx.client_port,
        ctx.conn_id,
        ctx.inboundTag(),
    }) catch "";
    p.len = s.len;
    return p;
}

/// Extract client IP + port from std.net.Address into SessionContext.
fn extractClientAddr(ctx: *session_mod.SessionContext, addr: std.net.Address) void {
    var buf: [46]u8 = undefined;
    switch (addr.any.family) {
        std.posix.AF.INET => {
            const a = addr.in.sa.addr;
            const ab = @as(*const [4]u8, @ptrCast(&a));
            const ip_str = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{
                ab[0], ab[1], ab[2], ab[3],
            }) catch return;
            ctx.setClientIp(ip_str);
            ctx.client_port = std.mem.bigToNative(u16, addr.in.sa.port);
        },
        std.posix.AF.INET6 => {
            const a = &addr.in6.sa.addr;
            const ip_str = std.fmt.bufPrint(&buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                a[0], a[1], a[2],  a[3],  a[4],  a[5],  a[6],  a[7],
                a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
            }) catch return;
            ctx.setClientIp(ip_str);
            ctx.client_port = std.mem.bigToNative(u16, addr.in6.sa.port);
        },
        else => {},
    }
}

// ── Trojan inbound ───────────────────────────────────────────────────────

fn handleTrojan(
    runtime: *Runtime,
    inbound: *const InboundRuntime,
    ctx: *const TrojanCtx,
    client_stream: *PrefixedStream,
    shard: *stats_mod.StatsShard,
    session_ctx: *session_mod.SessionContext,
    pfx: *const ConnPrefix,
) void {
    const logger = log.getLogger();

    const user_count = ctx.user_manager.count();
    logger.access("{s} TROJAN_AUTH_START users={d}", .{ pfx.str(), user_count });

    const handler = trojan_inbound.TrojanInboundHandler.init(&ctx.user_manager);
    const parsed = handler.parseStream(
        PrefixedStream,
        client_stream,
        session_ctx,
    ) catch |err| {
        shard.onError();
        var hdr_hex_buf: [170]u8 = undefined;
        const pending_data = client_stream.pending[0..client_stream.pending_len];
        const hdr_hex = hexDump(pending_data[0..@min(pending_data.len, 56)], &hdr_hex_buf);
        logger.connError("{s} AUTH_FAILED trojan err={s} users={d} pending_head=[{s}]", .{
            pfx.str(),
            @errorName(err),
            user_count,
            hdr_hex,
        });
        return;
    };

    logger.access("{s} AUTH_OK trojan user_id={d} email={s} cmd={s} initial_payload={d}bytes -> {s}:{d}", .{
        pfx.str(),
        session_ctx.user_id,
        if (session_ctx.user_email_len > 0) session_ctx.userEmail() else "-",
        @tagName(parsed.network),
        parsed.initial_payload.len,
        parsed.target.host(),
        parsed.target.port,
    });

    session_ctx.transitionTo(.sniffing);
    doSniff(inbound, session_ctx, parsed.initial_payload, parsed.target.port, pfx);
    session_ctx.transitionTo(.routing);

    // Trojan inbound: client stream is raw (encryption handled by TLS)
    var client_adapter = StreamAdapter.from(PrefixedStream, client_stream);
    doOutboundAndRelay(runtime, inbound, session_ctx, shard, &client_adapter, parsed.initial_payload, logger, pfx);
}

// ── VMess inbound ────────────────────────────────────────────────────────

fn handleVMess(
    runtime: *Runtime,
    inbound: *const InboundRuntime,
    ctx: *const VMessCtx,
    client_stream: *PrefixedStream,
    shard: *stats_mod.StatsShard,
    session_ctx: *session_mod.SessionContext,
    pfx: *const ConnPrefix,
) void {
    const logger = log.getLogger();

    const user_count = ctx.user_manager.users.len;
    logger.access("{s} VMESS_AUTH_START users={d} server_time={d}", .{
        pfx.str(),
        user_count,
        std.time.timestamp(),
    });

    const handler = vmess_inbound.VMessInboundHandler.init(&ctx.user_manager);
    const parsed = handler.parseStream(
        PrefixedStream,
        client_stream,
        session_ctx,
    ) catch |err| {
        shard.onError();
        // 获取 pending 数据的前 16 字节 (AuthID) 用于调试
        var auth_hex_buf: [96]u8 = undefined;
        const pending_data = client_stream.pending[0..client_stream.pending_len];
        const auth_hex = hexDump(pending_data[0..@min(pending_data.len, 16)], &auth_hex_buf);
        logger.connError("{s} AUTH_FAILED vmess err={s} users={d} pending_head=[{s}]", .{
            pfx.str(),
            @errorName(err),
            user_count,
            auth_hex,
        });
        return;
    };

    logger.access("{s} AUTH_OK vmess user_id={d} email={s} security={s} cmd={s} opt=0x{x:0>2} -> {s}:{d}", .{
        pfx.str(),
        session_ctx.user_id,
        if (session_ctx.user_email_len > 0) session_ctx.userEmail() else "-",
        @tagName(parsed.request.security),
        @tagName(parsed.request.command),
        parsed.request.options,
        session_ctx.target.host(),
        session_ctx.target.port,
    });

    // Send VMess AEAD response header
    logger.access("{s} VMESS_SEND_RESPONSE", .{pfx.str()});
    vmess_inbound.VMessInboundHandler.sendResponse(
        PrefixedStream,
        client_stream,
        &parsed.request,
    ) catch |err| {
        shard.onError();
        logger.connError("{s} VMESS_RESPONSE_SEND_FAILED err={s}", .{ pfx.str(), @errorName(err) });
        return;
    };
    logger.access("{s} VMESS_RESPONSE_SENT", .{pfx.str()});

    session_ctx.transitionTo(.routing);

    // Wrap client stream with VMessStream for AEAD chunk relay
    const cipher = parsed.request.security.toAeadCipher() orelse {
        // security=none/zero: relay raw
        logger.access("{s} VMESS_WRAP security=none/zero (raw relay)", .{pfx.str()});
        var client_adapter = StreamAdapter.from(PrefixedStream, client_stream);
        doOutboundAndRelay(runtime, inbound, session_ctx, shard, &client_adapter, &.{}, logger, pfx);
        return;
    };

    logger.access("{s} VMESS_WRAP cipher={s}", .{ pfx.str(), @tagName(cipher) });

    var vmess_client = vmess_stream_mod.VMessStream(PrefixedStream).init(
        client_stream.*,
        cipher,
        parsed.request.body_key,
        parsed.request.body_iv,
        parsed.request.response_key,
        parsed.request.response_iv,
        parsed.request.options,
    );
    var client_adapter = StreamAdapter.from(
        vmess_stream_mod.VMessStream(PrefixedStream),
        &vmess_client,
    );
    doOutboundAndRelay(runtime, inbound, session_ctx, shard, &client_adapter, &.{}, logger, pfx);
}

// ── Shadowsocks inbound ──────────────────────────────────────────────────

fn handleSs(
    runtime: *Runtime,
    inbound: *const InboundRuntime,
    ctx: *const SsCtx,
    client_stream: *PrefixedStream,
    shard: *stats_mod.StatsShard,
    session_ctx: *session_mod.SessionContext,
    pfx: *const ConnPrefix,
) void {
    const logger = log.getLogger();

    const user_count = ctx.user_manager.users.len;
    logger.access("{s} SS_AUTH_START users={d}", .{ pfx.str(), user_count });

    const handler = ss_inbound.SsInboundHandler.init(&ctx.user_manager);
    const parsed = handler.parseStream(
        PrefixedStream,
        client_stream,
        session_ctx,
    ) catch |err| {
        shard.onError();
        var salt_hex_buf: [96]u8 = undefined;
        const pending_data = client_stream.pending[0..client_stream.pending_len];
        const salt_hex = hexDump(pending_data[0..@min(pending_data.len, 32)], &salt_hex_buf);
        logger.connError("{s} AUTH_FAILED ss err={s} users={d} pending_head=[{s}]", .{
            pfx.str(),
            @errorName(err),
            user_count,
            salt_hex,
        });
        return;
    };

    logger.access("{s} AUTH_OK ss user_id={d} email={s} cipher={s} initial_payload={d}bytes -> {s}:{d}", .{
        pfx.str(),
        session_ctx.user_id,
        if (session_ctx.user_email_len > 0) session_ctx.userEmail() else "-",
        @tagName(parsed.cipher_type),
        parsed.initial_payload.len,
        parsed.target.host(),
        parsed.target.port,
    });

    session_ctx.transitionTo(.sniffing);
    doSniff(inbound, session_ctx, parsed.initial_payload, parsed.target.port, pfx);
    session_ctx.transitionTo(.routing);

    // Generate write subkey for server→client direction
    logger.access("{s} SS_KEYGEN generating write subkey", .{pfx.str()});
    var write_salt: [ss_protocol.max_salt_len]u8 = undefined;
    var write_subkey: [ss_protocol.max_key_len]u8 = undefined;
    ss_protocol.generateSalt(write_salt[0..parsed.read_subkey_len]) catch |err| {
        shard.onError();
        logger.connError("{s} SS_SALT_GEN_FAILED err={s}", .{ pfx.str(), @errorName(err) });
        return;
    };
    ss_protocol.deriveSessionKey(
        parsed.master_key[0..parsed.master_key_len],
        write_salt[0..parsed.read_subkey_len],
        write_subkey[0..parsed.read_subkey_len],
    ) catch |err| {
        shard.onError();
        logger.connError("{s} SS_SUBKEY_DERIVE_FAILED err={s}", .{ pfx.str(), @errorName(err) });
        return;
    };

    // Wrap client stream with SsStream for AEAD chunk relay
    logger.access("{s} SS_WRAP cipher={s}", .{ pfx.str(), @tagName(parsed.cipher_type) });
    var ss_client = ss_stream_mod.SsStream(PrefixedStream).init(
        client_stream.*,
        parsed.cipher_type,
        parsed.read_subkey[0..parsed.read_subkey_len],
        write_subkey[0..parsed.read_subkey_len],
        write_salt[0..parsed.read_subkey_len],
    );
    ss_client.read_nonce_counter = parsed.first_chunk_nonce;

    var client_adapter = StreamAdapter.from(
        ss_stream_mod.SsStream(PrefixedStream),
        &ss_client,
    );
    doOutboundAndRelay(runtime, inbound, session_ctx, shard, &client_adapter, parsed.initial_payload, logger, pfx);
}

// ── Shared pipeline stages ───────────────────────────────────────────────

fn doSniff(
    inbound: *const InboundRuntime,
    ctx: *session_mod.SessionContext,
    payload: []const u8,
    fallback_port: u16,
    pfx: *const ConnPrefix,
) void {
    const logger = log.getLogger();
    if (!inbound.sniff_enabled) {
        logger.access("{s} SNIFF_SKIP (disabled)", .{pfx.str()});
        return;
    }
    if (payload.len == 0) {
        logger.access("{s} SNIFF_SKIP (no payload)", .{pfx.str()});
        return;
    }

    logger.access("{s} SNIFF_START payload={d}bytes", .{ pfx.str(), payload.len });
    const result = sniffer.sniff(payload) orelse {
        logger.access("{s} SNIFF_NONE (no SNI/Host detected)", .{pfx.str()});
        return;
    };
    ctx.sniffed_target = result.toTarget(fallback_port);
    if (inbound.sniff_override) {
        ctx.final_target = ctx.sniffed_target;
        logger.access("{s} SNIFF_OVERRIDE {s} -> {s}:{d}", .{
            pfx.str(),
            ctx.target.host(),
            ctx.sniffed_target.host(),
            ctx.sniffed_target.port,
        });
    } else {
        logger.access("{s} SNIFF_DETECTED {s}:{d} (no override, keeping original {s}:{d})", .{
            pfx.str(),
            ctx.sniffed_target.host(),
            ctx.sniffed_target.port,
            ctx.target.host(),
            ctx.target.port,
        });
    }
}

/// Route + dial + outbound handshake + relay.
fn doOutboundAndRelay(
    runtime: *Runtime,
    inbound: *const InboundRuntime,
    ctx: *session_mod.SessionContext,
    shard: *stats_mod.StatsShard,
    client_adapter: *StreamAdapter,
    initial_payload: []const u8,
    logger: *log.Logger,
    pfx: *const ConnPrefix,
) void {
    const effective = ctx.effectiveTarget();

    // 路由决策
    if (inbound.fixed_outbound) |fixed| {
        logger.access("{s} ROUTE fixed_outbound={s} target={s}:{d}", .{
            pfx.str(), fixed, effective.host(), effective.port,
        });
    }
    const outbound_tag = inbound.fixed_outbound orelse runtime.router.route(effective);
    ctx.setOutboundTag(outbound_tag);

    logger.access("{s} ROUTE_RESULT target={s}:{d} via={s} original={s}:{d} sniffed={s}:{d}", .{
        pfx.str(),
        effective.host(),
        effective.port,
        outbound_tag,
        ctx.target.host(),
        ctx.target.port,
        if (!ctx.sniffed_target.isEmpty()) ctx.sniffed_target.host() else "-",
        ctx.sniffed_target.port,
    });

    const outbound = runtime.outbounds.find(outbound_tag) orelse {
        shard.onError();
        ctx.setError(.router_outbound_not_found);
        logger.connError("{s} OUTBOUND_NOT_FOUND tag={s} (available: check config)", .{ pfx.str(), outbound_tag });
        return;
    };

    logger.access("{s} OUTBOUND_FOUND tag={s} kind={s}", .{
        pfx.str(), outbound_tag, @tagName(outbound.kind),
    });

    if (outbound.kind == .blackhole) {
        logger.access("{s} BLACKHOLE dropping connection", .{pfx.str()});
        ctx.transitionTo(.closed);
        return;
    }

    // Determine dial target
    const dial_target = switch (outbound.kind) {
        .trojan, .vmess, .shadowsocks => DialTarget{
            .host = outbound.address,
            .port = outbound.port,
        },
        .freedom => DialTarget{
            .host = effective.host(),
            .port = effective.port,
        },
        .blackhole => return,
    };

    ctx.transitionTo(.dialing);
    logger.access("{s} DIALING {s}:{d} (outbound={s})", .{ pfx.str(), dial_target.host, dial_target.port, outbound_tag });

    var target_tcp = connectTarget(runtime.allocator, dial_target) catch |err| {
        shard.onError();
        ctx.setError(.dial_connect_failed);
        logger.connError("{s} DIAL_FAILED {s}:{d} via={s} err={s}", .{
            pfx.str(), dial_target.host, dial_target.port, outbound_tag, @errorName(err),
        });
        return;
    };
    defer target_tcp.close();

    logger.access("{s} DIAL_OK {s}:{d}", .{ pfx.str(), dial_target.host, dial_target.port });

    ctx.transitionTo(.relaying);
    const cfg = relayConfig(ctx, runtime);
    logger.access("{s} RELAY_START initial_payload={d}bytes speed_limit={d}", .{
        pfx.str(), initial_payload.len, cfg.speed_limit,
    });

    switch (outbound.kind) {
        .freedom => {
            logger.access("{s} OUTBOUND_FREEDOM direct relay", .{pfx.str()});
            const target_adapter = StreamAdapter.from(TcpStream, &target_tcp);
            const result = if (initial_payload.len > 0)
                relay_mod.doRelayAdaptedWithFirstPacket(client_adapter.*, target_adapter, initial_payload, shard, cfg)
            else
                relay_mod.doRelayAdapted(client_adapter.*, target_adapter, shard, cfg);
            recordTrafficAndLog(ctx, runtime, result, logger, pfx);
        },
        .trojan => {
            switch (outbound.proto) {
                .trojan => |*t| {
                    logger.access("{s} OUTBOUND_TROJAN encoding handshake", .{pfx.str()});
                    var hdr_buf: [512]u8 = undefined;
                    const hdr_len = t.encodeHandshake(effective, .connect, &hdr_buf) orelse {
                        shard.onError();
                        ctx.setError(.protocol_encode_failed);
                        logger.connError("{s} OUTBOUND_TROJAN_ENCODE_FAILED", .{pfx.str()});
                        return;
                    };
                    logger.access("{s} OUTBOUND_TROJAN handshake={d}bytes, sending", .{ pfx.str(), hdr_len });
                    target_tcp.writeAll(hdr_buf[0..hdr_len]) catch |err| {
                        shard.onError();
                        ctx.setError(.outbound_connection_failed);
                        logger.connError("{s} OUTBOUND_TROJAN_WRITE_FAILED err={s}", .{ pfx.str(), @errorName(err) });
                        return;
                    };
                    if (initial_payload.len > 0) {
                        target_tcp.writeAll(initial_payload) catch |err| {
                            shard.onError();
                            ctx.setError(.outbound_connection_failed);
                            logger.connError("{s} OUTBOUND_TROJAN_PAYLOAD_WRITE_FAILED err={s}", .{ pfx.str(), @errorName(err) });
                            return;
                        };
                    }
                    logger.access("{s} OUTBOUND_TROJAN_HANDSHAKE_OK, relay starting", .{pfx.str()});
                    const target_adapter = StreamAdapter.from(TcpStream, &target_tcp);
                    const result = relay_mod.doRelayAdapted(client_adapter.*, target_adapter, shard, cfg);
                    var r = result;
                    r.bytes_up += hdr_len + initial_payload.len;
                    recordTrafficAndLog(ctx, runtime, r, logger, pfx);
                },
                else => {
                    logger.connError("{s} OUTBOUND_PROTO_MISMATCH expected=trojan got={s}", .{ pfx.str(), @tagName(outbound.proto) });
                    shard.onError();
                    return;
                },
            }
        },
        .vmess => {
            switch (outbound.proto) {
                .vmess => |*v| {
                    logger.access("{s} OUTBOUND_VMESS encoding handshake", .{pfx.str()});
                    const hs = v.encodeHandshake(effective, .tcp) catch |err| {
                        shard.onError();
                        ctx.setError(.protocol_encode_failed);
                        logger.connError("{s} OUTBOUND_VMESS_ENCODE_FAILED err={s}", .{ pfx.str(), @errorName(err) });
                        return;
                    };
                    logger.access("{s} OUTBOUND_VMESS handshake={d}bytes, sending", .{ pfx.str(), hs.data_len });
                    target_tcp.writeAll(hs.data[0..hs.data_len]) catch |err| {
                        shard.onError();
                        ctx.setError(.outbound_connection_failed);
                        logger.connError("{s} OUTBOUND_VMESS_WRITE_FAILED err={s}", .{ pfx.str(), @errorName(err) });
                        return;
                    };
                    logger.access("{s} OUTBOUND_VMESS reading response", .{pfx.str()});
                    vmess_outbound.VMessOutbound.readResponse(
                        TcpStream,
                        &target_tcp,
                        &hs.response_key,
                        &hs.response_iv,
                        hs.response_header,
                    ) catch |err| {
                        shard.onError();
                        ctx.setError(.vmess_invalid_response);
                        logger.connError("{s} OUTBOUND_VMESS_RESPONSE_FAILED err={s}", .{ pfx.str(), @errorName(err) });
                        return;
                    };
                    logger.access("{s} OUTBOUND_VMESS_HANDSHAKE_OK security={s}", .{ pfx.str(), @tagName(hs.security) });
                    const cipher = hs.security.toAeadCipher() orelse {
                        logger.access("{s} OUTBOUND_VMESS security=none/zero (raw relay)", .{pfx.str()});
                        const target_adapter = StreamAdapter.from(TcpStream, &target_tcp);
                        const result = if (initial_payload.len > 0)
                            relay_mod.doRelayAdaptedWithFirstPacket(client_adapter.*, target_adapter, initial_payload, shard, cfg)
                        else
                            relay_mod.doRelayAdapted(client_adapter.*, target_adapter, shard, cfg);
                        recordTrafficAndLog(ctx, runtime, result, logger, pfx);
                        return;
                    };
                    var vmess_target = vmess_stream_mod.VMessStream(TcpStream).init(
                        target_tcp, cipher,
                        hs.response_key, hs.response_iv,
                        hs.request_key, hs.request_iv,
                        hs.options,
                    );
                    if (initial_payload.len > 0) {
                        vmess_target.writeAll(initial_payload) catch |err| {
                            shard.onError();
                            ctx.setError(.outbound_connection_failed);
                            logger.connError("{s} OUTBOUND_VMESS_PAYLOAD_WRITE_FAILED err={s}", .{ pfx.str(), @errorName(err) });
                            return;
                        };
                    }
                    logger.access("{s} OUTBOUND_VMESS_RELAY_START cipher={s}", .{ pfx.str(), @tagName(cipher) });
                    const target_adapter = StreamAdapter.from(
                        vmess_stream_mod.VMessStream(TcpStream),
                        &vmess_target,
                    );
                    const result = relay_mod.doRelayAdapted(client_adapter.*, target_adapter, shard, cfg);
                    var r = result;
                    r.bytes_up += initial_payload.len;
                    recordTrafficAndLog(ctx, runtime, r, logger, pfx);
                },
                else => {
                    logger.connError("{s} OUTBOUND_PROTO_MISMATCH expected=vmess got={s}", .{ pfx.str(), @tagName(outbound.proto) });
                    shard.onError();
                    return;
                },
            }
        },
        .shadowsocks => {
            switch (outbound.proto) {
                .ss => |*s| {
                    logger.access("{s} OUTBOUND_SS generating keys", .{pfx.str()});
                    const write_keys = s.generateWriteKeys() catch |err| {
                        shard.onError();
                        ctx.setError(.protocol_encode_failed);
                        logger.connError("{s} OUTBOUND_SS_KEY_FAILED err={s}", .{ pfx.str(), @errorName(err) });
                        return;
                    };
                    var addr_buf: [256]u8 = undefined;
                    const addr_len = ss_outbound.SsOutbound.encodeAddress(effective, &addr_buf) orelse {
                        shard.onError();
                        ctx.setError(.protocol_encode_failed);
                        logger.connError("{s} OUTBOUND_SS_ADDR_ENCODE_FAILED", .{pfx.str()});
                        return;
                    };
                    var first_buf: [4096 + 256]u8 = undefined;
                    @memcpy(first_buf[0..addr_len], addr_buf[0..addr_len]);
                    var first_len = addr_len;
                    if (initial_payload.len > 0 and initial_payload.len <= first_buf.len - addr_len) {
                        @memcpy(first_buf[addr_len..][0..initial_payload.len], initial_payload);
                        first_len += initial_payload.len;
                    }
                    logger.access("{s} OUTBOUND_SS writing first chunk addr={d}bytes+payload={d}bytes", .{
                        pfx.str(), addr_len, initial_payload.len,
                    });
                    var ss_target = ss_stream_mod.SsStream(TcpStream).init(
                        target_tcp,
                        s.cipher_info.cipher_type,
                        write_keys.subkey[0..write_keys.subkey_len],
                        write_keys.subkey[0..write_keys.subkey_len],
                        write_keys.salt[0..write_keys.salt_len],
                    );
                    ss_target.writeAll(first_buf[0..first_len]) catch |err| {
                        shard.onError();
                        ctx.setError(.outbound_connection_failed);
                        logger.connError("{s} OUTBOUND_SS_WRITE_FAILED err={s}", .{ pfx.str(), @errorName(err) });
                        return;
                    };
                    logger.access("{s} OUTBOUND_SS_RELAY_START cipher={s}", .{ pfx.str(), @tagName(s.cipher_info.cipher_type) });
                    const target_adapter = StreamAdapter.from(
                        ss_stream_mod.SsStream(TcpStream),
                        &ss_target,
                    );
                    const result = relay_mod.doRelayAdapted(client_adapter.*, target_adapter, shard, cfg);
                    var r = result;
                    r.bytes_up += initial_payload.len;
                    recordTrafficAndLog(ctx, runtime, r, logger, pfx);
                },
                else => {
                    logger.connError("{s} OUTBOUND_PROTO_MISMATCH expected=ss got={s}", .{ pfx.str(), @tagName(outbound.proto) });
                    shard.onError();
                    return;
                },
            }
        },
        .blackhole => return,
    }
}

/// Record traffic to panel tracker and write access log with final stats.
fn recordTrafficAndLog(
    ctx: *session_mod.SessionContext,
    runtime: *Runtime,
    result: relay_mod.RelayResult,
    logger: *log.Logger,
    pfx: *const ConnPrefix,
) void {
    ctx.bytes_up = result.bytes_up;
    ctx.bytes_down = result.bytes_down;
    ctx.transitionTo(.closed);
    runtime.tracker.add(ctx.user_id, result.bytes_up, result.bytes_down);

    var up_buf: [32]u8 = undefined;
    var down_buf: [32]u8 = undefined;
    const up_str = types.formatBytes(result.bytes_up, &up_buf);
    const down_str = types.formatBytes(result.bytes_down, &down_buf);
    const total_ms = ctx.durationMs();
    const effective = ctx.effectiveTarget();

    // 各阶段耗时
    const auth_ms = stageDurationMs(ctx.accept_time_us, ctx.handshake_done_us);
    const sniff_ms = stageDurationMs(ctx.handshake_done_us, ctx.sniff_done_us);
    const dial_ms = stageDurationMs(ctx.sniff_done_us, ctx.dial_done_us);
    const relay_ms = stageDurationMs(ctx.dial_done_us, ctx.close_time_us);

    const status: []const u8 = if (result.err == null) "ok" else "err";
    const err_name: []const u8 = if (result.err) |e| @errorName(e) else "-";

    logger.access("{s} CLOSED {s}:{s}:{d} [{s}->{s}] user={d} email={s} {s} up={s} down={s} total={d}ms auth={d}ms sniff={d}ms dial={d}ms relay={d}ms relay_err={s}", .{
        pfx.str(),
        @tagName(ctx.network),
        effective.host(),
        effective.port,
        ctx.inboundTag(),
        ctx.outboundTag(),
        ctx.user_id,
        if (ctx.user_email_len > 0) ctx.userEmail() else "-",
        status,
        up_str,
        down_str,
        total_ms,
        auth_ms,
        sniff_ms,
        dial_ms,
        relay_ms,
        err_name,
    });
}

fn relayConfig(ctx: *const session_mod.SessionContext, runtime: *const Runtime) relay_mod.RelayConfig {
    return .{
        .speed_limit = ctx.speed_limit,
        .uplink_only_timeout_ms = @as(u64, runtime.timeouts.uplink_only) * 1000,
        .downlink_only_timeout_ms = @as(u64, runtime.timeouts.downlink_only) * 1000,
    };
}

const DialTarget = struct {
    host: []const u8,
    port: u16,
};

fn connectTarget(
    allocator: std.mem.Allocator,
    target: DialTarget,
) !TcpStream {
    _ = allocator;
    // Try parsing as IP first; fall back to DNS
    const addr = zio.net.IpAddress.parseIp(target.host, target.port) catch {
        return TcpStream.init(try zio.net.tcpConnectToHost(target.host, target.port, .{}));
    };
    return TcpStream.init(try addr.connect(.{}));
}

fn statsLoop(runtime: *Runtime) void {
    const logger = log.getLogger();
    while (true) {
        zio.sleep(zio.time.Duration.fromSeconds(5)) catch break;
        const s = runtime.stats.aggregate();
        var up_buf: [32]u8 = undefined;
        var down_buf: [32]u8 = undefined;
        const up = types.formatBytes(s.bytes_up, &up_buf);
        const down = types.formatBytes(s.bytes_down, &down_buf);
        logger.console("conn={d}/{d} up={s} down={s} err={d}", .{
            s.active_connections,
            s.total_connections,
            up,
            down,
            s.errors,
        });
    }
}
