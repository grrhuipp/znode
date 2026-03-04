/// Connection handler — multi-protocol inbound/outbound pipeline.
///
/// Supports Trojan, VMess, Shadowsocks inbound protocols.
/// Supports Freedom, Blackhole, Trojan, VMess, Shadowsocks outbound protocols.
/// Pipeline: accept → proxy protocol → protocol parse → sniff → route → dial → outbound handshake → relay.
const std = @import("std");

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

const StreamAdapter = relay_mod.StreamAdapter;

// ── PrefixedStream: 预读缓冲 + 真实流 ─────────────────────────────────────
/// 把 proxy protocol 检测阶段预读的数据放在前面，读完后透传到底层 stream。
/// 实现 read/write/writeAll 接口，可直接传给 protocol parseStream (comptime Transport)。
pub const PrefixedStream = struct {
    inner: std.net.Stream,
    pending: [2048]u8 = undefined,
    pending_len: usize = 0,
    pending_pos: usize = 0,

    pub fn init(inner: std.net.Stream, pending_data: []const u8) PrefixedStream {
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
    pool: std.Thread.Pool,
    stats: stats_mod.ShardedStats,
    timeouts: config.TimeoutsConfig,
    tracker: panel_sync.TrafficTracker,
};

pub fn run(allocator: std.mem.Allocator, cfg: *const config.Config) !void {
    var runtime = Runtime{
        .allocator = allocator,
        .router = try router_mod.Router.init(allocator, cfg.routing),
        .outbounds = try outbound_mod.Manager.init(allocator, cfg.outbounds),
        .pool = undefined,
        .stats = try stats_mod.ShardedStats.init(allocator, cfg.workers),
        .timeouts = cfg.timeouts,
        .tracker = panel_sync.TrafficTracker.init(allocator),
    };

    try runtime.pool.init(.{
        .allocator = allocator,
        .n_jobs = cfg.workers,
    });
    defer runtime.pool.deinit();

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

    const stats_thread = try std.Thread.spawn(.{}, statsLoop, .{&runtime});
    stats_thread.detach();

    if (inbounds.len == 0) {
        logger.console("没有 inbound 监听器，等待面板同步...", .{});
        // Block forever — panel sync runs in background
        while (true) {
            std.Thread.sleep(60 * std.time.ns_per_s);
        }
    }

    var listener_threads = try allocator.alloc(std.Thread, inbounds.len);
    var listener_count: usize = 0;

    for (inbounds) |*inbound| {
        if (inbound.protocol == .unsupported) continue;
        listener_threads[listener_count] = try std.Thread.spawn(
            .{},
            listenerThreadMain,
            .{ &runtime, inbound },
        );
        logger.console("监听启动: tag={s} protocol={s} {s}:{d}", .{
            inbound.tag,
            @tagName(inbound.protocol),
            inbound.listen,
            inbound.port,
        });
        listener_count += 1;
    }

    if (listener_count == 0) {
        logger.console("没有可用的 inbound 监听器", .{});
        while (true) {
            std.Thread.sleep(60 * std.time.ns_per_s);
        }
    }

    for (listener_threads[0..listener_count]) |thread| {
        thread.join();
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

fn listenerThreadMain(runtime: *Runtime, inbound: *const InboundRuntime) void {
    const logger = log.getLogger();
    listenerLoop(runtime, inbound) catch |err| {
        logger.app(.err, "监听线程退出: tag={s} err={s}", .{ inbound.tag, @errorName(err) });
    };
}

fn listenerLoop(runtime: *Runtime, inbound: *const InboundRuntime) !void {
    const logger = log.getLogger();
    const address = try std.net.Address.parseIp(inbound.listen, inbound.port);
    var server = try address.listen(.{
        .reuse_address = true,
        .kernel_backlog = 1024,
    });
    defer server.deinit();

    logger.app(.info, "监听启动: tag={s} protocol={s} {s}:{d}", .{
        inbound.tag,
        @tagName(inbound.protocol),
        inbound.listen,
        inbound.port,
    });

    while (true) {
        const conn = server.accept() catch |err| {
            logger.app(.warn, "accept 失败: tag={s} err={s}", .{ inbound.tag, @errorName(err) });
            continue;
        };

        const shard = runtime.stats.getShard(0);
        shard.onAccepted();
        runtime.pool.spawn(handleConnectionTask, .{ runtime, inbound, conn }) catch |err| {
            shard.onClosed();
            shard.onError();
            conn.stream.close();
            logger.app(.warn, "任务派发失败: tag={s} err={s}", .{ inbound.tag, @errorName(err) });
        };
    }
}

// ── Connection dispatch ──────────────────────────────────────────────────

fn handleConnectionTask(
    runtime: *Runtime,
    inbound: *const InboundRuntime,
    conn: std.net.Server.Connection,
) void {
    const shard = runtime.stats.getShard(0);
    defer shard.onClosed();

    // Create session context and extract client IP + port
    var session_ctx = session_mod.SessionContext.init();
    session_ctx.setInboundTag(inbound.tag);
    extractClientAddr(&session_ctx, conn.address);

    const logger = log.getLogger();
    var pfx = connPrefix(&session_ctx);

    logger.access("{s} ACCEPTED", .{pfx.str()});

    // ── Proxy Protocol 自动检测 ─────────────────────────────────────────
    var peek_buf: [2048]u8 = undefined;
    var peek_len: usize = 0;
    var tcp_stream = conn.stream;

    // 读第一块数据
    peek_len = tcp_stream.read(&peek_buf) catch |err| {
        logger.access("{s} READ_ERROR {s}", .{ pfx.str(), @errorName(err) });
        tcp_stream.close();
        return;
    };
    if (peek_len == 0) {
        logger.access("{s} EMPTY_CONN", .{pfx.str()});
        tcp_stream.close();
        return;
    }

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
                logger.access("{s} PROXY_PROTOCOL real_ip={s}:{d}", .{
                    pfx.str(),
                    pp_result.srcIp(),
                    pp_result.src_port,
                });
            } else {
                logger.access("{s} PROXY_PROTOCOL (unknown/local)", .{pfx.str()});
            }
        },
        .not_proxy => {
            // 不是 proxy protocol，所有数据回流
            pp_consumed = 0;
        },
        .incomplete => {
            // 部分匹配但不完整 — 尝试再读一次
            if (tcp_stream.read(peek_buf[peek_len..])) |n2| {
                peek_len += n2;
                const pp2 = proxy_protocol.parse(peek_buf[0..peek_len]);
                if (pp2.status == .success) {
                    pp_consumed = pp2.consumed;
                    if (pp2.src_ip_len > 0) {
                        session_ctx.setClientIp(pp2.srcIp());
                        session_ctx.client_port = pp2.src_port;
                        pfx = connPrefix(&session_ctx);
                        logger.access("{s} PROXY_PROTOCOL real_ip={s}:{d}", .{
                            pfx.str(),
                            pp2.srcIp(),
                            pp2.src_port,
                        });
                    }
                }
                // 其他情况 pp_consumed 保持 0，当做非 proxy protocol
            } else |_| {
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

    logger.access("{s} DISPATCH protocol={s} pending={d}bytes", .{
        pfx.str(),
        @tagName(inbound.protocol),
        remaining.len,
    });

    switch (inbound.handler) {
        .trojan => |*ctx| handleTrojan(runtime, inbound, ctx, &client_stream, shard, &session_ctx, &pfx),
        .vmess => |*ctx| handleVMess(runtime, inbound, ctx, &client_stream, shard, &session_ctx, &pfx),
        .ss => |*ctx| handleSs(runtime, inbound, ctx, &client_stream, shard, &session_ctx, &pfx),
        .none => shard.onError(),
    }
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

    const handler = trojan_inbound.TrojanInboundHandler.init(&ctx.user_manager);
    const parsed = handler.parseStream(
        PrefixedStream,
        client_stream,
        session_ctx,
    ) catch {
        shard.onError();
        logger.connError("{s} AUTH_FAILED trojan", .{pfx.str()});
        return;
    };

    logger.access("{s} AUTH_OK trojan user={d} email={s} -> {s}:{d}", .{
        pfx.str(),
        session_ctx.user_id,
        if (session_ctx.user_email_len > 0) session_ctx.userEmail() else "-",
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

    const handler = vmess_inbound.VMessInboundHandler.init(&ctx.user_manager);
    const parsed = handler.parseStream(
        PrefixedStream,
        client_stream,
        session_ctx,
    ) catch {
        shard.onError();
        logger.connError("{s} AUTH_FAILED vmess", .{pfx.str()});
        return;
    };

    logger.access("{s} AUTH_OK vmess user={d} email={s} -> {s}:{d}", .{
        pfx.str(),
        session_ctx.user_id,
        if (session_ctx.user_email_len > 0) session_ctx.userEmail() else "-",
        session_ctx.target.host(),
        session_ctx.target.port,
    });

    // Send VMess AEAD response header
    vmess_inbound.VMessInboundHandler.sendResponse(
        PrefixedStream,
        client_stream,
        &parsed.request,
    ) catch {
        shard.onError();
        logger.connError("{s} RESPONSE_SEND_FAILED vmess", .{pfx.str()});
        return;
    };

    session_ctx.transitionTo(.routing);

    // Wrap client stream with VMessStream for AEAD chunk relay
    const cipher = parsed.request.security.toAeadCipher() orelse {
        // security=none/zero: relay raw
        var client_adapter = StreamAdapter.from(PrefixedStream, client_stream);
        doOutboundAndRelay(runtime, inbound, session_ctx, shard, &client_adapter, &.{}, logger, pfx);
        return;
    };

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

    const handler = ss_inbound.SsInboundHandler.init(&ctx.user_manager);
    const parsed = handler.parseStream(
        PrefixedStream,
        client_stream,
        session_ctx,
    ) catch {
        shard.onError();
        logger.connError("{s} AUTH_FAILED ss", .{pfx.str()});
        return;
    };

    logger.access("{s} AUTH_OK ss user={d} email={s} -> {s}:{d}", .{
        pfx.str(),
        session_ctx.user_id,
        if (session_ctx.user_email_len > 0) session_ctx.userEmail() else "-",
        parsed.target.host(),
        parsed.target.port,
    });

    session_ctx.transitionTo(.sniffing);
    doSniff(inbound, session_ctx, parsed.initial_payload, parsed.target.port, pfx);
    session_ctx.transitionTo(.routing);

    // Generate write subkey for server→client direction
    var write_salt: [ss_protocol.max_salt_len]u8 = undefined;
    var write_subkey: [ss_protocol.max_key_len]u8 = undefined;
    ss_protocol.generateSalt(write_salt[0..parsed.read_subkey_len]) catch {
        shard.onError();
        return;
    };
    ss_protocol.deriveSessionKey(
        parsed.master_key[0..parsed.master_key_len],
        write_salt[0..parsed.read_subkey_len],
        write_subkey[0..parsed.read_subkey_len],
    ) catch {
        shard.onError();
        return;
    };

    // Wrap client stream with SsStream for AEAD chunk relay
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
    if (!inbound.sniff_enabled or payload.len == 0) return;
    const result = sniffer.sniff(payload) orelse return;
    ctx.sniffed_target = result.toTarget(fallback_port);
    const logger = log.getLogger();
    if (inbound.sniff_override) {
        ctx.final_target = ctx.sniffed_target;
        logger.access("{s} SNIFF override {s} -> {s}:{d}", .{
            pfx.str(),
            ctx.target.host(),
            ctx.sniffed_target.host(),
            ctx.sniffed_target.port,
        });
    } else {
        logger.access("{s} SNIFF detected {s}:{d} (no override)", .{
            pfx.str(),
            ctx.sniffed_target.host(),
            ctx.sniffed_target.port,
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
    const outbound_tag = inbound.fixed_outbound orelse runtime.router.route(effective);
    ctx.setOutboundTag(outbound_tag);

    logger.access("{s} ROUTE -> {s}:{d} via {s}", .{
        pfx.str(),
        effective.host(),
        effective.port,
        outbound_tag,
    });

    const outbound = runtime.outbounds.find(outbound_tag) orelse {
        shard.onError();
        ctx.setError(.router_outbound_not_found);
        logger.connError("{s} OUTBOUND_NOT_FOUND via {s}", .{ pfx.str(), outbound_tag });
        return;
    };

    if (outbound.kind == .blackhole) {
        logger.access("{s} BLACKHOLE", .{pfx.str()});
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
    logger.access("{s} DIALING {s}:{d}", .{ pfx.str(), dial_target.host, dial_target.port });

    var target_tcp = connectTarget(runtime.allocator, dial_target) catch {
        shard.onError();
        ctx.setError(.dial_connect_failed);
        logger.connError("{s} DIAL_FAILED {s}:{d} via {s}", .{
            pfx.str(), dial_target.host, dial_target.port, outbound_tag,
        });
        return;
    };
    defer target_tcp.close();

    logger.access("{s} DIAL_OK {s}:{d}", .{ pfx.str(), dial_target.host, dial_target.port });

    ctx.transitionTo(.relaying);
    const cfg = relayConfig(ctx, runtime);

    switch (outbound.kind) {
        .freedom => {
            const target_adapter = StreamAdapter.fromNetStream(&target_tcp);
            const result = if (initial_payload.len > 0)
                relay_mod.doRelayAdaptedWithFirstPacket(client_adapter.*, target_adapter, initial_payload, shard, cfg)
            else
                relay_mod.doRelayAdapted(client_adapter.*, target_adapter, shard, cfg);
            recordTrafficAndLog(ctx, runtime, result, logger, pfx);
        },
        .trojan => {
            switch (outbound.proto) {
                .trojan => |*t| {
                    var hdr_buf: [512]u8 = undefined;
                    const hdr_len = t.encodeHandshake(effective, .connect, &hdr_buf) orelse {
                        shard.onError();
                        ctx.setError(.protocol_encode_failed);
                        logger.connError("{s} OUTBOUND_ENCODE_FAILED trojan", .{pfx.str()});
                        return;
                    };
                    target_tcp.writeAll(hdr_buf[0..hdr_len]) catch {
                        shard.onError();
                        ctx.setError(.outbound_connection_failed);
                        logger.connError("{s} OUTBOUND_WRITE_FAILED trojan", .{pfx.str()});
                        return;
                    };
                    if (initial_payload.len > 0) {
                        target_tcp.writeAll(initial_payload) catch {
                            shard.onError();
                            ctx.setError(.outbound_connection_failed);
                            return;
                        };
                    }
                    const target_adapter = StreamAdapter.fromNetStream(&target_tcp);
                    const result = relay_mod.doRelayAdapted(client_adapter.*, target_adapter, shard, cfg);
                    var r = result;
                    r.bytes_up += hdr_len + initial_payload.len;
                    recordTrafficAndLog(ctx, runtime, r, logger, pfx);
                },
                else => { shard.onError(); return; },
            }
        },
        .vmess => {
            switch (outbound.proto) {
                .vmess => |*v| {
                    const hs = v.encodeHandshake(effective, .tcp) catch {
                        shard.onError();
                        ctx.setError(.protocol_encode_failed);
                        logger.connError("{s} OUTBOUND_ENCODE_FAILED vmess", .{pfx.str()});
                        return;
                    };
                    target_tcp.writeAll(hs.data[0..hs.data_len]) catch {
                        shard.onError();
                        ctx.setError(.outbound_connection_failed);
                        logger.connError("{s} OUTBOUND_WRITE_FAILED vmess", .{pfx.str()});
                        return;
                    };
                    vmess_outbound.VMessOutbound.readResponse(
                        std.net.Stream,
                        &target_tcp,
                        &hs.response_key,
                        &hs.response_iv,
                        hs.response_header,
                    ) catch {
                        shard.onError();
                        ctx.setError(.vmess_invalid_response);
                        logger.connError("{s} OUTBOUND_RESPONSE_FAILED vmess", .{pfx.str()});
                        return;
                    };
                    const cipher = hs.security.toAeadCipher() orelse {
                        const target_adapter = StreamAdapter.fromNetStream(&target_tcp);
                        const result = if (initial_payload.len > 0)
                            relay_mod.doRelayAdaptedWithFirstPacket(client_adapter.*, target_adapter, initial_payload, shard, cfg)
                        else
                            relay_mod.doRelayAdapted(client_adapter.*, target_adapter, shard, cfg);
                        recordTrafficAndLog(ctx, runtime, result, logger, pfx);
                        return;
                    };
                    var vmess_target = vmess_stream_mod.VMessStream(std.net.Stream).init(
                        target_tcp, cipher,
                        hs.response_key, hs.response_iv,
                        hs.request_key, hs.request_iv,
                        hs.options,
                    );
                    if (initial_payload.len > 0) {
                        vmess_target.writeAll(initial_payload) catch {
                            shard.onError();
                            ctx.setError(.outbound_connection_failed);
                            return;
                        };
                    }
                    const target_adapter = StreamAdapter.from(
                        vmess_stream_mod.VMessStream(std.net.Stream),
                        &vmess_target,
                    );
                    const result = relay_mod.doRelayAdapted(client_adapter.*, target_adapter, shard, cfg);
                    var r = result;
                    r.bytes_up += initial_payload.len;
                    recordTrafficAndLog(ctx, runtime, r, logger, pfx);
                },
                else => { shard.onError(); return; },
            }
        },
        .shadowsocks => {
            switch (outbound.proto) {
                .ss => |*s| {
                    const write_keys = s.generateWriteKeys() catch {
                        shard.onError();
                        ctx.setError(.protocol_encode_failed);
                        logger.connError("{s} OUTBOUND_KEY_FAILED ss", .{pfx.str()});
                        return;
                    };
                    var addr_buf: [256]u8 = undefined;
                    const addr_len = ss_outbound.SsOutbound.encodeAddress(effective, &addr_buf) orelse {
                        shard.onError();
                        ctx.setError(.protocol_encode_failed);
                        return;
                    };
                    var first_buf: [4096 + 256]u8 = undefined;
                    @memcpy(first_buf[0..addr_len], addr_buf[0..addr_len]);
                    var first_len = addr_len;
                    if (initial_payload.len > 0 and initial_payload.len <= first_buf.len - addr_len) {
                        @memcpy(first_buf[addr_len..][0..initial_payload.len], initial_payload);
                        first_len += initial_payload.len;
                    }
                    var ss_target = ss_stream_mod.SsStream(std.net.Stream).init(
                        target_tcp,
                        s.cipher_info.cipher_type,
                        write_keys.subkey[0..write_keys.subkey_len],
                        write_keys.subkey[0..write_keys.subkey_len],
                        write_keys.salt[0..write_keys.salt_len],
                    );
                    ss_target.writeAll(first_buf[0..first_len]) catch {
                        shard.onError();
                        ctx.setError(.outbound_connection_failed);
                        logger.connError("{s} OUTBOUND_WRITE_FAILED ss", .{pfx.str()});
                        return;
                    };
                    const target_adapter = StreamAdapter.from(
                        ss_stream_mod.SsStream(std.net.Stream),
                        &ss_target,
                    );
                    const result = relay_mod.doRelayAdapted(client_adapter.*, target_adapter, shard, cfg);
                    var r = result;
                    r.bytes_up += initial_payload.len;
                    recordTrafficAndLog(ctx, runtime, r, logger, pfx);
                },
                else => { shard.onError(); return; },
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
    const duration = ctx.durationMs();
    const effective = ctx.effectiveTarget();
    const status: []const u8 = if (result.err == null) "ok" else "err";

    logger.access("{s} CLOSED {s}:{s}:{d} [{s}->{s}] email:{s} {s} up={s} down={s} {d}ms", .{
        pfx.str(),
        @tagName(ctx.network),
        effective.host(),
        effective.port,
        ctx.inboundTag(),
        ctx.outboundTag(),
        if (ctx.user_email_len > 0) ctx.userEmail() else "-",
        status,
        up_str,
        down_str,
        duration,
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
) !std.net.Stream {
    // Try parsing as IP first; fall back to DNS
    const addr = std.net.Address.parseIp(target.host, target.port) catch {
        return try std.net.tcpConnectToHost(allocator, target.host, target.port);
    };
    return try std.net.tcpConnectToAddress(addr);
}

fn statsLoop(runtime: *Runtime) void {
    const logger = log.getLogger();
    while (true) {
        std.Thread.sleep(5 * std.time.ns_per_s);
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
