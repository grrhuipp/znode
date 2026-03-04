/// Connection handler — multi-protocol inbound/outbound pipeline.
///
/// Supports Trojan, VMess, Shadowsocks inbound protocols.
/// Supports Freedom, Blackhole, Trojan, VMess, Shadowsocks outbound protocols.
/// Pipeline: accept → protocol parse → sniff → route → dial → outbound handshake → relay.
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

    const inbounds = try buildInbounds(allocator, cfg.inbounds);
    if (inbounds.len == 0) {
        return config.ConfigError.InvalidConfig;
    }

    const stats_thread = try std.Thread.spawn(.{}, statsLoop, .{&runtime});
    stats_thread.detach();

    // Start panel sync if configured
    if (cfg.panels.len > 0) {
        var sync = panel_sync.PanelSyncManager.init(allocator, cfg.panels, &runtime.tracker);
        sync.start();
    }

    var listener_threads = try allocator.alloc(std.Thread, inbounds.len);
    var listener_count: usize = 0;

    const logger = log.getLogger();

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
        return config.ConfigError.InvalidConfig;
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
    var client_stream = conn.stream;
    defer client_stream.close();

    // Create session context and extract client IP
    var session_ctx = session_mod.SessionContext.init();
    session_ctx.setInboundTag(inbound.tag);
    extractClientIp(&session_ctx, conn.address);

    switch (inbound.handler) {
        .trojan => |*ctx| handleTrojan(runtime, inbound, ctx, &client_stream, shard, &session_ctx),
        .vmess => |*ctx| handleVMess(runtime, inbound, ctx, &client_stream, shard, &session_ctx),
        .ss => |*ctx| handleSs(runtime, inbound, ctx, &client_stream, shard, &session_ctx),
        .none => shard.onError(),
    }
}

/// Extract client IP from std.net.Address into SessionContext.
fn extractClientIp(ctx: *session_mod.SessionContext, addr: std.net.Address) void {
    var buf: [46]u8 = undefined;
    const ip_str = formatAddress(addr, &buf) catch return;
    ctx.setClientIp(ip_str);
}

fn formatAddress(addr: std.net.Address, buf: []u8) ![]const u8 {
    // Use std.net.Address formatting
    const bytes = switch (addr.any.family) {
        std.posix.AF.INET => blk: {
            const a = addr.in.sa.addr;
            const ab = @as(*const [4]u8, @ptrCast(&a));
            break :blk std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
                ab[0], ab[1], ab[2], ab[3],
            }) catch return error.FormatError;
        },
        std.posix.AF.INET6 => blk: {
            // Simplified: just format as hex pairs
            const a = &addr.in6.sa.addr;
            break :blk std.fmt.bufPrint(buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                a[0], a[1], a[2],  a[3],  a[4],  a[5],  a[6],  a[7],
                a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
            }) catch return error.FormatError;
        },
        else => return error.FormatError,
    };
    return bytes;
}

// ── Trojan inbound ───────────────────────────────────────────────────────

fn handleTrojan(
    runtime: *Runtime,
    inbound: *const InboundRuntime,
    ctx: *const TrojanCtx,
    client_stream: *std.net.Stream,
    shard: *stats_mod.StatsShard,
    session_ctx: *session_mod.SessionContext,
) void {
    const logger = log.getLogger();

    const handler = trojan_inbound.TrojanInboundHandler.init(&ctx.user_manager);
    const parsed = handler.parseStream(
        std.net.Stream,
        client_stream,
        session_ctx,
    ) catch {
        shard.onError();
        logger.connError("[conn={d}][tag={s}] AUTH_FAILED from {s}", .{
            session_ctx.conn_id,
            session_ctx.inboundTag(),
            session_ctx.clientIp(),
        });
        return;
    };

    session_ctx.transitionTo(.sniffing);
    doSniff(inbound, session_ctx, parsed.initial_payload, parsed.target.port);
    session_ctx.transitionTo(.routing);

    // Trojan inbound: client stream is raw (encryption handled by TLS)
    var client_adapter = StreamAdapter.fromNetStream(client_stream);
    doOutboundAndRelay(runtime, inbound, session_ctx, shard, &client_adapter, parsed.initial_payload, logger);
}

// ── VMess inbound ────────────────────────────────────────────────────────

fn handleVMess(
    runtime: *Runtime,
    inbound: *const InboundRuntime,
    ctx: *const VMessCtx,
    client_stream: *std.net.Stream,
    shard: *stats_mod.StatsShard,
    session_ctx: *session_mod.SessionContext,
) void {
    const logger = log.getLogger();

    const handler = vmess_inbound.VMessInboundHandler.init(&ctx.user_manager);
    const parsed = handler.parseStream(
        std.net.Stream,
        client_stream,
        session_ctx,
    ) catch {
        shard.onError();
        logger.connError("[conn={d}][tag={s}] AUTH_FAILED from {s}", .{
            session_ctx.conn_id,
            session_ctx.inboundTag(),
            session_ctx.clientIp(),
        });
        return;
    };

    // Send VMess AEAD response header
    vmess_inbound.VMessInboundHandler.sendResponse(
        std.net.Stream,
        client_stream,
        &parsed.request,
    ) catch {
        shard.onError();
        logger.connError("[conn={d}][tag={s}] RESPONSE_SEND_FAILED from {s}", .{
            session_ctx.conn_id,
            session_ctx.inboundTag(),
            session_ctx.clientIp(),
        });
        return;
    };

    session_ctx.transitionTo(.routing);

    // Wrap client stream with VMessStream for AEAD chunk relay
    const cipher = parsed.request.security.toAeadCipher() orelse {
        // security=none/zero: relay raw
        var client_adapter = StreamAdapter.fromNetStream(client_stream);
        doOutboundAndRelay(runtime, inbound, session_ctx, shard, &client_adapter, &.{}, logger);
        return;
    };

    var vmess_client = vmess_stream_mod.VMessStream(std.net.Stream).init(
        client_stream.*,
        cipher,
        parsed.request.body_key, // client→server: we read with request keys
        parsed.request.body_iv,
        parsed.request.response_key, // server→client: we write with response keys
        parsed.request.response_iv,
        parsed.request.options,
    );
    var client_adapter = StreamAdapter.from(
        vmess_stream_mod.VMessStream(std.net.Stream),
        &vmess_client,
    );
    doOutboundAndRelay(runtime, inbound, session_ctx, shard, &client_adapter, &.{}, logger);
}

// ── Shadowsocks inbound ──────────────────────────────────────────────────

fn handleSs(
    runtime: *Runtime,
    inbound: *const InboundRuntime,
    ctx: *const SsCtx,
    client_stream: *std.net.Stream,
    shard: *stats_mod.StatsShard,
    session_ctx: *session_mod.SessionContext,
) void {
    const logger = log.getLogger();

    const handler = ss_inbound.SsInboundHandler.init(&ctx.user_manager);
    const parsed = handler.parseStream(
        std.net.Stream,
        client_stream,
        session_ctx,
    ) catch {
        shard.onError();
        logger.connError("[conn={d}][tag={s}] AUTH_FAILED from {s}", .{
            session_ctx.conn_id,
            session_ctx.inboundTag(),
            session_ctx.clientIp(),
        });
        return;
    };

    session_ctx.transitionTo(.sniffing);
    doSniff(inbound, session_ctx, parsed.initial_payload, parsed.target.port);
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
    var ss_client = ss_stream_mod.SsStream(std.net.Stream).init(
        client_stream.*,
        parsed.cipher_type,
        parsed.read_subkey[0..parsed.read_subkey_len],
        write_subkey[0..parsed.read_subkey_len],
        write_salt[0..parsed.read_subkey_len], // salt_len == key_len for SS
    );
    ss_client.read_nonce_counter = parsed.first_chunk_nonce; // skip already-consumed nonces

    var client_adapter = StreamAdapter.from(
        ss_stream_mod.SsStream(std.net.Stream),
        &ss_client,
    );
    doOutboundAndRelay(runtime, inbound, session_ctx, shard, &client_adapter, parsed.initial_payload, logger);
}

// ── Shared pipeline stages ───────────────────────────────────────────────

fn doSniff(
    inbound: *const InboundRuntime,
    ctx: *session_mod.SessionContext,
    payload: []const u8,
    fallback_port: u16,
) void {
    if (!inbound.sniff_enabled or payload.len == 0) return;
    const result = sniffer.sniff(payload) orelse return;
    ctx.sniffed_target = result.toTarget(fallback_port);
    if (inbound.sniff_override) {
        ctx.final_target = ctx.sniffed_target;
    }
}

/// Route + dial + outbound handshake + relay.
/// Handles all outbound protocol types (freedom/trojan/vmess/ss).
fn doOutboundAndRelay(
    runtime: *Runtime,
    inbound: *const InboundRuntime,
    ctx: *session_mod.SessionContext,
    shard: *stats_mod.StatsShard,
    client_adapter: *StreamAdapter,
    initial_payload: []const u8,
    logger: *log.Logger,
) void {
    const effective = ctx.effectiveTarget();
    const outbound_tag = inbound.fixed_outbound orelse runtime.router.route(effective);
    ctx.setOutboundTag(outbound_tag);

    const outbound = runtime.outbounds.find(outbound_tag) orelse {
        shard.onError();
        ctx.setError(.router_outbound_not_found);
        logger.connError("[conn={d}][tag={s}] OUTBOUND_NOT_FOUND {s} -> {s}:{d} via {s}", .{
            ctx.conn_id,
            ctx.inboundTag(),
            ctx.clientIp(),
            effective.host(),
            effective.port,
            outbound_tag,
        });
        return;
    };

    if (outbound.kind == .blackhole) {
        ctx.transitionTo(.closed);
        return;
    }

    // Determine dial target: proxy outbound → dial proxy server; freedom → dial real target
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
    var target_tcp = connectTarget(runtime.allocator, dial_target) catch {
        shard.onError();
        ctx.setError(.dial_connect_failed);
        logger.connError("[conn={d}][tag={s}] DIAL_FAILED {s} -> {s}:{d} via {s}", .{
            ctx.conn_id,
            ctx.inboundTag(),
            ctx.clientIp(),
            effective.host(),
            effective.port,
            outbound_tag,
        });
        return;
    };
    defer target_tcp.close();

    // Access log: connection accepted (written after successful dial, before relay)
    logger.access("from {s} accepted {s}:{s}:{d} [{s} -> {s}] email:{s}", .{
        ctx.clientIp(),
        @tagName(ctx.network),
        effective.host(),
        effective.port,
        ctx.inboundTag(),
        outbound_tag,
        if (ctx.user_email_len > 0) ctx.userEmail() else "-",
    });

    ctx.transitionTo(.relaying);

    const cfg = relayConfig(ctx, runtime);

    switch (outbound.kind) {
        .freedom => {
            // Direct relay: raw TCP to target
            const target_adapter = StreamAdapter.fromNetStream(&target_tcp);
            const result = if (initial_payload.len > 0)
                relay_mod.doRelayAdaptedWithFirstPacket(client_adapter.*, target_adapter, initial_payload, shard, cfg)
            else
                relay_mod.doRelayAdapted(client_adapter.*, target_adapter, shard, cfg);
            recordTrafficAndLog(ctx, runtime, result, logger);
        },
        .trojan => {
            // Send Trojan handshake header, then relay raw
            switch (outbound.proto) {
                .trojan => |*t| {
                    var hdr_buf: [512]u8 = undefined;
                    const hdr_len = t.encodeHandshake(effective, .connect, &hdr_buf) orelse {
                        shard.onError();
                        ctx.setError(.protocol_encode_failed);
                        logger.connError("[conn={d}][tag={s}] OUTBOUND_HANDSHAKE_FAILED {s} -> {s}:{d} via {s}", .{
                            ctx.conn_id, ctx.inboundTag(), ctx.clientIp(),
                            effective.host(), effective.port, outbound_tag,
                        });
                        return;
                    };
                    // Send header + initial payload together
                    target_tcp.writeAll(hdr_buf[0..hdr_len]) catch {
                        shard.onError();
                        ctx.setError(.outbound_connection_failed);
                        logger.connError("[conn={d}][tag={s}] OUTBOUND_HANDSHAKE_FAILED {s} -> {s}:{d} via {s}", .{
                            ctx.conn_id, ctx.inboundTag(), ctx.clientIp(),
                            effective.host(), effective.port, outbound_tag,
                        });
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
                    recordTrafficAndLog(ctx, runtime, r, logger);
                },
                else => {
                    shard.onError();
                    return;
                },
            }
        },
        .vmess => {
            // VMess AEAD handshake + VMessStream wrap
            switch (outbound.proto) {
                .vmess => |*v| {
                    const hs = v.encodeHandshake(effective, .tcp) catch {
                        shard.onError();
                        ctx.setError(.protocol_encode_failed);
                        logger.connError("[conn={d}][tag={s}] OUTBOUND_HANDSHAKE_FAILED {s} -> {s}:{d} via {s}", .{
                            ctx.conn_id, ctx.inboundTag(), ctx.clientIp(),
                            effective.host(), effective.port, outbound_tag,
                        });
                        return;
                    };

                    // Send handshake wire data
                    target_tcp.writeAll(hs.data[0..hs.data_len]) catch {
                        shard.onError();
                        ctx.setError(.outbound_connection_failed);
                        logger.connError("[conn={d}][tag={s}] OUTBOUND_HANDSHAKE_FAILED {s} -> {s}:{d} via {s}", .{
                            ctx.conn_id, ctx.inboundTag(), ctx.clientIp(),
                            effective.host(), effective.port, outbound_tag,
                        });
                        return;
                    };

                    // Read server response
                    vmess_outbound.VMessOutbound.readResponse(
                        std.net.Stream,
                        &target_tcp,
                        &hs.response_key,
                        &hs.response_iv,
                        hs.response_header,
                    ) catch {
                        shard.onError();
                        ctx.setError(.vmess_invalid_response);
                        logger.connError("[conn={d}][tag={s}] OUTBOUND_RESPONSE_FAILED {s} -> {s}:{d} via {s}", .{
                            ctx.conn_id, ctx.inboundTag(), ctx.clientIp(),
                            effective.host(), effective.port, outbound_tag,
                        });
                        return;
                    };

                    // Wrap with VMessStream
                    const cipher = hs.security.toAeadCipher() orelse {
                        // No AEAD cipher → relay raw after handshake
                        const target_adapter = StreamAdapter.fromNetStream(&target_tcp);
                        const result = if (initial_payload.len > 0)
                            relay_mod.doRelayAdaptedWithFirstPacket(client_adapter.*, target_adapter, initial_payload, shard, cfg)
                        else
                            relay_mod.doRelayAdapted(client_adapter.*, target_adapter, shard, cfg);
                        recordTrafficAndLog(ctx, runtime, result, logger);
                        return;
                    };

                    var vmess_target = vmess_stream_mod.VMessStream(std.net.Stream).init(
                        target_tcp,
                        cipher,
                        hs.response_key, // server→us: we read with response keys
                        hs.response_iv,
                        hs.request_key, // us→server: we write with request keys
                        hs.request_iv,
                        hs.options,
                    );

                    // Send initial payload through VMessStream
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
                    recordTrafficAndLog(ctx, runtime, r, logger);
                },
                else => {
                    shard.onError();
                    return;
                },
            }
        },
        .shadowsocks => {
            // SS: salt + AEAD chunks through SsStream
            switch (outbound.proto) {
                .ss => |*s| {
                    const write_keys = s.generateWriteKeys() catch {
                        shard.onError();
                        ctx.setError(.protocol_encode_failed);
                        logger.connError("[conn={d}][tag={s}] OUTBOUND_HANDSHAKE_FAILED {s} -> {s}:{d} via {s}", .{
                            ctx.conn_id, ctx.inboundTag(), ctx.clientIp(),
                            effective.host(), effective.port, outbound_tag,
                        });
                        return;
                    };

                    // Encode target address (goes as first plaintext in SS stream)
                    var addr_buf: [256]u8 = undefined;
                    const addr_len = ss_outbound.SsOutbound.encodeAddress(effective, &addr_buf) orelse {
                        shard.onError();
                        ctx.setError(.protocol_encode_failed);
                        return;
                    };

                    // Build first payload: address + initial data
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

                    // Write address + initial payload as first encrypted chunk
                    ss_target.writeAll(first_buf[0..first_len]) catch {
                        shard.onError();
                        ctx.setError(.outbound_connection_failed);
                        logger.connError("[conn={d}][tag={s}] OUTBOUND_HANDSHAKE_FAILED {s} -> {s}:{d} via {s}", .{
                            ctx.conn_id, ctx.inboundTag(), ctx.clientIp(),
                            effective.host(), effective.port, outbound_tag,
                        });
                        return;
                    };

                    const target_adapter = StreamAdapter.from(
                        ss_stream_mod.SsStream(std.net.Stream),
                        &ss_target,
                    );
                    const result = relay_mod.doRelayAdapted(client_adapter.*, target_adapter, shard, cfg);
                    var r = result;
                    r.bytes_up += initial_payload.len;
                    recordTrafficAndLog(ctx, runtime, r, logger);
                },
                else => {
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
) void {
    ctx.bytes_up = result.bytes_up;
    ctx.bytes_down = result.bytes_down;
    ctx.transitionTo(.closed);
    runtime.tracker.add(ctx.user_id, result.bytes_up, result.bytes_down);

    // Format bytes for readability
    var up_buf: [32]u8 = undefined;
    var down_buf: [32]u8 = undefined;
    const up_str = types.formatBytes(result.bytes_up, &up_buf);
    const down_str = types.formatBytes(result.bytes_down, &down_buf);
    const duration = ctx.durationMs();
    const effective = ctx.effectiveTarget();
    const status: []const u8 = if (result.err == null) "ok" else "error";

    logger.access("from {s} closed {s}:{s}:{d} [{s} -> {s}] email:{s} {s} {s}/{s} {d}ms", .{
        ctx.clientIp(),
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
