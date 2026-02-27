/// Coroutine-based proxy session handler — zero protocol knowledge orchestrator.
///
/// Each accepted connection spawns one coroutine that runs this linear lifecycle:
///   1. Build inbound Transport (TLS handshake if enabled)
///   2. Parse protocol header via InboundHandler vtable
///   3. Route decision (direct/outbound proxy)
///   4. Connect to target (DNS resolve + TCP connect)
///   5. Build outbound Transport (TLS + WS handshake)
///   6. Outbound protocol handshake via OutboundHandler vtable
///   7. Bidirectional relay via Codec vtable
///   8. Close + log
///
/// All protocol-specific logic lives in vtable implementations.
/// Adding a new protocol or transport requires zero changes here.
const std = @import("std");
const zio = @import("zio");
const log = @import("log.zig");
const config_mod = @import("config.zig");
const session_mod = @import("session.zig");
const conn_types = @import("conn_types.zig");
const router_mod = @import("../router/router.zig");
const Worker = @import("worker.zig").Worker;
const InboundResult = @import("inbound_result.zig").InboundResult;
const ConnectAction = @import("inbound_result.zig").ConnectAction;
const TargetAddress = session_mod.TargetAddress;

// Transport layer — vtable + builder dependencies
const tls_mod = @import("../transport/tls_stream.zig");
const ws_mod = @import("../transport/ws_stream.zig");
const transport_mod = @import("transport.zig");
const proxy_protocol = @import("../protocol/proxy_protocol.zig");
const ip_error_ban_mod = @import("ip_error_ban.zig");
const Transport = transport_mod.Transport;
const TransportStorage = transport_mod.TransportStorage;

// Codec layer — vtable
const codec_mod = @import("codec.zig");
const Codec = codec_mod.Codec;
const CodecPair = codec_mod.CodecPair;

// Protocol handler vtables
const inbound_mod = @import("inbound_handler.zig");
const outbound_mod = @import("outbound_handler.zig");
const InboundHandler = inbound_mod.InboundHandler;
const OutboundHandler = outbound_mod.OutboundHandler;

// VMess replay filter — needed by Shared (cross-session state)
const vmess_protocol = @import("../protocol/vmess/vmess_protocol.zig");

// Buffer pool
const buf_pool_mod = @import("buf_pool.zig");

// UDP relay
const udp_packet = @import("../udp/udp_packet.zig");
const UdpSys = @import("../udp/udp_sys.zig").UdpSys;

const ParsedAction = @import("inbound_result.zig").ParsedAction;

/// Pool for per-session buffers — avoids repeated 216KB heap alloc/free.
pub const BufPool = buf_pool_mod.FixedPool(SessionBufs, 64);

/// Shared resources for all session handlers (thread-safe).
pub const Shared = struct {
    allocator: std.mem.Allocator,
    router: *router_mod.Router,
    ip_error_ban: ip_error_ban_mod.IpErrorBan = .{},
    replay_filter: vmess_protocol.ReplayFilter = .{},
    replay_mutex: std.Thread.Mutex = .{},
    active_sessions: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    total_sessions: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    buf_pool: BufPool,
};

/// Buffer size for relay I/O — must exceed max VMess chunk wire size (~18.5KB).
const buf_size: usize = 20 * 1024;
/// Max plaintext per encrypt call. Must not exceed SS AEAD max_payload_size (0x3FFF = 16383);
/// also leaves room for VMess AEAD overhead (tag + padding) within buf_size.
const max_encrypt_payload: usize = 16383;
/// Max bytes to dump as hex when decrypt/incomplete anomalies occur.
const error_sample_bytes: usize = 24;

/// Heap-allocated per-session buffers.
const SessionBufs = struct {
    // Transport layer I/O (TLS/WS internal buffers)
    in_read: [buf_size]u8 align(8) = undefined, // align(8) ensures FixedPool Node overlay is safe
    in_write: [buf_size]u8 = undefined,
    out_read: [buf_size]u8 = undefined,
    out_write: [buf_size]u8 = undefined,

    // Protocol parsing + outbound handshake
    proto: [8192]u8 = undefined,
    payload: [8192]u8 = undefined,

    // Relay uplink (client → target)
    up_data: [buf_size]u8 = undefined,
    up_dec: [buf_size]u8 = undefined,
    up_enc: [buf_size]u8 = undefined,

    // Relay downlink (target → client)
    dl_data: [buf_size]u8 = undefined,
    dl_dec: [buf_size]u8 = undefined,
    dl_enc: [buf_size]u8 = undefined,
};

const hs_timeout: zio.Timeout = .{ .duration = .fromSeconds(30) };
const relay_timeout: zio.Timeout = .{ .duration = .fromSeconds(300) };
const write_timeout: zio.Timeout = .{ .duration = .fromSeconds(15) };

const Logger = log.ScopedLogger;

/// Per-session logging context — tracks current stage and target for error diagnostics.
const SessionLog = struct {
    stage: []const u8 = "init",
    target_buf: [128]u8 = [_]u8{0} ** 128,
    target_len: u8 = 0,

    fn setTarget(self: *SessionLog, target: *const TargetAddress) void {
        const s = switch (target.addr_type) {
            .ipv4 => std.fmt.bufPrint(&self.target_buf, "{d}.{d}.{d}.{d}:{d}", .{
                target.ip4[0], target.ip4[1], target.ip4[2], target.ip4[3], target.port,
            }) catch return,
            .ipv6 => std.fmt.bufPrint(&self.target_buf, "[ipv6]:{d}", .{target.port}) catch return,
            .domain => std.fmt.bufPrint(&self.target_buf, "{s}:{d}", .{ target.getDomain(), target.port }) catch return,
            .none => return,
        };
        self.target_len = @intCast(s.len);
    }

    fn getTarget(self: *const SessionLog) []const u8 {
        return self.target_buf[0..self.target_len];
    }
};

fn shouldCountIpBanError(err: anyerror) bool {
    return switch (err) {
        // Ban only on authentication failures.
        error.VMessAuthFailed,
        error.TrojanAuthFailed,
        => true,
        else => false,
    };
}

// ══════════════════════════════════════════════════════════════
//  Entry Point
// ══════════════════════════════════════════════════════════════

/// Spawn target: called from dispatcher's accept loop for each new connection.
pub fn handleSession(
    stream: zio.net.Stream,
    info: *const Worker.ListenerInfo,
    shared: *Shared,
) void {
    defer stream.close();
    const client_ip_hash = ip_error_ban_mod.hashIpAddress(stream.socket.address.ip);
    const session_id = shared.total_sessions.fetchAdd(1, .monotonic);
    _ = shared.active_sessions.fetchAdd(1, .monotonic);

    const executor_id: u16 = if (zio.getCurrentExecutorOrNull()) |exec| exec.id else 0;
    var logger = Logger.init(executor_id, info.getTag());
    logger.conn_id = session_id;
    logger.setSource(stream.socket.address.ip);

    defer {
        const remaining = shared.active_sessions.fetchSub(1, .monotonic);
        logger.debug("ENDED, active={d}", .{remaining -| 1});
    }

    const tag = info.getTag();
    logger.debug("START [{s}] tls={} proto={s}", .{
        tag, info.tls_enabled, @tagName(info.protocol),
    });

    var slog = SessionLog{};
    handleSessionInner(stream, info, shared, &slog, &logger) catch |err| {
        if (err == error.Canceled) {
            logger.debug("canceled at {s}", .{slog.stage});
            return;
        }
        if (shouldCountIpBanError(err)) {
            const now_ms = std.time.milliTimestamp();
            const ev = shared.ip_error_ban.recordError(client_ip_hash, now_ms);
            if (ev.banned_now) {
                logger.warn("ip_error_ban triggered: {d} errors/{d}s -> ban {d}s", .{
                    shared.ip_error_ban.threshold(),
                    shared.ip_error_ban.windowSeconds(),
                    shared.ip_error_ban.banSeconds(),
                });
            }
        }
        const target = slog.getTarget();
        switch (err) {
            error.OutOfMemory, error.UdpSocketFailed => {
                if (target.len > 0)
                    logger.err("[{s}] {s} -> {s}: {s}", .{ tag, slog.stage, target, @errorName(err) })
                else
                    logger.err("[{s}] {s}: {s}", .{ tag, slog.stage, @errorName(err) });
            },
            error.ClientDisconnected => {
                logger.debug("[{s}] {s}: client disconnected", .{ tag, slog.stage });
            },
            else => {
                if (target.len > 0)
                    logger.info("[{s}] {s} -> {s}: {s}", .{ tag, slog.stage, target, @errorName(err) })
                else
                    logger.info("[{s}] {s}: {s}", .{ tag, slog.stage, @errorName(err) });
            },
        }
    };
}

// ══════════════════════════════════════════════════════════════
//  Core Flow — zero protocol knowledge
// ══════════════════════════════════════════════════════════════

fn handleSessionInner(
    stream: zio.net.Stream,
    info: *const Worker.ListenerInfo,
    shared: *Shared,
    slog: *SessionLog,
    lg: *Logger,
) !void {
    const bufs = try shared.buf_pool.acquire();
    defer shared.buf_pool.release(bufs);

    // ── 1. Build inbound Transport (TLS handshake inside) ──
    slog.stage = "inbound_transport";
    var in_tls: ?tls_mod.TlsStream = null;
    defer if (in_tls) |*t| t.deinit();
    var in_ws_storage: ws_mod.WsStream = undefined;
    var in_storage: TransportStorage = .{};

    const in_t = try buildInboundTransport(
        stream,
        info,
        &in_tls,
        &in_ws_storage,
        &in_storage,
        &bufs.in_read,
        &bufs.in_write,
        lg,
    );

    // ── 2. Build InboundHandler + parse protocol ──
    slog.stage = "protocol_parse";
    var in_handler_storage: inbound_mod.InboundHandlerStorage = .{};
    const inbound = buildInboundHandler(info, shared, &in_handler_storage);

    lg.debug("parsing protocol ({s})", .{@tagName(info.protocol)});
    const parsed = try parseProtocol(in_t, inbound, bufs, lg);
    var action = parsed.action;
    slog.setTarget(&action.target);
    lg.debug("parsed: udp={} target={s} payload={d}B", .{
        parsed.is_udp, slog.getTarget(), action.payload_len,
    });
    switch (action.protocol_state) {
        .vmess => |vs| {
            const opts = vs.request_state.options;
            lg.debug("vmess opts (debug-temp): auth_length={} chunk_masking={} global_padding={}", .{
                opts.auth_length,
                opts.chunk_masking,
                opts.global_padding,
            });
        },
        else => {},
    }

    // ── 3. Decrypt initial payload via inbound codec ──
    const in_codecs = inbound.codecs(&action.protocol_state);
    var initial_payload: ?[]const u8 = null;
    if (action.payload_len > 0) {
        initial_payload = try decryptInitialPayload(&action, in_codecs.decoder, bufs, lg);
    }

    // ── 4. UDP relay (if client requested UDP associate) ──
    if (parsed.is_udp) {
        slog.stage = "udp_relay";
        lg.debug("entering UDP relay", .{});
        return handleUdpRelay(in_t, &action, initial_payload, info, lg);
    }

    // ── 5. Route decision ──
    var route_ctx = session_mod.SessionContext{
        .protocol = info.protocol,
        .transport = info.transport,
        .target = action.target,
    };
    const tag = info.tag_buf[0..info.tag_len];
    const tl: u8 = @intCast(@min(tag.len, route_ctx.inbound_tag.len));
    @memcpy(route_ctx.inbound_tag[0..tl], tag[0..tl]);
    route_ctx.inbound_tag_len = tl;

    const route_result = shared.router.route(&route_ctx);
    const out_config: ?*const config_mod.OutConfig = if (route_result) |rr| rr.out else null;

    if (out_config) |oc| {
        lg.debug("route: outbound proto={s} transport={s}", .{
            @tagName(oc.protocol), @tagName(oc.transport),
        });
    } else {
        lg.debug("route: DIRECT", .{});
    }

    // ── Access log (one line per session, emitted after routing) ──
    {
        const out_label: []const u8 = if (out_config) |oc| @tagName(oc.protocol) else "direct";
        if (action.user_id >= 0) {
            lg.info("{s} {s} [{s}>{s}] uid:{d}", .{
                action.protoLabel(), slog.getTarget(), tag, out_label, action.user_id,
            });
        } else {
            lg.info("{s} {s} [{s}>{s}]", .{
                action.protoLabel(), slog.getTarget(), tag, out_label,
            });
        }
    }

    // ── 6. Connect to target ──
    slog.stage = "connect";
    const effective_target = resolveEffectiveTarget(&action.target, out_config);
    lg.debug("connecting to target...", .{});
    const target_stream = try connectTarget(&effective_target, info);
    defer target_stream.close();
    lg.debug("target connected", .{});

    // ── 7. Build outbound Transport (TLS + WS handshake inside) ──
    slog.stage = "outbound_transport";
    var out_tls: ?tls_mod.TlsStream = null;
    defer if (out_tls) |*t| t.deinit();
    var out_tls_ctx: ?tls_mod.TlsContext = null;
    defer if (out_tls_ctx) |*c| c.deinit();
    var out_ws_storage: ws_mod.WsStream = undefined;
    var out_storage: TransportStorage = .{};

    const out_t = try buildOutboundTransport(
        target_stream,
        out_config,
        &out_tls,
        &out_tls_ctx,
        &out_ws_storage,
        &out_storage,
        &bufs.out_read,
        &bufs.out_write,
        lg,
    );

    // ── 8. Outbound protocol handshake ──
    slog.stage = "outbound_handshake";
    var out_handler_storage: outbound_mod.OutboundHandlerStorage = .{};
    const outbound = buildOutboundHandler(out_config, &out_handler_storage);

    lg.debug("outbound handshake starting", .{});
    try outbound.handshake(
        out_t,
        &action.target,
        initial_payload,
        &bufs.up_data, // 20KB: proto (8192) too small for header + full initial_payload
        &bufs.payload,
        hs_timeout,
    );
    const out_codecs = outbound.codecs();
    lg.debug("outbound handshake done", .{});

    // ── 9. Send inbound response (VMess header / SS salt) ──
    if (inbound.response(&action)) |resp| {
        lg.debug("sending inbound response ({d}B)", .{resp.len});
        try in_t.write(resp, write_timeout);
    }

    // ── 10. Bidirectional relay ──
    slog.stage = "relay";
    lg.debug("entering RELAY", .{});
    try relayBidirectional(in_t, out_t, in_codecs, out_codecs, bufs, lg);
    lg.debug("relay finished normally", .{});
}

// ══════════════════════════════════════════════════════════════
//  Builder Functions — the only place with transport/protocol knowledge
// ══════════════════════════════════════════════════════════════

fn buildInboundTransport(
    stream: zio.net.Stream,
    info: *const Worker.ListenerInfo,
    in_tls: *?tls_mod.TlsStream,
    in_ws_storage: *ws_mod.WsStream,
    storage: *TransportStorage,
    read_buf: []u8,
    write_buf: []u8,
    lg: *Logger,
) !Transport {
    storage.raw = .{ .stream = stream };
    var current = storage.raw.transport();
    current = try applyProxyProtocolAutoDetect(current, storage, lg);

    if (info.tls_enabled) {
        lg.debug("inbound TLS handshake starting", .{});
        const ctx = info.tls_ctx orelse return error.TlsNotConfigured;
        in_tls.* = tls_mod.TlsStream.initServer(ctx.ctx) catch return error.TlsInitFailed;
        storage.tls_transport = .{
            .lower = current,
            .tls = &in_tls.*.?,
            .read_buf = read_buf,
            .write_buf = write_buf,
        };
        try storage.tls_transport.doHandshake(hs_timeout);
        current = storage.tls_transport.transport();
        lg.debug("inbound TLS handshake done", .{});
    }

    if (info.transport == .ws or info.transport == .wss) {
        lg.debug("inbound WS handshake starting", .{});
        in_ws_storage.* = ws_mod.WsStream.initServer(info.getWsPath(), "");
        storage.ws_transport = .{
            .lower = current,
            .ws = in_ws_storage,
            .read_buf = read_buf,
            .write_buf = write_buf,
        };
        try storage.ws_transport.doHandshake(hs_timeout);
        current = storage.ws_transport.transport();
        lg.debug("inbound WS handshake done", .{});
    }

    return current;
}

fn applyProxyProtocolAutoDetect(
    current: Transport,
    storage: *TransportStorage,
    lg: *Logger,
) !Transport {
    var probe_buf: [8192]u8 = undefined;
    const first_cap = @min(@as(usize, 512), probe_buf.len);

    var total = try current.read(probe_buf[0..first_cap], hs_timeout);
    if (total == 0) return error.ConnectionClosed;

    while (proxyProtocolNeedMore(probe_buf[0..total]) and total < probe_buf.len) {
        const n = try current.read(probe_buf[total..], hs_timeout);
        if (n == 0) break;
        total += n;

        const early = proxy_protocol.parse(probe_buf[0..total]);
        if (early.success) break;
    }

    const parsed = proxy_protocol.parse(probe_buf[0..total]);
    const replay = if (parsed.success) probe_buf[parsed.consumed..total] else probe_buf[0..total];
    storage.prefixed_transport = transport_mod.PrefixedTransport.init(current, replay);

    if (parsed.success) {
        var src_buf: [96]u8 = undefined;
        if (formatProxySource(parsed, &src_buf)) |src| {
            lg.setSourceText(src);
            lg.debug("proxy_protocol detected: src={s} consumed={d} replay={d}", .{
                src,
                parsed.consumed,
                replay.len,
            });
        } else {
            lg.debug("proxy_protocol detected: consumed={d} replay={d}", .{
                parsed.consumed,
                replay.len,
            });
        }
    } else if (proxyProtocolNeedMore(probe_buf[0..total])) {
        lg.warn("proxy_protocol candidate incomplete/invalid, fallback replay={d}", .{replay.len});
    }

    return storage.prefixed_transport.transport();
}

fn proxyProtocolNeedMore(data: []const u8) bool {
    const v2_sig = [12]u8{ 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };
    const v1_prefix = "PROXY ";

    if (isPrefix(data, &v2_sig)) return true;
    if (data.len >= v2_sig.len and std.mem.eql(u8, data[0..v2_sig.len], &v2_sig)) {
        if (data.len < 16) return true;
        const addr_len = (@as(usize, data[14]) << 8) | @as(usize, data[15]);
        return data.len < 16 + addr_len;
    }

    if (isPrefix(data, v1_prefix)) return true;
    if (data.len >= v1_prefix.len and std.mem.eql(u8, data[0..v1_prefix.len], v1_prefix)) {
        return std.mem.indexOf(u8, data, "\r\n") == null;
    }

    return false;
}

fn isPrefix(data: []const u8, full: []const u8) bool {
    if (data.len > full.len) return false;
    return std.mem.eql(u8, data, full[0..data.len]);
}

fn formatProxySource(parsed: proxy_protocol.ParseResult, out: *[96]u8) ?[]const u8 {
    if (parsed.src_ip4 == null and parsed.src_ip6 == null) return null;

    var ip_buf: [64]u8 = undefined;
    const ip = proxy_protocol.fmtIp(parsed, &ip_buf);
    if (parsed.src_ip6 != null) {
        return std.fmt.bufPrint(out, "[{s}]:{d}", .{ ip, parsed.src_port }) catch null;
    }
    return std.fmt.bufPrint(out, "{s}:{d}", .{ ip, parsed.src_port }) catch null;
}

fn buildOutboundTransport(
    target: zio.net.Stream,
    out_config: ?*const config_mod.OutConfig,
    out_tls: *?tls_mod.TlsStream,
    out_tls_ctx: *?tls_mod.TlsContext,
    out_ws_storage: *ws_mod.WsStream,
    storage: *TransportStorage,
    read_buf: []u8,
    write_buf: []u8,
    lg: *Logger,
) !Transport {
    storage.raw = .{ .stream = target };
    var current = storage.raw.transport();

    const oc = out_config orelse return current;
    const need_out_tls = (oc.transport == .tls or oc.transport == .wss) or oc.tls;
    const need_out_ws = (oc.transport == .ws or oc.transport == .wss);

    // Outbound TLS
    if (need_out_tls) {
        lg.debug("outbound TLS handshake starting", .{});
        out_tls_ctx.* = tls_mod.TlsContext.initClient() catch return error.OutTlsInitFailed;
        out_tls_ctx.*.?.configureOutbound(
            oc.skip_cert_verify,
            if (oc.sni_len > 0) oc.getSni() else null,
        );
        const sni = if (oc.sni_len > 0) oc.getSni() else null;
        out_tls.* = tls_mod.TlsStream.initClient(out_tls_ctx.*.?.ctx, sni) catch return error.OutTlsInitFailed;
        storage.tls_transport = .{
            .lower = current,
            .tls = &out_tls.*.?,
            .read_buf = read_buf,
            .write_buf = write_buf,
        };
        try storage.tls_transport.doHandshake(hs_timeout);
        current = storage.tls_transport.transport();
        lg.debug("outbound TLS handshake done", .{});
    }

    // Outbound WebSocket
    if (need_out_ws) {
        lg.debug("outbound WS handshake starting", .{});
        out_ws_storage.* = ws_mod.WsStream.initClient(
            oc.ws_path_buf[0..oc.ws_path_len],
            oc.ws_host_buf[0..oc.ws_host_len],
        );
        storage.ws_transport = .{
            .lower = current,
            .ws = out_ws_storage,
            .read_buf = read_buf,
            .write_buf = write_buf,
        };
        try storage.ws_transport.doHandshake(hs_timeout);
        current = storage.ws_transport.transport();
        lg.debug("outbound WS handshake done", .{});
    }

    return current;
}

fn buildInboundHandler(
    info: *const Worker.ListenerInfo,
    shared: *Shared,
    storage: *inbound_mod.InboundHandlerStorage,
) InboundHandler {
    switch (info.protocol) {
        .trojan => {
            storage.trojan = .{ .user_store = info.user_store };
            return storage.trojan.handler();
        },
        .vmess => {
            storage.vmess = .{
                .user_store = info.user_store,
                .replay_filter = &shared.replay_filter,
                .replay_mutex = &shared.replay_mutex,
                .hot_cache = if (info.hot_cache.ttl > 0) @constCast(&info.hot_cache) else null,
                .allocator = shared.allocator,
            };
            return storage.vmess.handler();
        },
        .shadowsocks => {
            if (info.ss_inbound) |ss| {
                storage.ss = .{
                    .method = @enumFromInt(ss.method),
                    .psk = ss.psk[0..ss.key_len],
                };
                return storage.ss.handler();
            }
            // Fallback: create a trojan handler (will reject all connections)
            storage.trojan = .{ .user_store = null };
            return storage.trojan.handler();
        },
        else => {
            storage.trojan = .{ .user_store = null };
            return storage.trojan.handler();
        },
    }
}

fn buildOutboundHandler(
    out_config: ?*const config_mod.OutConfig,
    storage: *outbound_mod.OutboundHandlerStorage,
) OutboundHandler {
    const oc = out_config orelse {
        storage.direct = .{};
        return storage.direct.handler();
    };

    switch (oc.protocol) {
        .trojan => {
            storage.trojan = .{ .password_hash = &oc.trojan_password_hash };
            return storage.trojan.handler();
        },
        .vmess => {
            storage.vmess = .{
                .uuid = &oc.vmess_uuid,
                .security = @enumFromInt(oc.vmess_security),
            };
            return storage.vmess.handler();
        },
        .shadowsocks => {
            const method: @import("../protocol/shadowsocks/ss_crypto.zig").Method = @enumFromInt(oc.ss_method);
            storage.ss = .{
                .method = method,
                .psk = oc.ss_psk[0..method.keySize()],
            };
            return storage.ss.handler();
        },
        else => {
            storage.direct = .{};
            return storage.direct.handler();
        },
    }
}

// ══════════════════════════════════════════════════════════════
//  Generic Protocol Parse — zero protocol knowledge (streaming)
// ══════════════════════════════════════════════════════════════

fn parseProtocol(
    t: Transport,
    inbound: InboundHandler,
    bufs: *SessionBufs,
    lg: *Logger,
) !ParsedAction {
    lg.debug("proto: streaming parse", .{});
    // Each protocol implementation reads exactly the bytes it needs.
    // work_buf = up_data (20KB), plain_buf = up_dec (20KB), payload_buf = payload (8KB)
    const parsed = try inbound.parseStreaming(
        t,
        &bufs.up_data,
        &bufs.up_dec,
        &bufs.payload,
        hs_timeout,
        lg,
    );
    lg.debug("proto: parsed udp={} payload={d}B decrypted={}", .{
        parsed.is_udp, parsed.action.payload_len, parsed.action.payload_is_decrypted,
    });
    return parsed;
}

/// Return the initial payload for use in the outbound handshake.
/// SS streaming parse already decrypts the first AEAD frame, so we skip
/// re-decryption. VMess has no initial payload (relay handles it).
/// Trojan payload is raw plaintext.
fn decryptInitialPayload(
    action: *ConnectAction,
    decoder: Codec,
    bufs: *SessionBufs,
    lg: *Logger,
) !?[]const u8 {
    if (action.payload_len == 0) return null;

    const raw = bufs.payload[0..action.payload_len];

    // SS streaming: first frame already decrypted by parseStreaming
    if (action.payload_is_decrypted) {
        lg.debug("payload already decrypted: {d}B", .{action.payload_len});
        return raw;
    }

    if (decoder.is_noop) {
        return raw; // Trojan: passthrough codec, payload is plaintext
    }

    // VMess: payload_len == 0 (relay handles all chunks), so we never reach here.
    // Generic fallback: decrypt codec chunks from raw into up_enc.
    var dec_total: usize = 0;
    var consumed: usize = 0;
    while (consumed < raw.len) {
        const result = decoder.decrypt(raw[consumed..], bufs.up_enc[dec_total..]);
        switch (result) {
            .success => |s| {
                dec_total += s.plaintext_len;
                consumed += s.bytes_consumed;
            },
            .incomplete => break,
            .integrity_error => return error.InitialPayloadDecryptFailed,
        }
    }

    if (dec_total > 0) {
        @memcpy(bufs.payload[0..dec_total], bufs.up_enc[0..dec_total]);
        lg.debug("payload decrypted: {d}B -> {d}B", .{ raw.len, dec_total });
        return bufs.payload[0..dec_total];
    }

    return null;
}

// ══════════════════════════════════════════════════════════════
//  Generic Bidirectional Relay — zero protocol knowledge
// ══════════════════════════════════════════════════════════════

fn relayBidirectional(
    in_t: Transport,
    out_t: Transport,
    in_codecs: CodecPair,
    out_codecs: CodecPair,
    bufs: *SessionBufs,
    lg: *Logger,
) !void {
    lg.debug("relay: spawning uplink+downlink coroutines", .{});

    var done: zio.Notify = .init;
    var group: zio.Group = .init;
    defer {
        lg.debug("relay: canceling group", .{});
        group.cancel();
        lg.debug("relay: group canceled", .{});
    }

    try group.spawn(relayUplinkWrapper, .{
        &done, in_t, out_t,
        in_codecs.decoder, out_codecs.encoder,
        &bufs.up_data, &bufs.up_dec, &bufs.up_enc, lg,
    });
    try group.spawn(relayDownlinkWrapper, .{
        &done, out_t, in_t,
        out_codecs.decoder, in_codecs.encoder,
        &bufs.dl_data, &bufs.dl_dec, &bufs.dl_enc, lg,
    });

    lg.debug("relay: waiting for first direction to finish...", .{});
    done.wait() catch {};
    lg.debug("relay: done.wait() returned", .{});
}

fn relayUplinkWrapper(
    done: *zio.Notify,
    read_t: Transport,
    write_t: Transport,
    decoder: Codec,
    encoder: Codec,
    read_buf: *[buf_size]u8,
    dec_buf: *[buf_size]u8,
    enc_buf: *[buf_size]u8,
    lg: *Logger,
) void {
    defer {
        lg.debug("UPLINK done, signaling", .{});
        done.signal();
    }
    relayDirection(read_t, write_t, decoder, encoder, read_buf, dec_buf, enc_buf, lg, "UL") catch |err| {
        if (err != error.Canceled)
            lg.debug("UPLINK error: {s}", .{@errorName(err)});
    };
}

fn relayDownlinkWrapper(
    done: *zio.Notify,
    read_t: Transport,
    write_t: Transport,
    decoder: Codec,
    encoder: Codec,
    read_buf: *[buf_size]u8,
    dec_buf: *[buf_size]u8,
    enc_buf: *[buf_size]u8,
    lg: *Logger,
) void {
    defer {
        lg.debug("DOWNLINK done, signaling", .{});
        done.signal();
    }
    relayDirection(read_t, write_t, decoder, encoder, read_buf, dec_buf, enc_buf, lg, "DL") catch |err| {
        if (err != error.Canceled)
            lg.debug("DOWNLINK error: {s}", .{@errorName(err)});
    };
}

/// Generic relay direction: read → decrypt → encrypt → write.
/// Handles frame accumulation for codecs that return .incomplete.
fn relayDirection(
    read_t: Transport,
    write_t: Transport,
    decoder: Codec,
    encoder: Codec,
    read_buf: *[buf_size]u8,
    dec_buf: *[buf_size]u8,
    enc_buf: *[buf_size]u8,
    lg: *Logger,
    comptime tag: []const u8,
) !void {
    var chunks: u64 = 0;
    var total_bytes: u64 = 0;
    var accum: usize = 0;
    lg.debug(tag ++ ": starting loop", .{});

    while (true) {
        const n = try read_t.read(read_buf[accum..], relay_timeout);
        if (n == 0) {
            lg.debug(tag ++ ": EOF after {d} chunks, {d}B total", .{ chunks, total_bytes });
            return;
        }
        accum += n;

        if (decoder.is_noop and encoder.is_noop) {
            // Zero-copy passthrough (e.g. Trojan → Direct)
            try write_t.write(read_buf[0..accum], write_timeout);
            chunks += 1;
            total_bytes += accum;
            accum = 0;
        } else {
            // Codec processing — accumulate for partial frames
            var consumed: usize = 0;
            while (consumed < accum) {
                if (decoder.is_noop) {
                    // No decrypt — plaintext is raw data, just encrypt + send
                    try encryptAndSend(write_t, encoder, read_buf[consumed..accum], enc_buf);
                    total_bytes += accum - consumed;
                    chunks += 1;
                    consumed = accum;
                } else {
                    // Decrypt one frame
                    const result = decoder.decrypt(read_buf[consumed..accum], dec_buf);
                    switch (result) {
                        .success => |s| {
                            if (s.plaintext_len > 0) {
                                if (encoder.is_noop) {
                                    try write_t.write(dec_buf[0..s.plaintext_len], write_timeout);
                                } else {
                                    try encryptAndSend(write_t, encoder, dec_buf[0..s.plaintext_len], enc_buf);
                                }
                                total_bytes += s.plaintext_len;
                            }
                            consumed += s.bytes_consumed;
                            chunks += 1;
                        },
                        .incomplete => {
                            if (consumed == 0 and accum == read_buf.len) {
                                const sample_len = @min(error_sample_bytes, accum);
                                lg.warn(tag ++ ": decoder incomplete with full buffer read={d}B accum={d} dec_noop={} enc_noop={} sample={x}", .{
                                    n,
                                    accum,
                                    decoder.is_noop,
                                    encoder.is_noop,
                                    read_buf[0..sample_len],
                                });
                            }
                            break;
                        },
                        .integrity_error => {
                            const pending = accum - consumed;
                            const sample_len = @min(error_sample_bytes, pending);
                            if (decoder.decryptDebug()) |dbg| switch (dbg) {
                                .vmess => |v| {
                                    if (sample_len > 0) {
                                        lg.warn(tag ++ ": decrypt integrity_error chunk={d} total={d}B read={d}B accum={d} consumed={d} pending={d} proto=vmess reason={s} sec={s} nonce={d} size_nonce={d} auth_len={} mask={} padding={} data_len={d} size_field={d} total_payload={d} padding_len={d} enc_len={d} tag_len={d} wire_len={d} sample={x}", .{
                                            chunks + 1,
                                            total_bytes,
                                            n,
                                            accum,
                                            consumed,
                                            pending,
                                            @tagName(v.kind),
                                            @tagName(v.security),
                                            v.nonce_counter,
                                            v.auth_length_nonce_counter,
                                            v.auth_length,
                                            v.chunk_masking,
                                            v.global_padding,
                                            v.data_len,
                                            v.size_field_len,
                                            v.total_payload,
                                            v.padding_len,
                                            v.enc_len,
                                            v.tag_len,
                                            v.wire_len,
                                            read_buf[consumed .. consumed + sample_len],
                                        });
                                    } else {
                                        lg.warn(tag ++ ": decrypt integrity_error chunk={d} total={d}B read={d}B accum={d} consumed={d} pending=0 proto=vmess reason={s} sec={s} nonce={d} size_nonce={d} auth_len={} mask={} padding={} data_len={d} size_field={d} total_payload={d} padding_len={d} enc_len={d} tag_len={d} wire_len={d}", .{
                                            chunks + 1,
                                            total_bytes,
                                            n,
                                            accum,
                                            consumed,
                                            @tagName(v.kind),
                                            @tagName(v.security),
                                            v.nonce_counter,
                                            v.auth_length_nonce_counter,
                                            v.auth_length,
                                            v.chunk_masking,
                                            v.global_padding,
                                            v.data_len,
                                            v.size_field_len,
                                            v.total_payload,
                                            v.padding_len,
                                            v.enc_len,
                                            v.tag_len,
                                            v.wire_len,
                                        });
                                    }
                                },
                            } else if (sample_len > 0) {
                                lg.warn(tag ++ ": decrypt integrity_error chunk={d} total={d}B read={d}B accum={d} consumed={d} pending={d} dec_noop={} enc_noop={} sample={x}", .{
                                    chunks + 1,
                                    total_bytes,
                                    n,
                                    accum,
                                    consumed,
                                    pending,
                                    decoder.is_noop,
                                    encoder.is_noop,
                                    read_buf[consumed .. consumed + sample_len],
                                });
                            } else {
                                lg.warn(tag ++ ": decrypt integrity_error chunk={d} total={d}B read={d}B accum={d} consumed={d} pending=0 dec_noop={} enc_noop={}", .{
                                    chunks + 1,
                                    total_bytes,
                                    n,
                                    accum,
                                    consumed,
                                    decoder.is_noop,
                                    encoder.is_noop,
                                });
                            }
                            return error.DecryptFailed;
                        },
                    }
                }
            }

            // Shift unconsumed data to buffer start
            if (consumed > 0) {
                const remaining = accum - consumed;
                if (remaining > 0) std.mem.copyForwards(u8, read_buf[0..remaining], read_buf[consumed..accum]);
                accum = remaining;
            }
        }

        if (chunks > 0 and (chunks <= 5 or chunks % 100 == 0)) {
            lg.debug(tag ++ ": chunk#{d} read={d}B accum={d} dec_noop={} enc_noop={} total={d}B", .{
                chunks, n, accum, decoder.is_noop, encoder.is_noop, total_bytes,
            });
        }
    }
}

/// Encrypt plaintext in safe-sized chunks and send via transport.
fn encryptAndSend(t: Transport, encoder: Codec, plaintext: []const u8, enc_buf: []u8) !void {
    var offset: usize = 0;
    while (offset < plaintext.len) {
        const end = @min(offset + max_encrypt_payload, plaintext.len);
        const n = encoder.encrypt(plaintext[offset..end], enc_buf) orelse return error.EncryptFailed;
        try t.write(enc_buf[0..n], write_timeout);
        offset = end;
    }
}

// ══════════════════════════════════════════════════════════════
//  Target Connection
// ══════════════════════════════════════════════════════════════

fn resolveEffectiveTarget(target: *const TargetAddress, out_config: ?*const config_mod.OutConfig) TargetAddress {
    if (out_config) |oc| {
        if (oc.server_host_len > 0) {
            var proxy_target = TargetAddress{};
            proxy_target.setDomain(oc.getServerHost(), oc.server_port);
            return proxy_target;
        } else if (oc.server_addr) |addr| {
            var proxy_target = TargetAddress{};
            const sa: *const [16]u8 = @ptrCast(std.mem.asBytes(&addr.any));
            const port = std.mem.readInt(u16, sa[2..4], .big);
            proxy_target.setIpv4(sa[4..8].*, port);
            return proxy_target;
        }
    }
    return target.*;
}

fn connectTarget(
    target: *const TargetAddress,
    info: *const Worker.ListenerInfo,
) !zio.net.Stream {
    _ = info;
    switch (target.addr_type) {
        .ipv4 => {
            const addr = zio.net.IpAddress.initIp4(target.ip4, target.port);
            return addr.connect(.{ .timeout = hs_timeout });
        },
        .ipv6 => {
            const addr = zio.net.IpAddress.initIp6(target.ip6, target.port, 0, 0);
            return addr.connect(.{ .timeout = hs_timeout });
        },
        .domain => {
            return zio.net.tcpConnectToHost(target.getDomain(), target.port, .{ .timeout = hs_timeout });
        },
        .none => return error.NoTarget,
    }
}

// ══════════════════════════════════════════════════════════════
//  UDP Relay (V1: kept mostly unchanged, uses raw stream I/O)
// ══════════════════════════════════════════════════════════════

const UdpBufs = struct {
    pending: [16384]u8 = undefined,
    recv: [1500]u8 = undefined,
    down_enc: [2048]u8 = undefined,
};

fn handleUdpRelay(
    in_t: Transport,
    action: *const ConnectAction,
    initial_payload: ?[]const u8,
    info: *const Worker.ListenerInfo,
    lg: *Logger,
) !void {
    _ = action;

    const bind_ip4: ?[4]u8 = if (info.send_through_addr) |ba| blk: {
        const sa: *const [16]u8 = @ptrCast(&ba);
        if (sa[0] == 2 or sa[1] == 2) {
            break :blk sa[4..8].*;
        }
        break :blk null;
    } else null;

    const udp_sock = UdpSys.create(bind_ip4) orelse return error.UdpSocketFailed;
    defer UdpSys.close(udp_sock);

    var udp_bufs: UdpBufs = .{};

    var pending_len: usize = 0;
    if (initial_payload) |payload| {
        if (payload.len <= udp_bufs.pending.len) {
            @memcpy(udp_bufs.pending[0..payload.len], payload);
            pending_len = payload.len;
        }
    }

    processUdpUplink(&udp_bufs.pending, &pending_len, udp_sock);

    lg.debug("UDP relay: starting uplink+downlink", .{});

    var done: zio.Notify = .init;
    var group: zio.Group = .init;
    defer {
        lg.debug("UDP relay: canceling group", .{});
        group.cancel();
        lg.debug("UDP relay: group canceled", .{});
    }

    try group.spawn(udpUplinkWrapper, .{ &done, in_t, udp_sock, &udp_bufs, &pending_len, lg });
    try group.spawn(udpDownlinkWrapper, .{ &done, in_t, udp_sock, &udp_bufs, lg });

    done.wait() catch {};
    lg.debug("UDP relay: done", .{});
}

fn udpUplinkWrapper(
    done: *zio.Notify,
    in_t: Transport,
    udp_sock: usize,
    udp_bufs: *UdpBufs,
    pending_len: *usize,
    lg: *Logger,
) void {
    defer {
        lg.debug("UDP UL done, signaling", .{});
        done.signal();
    }
    udpUplinkLoop(in_t, udp_sock, udp_bufs, pending_len, lg) catch |err| {
        if (err != error.Canceled)
            lg.debug("UDP UL error: {s}", .{@errorName(err)});
    };
}

fn udpDownlinkWrapper(
    done: *zio.Notify,
    in_t: Transport,
    udp_sock: usize,
    udp_bufs: *UdpBufs,
    lg: *Logger,
) void {
    defer {
        lg.debug("UDP DL done, signaling", .{});
        done.signal();
    }
    udpDownlinkLoop(in_t, udp_sock, udp_bufs) catch |err| {
        if (err != error.Canceled)
            lg.debug("UDP DL error: {s}", .{@errorName(err)});
    };
}

fn udpUplinkLoop(
    in_t: Transport,
    udp_sock: usize,
    udp_bufs: *UdpBufs,
    pending_len: *usize,
    lg: *Logger,
) !void {
    while (true) {
        const n = try in_t.read(udp_bufs.pending[pending_len.*..], relay_timeout);
        if (n == 0) return;
        pending_len.* += n;
        lg.debug("UDP UL: read {d}B, pending={d}", .{ n, pending_len.* });
        processUdpUplink(&udp_bufs.pending, pending_len, udp_sock);
    }
}

fn udpDownlinkLoop(
    in_t: Transport,
    udp_sock: usize,
    udp_bufs: *UdpBufs,
) !void {
    while (true) {
        const recv_result = zio.blockInPlace(udpRecvBlocking, .{ udp_sock, &udp_bufs.recv }) orelse continue;

        var udp_target = TargetAddress{};
        if (recv_result.ip4) |ip4| {
            udp_target.setIpv4(ip4, recv_result.port);
        } else if (recv_result.ip6) |ip6| {
            udp_target.setIpv6(ip6, recv_result.port);
        } else continue;

        const enc_len = udp_packet.encodeTrojanUdpPacket(
            &udp_bufs.down_enc,
            &udp_target,
            udp_bufs.recv[0..recv_result.len],
        ) orelse continue;

        try in_t.write(udp_bufs.down_enc[0..enc_len], write_timeout);
    }
}

fn processUdpUplink(pending: *[16384]u8, pending_len: *usize, udp_sock: usize) void {
    while (pending_len.* > 0) {
        const parse_result = udp_packet.parseTrojanUdpPacket(pending[0..pending_len.*]);
        const pkt = switch (parse_result) {
            .success => |p| p,
            .incomplete => break,
            .protocol_error => break,
        };
        const payload = pending[pkt.payload_offset..][0..pkt.payload_len];
        const total_consumed = pkt.payload_offset + pkt.payload_len;

        // Send UDP payload to target
        switch (pkt.target.addr_type) {
            .ipv4 => _ = UdpSys.send4(udp_sock, payload, pkt.target.ip4, pkt.target.port),
            .ipv6 => _ = UdpSys.send6(udp_sock, payload, pkt.target.ip6, pkt.target.port),
            else => {},
        }

        const remaining = pending_len.* - total_consumed;
        if (remaining > 0) {
            std.mem.copyForwards(u8, pending[0..remaining], pending[total_consumed..pending_len.*]);
        }
        pending_len.* = remaining;
    }
}

fn udpRecvBlocking(udp_sock: usize, buf: *[1500]u8) ?UdpSys.RecvResult {
    return UdpSys.recv(udp_sock, buf);
}
