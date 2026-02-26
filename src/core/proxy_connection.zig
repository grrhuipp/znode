const std = @import("std");
const builtin = @import("builtin");
const xev = @import("xev");
const log = @import("log.zig");
const conn_fsm = @import("connection_fsm.zig");
const ConnFSM = conn_fsm.ConnFSM;
const config_mod = @import("config.zig");
const session_mod = @import("session.zig");
const user_store_mod = @import("user_store.zig");
const tls_mod = @import("../transport/tls_stream.zig");
const vmess_stream = @import("../protocol/vmess/vmess_stream.zig");
const vmess_relay = @import("../protocol/vmess/vmess_relay.zig");
const dns_resolver = @import("../dns/resolver.zig");
const udp_relay = @import("../udp/udp_relay_handler.zig");
const router_mod = @import("../router/router.zig");
const ss_crypto = @import("../protocol/shadowsocks/ss_crypto.zig");
const ws_mod = @import("../transport/ws_stream.zig");
const outbound_transport = @import("../transport/outbound_transport.zig");
const outbound_dispatch = @import("outbound_dispatch.zig");
const ss_relay = @import("../protocol/shadowsocks/ss_relay.zig");
const pp_mod = @import("../protocol/proxy_protocol.zig");
const dynamic_cert = @import("../transport/dynamic_cert.zig");
const tls_init = @import("../transport/tls_init.zig");
const Worker = @import("worker.zig").Worker;
const relay_pipeline = @import("relay_pipeline.zig");
const inbound_dispatch = @import("inbound_dispatch.zig");
const sniffer = @import("../sniff/sniffer.zig");
const buffer_pool = @import("buffer_pool.zig");
const conn_types = @import("conn_types.zig");
const conn_timeout = @import("conn_timeout.zig");
const TimeoutManager = conn_timeout.TimeoutManager;
const conn_metrics = @import("conn_metrics.zig");
const ConnMetrics = conn_metrics.ConnMetrics;
const conn_config = @import("conn_config.zig");
const ConnConfig = conn_config.ConnConfig;
const conn_lifecycle = @import("conn_lifecycle.zig");
const Lifecycle = conn_lifecycle.Lifecycle;
const outbound_side = @import("outbound_side.zig");
const OutboundSide = outbound_side.OutboundSide;
const inbound_side = @import("inbound_side.zig");
const InboundSide = inbound_side.InboundSide;

// ── Buffer pool tier aliases (all buffers borrowed from per-worker BufferPool) ──
// Core I/O buffers use medium tier (8KB = Xray buf.Size).
// Pending accumulation buffers use large tier (32KB) for AEAD chunks spanning TCP segments.
//
// Relay batch_limit (7680B) ensures all protocol layers fit within 8KB:
//   7680B plaintext → +34B VMess AEAD → +18B WS header+mask → +37B TLS ≈ 7769B < 8192
pub const pool_medium = buffer_pool.BufferPool.medium_size; // 8KB — recv, target, protocol, enc
pub const pool_iodata = buffer_pool.BufferPool.iodata_size; // 20KB — decrypt, send, pending (max 16KB AEAD chunk + overhead)

/// Relay batch limit: max plaintext bytes per write through the full protocol pipeline.
/// Sized so that VMess AEAD + WS frame + TLS record overhead stays within 8KB pool buffers.
pub const relay_batch_limit: usize = 7680;

const UdpSys = @import("../udp/udp_sys.zig").UdpSys;

/// Outbound protocol state — heap-allocated on-demand.
/// Used by VMess outbound (encrypt/decrypt), Trojan outbound, and outbound TLS buffering.
///
/// Organized into sub-structs for clear protocol/transport separation:
///   - `vmess`: VMess-specific crypto state (keys, stream states)
///   - `ws`: WebSocket transport state (frame tracking, pong buffering)
///   - Common: shared buffers used by all outbound protocols
pub const OutboundState = struct {
    // ── Common buffers (pool-borrowed on demand) ──
    enc_buf: ?[]u8 = null, // pool medium (8KB) — outbound encrypt + TLS output
    pending: ?[]u8 = null, // pool large (32KB) — downlink AEAD chunk accumulation
    pending_head: usize = 0,
    pending_tail: usize = 0,

    // ── VMess protocol state ──
    vmess: VMessState = .{},

    // ── Shadowsocks protocol state ──
    ss: SsState = .{},

    // ── WebSocket transport state ──
    ws: WsState = .{},

    /// VMess outbound protocol state: encryption keys and stream states.
    pub const VMessState = struct {
        request_state: ?vmess_stream.StreamState = null, // encrypt uplink to target
        response_state: ?vmess_stream.StreamState = null, // decrypt downlink from target
        body_key: [16]u8 = undefined,
        body_iv: [16]u8 = undefined,
        resp_header: u8 = 0,
    };

    /// Shadowsocks outbound protocol state: encrypt/decrypt stream states.
    pub const SsState = struct {
        encrypt: ?ss_crypto.StreamState = null, // outbound: znode → SS server encrypt
        decrypt: ?ss_crypto.StreamState = null, // outbound: SS server → znode decrypt
        first_sent: bool = false, // outbound: first packet (with salt) sent?
        down_pending: usize = 0, // outbound downlink: bytes in protocol_buf pending
    };

    /// WebSocket transport state: frame parsing, control frame handling.
    /// Active only when outbound WS/WSS transport is in use.
    pub const WsState = struct {
        frame_remaining: u32 = 0, // payload bytes remaining in current WS frame
        header_buf: [10]u8 = undefined, // partial WS header accumulation (max: 10 bytes, no mask server→client)
        header_len: u8 = 0,
        ctrl_skip: u32 = 0, // remaining control frame payload bytes to skip
        pong_buf: [140]u8 = undefined, // pending pong frame (max: 6 header + 4 mask + 125 payload)
        pong_len: u8 = 0,
        // Streaming: ping payload accumulation across reads
        ctrl_is_ping: bool = false,
        ping_payload: [125]u8 = undefined,
        ping_len: u8 = 0,
    };

    /// Strip WS frame headers from incoming data, extracting payload into output buffer.
    /// Server→client frames are NOT masked (RFC 6455). Returns payload bytes written, or null on close/error.
    ///
    /// Uses a unified 3-state machine (matching the inbound streaming pattern):
    ///   State A: mid data-frame payload → memcpy to output
    ///   State B: skipping control frame payload (accumulate ping payload for pong)
    ///   State C: parse new frame header (via header_buf accumulation)
    pub fn stripWsFrames(self: *OutboundState, data: []const u8, output: []u8) ?usize {
        var ws = &self.ws;
        var pos: usize = 0;
        var out_pos: usize = 0;

        while (pos < data.len) {
            // ── State A: Mid data-frame payload ──
            if (ws.frame_remaining > 0 and ws.ctrl_skip == 0) {
                const n = @min(
                    @as(usize, ws.frame_remaining),
                    @min(data.len - pos, output.len - out_pos),
                );
                if (n == 0) break; // output buffer full
                @memcpy(output[out_pos..][0..n], data[pos..][0..n]);
                out_pos += n;
                pos += n;
                ws.frame_remaining -= @intCast(n);
                continue;
            }

            // ── State B: Skipping control frame payload ──
            if (ws.ctrl_skip > 0) {
                const avail = @min(data.len - pos, @as(usize, ws.ctrl_skip));
                // Accumulate ping payload for pong response
                if (ws.ctrl_is_ping) {
                    const ping_room = @as(usize, 125) - @as(usize, ws.ping_len);
                    const ping_copy = @min(avail, ping_room);
                    if (ping_copy > 0) {
                        @memcpy(ws.ping_payload[ws.ping_len..][0..ping_copy], data[pos..][0..ping_copy]);
                        ws.ping_len += @intCast(ping_copy);
                    }
                }
                pos += avail;
                ws.ctrl_skip -= @intCast(avail);
                ws.frame_remaining -= @intCast(avail);

                // Control frame fully consumed — build pong if ping
                if (ws.ctrl_skip == 0 and ws.ctrl_is_ping) {
                    // Server→client ping is unmasked; pong must be masked (client→server)
                    if (ws_mod.encodeFrame(&ws.pong_buf, .pong, ws.ping_payload[0..ws.ping_len], true)) |pn| {
                        ws.pong_len = @intCast(pn);
                    }
                    ws.ctrl_is_ping = false;
                    ws.ping_len = 0;
                }
                continue;
            }

            // ── State C: Parse new frame header ──
            const remaining = data.len - pos;
            const header_space = @as(usize, 10) - @as(usize, ws.header_len);
            const to_copy = @min(remaining, header_space);
            @memcpy(ws.header_buf[ws.header_len..][0..to_copy], data[pos..][0..to_copy]);
            ws.header_len += @intCast(to_copy);
            pos += to_copy;

            if (ws_mod.parseFrameHeader(ws.header_buf[0..ws.header_len])) |hdr| {
                // Put back excess bytes (copied but belong to payload/next frame)
                const excess = @as(usize, ws.header_len) - hdr.header_size;
                pos -= excess;

                ws.frame_remaining = @intCast(hdr.payload_len);
                ws.header_len = 0;

                switch (hdr.opcode) {
                    .close => return null,
                    .ping => {
                        ws.ctrl_skip = ws.frame_remaining;
                        ws.ctrl_is_ping = true;
                        ws.ping_len = 0;
                    },
                    .pong => {
                        ws.ctrl_skip = ws.frame_remaining;
                    },
                    .binary, .text, .continuation => {}, // continue to State A
                }
            } else {
                // Server→client: unmasked, max header 10 bytes.
                // If 10+ bytes can't parse → corrupt data.
                if (ws.header_len >= 10) return null;
                break; // incomplete header, wait for more data
            }
        }

        return out_pos;
    }
};

// ── Shared types (defined in conn_types.zig, re-exported for backward compat) ──
pub const InboundProtocol = conn_types.InboundProtocol;
pub const OutboundKind = conn_types.OutboundKind;
pub const CloseReason = conn_types.CloseReason;
pub const InboundWsState = conn_types.InboundWsState;

/// Enable TCP keepalive on a socket: detect dead connections within ~60s.
/// (30s idle + 3 probes × 10s = 60s total before declaring dead)
fn setTcpKeepalive(fd: std.posix.fd_t) void {
    if (comptime builtin.os.tag == .linux) {
        const IPPROTO_TCP = 6;
        const TCP_KEEPIDLE = 4;
        const TCP_KEEPINTVL = 5;
        const TCP_KEEPCNT = 6;
        const enable: c_int = 1;
        const idle: c_int = 30; // 30s before first probe
        const interval: c_int = 10; // 10s between probes
        const count: c_int = 3; // 3 failed probes → dead
        std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, std.mem.asBytes(&enable)) catch {};
        std.posix.setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, std.mem.asBytes(&idle)) catch {};
        std.posix.setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, std.mem.asBytes(&interval)) catch {};
        std.posix.setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, std.mem.asBytes(&count)) catch {};
    } else if (comptime builtin.os.tag == .windows) {
        // Windows: use SIO_KEEPALIVE_VALS via WSAIoctl (or just SO_KEEPALIVE)
        const ws = struct {
            extern "ws2_32" fn setsockopt(s: usize, level: c_int, optname: c_int, optval: [*]const u8, optlen: c_int) callconv(.winapi) c_int;
        };
        const enable: c_int = 1;
        _ = ws.setsockopt(@intFromPtr(fd), 0xFFFF, 0x0008, @ptrCast(&enable), @sizeOf(c_int)); // SOL_SOCKET, SO_KEEPALIVE
    }
}

/// Platform-specific TCP shutdown (send direction only).
/// Used in half-close to propagate FIN to the other side.
fn socketShutdownSend(fd: std.posix.fd_t) void {
    if (comptime builtin.os.tag == .windows) {
        const SD_SEND: c_int = 1;
        const ws = struct {
            extern "ws2_32" fn shutdown(s: usize, how: c_int) callconv(.winapi) c_int;
        };
        _ = ws.shutdown(@intFromPtr(fd), SD_SEND);
    } else {
        std.posix.shutdown(fd, .send) catch {};
    }
}

/// Platform-specific forced fd close.
/// Used by forceDestroyLeaked to close sockets that the normal xev close path missed.
fn forceCloseFd(fd: std.posix.fd_t) void {
    std.posix.close(fd); // Zig 0.15.2: returns void on all platforms
}

/// Session: handles the full lifecycle of an inbound connection.
///
/// Pipeline: TCP accept → [TLS handshake] → Protocol parse → DNS resolve → TCP connect → Relay
///
/// Lifecycle: Uses `pending_ops` ref counting to prevent use-after-free on IOCP.
/// Every xev submission increments pending_ops; every callback .disarm decrements it.
/// Self is only destroyed when pending_ops == 0 AND state == .closed.

pub const Session = struct {
    // ── Inbound (sub-struct) ──
    inbound: InboundSide,

    // ── Outbound (sub-struct) ──
    outbound: OutboundSide = .{},

    // ── Lifecycle (sub-struct) ──
    lifecycle: Lifecycle = .{},

    // ── Config (sub-struct) ──
    cfg: ConnConfig,

    // (buffers, inbound completions, inbound_protocol moved to inbound)

    // (outbound_config, outbound_kind, xudp_*, real_target moved to outbound)
    outbound_state: ?*OutboundState = null, // kept here: OutboundState defined in this struct (circular import)

    // ── Half-close: tracked via FSM states + real TCP shutdown(SHUT_WR) ──
    //   fsm.is(.half_close_client) = client EOF → shutdown(target, SHUT_WR) → FIN propagated
    //   fsm.is(.half_close_target) = target EOF → shutdown(client, SHUT_WR) → FIN propagated
    //   Grace period: half_close_grace_ms (default 5s) hard cap from half-close start

    // (close_count, sockets_to_close, pending_ops moved to lifecycle)

    // (node_type, inbound_ws* moved to inbound)

    // ── Protocol info ──
    // (target_addr moved to outbound)
    initial_payload: ?[]const u8 = null, // data after protocol header
    initial_payload_len: usize = 0,

    // ── DNS resolve port (saved across async DNS) ──
    dns_target_port: u16 = 0,

    // ── SendThrough: local IP the client connected to (for outbound bind) ──
    local_addr: ?std.net.Address = null,

    // ── Metrics + access log (sub-struct) ──
    metrics: ConnMetrics = .{},
    // (close_reason moved to lifecycle)

    // ── UDP relay (Full Cone NAT) ──
    udp_sock: usize = UdpSys.INVALID_SOCKET,
    udp_write_pending: bool = false,
    udp_closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    udp_pending_len: usize = 0, // uplink accumulation (stored in target_buf)

    // ── Timeout timer (sub-struct) ──
    timeout: TimeoutManager = .{},
    // (half_close_start_ms moved to lifecycle)

    // ── Drain management (epoll / Option A: shutdown → drain → close) ──
    // On epoll: shutdown() causes pending dup'd-fd ops to complete naturally,
    // letting xev clean up its own state. tcp.close() is deferred until all I/O drains.
    // On IOCP (Windows): closesocket() fires ABORTED completions directly — no drain needed.
    cached_loop: ?*xev.Loop = null,    // set in initiateClose, read by opDone
    drain_timer: ?xev.Timer = null,    // 5s safety timeout if drain stalls
    drain_comp: xev.Completion = .{},
    drain_cancel_comp: xev.Completion = .{},
    drain_active: bool = false,        // true = shutdown issued, waiting for I/O to drain
    drain_timer_running: bool = false, // true = drain timer trackOp is held

    // ── Active session list (intrusive doubly-linked, owned by Worker) ──
    // Used by the periodic session reaper to detect and force-close stuck sessions.
    next_session: ?*Session = null,
    prev_session: ?*Session = null,

    pub const State = conn_fsm.State;

    pub fn create(
        fd: std.posix.fd_t,
        worker: *Worker,
        protocol: config_mod.Protocol,
        use_tls: bool,
        fb_addr: ?std.net.Address,
        inbound_tag: []const u8,
        conn_tls_ctx: ?*tls_mod.TlsContext,
        conn_user_store: ?*user_store_mod.UserStore,
        conn_listener_id: u8,
    ) ?*Session {
        const self = worker.allocConn() orelse {
            worker.logger.err("failed to allocate Session", .{});
            return null;
        };

        // Enable TCP keepalive on client socket (detect dead connections)
        setTcpKeepalive(fd);

        self.* = Session{
            .inbound = .{
                .tcp = xev.TCP.initFd(fd),
                .node_type = protocol,
            },
            .cfg = .{
                .worker = worker,
                .logger = undefined, // set below after tag copy
                .fallback_addr = fb_addr,
                .tls_ctx_ptr = conn_tls_ctx,
                .user_store_ptr = conn_user_store,
                .listener_id = conn_listener_id,
            },
            .metrics = .{
                .conn_start_ms = currentMs(),
                .conn_id = session_mod.nextConnId(),
            },
        };

        // Copy inbound tag and point logger scope at it
        if (inbound_tag.len > 0) {
            const n: u8 = @intCast(@min(inbound_tag.len, self.cfg.inbound_tag_buf.len));
            @memcpy(self.cfg.inbound_tag_buf[0..n], inbound_tag[0..n]);
            self.cfg.inbound_tag_len = n;
            self.cfg.logger = log.ScopedLogger.init(worker.id, self.cfg.inbound_tag_buf[0..n]);
        } else {
            self.cfg.logger = log.ScopedLogger.init(worker.id, "proxy");
        }
        self.cfg.logger.conn_id = self.metrics.conn_id;

        // Initialize TLS if enabled for this listener
        if (use_tls) {
            if (conn_tls_ctx) |ctx| {
                self.inbound.tls = ctx.newServer() catch {
                    self.cfg.logger.err("failed to create TLS stream", .{});
                    worker.freeConn(self);
                    return null;
                };
            }
        }

        // Pre-allocate all core buffers upfront (avoids scattered ensure guards)
        self.inbound.recv_buf = worker.pool.acquire(pool_medium) catch {
            worker.freeConn(self);
            return null;
        };
        self.inbound.decrypt_buf = worker.pool.acquire(pool_iodata) catch {
            worker.pool.release(self.inbound.recv_buf.?);
            worker.freeConn(self);
            return null;
        };
        self.inbound.send_buf = worker.pool.acquire(pool_iodata) catch {
            worker.pool.release(self.inbound.decrypt_buf.?);
            worker.pool.release(self.inbound.recv_buf.?);
            worker.freeConn(self);
            return null;
        };
        self.inbound.protocol_buf = worker.pool.acquire(pool_medium) catch {
            worker.pool.release(self.inbound.send_buf.?);
            worker.pool.release(self.inbound.decrypt_buf.?);
            worker.pool.release(self.inbound.recv_buf.?);
            worker.freeConn(self);
            return null;
        };
        self.outbound.target_buf = worker.pool.acquire(pool_medium) catch {
            worker.pool.release(self.inbound.protocol_buf.?);
            worker.pool.release(self.inbound.send_buf.?);
            worker.pool.release(self.inbound.decrypt_buf.?);
            worker.pool.release(self.inbound.recv_buf.?);
            worker.freeConn(self);
            return null;
        };

        // Per-listener config from ListenerInfo
        if (conn_listener_id < worker.listener_info_count) {
            const li = worker.listener_infos[conn_listener_id];
            self.cfg.enable_routing = li.enable_routing;
            self.metrics.sniff_enabled = li.sniff_enabled;
            self.metrics.sniff_redirect = li.sniff_redirect;
            if (li.transport == .ws or li.transport == .wss) {
                self.inbound.ws_active = true;
            }
        }

        // fsm defaults to .proxy_protocol — no explicit assignment needed
        self.cfg.logger.debug("#{d} [inbound] OPEN pending_ops=0", .{self.metrics.conn_id});
        return self;
    }

    pub fn start(self: *Session, loop: *xev.Loop) void {
        self.cached_loop = loop; // cache for emergency cleanup in LEAK_DETECT
        self.startTimeoutTimer(loop);
        self.startClientRead(loop);
    }

    // ── Ref counting ──

    pub fn trackOp(self: *Session) void {
        self.lifecycle.pending_ops += 1;
    }

    /// Called when an xev operation completes (callback returns .disarm).
    /// Destroys self when all ops are done and state is .closed.
    pub fn opDone(self: *Session) void {
        // Guard against underflow: if pending_ops is already 0, something double-decremented.
        // Log and bail — decrementing a u16 from 0 would wrap to 65535, leaking the session forever.
        if (self.lifecycle.pending_ops == 0) {
            self.cfg.logger.err("#{d} opDone UNDERFLOW (already 0), state={s} close_count={d}/{d}", .{
                self.metrics.conn_id,
                self.lifecycle.fsm.state.name(),
                self.lifecycle.close_count,
                self.lifecycle.sockets_to_close,
            });
            // Force cleanup to prevent fd/session leak regardless of FSM state.
            // This is a safety net for double-opDone bugs — the session is stuck.
            self.forceDestroyLeaked();
            return;
        }
        self.lifecycle.pending_ops -= 1;

        // Option A drain detection (epoll only):
        // When pending_ops drops to 1, only the drain timer trackOp remains.
        // All real I/O ops have naturally completed (xev cleaned up their dup'd fds).
        // Cancel the timer early and submit the actual tcp.close() now.
        if (self.drain_active and self.drain_timer_running and self.lifecycle.pending_ops == 1) {
            self.drain_active = false;
            self.drain_timer_running = false;
            const l = self.cached_loop.?;
            self.trackOp(); // for drain timer cancel confirmation
            self.drain_timer.?.cancel(l, &self.drain_comp, &self.drain_cancel_comp, Session, self, &onDrainTimerCancel);
            self.queueTcpClose(l);
            return; // pending_ops > 1 now; don't fall through to destroy check
        }

        if (self.lifecycle.pending_ops == 0 and self.lifecycle.fsm.isClosed()) {
            self.destroy();
        } else if (self.lifecycle.pending_ops == 0 and !self.lifecycle.fsm.isClosed()) {
            // LEAK DETECTOR: pending_ops reached 0 but session isn't closed — stuck session.
            // This can happen due to xev dup-fd callback races, timer cancel timing,
            // or pending_ops accounting edge cases. Previously this only logged,
            // causing the session + all its socket fds to leak forever.
            self.cfg.logger.warn("#{d} LEAK_DETECT pending_ops=0 but state={s} close_count={d}/{d} reason={s}", .{
                self.metrics.conn_id,
                self.lifecycle.fsm.state.name(),
                self.lifecycle.close_count,
                self.lifecycle.sockets_to_close,
                @tagName(self.lifecycle.close_reason),
            });
            self.forceDestroyLeaked();
        }
    }

    // ── Buffer pool helpers: lazy acquire / release ──

    pub fn ensureRecvBuf(self: *Session) ?[]u8 {
        if (self.inbound.recv_buf) |b| return b;
        self.inbound.recv_buf = self.cfg.worker.pool.acquire(pool_medium) catch return null;
        return self.inbound.recv_buf;
    }

    pub fn ensureDecryptBuf(self: *Session) ?[]u8 {
        if (self.inbound.decrypt_buf) |b| return b;
        self.inbound.decrypt_buf = self.cfg.worker.pool.acquire(pool_iodata) catch return null;
        return self.inbound.decrypt_buf;
    }

    pub fn ensureTargetBuf(self: *Session) ?[]u8 {
        if (self.outbound.target_buf) |b| return b;
        self.outbound.target_buf = self.cfg.worker.pool.acquire(pool_medium) catch return null;
        return self.outbound.target_buf;
    }

    pub fn ensureSendBuf(self: *Session) ?[]u8 {
        if (self.inbound.send_buf) |b| return b;
        self.inbound.send_buf = self.cfg.worker.pool.acquire(pool_iodata) catch return null;
        return self.inbound.send_buf;
    }

    pub fn ensureProtocolBuf(self: *Session) ?[]u8 {
        if (self.inbound.protocol_buf) |b| return b;
        self.inbound.protocol_buf = self.cfg.worker.pool.acquire(pool_medium) catch return null;
        return self.inbound.protocol_buf;
    }

    pub fn ensureInboundPending(self: *Session) ?[]u8 {
        if (self.inbound.pending) |b| return b;
        self.inbound.pending = self.cfg.worker.pool.acquire(pool_iodata) catch {
            self.cfg.logger.err("failed to acquire inbound_pending", .{});
            return null;
        };
        return self.inbound.pending;
    }

    pub fn ensureEncBuf(self: *Session) ?[]u8 {
        const out = self.outbound_state orelse return null;
        if (out.enc_buf) |b| return b;
        out.enc_buf = self.cfg.worker.pool.acquire(pool_medium) catch return null;
        return out.enc_buf;
    }

    pub fn ensureOutPending(self: *Session) ?[]u8 {
        const out = self.outbound_state orelse return null;
        if (out.pending) |b| return b;
        out.pending = self.cfg.worker.pool.acquire(pool_iodata) catch return null;
        return out.pending;
    }

    pub fn ensureXudpDownPending(self: *Session) ?[]u8 {
        if (self.outbound.xudp_down_pending) |b| return b;
        self.outbound.xudp_down_pending = self.cfg.worker.pool.acquire(pool_medium) catch return null;
        return self.outbound.xudp_down_pending;
    }

    /// Release protocol_buf back to pool (called at handshake→relay transition).
    pub fn releaseProtocolBuf(self: *Session) void {
        if (self.inbound.protocol_buf) |b| {
            self.cfg.worker.pool.release(b);
            self.inbound.protocol_buf = null;
            self.inbound.protocol_buf_len = 0;
        }
    }

    /// Emergency cleanup for leaked sessions: force-close ALL socket fds (including
    /// xev dup'd fds on epoll) and destroy the session. Called when pending_ops hits 0
    /// without the normal close path completing (LEAK_DETECT / underflow).
    ///
    /// This is a safety net — the normal path (initiateClose → drain → queueTcpClose →
    /// onCloseComplete → destroy) should handle all closes. But if pending_ops accounting
    /// goes wrong due to xev callback races or timer cancel edge cases, this prevents
    /// socket fd leaks that would consume kernel memory indefinitely.
    pub fn forceDestroyLeaked(self: *Session) void {
        self.cfg.logger.err("#{d} [session] FORCE_DESTROY_LEAKED state={s} close_count={d}/{d}", .{
            self.metrics.conn_id,
            self.lifecycle.fsm.state.name(),
            self.lifecycle.close_count,
            self.lifecycle.sockets_to_close,
        });
        _ = self.cfg.worker.leaked_sessions.fetchAdd(1, .monotonic);

        // Force-close any xev dup'd fds still registered in epoll.
        // Normal drain/disarm should have closed these, but if pending_ops
        // went wrong, some dup'd fds may still be open (keeping the socket alive
        // even after we close the original fd).
        if (comptime xev.backend == .epoll) {
            // TCP I/O completions (may have dup'd fds)
            const tcp_comps = [_]*xev.Completion{
                &self.inbound.read_comp,
                &self.inbound.write_comp,
                &self.outbound.read_comp,
                &self.outbound.write_comp,
                &self.outbound.connect_comp,
            };
            for (tcp_comps) |comp| {
                if (comp.flags.dup and comp.flags.dup_fd > 0) {
                    const linux = std.os.linux;
                    if (self.cached_loop) |l| {
                        std.posix.epoll_ctl(l.fd, linux.EPOLL.CTL_DEL, comp.flags.dup_fd, null) catch {};
                    }
                    std.posix.close(comp.flags.dup_fd);
                    comp.flags.dup_fd = 0;
                }
                if (comp.flags.state == .active) {
                    comp.flags.state = .dead;
                    if (self.cached_loop) |l| l.active -|= 1;
                } else if (comp.flags.state == .adding) {
                    comp.flags.state = .dead;
                }
            }
            // Timer completions (timeout, drain) — no dup fds but need dead marking
            const timer_comps = [_]*xev.Completion{
                &self.timeout.comp,
                &self.timeout.cancel_comp,
                &self.drain_comp,
                &self.drain_cancel_comp,
            };
            for (timer_comps) |comp| {
                if (comp.flags.state == .active) {
                    comp.flags.state = .dead;
                    if (self.cached_loop) |l| l.active -|= 1;
                } else if (comp.flags.state == .adding) {
                    comp.flags.state = .dead;
                }
            }
        }

        // Force-close original socket fds directly (bypassing xev).
        if (!self.lifecycle.fsm.isClosed()) {
            forceCloseFd(self.inbound.tcp.fd);
            if (self.outbound.tcp) |tcp| forceCloseFd(tcp.fd);
        }

        // Decrement outbound counter if we had an outbound socket that wasn't
        // decremented during initiateClose (e.g., if initiateClose never ran).
        if (self.outbound.tcp != null and !self.lifecycle.fsm.isClosingOrClosed()) {
            _ = self.cfg.worker.conns_outbound.fetchSub(1, .monotonic);
        }

        // Decrement relay counter if session was in relay phase
        if (self.lifecycle.fsm.isRelayingOrUdp()) {
            _ = self.cfg.worker.conns_relay.fetchSub(1, .monotonic);
        }

        // Ensure FSM reaches terminal state for destroy()
        if (!self.lifecycle.fsm.isClosed()) {
            if (!self.lifecycle.fsm.isClosingOrClosed()) {
                self.lifecycle.fsm.transitionToClosing();
            }
            self.lifecycle.fsm.transitionToClosed();
        }

        self.destroy();
    }

    fn destroy(self: *Session) void {
        const duration_ms = currentMs() -| self.metrics.conn_start_ms;
        self.cfg.logger.debug("#{d} [session] DESTROY duration={d}ms up={d}B dn={d}B reason={s} sockets={d}", .{
            self.metrics.conn_id,
            duration_ms,
            self.metrics.conn_bytes_up,
            self.metrics.conn_bytes_dn,
            @tagName(self.lifecycle.close_reason),
            self.lifecycle.sockets_to_close,
        });
        // Remove from active session list before freeing
        self.cfg.worker.unlinkSession(self);
        self.timeout.deinitTimer();
        if (self.drain_timer) |*dt| dt.deinit();
        if (self.outbound.tls) |*ttls| ttls.deinit();
        if (self.inbound.tls) |*tls| tls.deinit();
        if (self.outbound.ws) |ws| self.cfg.worker.allocator.destroy(ws);
        // Release pool-borrowed buffers
        if (self.inbound.recv_buf) |b| self.cfg.worker.pool.release(b);
        if (self.inbound.decrypt_buf) |b| self.cfg.worker.pool.release(b);
        if (self.outbound.target_buf) |b| self.cfg.worker.pool.release(b);
        if (self.inbound.send_buf) |b| self.cfg.worker.pool.release(b);
        if (self.inbound.protocol_buf) |b| self.cfg.worker.pool.release(b);
        if (self.inbound.pending) |b| self.cfg.worker.pool.release(b);
        if (self.outbound.xudp_down_pending) |b| self.cfg.worker.pool.release(b);
        if (self.outbound_state) |out| {
            if (out.enc_buf) |b| self.cfg.worker.pool.release(b);
            if (out.pending) |b| self.cfg.worker.pool.release(b);
            self.cfg.worker.allocator.destroy(out);
        }
        self.cfg.worker.connectionClosed();
        self.cfg.worker.freeConn(self);
    }

    // ══════════════════════════════════════════════════════════════
    //  Timeout timer (handshake + idle)
    // ══════════════════════════════════════════════════════════════

    /// Schedule timeout callback after `ms`.
    ///
    /// When `earlier_only` is true, keeps an existing pending timeout if it
    /// already fires earlier than the requested deadline.
    fn scheduleTimeout(self: *Session, loop: *xev.Loop, ms: u64, earlier_only: bool) void {
        if (ms == 0 or self.lifecycle.fsm.isClosingOrClosed()) return;

        if (self.timeout.timer == null) {
            self.timeout.timer = xev.Timer.init() catch return;
        }

        const now = currentMs();
        const desired_due = now +| ms;

        if (self.timeout.active) {
            if (earlier_only and self.timeout.due_ms != 0 and self.timeout.due_ms <= desired_due) {
                // Existing timer already fires no later than requested.
                return;
            }

            // Rearm requires cancel confirmation first.
            self.timeout.rearm_ms = ms;
            self.timeout.active = false;
            self.timeout.due_ms = 0;
            self.trackOp();
            self.timeout.timer.?.cancel(loop, &self.timeout.comp, &self.timeout.cancel_comp, Session, self, &onTimeoutCancelDone);
            return;
        }

        self.timeout.rearm_ms = 0;
        self.timeout.active = true;
        self.timeout.due_ms = desired_due;
        self.trackOp();
        self.timeout.timer.?.run(loop, &self.timeout.comp, ms, Session, self, &onTimeoutFired);
    }

    /// Entered half-close: enforce grace timeout even when idle/handshake timer
    /// is disabled or currently scheduled too far in the future.
    fn scheduleHalfCloseTimeout(self: *Session, loop: *xev.Loop) void {
        const grace_ms: u64 = self.cfg.worker.half_close_grace_ms;
        if (grace_ms == 0) return;
        self.scheduleTimeout(loop, grace_ms, true);
    }

    /// Start handshake timeout (or idle timeout if no handshake timeout configured).
    fn startTimeoutTimer(self: *Session, loop: *xev.Loop) void {
        var ms: u64 = self.cfg.worker.handshake_timeout_ms;
        if (ms == 0) ms = self.cfg.worker.idle_timeout_ms;
        if (ms == 0) return;

        self.timeout.last_activity_ms = currentMs();
        self.scheduleTimeout(loop, ms, false);
    }

    /// Update last activity timestamp (call on relay data transfer).
    pub fn touchActivity(self: *Session) void {
        self.timeout.last_activity_ms = currentMs();
    }

    fn onTimeoutFired(ud: ?*Session, l: *xev.Loop, _: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        const self = ud.?;
        self.timeout.active = false;
        self.timeout.due_ms = 0;
        defer self.opDone();

        _ = r catch return .disarm; // cancelled
        if (self.lifecycle.fsm.isClosingOrClosed()) return .disarm;

        if (self.lifecycle.fsm.isRelayingOrUdp()) {
            const now = currentMs();

            // Half-close grace: hard cap from half-close start (default 5s).
            // After TCP shutdown(SHUT_WR) propagates FIN, the other side should
            // EOF quickly. This grace period is a safety net for slow peers.
            const in_half_close = self.lifecycle.fsm.is(.half_close_client) or self.lifecycle.fsm.is(.half_close_target);
            if (in_half_close and self.lifecycle.half_close_start_ms > 0) {
                const grace_ms: u64 = self.cfg.worker.half_close_grace_ms;
                if (grace_ms > 0) {
                    const grace_elapsed = now -| self.lifecycle.half_close_start_ms;
                    if (grace_elapsed >= grace_ms) {
                        self.lifecycle.close_reason = .idle;
                        self.initiateClose(l);
                        return .disarm;
                    }
                    // Reschedule for remaining grace
                    const remaining = grace_ms - grace_elapsed;
                    self.scheduleTimeout(l, remaining, false);
                    return .disarm;
                }
            }

            // Normal relay: check idle timeout
            const idle_ms: u64 = self.cfg.worker.idle_timeout_ms;
            if (idle_ms == 0) return .disarm;

            const elapsed = now -| self.timeout.last_activity_ms;
            if (elapsed >= idle_ms) {
                self.lifecycle.close_reason = .idle;
                self.initiateClose(l);
                return .disarm;
            }
            // Reschedule — cap at grace_ms if approaching half-close
            var next_ms = idle_ms - elapsed;
            if (in_half_close and self.lifecycle.half_close_start_ms > 0) {
                const grace_ms: u64 = self.cfg.worker.half_close_grace_ms;
                if (grace_ms > 0) {
                    const grace_remaining = grace_ms -| (now -| self.lifecycle.half_close_start_ms);
                    next_ms = @min(next_ms, grace_remaining);
                }
            }
            if (next_ms == 0) next_ms = 1;
            self.scheduleTimeout(l, next_ms, false);
            return .disarm;
        }

        // Pre-relay: handshake timeout
        self.lifecycle.close_reason = .hs_timeout;
        self.initiateClose(l);
        return .disarm;
    }

    fn onTimeoutCancelDone(ud: ?*Session, l: *xev.Loop, _: *xev.Completion, r: xev.Timer.CancelError!void) xev.CallbackAction {
        const self = ud.?;
        _ = r catch {
            // Cancel failed (already fired / not found). Do not rearm.
            self.timeout.rearm_ms = 0;
            self.opDone();
            return .disarm;
        };

        const rearm_ms = self.timeout.rearm_ms;
        self.timeout.rearm_ms = 0;
        if (rearm_ms > 0 and !self.lifecycle.fsm.isClosingOrClosed()) {
            self.timeout.active = true;
            self.timeout.due_ms = currentMs() +| rearm_ms;
            self.trackOp();
            self.timeout.timer.?.run(l, &self.timeout.comp, rearm_ms, Session, self, &onTimeoutFired);
        }

        self.opDone();
        return .disarm;
    }

    pub fn currentMs() u64 {
        return @intCast(@max(0, std.time.milliTimestamp()));
    }

    // ══════════════════════════════════════════════════════════════
    //  Client-side read/write
    // ══════════════════════════════════════════════════════════════

    pub fn startClientRead(self: *Session, loop: *xev.Loop) void {
        if (self.inbound.read_pending) return; // already pending — avoid double-submit
        self.inbound.read_pending = true;
        self.trackOp();
        self.inbound.tcp.read(loop, &self.inbound.read_comp, .{ .slice = self.inbound.recv_buf.? }, Session, self, &onClientRead);
    }

    /// Main client read callback.
    ///
    /// Return value semantics:
    ///   .rearm  = need more data from client (xev re-arms automatically, op stays pending)
    ///   .disarm = submitted an op on a DIFFERENT completion, or initiated close
    fn onClientRead(ud: ?*Session, l: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.ReadBuffer, r: xev.ReadError!usize) xev.CallbackAction {
        const self = ud.?;
        self.inbound.read_pending = false;
        const is_early_detect = self.outbound.early_detect_active;
        self.outbound.early_detect_active = false;

        // Cancelled operation during close — just release the ref
        if (self.lifecycle.fsm.isClosingOrClosed()) {
            self.opDone();
            return .disarm;
        }

        const n = r catch {
            self.cfg.logger.debug("#{d} [inbound] READ_ERR state={s} early_detect={} pending_ops={d}", .{
                self.metrics.conn_id, self.lifecycle.fsm.state.name(), is_early_detect, self.lifecycle.pending_ops,
            });
            self.initiateClose(l);
            self.opDone();
            return .disarm;
        };
        if (n == 0) {
            // Client sent FIN
            self.cfg.logger.debug("#{d} [inbound] FIN state={s} early_detect={} pending_ops={d}", .{
                self.metrics.conn_id, self.lifecycle.fsm.state.name(), is_early_detect, self.lifecycle.pending_ops,
            });
            // Half-close with real TCP shutdown(SHUT_WR).
            // Propagate FIN to target so it knows uplink is done.
            // The other direction (target→client) continues until target also EOF's
            // or half-close grace period expires.
            if (self.lifecycle.fsm.isRelaying() or self.lifecycle.fsm.is(.half_close_target)) {
                if (self.lifecycle.fsm.is(.half_close_target)) {
                    self.cfg.logger.debug("#{d} [inbound] FIN both_done pending_ops={d}", .{
                        self.metrics.conn_id, self.lifecycle.pending_ops,
                    });
                    self.initiateClose(l); // both directions done → fd close
                } else {
                    self.cfg.logger.debug("#{d} [inbound] HALF_CLOSE pending_ops={d}", .{
                        self.metrics.conn_id, self.lifecycle.pending_ops,
                    });
                    _ = self.lifecycle.fsm.transition(.half_close_client);
                    self.lifecycle.half_close_start_ms = currentMs();
                    // Send VMess empty chunk (EOF marker) to signal end of uplink
                    // to the outbound server. Without this, the server may wait
                    // indefinitely for more uplink data, causing a deadlock.
                    if (self.outbound_state) |vout| {
                        if (vout.vmess.request_state) |*req_state| {
                            if (vout.enc_buf orelse self.ensureEncBuf()) |ebuf| {
                                if (vmess_stream.encryptChunk(req_state, &[_]u8{}, ebuf)) |chunk_len| {
                                    if (self.wrapOutboundTransport(ebuf[0..chunk_len])) |wrapped| {
                                        if (self.outbound.tcp) |*tcp| {
                                            self.trackOp();
                                            tcp.write(l, &self.outbound.write_comp, .{ .slice = wrapped }, Session, self, &onTargetWrite);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Propagate FIN to target via TCP shutdown(SHUT_WR).
                    // Pending IOCP writes (e.g. VMess EOF chunk above) complete first,
                    // then OS sends FIN. Safe to call after async write submission.
                    if (self.outbound.tcp) |tcp| {
                        socketShutdownSend(tcp.fd);
                    }
                    self.scheduleHalfCloseTimeout(l);
                }
                self.opDone();
                return .disarm;
            }
            // Not in relay phase (handshake/connect) → full close
            self.initiateClose(l);
            self.opDone();
            return .disarm;
        }

        const action = switch (self.lifecycle.fsm.state) {
            .proxy_protocol => self.driveProxyProtocol(l, n),
            .tls_handshake => self.driveHandshake(l, n),
            .protocol_parse => self.driveProtocolParse(l, n),
            // VMess outbound pre-response phase: target_write_comp may be busy
            // with the header write. Forwarding uplink here risks double-submit
            // on outbound.write_comp, causing a leaked trackOp (callback overwritten,
            // opDone never fires for the header write → session stuck forever).
            // handleVMessPostWrite sends initial payload after header write completes.
            .outbound_vmess_header => blk: {
                self.cfg.logger.debug("#{d} [inbound] VMESS_HEADER_PHASE data={d}B early_detect={} pending_ops={d} (discarded)", .{
                    self.metrics.conn_id, n, is_early_detect, self.lifecycle.pending_ops,
                });
                break :blk .disarm;
            },
            .relaying => self.driveRelayUplink(l, n),
            // half_close_target: target FIN'd but client still sending (uplink active)
            .half_close_target => self.driveRelayUplink(l, n),
            .udp_relaying => self.driveUdpUplink(l, n),
            // Outbound handshake: early disconnect detection only.
            // FIN/error already handled above. Data during these states is unexpected;
            // discard without re-arm. Handshake flow will call startClientRead when ready.
            // half_close_client: client already FIN'd, no more data expected.
            // Defensive: disarm without re-arm (startClientRead is not called in this state).
            .half_close_client => .disarm,
            // Outbound handshake: early disconnect detection only.
            // FIN/error already handled above. Data during these states is unexpected;
            // discard without re-arm. Handshake flow will call startClientRead when ready.
            .connecting, .outbound_tls_handshake,
            .outbound_ws_handshake, .outbound_trojan_header,
            .outbound_ss_header,
            => blk: {
                self.cfg.logger.debug("#{d} [inbound] EARLY_DETECT data={d}B state={s} pending_ops={d} (discarded)", .{
                    self.metrics.conn_id, n, self.lifecycle.fsm.state.name(), self.lifecycle.pending_ops,
                });
                break :blk .disarm;
            },
            else => blk: {
                self.initiateClose(l);
                break :blk .disarm;
            },
        };

        if (action == .disarm) {
            self.opDone(); // client_read op is done
        }
        // .rearm: xev re-arms the read, op stays pending — don't opDone
        if (action == .rearm) self.inbound.read_pending = true;
        return action;
    }

    pub fn sendToClient(self: *Session, loop: *xev.Loop, data: []const u8) void {
        // Copy to send_buf since we need stable memory for async write
        const sbuf = self.ensureSendBuf() orelse {
            self.initiateClose(loop);
            return;
        };
        const len = @min(data.len, sbuf.len);
        @memcpy(sbuf[0..len], data[0..len]);
        self.trackOp();
        self.inbound.tcp.write(loop, &self.inbound.write_comp, .{ .slice = sbuf[0..len] }, Session, self, &onClientWrite);
    }

    pub fn onClientWrite(ud: ?*Session, l: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.WriteBuffer, r: xev.WriteError!usize) xev.CallbackAction {
        const self = ud.?;
        defer self.opDone();

        if (self.lifecycle.fsm.isClosingOrClosed()) return .disarm;

        _ = r catch |e| {
            self.cfg.logger.debug("client write: {}", .{e});
            self.initiateClose(l);
            return .disarm;
        };

        switch (self.lifecycle.fsm.state) {
            .tls_handshake => {
                // Drain remaining handshake data from write BIO before reading more.
                // A large certificate chain can exceed send_buf (20KB), leaving
                // data stranded in the BIO — the client waits for the rest while
                // we wait for the client, causing a TLS handshake deadlock.
                if (self.inbound.tls) |*tls| {
                    if (tls.hasNetworkDataPending()) {
                        const more = tls.getNetworkData(self.inbound.send_buf.?);
                        if (more > 0) {
                            self.trackOp();
                            self.inbound.tcp.write(l, &self.inbound.write_comp, .{ .slice = self.inbound.send_buf.?[0..more] }, Session, self, &onClientWrite);
                            return .disarm; // loop until BIO drained
                        }
                    }
                }
                self.startClientRead(l);
            },
            .protocol_parse => {
                // WS 101 response sent → continue reading for WS frames (protocol data)
                if (self.inbound.ws_active and self.inbound.ws_done and self.inbound.protocol == .none) {
                    // Drain TLS BIO first if applicable
                    if (self.inbound.tls) |*tls| {
                        if (tls.hasNetworkDataPending()) {
                            const more = tls.getNetworkData(self.inbound.send_buf.?);
                            if (more > 0) {
                                self.trackOp();
                                self.inbound.tcp.write(l, &self.inbound.write_comp, .{ .slice = self.inbound.send_buf.?[0..more] }, Session, self, &onClientWrite);
                                return .disarm;
                            }
                        }
                    }
                    // Check for leftover data from handshake (first WS frame arrived with HTTP headers)
                    if (self.inbound.ws_state.accum_len > 0) {
                        const leftover_len = self.inbound.ws_state.accum_len;
                        self.inbound.ws_state.accum_len = 0;
                        const action = self.unwrapWsAndDispatch(l, self.outbound.target_buf.?[0..leftover_len]);
                        if (action == .rearm) self.startClientRead(l);
                        return .disarm;
                    }
                    self.startClientRead(l);
                    return .disarm;
                }
                if (self.inbound.protocol == .vmess and self.inbound.protocol.vmess.response_sent) {
                    // VMess response sent → now connect to target
                    if (self.outbound.target_addr) |addr| {
                        self.startConnect(l, addr);
                        self.outbound.target_addr = null;
                    } else {
                        self.initiateClose(l);
                    }
                } else {
                    // After handshake completion write, drain any remaining BIO data first
                    if (self.inbound.tls) |*tls| {
                        if (tls.hasNetworkDataPending()) {
                            const more = tls.getNetworkData(self.inbound.send_buf.?);
                            if (more > 0) {
                                self.trackOp();
                                self.inbound.tcp.write(l, &self.inbound.write_comp, .{ .slice = self.inbound.send_buf.?[0..more] }, Session, self, &onClientWrite);
                                return .disarm;
                            }
                        }
                        // BIO drained, try buffered decrypted data
                        switch (tls.readDecrypted(self.inbound.decrypt_buf.?)) {
                            .bytes => |dn| {
                                const action = self.handleProtocolData(l, self.inbound.decrypt_buf.?[0..dn]);
                                if (action == .rearm) {
                                    // Protocol incomplete, need more data
                                    self.startClientRead(l);
                                }
                            },
                            .want_read => self.startClientRead(l),
                            .closed => self.initiateClose(l),
                            else => self.initiateClose(l),
                        }
                    } else {
                        self.startClientRead(l);
                    }
                }
            },
            .relaying, .half_close_client => {
                // Client write done — drain any buffered outbound data before
                // issuing a new target read. Delegated to relay_pipeline.
                // Also handles half_close_client: client FIN'd but downlink
                // is still active — must re-arm target read to receive remaining
                // data and eventually the target FIN to complete close.
                if (relay_pipeline.drainPendingDownlink(self, l)) |action| return action;
                self.startTargetRead(l);
            },
            .udp_relaying => {
                // UDP downlink write done, ready for next packet
                self.udp_write_pending = false;
            },
            else => {},
        }
        return .disarm;
    }

    // ══════════════════════════════════════════════════════════════
    //  PROXY Protocol Detection — driven from onClientRead (first read)
    // ══════════════════════════════════════════════════════════════

    fn driveProxyProtocol(self: *Session, loop: *xev.Loop, n: usize) xev.CallbackAction {
        const data = self.inbound.recv_buf.?[0..n];
        const result = pp_mod.parse(data);

        if (result.success) {
            // Update real client address from PP header
            if (pp_mod.toNetAddress(result)) |addr| {
                self.metrics.src_addr = addr;
                self.cfg.logger.setClientIp(addr);
            }

            // Transition to next state
            const remaining = n - result.consumed;
            if (self.inbound.tls != null) {
                _ = self.lifecycle.fsm.transition(.tls_handshake);
            } else {
                _ = self.lifecycle.fsm.transition(.protocol_parse);
            }

            if (remaining > 0) {
                // Move remaining data to front of recv_buf and process
                std.mem.copyForwards(u8, self.inbound.recv_buf.?[0..remaining], data[result.consumed..n]);
                return switch (self.lifecycle.fsm.state) {
                    .tls_handshake => self.driveHandshake(loop, remaining),
                    .protocol_parse => self.driveProtocolParse(loop, remaining),
                    else => unreachable,
                };
            }
            return .rearm; // wait for more data
        }

        // No PP header detected — fallback to normal flow with current data
        if (self.inbound.tls != null) {
            _ = self.lifecycle.fsm.transition(.tls_handshake);
            return self.driveHandshake(loop, n);
        } else {
            _ = self.lifecycle.fsm.transition(.protocol_parse);
            return self.driveProtocolParse(loop, n);
        }
    }

    // ══════════════════════════════════════════════════════════════
    //  TLS Handshake — driven from onClientRead
    // ══════════════════════════════════════════════════════════════

    fn driveHandshake(self: *Session, loop: *xev.Loop, n: usize) xev.CallbackAction {
        var tls = &(self.inbound.tls.?);
        const buf = self.inbound.recv_buf.?[0..n];

        // Dynamic SNI cert: on ClientHello, parse SNI and override per-connection cert
        if (buf.len > 5 and buf[0] == 0x16 and buf[5] == 0x01) {
            if (dynamic_cert.parseSniFromClientHello(buf)) |sni| {
                if (tls_init.getDynamicCertProvider()) |provider| {
                    if (provider.getOrCreateCert(sni)) |pair| {
                        tls.overrideCert(pair.cert, pair.key);
                    }
                }
            }
        }

        _ = tls.feedNetworkData(buf) catch {
            self.lifecycle.close_reason = .tls_err;
            self.initiateClose(loop);
            return .disarm;
        };

        switch (tls.handshake()) {
            .done => {
                _ = self.lifecycle.fsm.transition(.protocol_parse);

                // Send pending TLS data (ServerFinished) via client_write_comp
                const pending_n = tls.getNetworkData(self.inbound.send_buf.?);
                if (pending_n > 0) {
                    self.trackOp();
                    self.inbound.tcp.write(loop, &self.inbound.write_comp, .{ .slice = self.inbound.send_buf.?[0..pending_n] }, Session, self, &onClientWrite);
                    return .disarm; // onClientWrite(.protocol_parse) will handle next step
                }

                // No pending TLS data — check for early application data in BIO
                switch (tls.readDecrypted(self.inbound.decrypt_buf.?)) {
                    .bytes => |dn| {
                        return self.handleProtocolData(loop, self.inbound.decrypt_buf.?[0..dn]);
                    },
                    .want_read => return .rearm,
                    .closed => {
                        self.initiateClose(loop);
                        return .disarm;
                    },
                    else => {
                        self.initiateClose(loop);
                        return .disarm;
                    },
                }
            },
            .want_read => {
                // Send pending TLS data (e.g. ServerHello) if any
                const pending_n = tls.getNetworkData(self.inbound.send_buf.?);
                if (pending_n > 0) {
                    self.trackOp();
                    self.inbound.tcp.write(loop, &self.inbound.write_comp, .{ .slice = self.inbound.send_buf.?[0..pending_n] }, Session, self, &onClientWrite);
                    return .disarm; // onClientWrite(.tls_handshake) → startClientRead
                }
                return .rearm; // need more data from client
            },
            .want_write => {
                const pending_n = tls.getNetworkData(self.inbound.send_buf.?);
                if (pending_n > 0) {
                    self.trackOp();
                    self.inbound.tcp.write(loop, &self.inbound.write_comp, .{ .slice = self.inbound.send_buf.?[0..pending_n] }, Session, self, &onClientWrite);
                    return .disarm;
                }
                return .rearm;
            },
            .err => {
                self.lifecycle.close_reason = .tls_err;
                self.initiateClose(loop);
                return .disarm;
            },
        }
    }

    // ══════════════════════════════════════════════════════════════
    //  Protocol Parsing — driven from onClientRead
    // ══════════════════════════════════════════════════════════════

    fn driveProtocolParse(self: *Session, loop: *xev.Loop, n: usize) xev.CallbackAction {
        if (self.inbound.tls) |*tls| {
            // Feed ciphertext to TLS engine
            _ = tls.feedNetworkData(self.inbound.recv_buf.?[0..n]) catch {
                self.lifecycle.close_reason = .tls_err;
                self.initiateClose(loop);
                return .disarm;
            };

            // Drain all decrypted data from TLS BIO
            while (true) {
                switch (tls.readDecrypted(self.inbound.decrypt_buf.?)) {
                    .bytes => |dn| {
                        const action = self.dispatchProtocolOrWs(loop, self.inbound.decrypt_buf.?[0..dn]);
                        if (action == .disarm) return .disarm; // connect or write submitted
                        continue;
                    },
                    .want_read => return .rearm, // need more network data
                    .closed => {
                        self.initiateClose(loop);
                        return .disarm;
                    },
                    else => {
                        self.initiateClose(loop);
                        return .disarm;
                    },
                }
            }
        } else {
            // No TLS: raw TCP data is the protocol data
            return self.dispatchProtocolOrWs(loop, self.inbound.recv_buf.?[0..n]);
        }
    }

    /// Route data through inbound WS layer if active, then to protocol dispatch.
    fn dispatchProtocolOrWs(self: *Session, loop: *xev.Loop, data: []const u8) xev.CallbackAction {
        // Inbound WS handshake pending
        if (self.inbound.ws_active and !self.inbound.ws_done) {
            return self.driveInboundWsHandshake(loop, data);
        }
        // Inbound WS active: unwrap WS frames, then dispatch
        if (self.inbound.ws_active and self.inbound.ws_done) {
            return self.unwrapWsAndDispatch(loop, data);
        }
        // No WS: direct protocol dispatch
        return self.handleProtocolData(loop, data);
    }

    /// Accumulate and attempt to parse the protocol header.
    /// Delegated to inbound_dispatch module.
    fn handleProtocolData(self: *Session, loop: *xev.Loop, data: []const u8) xev.CallbackAction {
        return inbound_dispatch.handleProtocolData(self, loop, data);
    }

    // Protocol parsers delegated to inbound_dispatch module:
    // parseTrojan, parseVMess, parseShadowsocks, tryFallback, resolveFallbackAddr, extractHttpPath

    // ══════════════════════════════════════════════════════════════
    //  Inbound WebSocket Handshake + Frame Unwrapping
    // ══════════════════════════════════════════════════════════════

    /// Drive inbound WebSocket handshake: accumulate HTTP upgrade, send 101 response.
    fn driveInboundWsHandshake(self: *Session, loop: *xev.Loop, data: []const u8) xev.CallbackAction {
        // Accumulate into protocol_buf
        const pbuf = self.ensureProtocolBuf() orelse {
            self.initiateClose(loop);
            return .disarm;
        };
        const avail = pbuf.len - self.inbound.protocol_buf_len;
        const to_copy = @min(data.len, avail);
        @memcpy(pbuf[self.inbound.protocol_buf_len..][0..to_copy], data[0..to_copy]);
        self.inbound.protocol_buf_len += to_copy;

        const buf = pbuf[0..self.inbound.protocol_buf_len];

        // Look for end of HTTP headers
        const end_pos = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse {
            if (self.inbound.protocol_buf_len >= pbuf.len) {
                // Buffer full without finding headers — not a valid WS upgrade
                self.lifecycle.close_reason = .proto_err;
                self.initiateClose(loop);
                return .disarm;
            }
            return .rearm;
        };
        const header_end = end_pos + 4;

        // Validate GET request
        if (!std.mem.startsWith(u8, buf, "GET ")) {
            return inbound_dispatch.tryFallback(self, loop, "ws: not GET");
        }

        // Extract and validate path
        const path_end_idx = std.mem.indexOf(u8, buf[4..], " ") orelse {
            self.lifecycle.close_reason = .proto_err;
            self.initiateClose(loop);
            return .disarm;
        };
        const req_path = buf[4 .. 4 + path_end_idx];
        const expected_path = self.getInboundWsPath();
        if (!std.mem.eql(u8, req_path, expected_path)) {
            return inbound_dispatch.tryFallback(self, loop, "ws: path mismatch");
        }

        // Extract Sec-WebSocket-Key header
        const ws_key = findHeaderValueInBuf(buf[0..header_end], "Sec-WebSocket-Key") orelse {
            self.lifecycle.close_reason = .proto_err;
            self.initiateClose(loop);
            return .disarm;
        };
        if (ws_key.len == 0 or ws_key.len > 128) {
            self.lifecycle.close_reason = .proto_err;
            self.initiateClose(loop);
            return .disarm;
        }

        // Compute Sec-WebSocket-Accept
        const accept = ws_mod.computeAcceptKey(ws_key);

        // Build 101 Switching Protocols response
        const sbuf = self.ensureSendBuf() orelse {
            self.initiateClose(loop);
            return .disarm;
        };
        var resp_pos: usize = 0;
        const resp_parts = [_][]const u8{
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: ",
            &accept,
            "\r\n\r\n",
        };
        for (resp_parts) |part| {
            if (resp_pos + part.len > sbuf.len) {
                self.lifecycle.close_reason = .proto_err;
                self.initiateClose(loop);
                return .disarm;
            }
            @memcpy(sbuf[resp_pos..][0..part.len], part);
            resp_pos += part.len;
        }

        // Save leftover data after HTTP headers to WS accumulation buffer (target_buf)
        // This may contain the first WS frame (piggybacked with the HTTP upgrade)
        if (header_end < self.inbound.protocol_buf_len) {
            const tbuf = self.ensureTargetBuf() orelse {
                self.initiateClose(loop);
                return .disarm;
            };
            const leftover = self.inbound.protocol_buf_len - header_end;
            @memcpy(tbuf[0..leftover], pbuf[header_end..self.inbound.protocol_buf_len]);
            self.inbound.ws_state.accum_len = leftover;
        }
        self.inbound.protocol_buf_len = 0; // release protocol_buf for protocol header accumulation

        self.inbound.ws_done = true;

        // Send 101 response (through TLS if active)
        if (self.inbound.tls) |*tls| {
            switch (tls.writeEncrypted(sbuf[0..resp_pos])) {
                .bytes => {
                    const tls_n = tls.getNetworkData(sbuf);
                    if (tls_n > 0) {
                        self.trackOp();
                        self.inbound.tcp.write(loop, &self.inbound.write_comp, .{ .slice = sbuf[0..tls_n] }, Session, self, &onClientWrite);
                        return .disarm;
                    }
                },
                else => {
                    self.lifecycle.close_reason = .tls_err;
                    self.initiateClose(loop);
                    return .disarm;
                },
            }
        }
        // No TLS: send 101 directly
        self.trackOp();
        self.inbound.tcp.write(loop, &self.inbound.write_comp, .{ .slice = sbuf[0..resp_pos] }, Session, self, &onClientWrite);
        return .disarm;
    }

    /// After WS handshake: streaming unwrap WS frames and dispatch payload to protocol parser.
    /// Uses the shared unwrapInboundWsCore (no full-frame buffering needed).
    fn unwrapWsAndDispatch(self: *Session, loop: *xev.Loop, data: []const u8) xev.CallbackAction {
        switch (relay_pipeline.unwrapInboundWsCore(self, data)) {
            .payload => |payload| {
                const action = self.handleProtocolData(loop, payload);
                if (self.inbound.ws_state.close_received and action == .rearm) {
                    self.lifecycle.close_reason = .proto_err;
                    self.initiateClose(loop);
                    return .disarm;
                }
                return action;
            },
            .want_read => return .rearm,
            .close => {
                self.lifecycle.close_reason = .proto_err;
                self.initiateClose(loop);
                return .disarm;
            },
        }
    }

    /// Get the expected inbound WS path from ListenerInfo.
    fn getInboundWsPath(self: *Session) []const u8 {
        if (self.cfg.listener_id < self.cfg.worker.listener_info_count) {
            return self.cfg.worker.listener_infos[self.cfg.listener_id].getWsPath();
        }
        return "/";
    }

    /// Consume `n` bytes from the front of protocol_buf.
    pub fn consumeProtocolBuf(self: *Session, n: usize) void {
        if (n >= self.inbound.protocol_buf_len) {
            self.inbound.protocol_buf_len = 0;
        } else {
            const remaining = self.inbound.protocol_buf_len - n;
            std.mem.copyForwards(u8, self.inbound.protocol_buf.?[0..remaining], self.inbound.protocol_buf.?[n..self.inbound.protocol_buf_len]);
            self.inbound.protocol_buf_len = remaining;
        }
    }

    /// Find an HTTP header value by name (case-insensitive) in a raw header buffer.
    fn findHeaderValueInBuf(headers: []const u8, name: []const u8) ?[]const u8 {
        var iter = std.mem.splitSequence(u8, headers, "\r\n");
        while (iter.next()) |line| {
            const colon_pos = std.mem.indexOf(u8, line, ": ") orelse continue;
            const hdr_name = line[0..colon_pos];
            if (hdr_name.len != name.len) continue;
            var match = true;
            for (hdr_name, name) |a, b| {
                if (std.ascii.toLower(a) != std.ascii.toLower(b)) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return std.mem.trim(u8, line[colon_pos + 2 ..], " ");
            }
        }
        return null;
    }

    // ══════════════════════════════════════════════════════════════
    //  Outbound Connect
    // ══════════════════════════════════════════════════════════════

    /// Determine outbound config via router. Returns null → no match.
    pub fn resolveOutbound(self: *Session, target: session_mod.TargetAddress) ?router_mod.Router.RouteResult {
        if (!self.cfg.enable_routing) return null; // skip routing → direct connect
        return self.resolveOutboundWithTransport(target, .tcp);
    }

    fn resolveOutboundWithTransport(self: *Session, target: session_mod.TargetAddress, transport: config_mod.Transport) ?router_mod.Router.RouteResult {
        if (self.cfg.worker.router) |router| {
            var ctx = session_mod.SessionContext{};
            ctx.target = target;
            ctx.user_id = self.metrics.acc_user_id;
            ctx.protocol = self.inbound.node_type;
            ctx.transport = transport;
            ctx.src_addr = self.metrics.src_addr;
            if (self.metrics.src_addr) |sa| {
                if (sa.any.family == 2) { // AF_INET
                    ctx.src_port = std.mem.bigToNative(u16, sa.in.sa.port);
                }
            }
            if (self.cfg.inbound_tag_len > 0) {
                ctx.setInboundTag(self.cfg.inbound_tag_buf[0..self.cfg.inbound_tag_len]);
            }
            // Pass sniffed domain to router as resolved_target
            if (self.metrics.sniff_domain_len > 0) {
                ctx.resolved_target.setDomain(
                    self.metrics.sniff_domain_buf[0..self.metrics.sniff_domain_len],
                    target.port,
                );
            }
            return router.route(&ctx);
        }
        return null;
    }

    const default_direct_out = config_mod.OutConfig{ .protocol = .freedom };

    pub fn startConnect(self: *Session, loop: *xev.Loop, target: session_mod.TargetAddress) void {
        // Sniff initial payload for domain detection (TLS SNI / HTTP Host)
        if (self.metrics.sniff_enabled) {
            if (self.initial_payload) |payload| {
                if (payload.len > 0) {
                    if (sniffer.sniff(payload)) |result| {
                        const len: u8 = @intCast(@min(result.domain.len, self.metrics.sniff_domain_buf.len));
                        @memcpy(self.metrics.sniff_domain_buf[0..len], result.domain[0..len]);
                        self.metrics.sniff_domain_len = len;
                        self.metrics.sniff_proto = result.protocol;
                    }
                }
            }
        }

        // Redirect: override target address with sniffed domain
        var effective_target = target;
        if (self.metrics.sniff_redirect and self.metrics.sniff_domain_len > 0) {
            effective_target.setDomain(
                self.metrics.sniff_domain_buf[0..self.metrics.sniff_domain_len],
                target.port,
            );
        }

        // Route decision: determine which outbound to use (fallback: direct)
        const route_result = self.resolveOutbound(effective_target);
        const out = if (route_result) |r| r.out else &default_direct_out;
        self.outbound.config = out;

        // Save route info to access log: "protocol(matched_rule)" or just "freedom"
        if (route_result) |r| {
            const proto = @tagName(out.protocol);
            if (r.matched_rule.len > 0) {
                const s = std.fmt.bufPrint(&self.metrics.acc_route, "{s}({s})", .{ proto, r.matched_rule }) catch
                    std.fmt.bufPrint(&self.metrics.acc_route, "{s}", .{proto}) catch "";
                self.metrics.acc_route_len = @intCast(s.len);
            } else {
                const rlen: u8 = @intCast(@min(proto.len, self.metrics.acc_route.len));
                @memcpy(self.metrics.acc_route[0..rlen], proto[0..rlen]);
                self.metrics.acc_route_len = rlen;
            }
        } else {
            const tag = "freedom";
            @memcpy(self.metrics.acc_route[0..tag.len], tag);
            self.metrics.acc_route_len = tag.len;
        }

        // Log routing decision (one line per connection, emitted early)
        self.logRouteDecision();

        switch (out.protocol) {
            .blackhole => {
                self.lifecycle.close_reason = .blocked;
                self.initiateClose(loop);
            },
            .vmess, .trojan, .shadowsocks => {
                self.outbound.real_target = effective_target;
                self.outbound.kind = switch (out.protocol) {
                    .vmess => .vmess,
                    .trojan => .trojan,
                    .shadowsocks => .shadowsocks,
                    else => unreachable,
                };
                self.outbound_state = self.cfg.worker.allocator.create(OutboundState) catch {
                    self.cfg.logger.err("outbound alloc failed", .{});
                    self.initiateClose(loop);
                    return;
                };
                self.outbound_state.?.* = .{};
                // Pre-allocate enc_buf so outbound protocol handlers can safely use .?
                if (self.ensureEncBuf() == null) {
                    self.cfg.logger.err("outbound enc_buf alloc failed", .{});
                    self.initiateClose(loop);
                    return;
                }
                self.connectOutbound(loop, out);
            },
            .freedom => {
                self.directConnect(loop, effective_target);
            },
        }
    }

    /// Direct connection: resolve DNS if needed, then connect to target.
    fn directConnect(self: *Session, loop: *xev.Loop, target: session_mod.TargetAddress) void {
        switch (target.addr_type) {
            .ipv4 => {
                self.metrics.acc_dns = .direct;
                const addr = std.net.Address.initIp4(target.ip4, target.port);
                self.doConnect(loop, addr);
            },
            .ipv6 => {
                self.metrics.acc_dns = .direct;
                const addr = std.net.Address.initIp6(target.ip6, target.port, 0, 0);
                self.doConnect(loop, addr);
            },
            .domain => {
                const domain = target.getDomain();
                // AsyncResolver is always initialized by main.zig
                const resolver = self.cfg.worker.dns_resolver.?;
                _ = self.lifecycle.fsm.transition(.dns_resolving);
                self.dns_target_port = target.port;
                self.trackOp();
                if (!resolver.submitQuery(domain, &dnsResolveCallback, @ptrCast(self))) {
                    self.lifecycle.close_reason = .dns_err;
                    self.opDone();
                    self.initiateClose(loop);
                }
            },
            .none => {
                self.lifecycle.close_reason = .proto_err;
                self.initiateClose(loop);
            },
        }
    }

    /// Connect to outbound server (VMess/Trojan/SS). Resolves DNS if server is a hostname.
    fn connectOutbound(self: *Session, loop: *xev.Loop, out: *const config_mod.OutConfig) void {
        // If we have a resolved IP address, connect directly
        if (out.server_addr) |addr| {
            self.metrics.acc_dns = .direct;
            self.doConnect(loop, addr);
            return;
        }
        // Server is a hostname — need DNS resolution
        const host = out.getServerHost();
        if (host.len == 0) {
            self.lifecycle.close_reason = .dns_err;
            self.initiateClose(loop);
            return;
        }
        const port = out.server_port;
        // AsyncResolver is always initialized by main.zig
        const resolver = self.cfg.worker.dns_resolver.?;
        _ = self.lifecycle.fsm.transition(.dns_resolving);
        self.dns_target_port = port;
        self.trackOp();
        if (!resolver.submitQuery(host, &dnsResolveCallback, @ptrCast(self))) {
            self.lifecycle.close_reason = .dns_err;
            self.opDone();
            self.initiateClose(loop);
        }
    }

    /// Check if a bind address is suitable for outbound SendThrough.
    /// Skips loopback (127.x.x.x), unspecified (0.0.0.0), and address family mismatches.
    fn isRoutableBindAddr(bind_addr: std.net.Address, target_addr: std.net.Address) bool {
        // Address family must match (can't bind IPv4 on IPv6 socket or vice versa)
        if (bind_addr.any.family != target_addr.any.family) return false;
        if (bind_addr.any.family == 2) { // AF_INET
            const ip = bind_addr.in.sa.addr;
            // 0.0.0.0 — unspecified, no point binding
            if (ip == 0) return false;
            // 127.x.x.x — loopback, can't route to external targets
            const first_byte: u8 = @truncate(ip); // little-endian: first byte is lowest
            if (first_byte == 127) return false;
        }
        return true;
    }

    /// TCP connect after address is resolved.
    pub fn doConnect(self: *Session, loop: *xev.Loop, addr: std.net.Address) void {
        _ = self.lifecycle.fsm.transition(.connecting);

        var target_tcp = xev.TCP.init(addr) catch {
            self.cfg.logger.err("failed to create target socket", .{});
            self.initiateClose(loop);
            return;
        };

        // Linux: reduce TCP SYN retries from default 6 (~127s) to 3 (~7s)
        if (comptime builtin.os.tag == .linux) {
            const IPPROTO_TCP = 6;
            const TCP_SYNCNT = 7;
            const syncnt: c_int = 3;
            std.posix.setsockopt(target_tcp.fd, IPPROTO_TCP, TCP_SYNCNT, std.mem.asBytes(&syncnt)) catch {};
        }

        // Enable TCP keepalive on target socket (detect dead remote connections)
        setTcpKeepalive(target_tcp.fd);

        // SendThrough: bind outbound to same IP the client connected to (same IP in/out).
        // Falls back to per-listener send_through config if auto-detect unavailable.
        // Skip bind for non-routable addresses (loopback, unspecified) and on
        // address family mismatch (e.g. IPv4 local but IPv6 target).
        const per_listener_st = if (self.cfg.listener_id < self.cfg.worker.listener_info_count)
            self.cfg.worker.listener_infos[self.cfg.listener_id].send_through_addr
        else
            null;
        const bind_addr = self.cfg.local_addr orelse per_listener_st;
        if (bind_addr) |ba| {
            if (isRoutableBindAddr(ba, addr)) {
                target_tcp.bind(ba) catch |e| {
                    self.cfg.logger.err("send_through bind failed: {}", .{e});
                    // Non-fatal: proceed without bind rather than killing the connection
                };
            }
        }

        self.outbound.tcp = target_tcp;
        self.lifecycle.sockets_to_close = 2;
        _ = self.cfg.worker.conns_outbound.fetchAdd(1, .monotonic);

        self.cfg.logger.debug("#{d} [outbound] CONNECT kind={s} pending_ops={d}", .{
            self.metrics.conn_id,
            @tagName(self.outbound.kind),
            self.lifecycle.pending_ops,
        });

        self.trackOp();
        target_tcp.connect(loop, &self.outbound.connect_comp, addr, Session, self, &onConnect);

        // Early disconnect detection: start monitoring client socket for FIN/RST
        // during the outbound connect + handshake phase. Without this, a client
        // disconnect goes undetected until relay starts or handshake timeout (30s).
        // Protect initial_payload: it points into recv_buf which would be overwritten
        // by the client read. Move it to send_buf (free during outbound handshake).
        if (self.initial_payload) |payload| {
            if (payload.len > 0) {
                if (self.inbound.send_buf) |sbuf| {
                    @memcpy(sbuf[0..payload.len], payload);
                    self.initial_payload = sbuf[0..payload.len];
                }
            }
        }
        self.outbound.early_detect_active = true;
        self.startClientRead(loop);
    }

    /// Called by Worker.onAsyncNotify when async DNS result is delivered.
    pub fn onDnsResult(self: *Session, loop: *xev.Loop, result: ?dns_resolver.ResolveResult, cache_hit: bool) void {
        defer self.opDone(); // matches trackOp() in startConnect

        if (self.lifecycle.fsm.isClosingOrClosed()) return;

        if (result) |r| {
            self.metrics.acc_dns = if (cache_hit) .cache else .resolve;
            if (r.toAddress(self.dns_target_port)) |addr| {
                self.doConnect(loop, addr);
            } else {
                self.lifecycle.close_reason = .dns_err;
                self.initiateClose(loop);
            }
        } else {
            self.lifecycle.close_reason = .dns_err;
            self.initiateClose(loop);
        }
    }

    /// DNS callback — runs on the DNS worker thread. Must only touch
    /// the worker's lock-free queue and async notification, nothing else.
    fn dnsResolveCallback(req: *dns_resolver.DnsRequest) void {
        const self: *Session = @ptrCast(@alignCast(req.user_data.?));
        const entry = Worker.DnsResultQueue.Entry{
            .conn = self,
            .result = req.result,
            .cache_hit = req.cache_hit,
        };
        // Bounded spin: retry pushing with backoff. If exhausted, push a
        // null-result entry so the worker can still close the connection cleanly.
        const max_retries: u32 = 50_000; // ~10 seconds at 0.2ms per retry
        var retry_count: u32 = 0;
        while (!self.cfg.worker.dns_results.push(entry)) {
            retry_count += 1;
            if (retry_count >= max_retries) {
                // Force-push a failure entry to avoid leaking the connection.
                // Keep spinning — this MUST be delivered.
                const fail_entry = Worker.DnsResultQueue.Entry{
                    .conn = self,
                    .result = null,
                    .cache_hit = false,
                };
                self.cfg.logger.err("dns result queue full after {d} retries, forcing failure delivery", .{retry_count});
                while (!self.cfg.worker.dns_results.push(fail_entry)) {
                    self.cfg.worker.async_notify.notify() catch {};
                    std.Thread.sleep(1_000_000); // 1ms
                }
                break;
            }
            self.cfg.worker.async_notify.notify() catch {};
            std.Thread.sleep(200_000); // 0.2ms
            if (retry_count == 1 or retry_count % 5000 == 0) {
                self.cfg.logger.warn("dns result queue full, waiting (retries={d})", .{retry_count});
            }
        }
        self.cfg.worker.async_notify.notify() catch {};
    }

    // ── Access log helpers ──

    pub fn saveAccessMeta(self: *Session, user_id: i64, target: session_mod.TargetAddress, proto_tag: []const u8) void {
        self.metrics.acc_user_id = user_id;
        const plen: u8 = @intCast(@min(proto_tag.len, self.metrics.acc_proto.len));
        @memcpy(self.metrics.acc_proto[0..plen], proto_tag[0..plen]);
        self.metrics.acc_proto_len = plen;
        const ts = switch (target.addr_type) {
            .domain => std.fmt.bufPrint(&self.metrics.acc_target, "{s}:{d}", .{ target.getDomain(), target.port }),
            .ipv4 => std.fmt.bufPrint(&self.metrics.acc_target, "{d}.{d}.{d}.{d}:{d}", .{
                target.ip4[0], target.ip4[1], target.ip4[2], target.ip4[3], target.port,
            }),
            .ipv6 => std.fmt.bufPrint(&self.metrics.acc_target, "[ipv6]:{d}", .{target.port}),
            .none => std.fmt.bufPrint(&self.metrics.acc_target, "?:0", .{}),
        };
        self.metrics.acc_target_len = if (ts) |v| @intCast(v.len) else |_| 0;
    }

    /// Format source address as "ip:port" string for logging.
    fn fmtSrcAddr(self: *Session) []const u8 {
        const a = self.metrics.src_addr orelse return "-";
        const ip_bytes: [4]u8 = @bitCast(a.in.sa.addr);
        const port = a.getPort();
        return std.fmt.bufPrint(&self.metrics.src_ip_buf, "{d}.{d}.{d}.{d}:{d}", .{
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], port,
        }) catch "-";
    }

    /// Log routing decision immediately after route is resolved.
    /// Format: #{conn_id} {src} {proto} {target} sniff:{tls|http|-} [{inbound}>{route}] uid:{id}
    fn logRouteDecision(self: *Session) void {
        if (!self.cfg.logger.enabled(.info)) return;

        const src = self.fmtSrcAddr();
        const proto = if (self.metrics.acc_proto_len > 0) self.metrics.acc_proto[0..self.metrics.acc_proto_len] else @tagName(self.inbound.node_type);
        const target = if (self.metrics.acc_target_len > 0) self.metrics.acc_target[0..self.metrics.acc_target_len] else "-";
        const inbound = if (self.cfg.inbound_tag_len > 0) self.cfg.inbound_tag_buf[0..self.cfg.inbound_tag_len] else @tagName(self.inbound.node_type);
        const route_tag: []const u8 = if (self.metrics.acc_route_len > 0) self.metrics.acc_route[0..self.metrics.acc_route_len] else "-";
        const sniff_tag: []const u8 = if (!self.metrics.sniff_enabled) "off" else switch (self.metrics.sniff_proto) {
            .tls => "tls",
            .http => "http",
            .unknown => "-",
        };
        var uid_buf: [24]u8 = undefined;
        const uid_str = if (self.metrics.acc_user_id >= 0)
            std.fmt.bufPrint(&uid_buf, "{d}", .{self.metrics.acc_user_id}) catch "-"
        else
            @as([]const u8, "-");

        self.cfg.logger.accessInfo("#{d} {s} {s} {s} sniff:{s} [{s}>{s}] uid:{s}", .{
            self.metrics.conn_id, src, proto, target, sniff_tag, inbound, route_tag, uid_str,
        });
    }

    fn onConnect(ud: ?*Session, l: *xev.Loop, _: *xev.Completion, _: xev.TCP, r: xev.ConnectError!void) xev.CallbackAction {
        const self = ud.?;
        defer self.opDone();

        if (self.lifecycle.fsm.isClosingOrClosed()) {
            self.cfg.logger.debug("#{d} [outbound] CONNECTED already_closing pending_ops={d}", .{
                self.metrics.conn_id, self.lifecycle.pending_ops,
            });
            return .disarm;
        }

        r catch {
            self.cfg.logger.debug("#{d} [outbound] CONNECT_FAIL pending_ops={d}", .{
                self.metrics.conn_id, self.lifecycle.pending_ops,
            });
            self.lifecycle.close_reason = .conn_err;
            self.initiateClose(l);
            return .disarm;
        };

        self.cfg.logger.debug("#{d} [outbound] CONNECTED state={s} pending_ops={d}", .{
            self.metrics.conn_id, self.lifecycle.fsm.state.name(), self.lifecycle.pending_ops,
        });

        // Outbound transport + protocol handshake
        // Layer order: TCP connect → [TLS] → [WS upgrade] → protocol header
        const transport: config_mod.Transport = if (self.outbound.config) |oc| oc.transport else .tcp;
        switch (transport) {
            .wss => {
                // TLS first, then WS upgrade in onOutboundTlsReady
                outbound_transport.startOutboundTls(self, l);
                return .disarm;
            },
            .ws => {
                // WS upgrade directly over TCP
                outbound_transport.startOutboundWsUpgrade(self, l);
                return .disarm;
            },
            .tls => {
                // TLS only (Trojan default path)
                outbound_transport.startOutboundTls(self, l);
                return .disarm;
            },
            else => {},
        }
        // No transport layer — direct protocol handshake
        switch (self.outbound.kind) {
            .trojan => {
                // Trojan always needs TLS (even if transport=tcp)
                outbound_transport.startOutboundTls(self, l);
                return .disarm;
            },
            .vmess => {
                outbound_dispatch.sendProtocolHeader(self, l);
                return .disarm;
            },
            .shadowsocks => {
                outbound_dispatch.sendProtocolHeader(self, l);
                return .disarm;
            },
            .direct => {},
        }

        _ = self.lifecycle.fsm.transition(.relaying);
        _ = self.cfg.worker.conns_relay.fetchAdd(1, .monotonic);
        self.touchActivity();
        self.cfg.logger.debug("#{d} [session] RELAY_START kind=direct pending_ops={d}", .{
            self.metrics.conn_id, self.lifecycle.pending_ops,
        });

        // Send initial payload if any, then start both directions
        self.sendInitialPayload(l);
        return .disarm;
    }

    pub fn sendInitialPayload(self: *Session, loop: *xev.Loop) void {
        // When pending_downlink_flush is set, skip startTargetRead here —
        // it will be started by processVMessOutDownlinkData's flow instead,
        // avoiding a double-startTargetRead.
        const skip_target_read = self.outbound.pending_downlink_flush;

        if (self.inbound.node_type == .vmess) {
            // VMess inbound: body data is AEAD-encrypted and MUST go through
            // processVMessUplink to decrypt and advance the nonce counter.
            //
            // Two cases:
            //   1. inbound_pending has data (rare — accumulated during relay phase)
            //   2. initial_payload has data (common — client sent header + first body
            //      chunk in the same TCP segment; stored in send_buf by startConnect)
            //
            // Without processing the initial payload here, nonce_counter stays at 0
            // and subsequent client data fails AEAD at nonce=0 (integrity error).
            if (self.inbound.pending_tail > self.inbound.pending_head) {
                const action = vmess_relay.processVMessUplink(self, loop, &[_]u8{});
                if (!skip_target_read) self.startTargetRead(loop);
                if (action == .rearm) self.startClientRead(loop);
                // If .disarm, writeToTarget was submitted. onTargetWrite → startClientRead.
                return;
            }
            if (self.initial_payload) |payload| {
                if (payload.len > 0) {
                    // Feed encrypted initial body bytes through AEAD decrypt.
                    // processVMessUplink copies payload into inbound_pending,
                    // decrypts, and calls writeToTarget with plaintext.
                    self.initial_payload = null;
                    const action = vmess_relay.processVMessUplink(self, loop, payload);
                    if (!skip_target_read) self.startTargetRead(loop);
                    if (action == .rearm) self.startClientRead(loop);
                    return;
                }
            }
        } else if (self.initial_payload) |payload| {
            if (payload.len > 0) {
                // Trojan/direct: initial payload through transport layers (WS + TLS)
                self.writeToTarget(loop, payload);
                self.initial_payload = null;
                // Start downlink while waiting for write to complete
                if (!skip_target_read) self.startTargetRead(loop);
                return;
            }
        }

        // No initial payload
        self.startClientRead(loop);
        if (!skip_target_read) {
            self.startTargetRead(loop);
        }
        // When skip_target_read is true (called from onVMessOutResponseRead),
        // the caller handles target read via .rearm or onTargetWrite flush.
        // Do NOT call processVMessOutDownlinkData or startTargetRead here —
        // we may be inside target_read_comp callback (IOCP error 996).
    }

    // ══════════════════════════════════════════════════════════════
    //  Target-side read/write
    // ══════════════════════════════════════════════════════════════

    pub fn startTargetRead(self: *Session, loop: *xev.Loop) void {
        // Allow target reads in: relaying (full duplex) + half_close_client (downlink active)
        if (!self.lifecycle.fsm.isRelaying() and !self.lifecycle.fsm.is(.half_close_client)) return;
        if (self.outbound.tcp) |*tcp| {
            self.trackOp();
            tcp.read(loop, &self.outbound.read_comp, .{ .slice = self.outbound.target_buf.? }, Session, self, &onTargetRead);
        }
    }

    fn onTargetRead(ud: ?*Session, l: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.ReadBuffer, r: xev.ReadError!usize) xev.CallbackAction {
        const self = ud.?;
        defer self.opDone();

        if (self.lifecycle.fsm.isClosingOrClosed()) return .disarm;

        const n = r catch {
            self.cfg.logger.debug("#{d} [outbound] READ_ERR state={s} pending_ops={d}", .{
                self.metrics.conn_id, self.lifecycle.fsm.state.name(), self.lifecycle.pending_ops,
            });
            self.initiateClose(l);
            return .disarm;
        };
        if (n == 0) {
            // Target sent FIN
            self.cfg.logger.debug("#{d} [outbound] FIN state={s} pending_ops={d}", .{
                self.metrics.conn_id, self.lifecycle.fsm.state.name(), self.lifecycle.pending_ops,
            });
            // Half-close with real TCP shutdown(SHUT_WR).
            // Propagate FIN to client so it knows downlink is done.
            // The other direction (client→target) continues until client also EOF's
            // or half-close grace period expires.
            if (self.lifecycle.fsm.isRelaying() or self.lifecycle.fsm.is(.half_close_client)) {
                if (self.lifecycle.fsm.is(.half_close_client)) {
                    self.cfg.logger.debug("#{d} [outbound] FIN both_done pending_ops={d}", .{
                        self.metrics.conn_id, self.lifecycle.pending_ops,
                    });
                    self.initiateClose(l); // both directions done → fd close
                } else {
                    self.cfg.logger.debug("#{d} [outbound] HALF_CLOSE pending_ops={d}", .{
                        self.metrics.conn_id, self.lifecycle.pending_ops,
                    });
                    _ = self.lifecycle.fsm.transition(.half_close_target);
                    self.lifecycle.half_close_start_ms = currentMs();
                    // Propagate FIN to client via TCP shutdown(SHUT_WR)
                    socketShutdownSend(self.inbound.tcp.fd);
                    self.scheduleHalfCloseTimeout(l);
                }
                return .disarm;
            }
            self.initiateClose(l);
            return .disarm;
        }

        self.touchActivity();
        self.cfg.worker.stats.addBytesOut(n);
        self.metrics.conn_bytes_dn += n;

        // VMess outbound: unwrap transport + decrypt protocol chunks
        if (self.outbound_state != null and self.outbound_state.?.vmess.response_state != null) {
            switch (relay_pipeline.unwrapOutboundTransport(self, self.outbound.target_buf.?[0..n])) {
                .data => |data| {
                    // After WS unframe, check if a pong was buffered by stripWsFrames.
                    // target_write_comp is free here (we're in target_read callback).
                    // Send pong immediately to avoid server timeout.
                    if (self.outbound.ws_active) {
                        if (self.outbound_state) |out| {
                            if (out.ws.pong_len > 0) {
                                self.sendWsPongDirect(l);
                                // Pong now occupies target_write_comp.
                                // Process downlink data — it goes to client_write_comp (safe).
                            }
                        }
                    }
                    vmess_relay.processVMessOutDownlinkData(self, l, data);
                },
                .want_read => self.startTargetRead(l),
                .close, .err => self.initiateClose(l),
            }
            return .disarm;
        }

        // Downlink: target data → [transport unwrap] → [inbound encrypt] → client
        self.handleRelayDownlink(l, n);
        return .disarm;
    }

    pub fn onTargetWrite(ud: ?*Session, l: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.WriteBuffer, r: xev.WriteError!usize) xev.CallbackAction {
        const self = ud.?;
        defer self.opDone();

        if (self.lifecycle.fsm.isClosingOrClosed()) return .disarm;

        _ = r catch {
            self.initiateClose(l);
            return .disarm;
        };

        // VMess outbound: deferred response read after pre-response uplink write completes.
        // This avoids target_write_comp contention: uplink write must finish before
        // response callback can potentially trigger another target write.
        if (self.outbound.vmess_response_pending and self.lifecycle.fsm.is(.outbound_vmess_header)) {
            self.outbound.vmess_response_pending = false;
            outbound_dispatch.startVMessResponseRead(self, l);
            self.startClientRead(l);
            return .disarm;
        }

        // Target write done (uplink) — drain any remaining TLS BIO data
        // before waiting for new client data. Multiple TLS records may have
        // been fed from a single TCP read; only one was processed per cycle.
        // Also needed in half_close_target: target FIN'd but uplink is still
        // active, so client TLS BIO may still have buffered data to process.
        // NOTE: NOT half_close_client — uplink is stopped, calling startClientRead
        // would see FIN and prematurely close while downlink is still active.
        if (self.lifecycle.fsm.isRelaying() or self.lifecycle.fsm.is(.outbound_vmess_header) or self.lifecycle.fsm.is(.half_close_target)) {
            if (self.inbound.tls) |*tls| {
                while (true) {
                    switch (tls.readDecrypted(self.inbound.decrypt_buf.?)) {
                        .bytes => |dn| {
                            self.cfg.worker.stats.addBytesIn(dn);
                            self.metrics.conn_bytes_up += dn;
                            // Inbound WS: must unwrap WS frames before protocol dispatch
                            if (self.inbound.ws_active) {
                                const action = relay_pipeline.unwrapInboundWsAndDispatch(self, l, self.inbound.decrypt_buf.?[0..dn]);
                                if (action == .disarm) return .disarm;
                                continue;
                            }
                            switch (self.inbound.protocol) {
                                .vmess => {
                                    const action = vmess_relay.processVMessUplink(self, l, self.inbound.decrypt_buf.?[0..dn]);
                                    if (action == .disarm) return .disarm;
                                    continue;
                                },
                                .shadowsocks => {
                                    const action = ss_relay.processSsUplink(self, l, self.inbound.decrypt_buf.?[0..dn]);
                                    if (action == .disarm) return .disarm;
                                    continue;
                                },
                                .none => {
                                    if (self.outbound.xudp_mode) {
                                        vmess_relay.handleXudpUplink(self, l, self.inbound.decrypt_buf.?[0..dn]);
                                        return .disarm;
                                    } else {
                                        self.writeToTarget(l, self.inbound.decrypt_buf.?[0..dn]);
                                        return .disarm;
                                    }
                                },
                            }
                        },
                        .want_read => break, // BIO drained, fall through
                        .closed => {
                            self.initiateClose(l);
                            return .disarm;
                        },
                        else => {
                            self.initiateClose(l);
                            return .disarm;
                        },
                    }
                }
            }

            // **Critical**: After TLS BIO is drained (or when no TLS is used),
            // the VMess/SS pending buffer may still contain complete chunks from
            // a previous accumulation. One TLS record can carry multiple VMess
            // chunks (~2KB each in a 16KB record). processVMessUplink only
            // decrypts ONE chunk per call. Without this drain, the remaining
            // chunks are stranded until new client data arrives — which may
            // never come if the target is waiting for the full request.
            // This is the root cause of VMess connections getting stuck while
            // Trojan (no chunking) works fine.
            if (self.inbound.protocol != .none and self.inbound.pending_tail > self.inbound.pending_head) {
                const action = switch (self.inbound.protocol) {
                    .vmess => vmess_relay.processVMessUplink(self, l, &[_]u8{}),
                    .shadowsocks => ss_relay.processSsUplink(self, l, &[_]u8{}),
                    .none => unreachable,
                };
                if (action == .disarm) return .disarm;
            }

            // **Critical**: After the initial uplink write completes, flush pending
            // outbound downlink data. This data arrived with the VMess response
            // (e.g., upstream TLS ServerHello) and must be forwarded to the client
            // BEFORE starting target read to prevent deadlock: client waits for
            // this data, VMess server waits for client's next message.
            if (self.outbound.pending_downlink_flush) {
                self.outbound.pending_downlink_flush = false;
                vmess_relay.processVMessOutDownlinkData(self, l, &[_]u8{});
                // processVMessOutDownlinkData either:
                // - success → handleRelayDownlinkData → client write →
                //   onClientWrite → drain → startTargetRead
                // - incomplete → startTargetRead
                // Either way, startTargetRead is handled. Start client read here.
                self.startClientRead(l);
                return .disarm;
            }
        }

        // half_close_client: uplink is finished (client FIN'd). The target write
        // that triggered this callback (VMess EOF chunk or WS pong) is done.
        // Do NOT start client read — client has already closed sending, reading
        // would see FIN and trigger premature initiateClose while the downlink
        // chain (target_read → client_write → target_read) is still active.
        if (self.lifecycle.fsm.is(.half_close_client)) return .disarm;

        // Send pending WS pong while target_write_comp is free.
        // Pong was queued by stripWsFrames when a server ping was detected.
        // Sending it here (at the end of uplink processing) ensures timely
        // delivery without waiting for the next data write.
        // NOTE: Do NOT call startClientRead here — pong occupies target_write_comp,
        // and if a client read completes first, driveRelayUplink → writeToTarget
        // would try to reuse the busy target_write_comp. Let the pong write complete
        // first; onTargetWrite will call startClientRead naturally.
        if (self.outbound.ws_active) {
            if (self.outbound_state) |out| {
                if (out.ws.pong_len > 0) {
                    self.sendWsPongDirect(l);
                    return .disarm;
                }
            }
        }

        self.startClientRead(l);
        return .disarm;
    }

    /// Send a pending WS pong frame — delegated to relay_pipeline.
    fn sendWsPongDirect(self: *Session, loop: *xev.Loop) void {
        relay_pipeline.sendWsPongDirect(self, loop);
    }

    // ══════════════════════════════════════════════════════════════
    //  Relay: Uplink (client → target) — driven from onClientRead
    // ══════════════════════════════════════════════════════════════

    /// Drive uplink relay — delegated to relay_pipeline.
    fn driveRelayUplink(self: *Session, loop: *xev.Loop, n: usize) xev.CallbackAction {
        return relay_pipeline.driveRelayUplink(self, loop, n);
    }

    /// Write to target through outbound protocol + transport layers — delegated to relay_pipeline.
    pub fn writeToTarget(self: *Session, loop: *xev.Loop, data: []const u8) void {
        relay_pipeline.writeToTarget(self, loop, data);
    }

    /// Wrap through outbound transport layers — delegated to relay_pipeline.
    pub fn wrapOutboundTransport(self: *Session, data: []const u8) ?[]const u8 {
        return relay_pipeline.wrapOutboundTransport(self, data);
    }

    /// Send data to client through inbound pipeline — delegated to relay_pipeline.
    pub fn handleRelayDownlinkData(self: *Session, loop: *xev.Loop, data: []const u8) void {
        relay_pipeline.handleRelayDownlinkData(self, loop, data);
    }

    /// Handle downlink — delegated to relay_pipeline.
    fn handleRelayDownlink(self: *Session, loop: *xev.Loop, n: usize) void {
        relay_pipeline.handleRelayDownlink(self, loop, n);
    }

    // ══════════════════════════════════════════════════════════════
    //  UDP Relay (Full Cone NAT) — delegated to udp_relay_handler
    // ══════════════════════════════════════════════════════════════

    pub fn startUdpRelay(self: *Session, loop: *xev.Loop) void {
        udp_relay.startUdpRelay(self, loop);
    }

    fn driveUdpUplink(self: *Session, loop: *xev.Loop, n: usize) xev.CallbackAction {
        return udp_relay.driveUdpUplink(self, loop, n);
    }

    pub fn onUdpDownlink(self: *Session, loop: *xev.Loop, entry: Worker.UdpDownlinkQueue.Entry) void {
        udp_relay.onUdpDownlink(self, loop, entry);
    }

    // ══════════════════════════════════════════════════════════════
    //  Close
    //
    //  Half-close uses real TCP shutdown(SHUT_WR) to propagate FIN.
    //  Grace period (default 5s) caps half-close duration as safety net.
    //  Both fds are closed together when both directions are done.
    // ══════════════════════════════════════════════════════════════

    pub fn initiateClose(self: *Session, loop: *xev.Loop) void {
        if (self.lifecycle.fsm.isClosingOrClosed()) return;
        // Infer default close reason if not explicitly set
        if (self.lifecycle.close_reason == .none) {
            self.lifecycle.close_reason = if (self.lifecycle.fsm.isRelayingOrUdp()) .done else .err;
        }

        self.cfg.logger.debug("#{d} [session] CLOSE reason={s} state={s} pending_ops={d} has_outbound={}", .{
            self.metrics.conn_id,
            @tagName(self.lifecycle.close_reason),
            self.lifecycle.fsm.state.name(),
            self.lifecycle.pending_ops,
            self.outbound.tcp != null,
        });

        // Decrement relay counter if leaving relay phase
        if (self.lifecycle.fsm.isRelayingOrUdp()) {
            _ = self.cfg.worker.conns_relay.fetchSub(1, .monotonic);
        }
        self.lifecycle.fsm.transitionToClosing();
        self.lifecycle.close_count = 0;

        // Cancel timeout timer if pending
        self.timeout.rearm_ms = 0;
        if (self.timeout.active) {
            self.timeout.active = false;
            self.timeout.due_ms = 0;
            self.trackOp(); // for cancel confirmation callback
            self.timeout.timer.?.cancel(loop, &self.timeout.comp, &self.timeout.cancel_comp, Session, self, &onTimeoutCancelDone);
        }

        // Close UDP relay socket (causes recv thread to exit)
        if (self.udp_sock != UdpSys.INVALID_SOCKET) {
            self.udp_closed.store(true, .release);
            UdpSys.close(self.udp_sock);
            self.udp_sock = UdpSys.INVALID_SOCKET;
        }

        // Determine how many sockets to close (needed by onCloseComplete)
        if (self.outbound.tcp != null) {
            self.lifecycle.sockets_to_close = 2;
        } else {
            self.lifecycle.sockets_to_close = 1;
        }

        if (xev.backend == .epoll) {
            // Option A (epoll): shutdown both sockets synchronously.
            // shutdown(SHUT_RDWR) causes epoll to fire events on all registered fds
            // (including dup'd fds created by xev for concurrent read+write):
            //   - Read ops  → return 0 (EOF) or error → callback returns .disarm
            //   - Write ops → return error            → callback returns .disarm
            // xev's own disarm path (epoll.zig) does CTL_DEL + close(dup_fd),
            // cleaning up its internal state without us touching xev internals.
            // After all I/O ops drain, opDone() detects pending_ops==1 (only drain
            // timer remains) and calls queueTcpClose() to do the actual fd close.
            self.cached_loop = loop;
            std.posix.shutdown(self.inbound.tcp.fd, .both) catch {};
            if (self.outbound.tcp) |tcp| {
                _ = self.cfg.worker.conns_outbound.fetchSub(1, .monotonic);
                std.posix.shutdown(tcp.fd, .both) catch {};
            }

            // Safety drain timer: if I/O ops don't complete within 5s, force-close.
            self.drain_active = true;
            self.drain_timer_running = true;
            if (self.drain_timer == null) {
                self.drain_timer = xev.Timer.init() catch {
                    // Timer init failed — fall back to immediate close
                    self.drain_active = false;
                    self.drain_timer_running = false;
                    self.queueTcpClose(loop);
                    return;
                };
            }
            self.trackOp(); // for drain timer
            self.drain_timer.?.run(loop, &self.drain_comp, 5000, Session, self, &onDrainTimeout);
        } else {
            // IOCP (Windows): closesocket() cancels overlapped I/O and posts
            // ABORTED completions to the IOCP queue. Those callbacks fire and
            // call opDone() normally — no drain needed.
            self.trackOp();
            self.inbound.tcp.close(loop, &self.inbound.close_comp, Session, self, &onCloseComplete);
            if (self.outbound.tcp) |*tcp| {
                _ = self.cfg.worker.conns_outbound.fetchSub(1, .monotonic);
                self.trackOp();
                tcp.close(loop, &self.outbound.close_comp, Session, self, &onCloseComplete);
            }
        }
    }

    /// Submit actual tcp.close() for both sockets after I/O has drained.
    /// Called either from opDone() (natural drain) or onDrainTimeout() (forced).
    fn queueTcpClose(self: *Session, loop: *xev.Loop) void {
        self.lifecycle.close_count = 0;
        self.trackOp();
        self.inbound.tcp.close(loop, &self.inbound.close_comp, Session, self, &onCloseComplete);
        if (self.outbound.tcp) |*tcp| {
            self.trackOp();
            tcp.close(loop, &self.outbound.close_comp, Session, self, &onCloseComplete);
        }
    }

    fn onCloseComplete(ud: ?*Session, _: *xev.Loop, c: *xev.Completion, _: xev.TCP, r: xev.CloseError!void) xev.CallbackAction {
        const self = ud.?;
        self.lifecycle.close_count += 1;

        const which: []const u8 = if (c == &self.inbound.close_comp) "inbound" else "outbound";
        _ = r catch {
            self.cfg.logger.debug("#{d} [{s}] CLOSE_ERR count={d}/{d} pending_ops={d}", .{
                self.metrics.conn_id, which, self.lifecycle.close_count, self.lifecycle.sockets_to_close, self.lifecycle.pending_ops,
            });
        };
        self.cfg.logger.debug("#{d} [{s}] CLOSED count={d}/{d} pending_ops={d}", .{
            self.metrics.conn_id, which, self.lifecycle.close_count, self.lifecycle.sockets_to_close, self.lifecycle.pending_ops,
        });

        // On epoll (Option A): by the time queueTcpClose() is called, all I/O ops have
        // already returned .disarm and xev has cleaned up their dup'd fds. No orphaned
        // ops exist — just transition FSM and let opDone() reach 0 naturally.
        // On IOCP: closesocket() already cancelled overlapped I/O; same clean path.
        if (self.lifecycle.close_count >= self.lifecycle.sockets_to_close) {
            self.lifecycle.fsm.transitionToClosed();
        }

        self.opDone();
        return .disarm;
    }

    /// Drain safety timeout: fires if I/O ops don't complete within 5s after shutdown().
    /// This is the fallback for stuck connections (e.g. send buffer full, remote unresponsive).
    /// Normal connections drain well within 5s — this path should rarely trigger.
    fn onDrainTimeout(ud: ?*Session, l: *xev.Loop, _: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        const self = ud.?;
        defer self.opDone(); // release drain timer's trackOp
        _ = r catch return .disarm; // timer was cancelled (natural drain succeeded first)

        if (!self.drain_active) {
            // Natural drain already triggered close from opDone().
            // Timer fired after we submitted cancel but before cancel was processed.
            // onDrainTimerCancel will handle the cancel slot.
            return .disarm;
        }

        self.cfg.logger.debug("#{d} [session] DRAIN_TIMEOUT pending_ops={d}", .{
            self.metrics.conn_id, self.lifecycle.pending_ops,
        });

        self.drain_active = false;
        self.drain_timer_running = false;

        // Some I/O ops are still stuck after 5s. Force-drain them before closing.
        // (Fallback: same approach as the pre-Option-A force-drain in onCloseComplete.)
        //
        // pending_ops at this point = (stuck I/O ops) + 1 (this timer, not yet opDone'd).
        // Only subtract ops we ACTUALLY force-drain (xev completions). Non-xev ops like
        // the UDP recv thread's trackOp cannot be force-drained and will call opDone()
        // naturally when the thread exits. Blindly resetting pending_ops=1 would cause
        // underflow when those non-xev ops eventually complete.
        if (self.lifecycle.pending_ops > 1) {
            const orphaned = self.lifecycle.pending_ops - 1;
            var force_drained: u16 = 0;

            if (xev.backend == .epoll) {
                const linux = std.os.linux;
                const comps = [_]*xev.Completion{
                    &self.inbound.read_comp,
                    &self.inbound.write_comp,
                    &self.outbound.read_comp,
                    &self.outbound.write_comp,
                    &self.outbound.connect_comp,
                };
                for (comps) |comp| {
                    switch (comp.flags.state) {
                        .active => {
                            if (comp.flags.dup and comp.flags.dup_fd > 0) {
                                std.posix.epoll_ctl(l.fd, linux.EPOLL.CTL_DEL, comp.flags.dup_fd, null) catch {};
                                std.posix.close(comp.flags.dup_fd);
                                comp.flags.dup_fd = 0;
                            }
                            comp.flags.state = .dead;
                            l.active -= 1;
                            force_drained += 1;
                        },
                        .adding => {
                            comp.flags.state = .dead;
                            force_drained += 1;
                        },
                        else => {},
                    }
                }
            } else {
                force_drained = orphaned;
                l.active -|= force_drained;
            }

            self.cfg.logger.debug("#{d} [session] force_drain {d} stuck ops, {d} xev drained (drain timeout)", .{
                self.metrics.conn_id, orphaned, force_drained,
            });
            self.lifecycle.pending_ops -= force_drained;
        }

        self.queueTcpClose(l);
        return .disarm;
    }

    /// Confirmation callback for drain timer cancellation.
    /// Called when the drain timer cancel completes (either successfully or because
    /// the timer already fired before the cancel was processed).
    fn onDrainTimerCancel(ud: ?*Session, _: *xev.Loop, _: *xev.Completion, _: xev.Timer.CancelError!void) xev.CallbackAction {
        const self = ud.?;
        self.opDone(); // release cancel's trackOp
        return .disarm;
    }
};

// ── Tests ──

test "Session FSM type accessible" {
    var fsm = ConnFSM{};
    try std.testing.expect(fsm.state == .proxy_protocol);
    _ = fsm.transition(.tls_handshake);
    try std.testing.expect(fsm.state == .tls_handshake);

    // State alias works
    const s: Session.State = .relaying;
    try std.testing.expect(s == .relaying);
}
