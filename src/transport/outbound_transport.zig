// ══════════════════════════════════════════════════════════════
//  Outbound Transport Layer
//
//  Handles outbound TLS and WebSocket handshakes.
//  After transport is ready, dispatches to protocol-specific handlers.
//
//  Single responsibility: transport layer only — no protocol logic.
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const xev = @import("xev");
const tls_mod = @import("tls_stream.zig");
const ws_mod = @import("ws_stream.zig");
const config_mod = @import("../core/config.zig");
const relay_pipeline = @import("../core/relay_pipeline.zig");
const outbound_dispatch = @import("../core/outbound_dispatch.zig");
const protocol_registry = @import("../core/protocol_registry.zig");
const Session = @import("../core/proxy_connection.zig").Session;

// ══════════════════════════════════════════════════════════════
//  Outbound TLS Handshake
// ══════════════════════════════════════════════════════════════

pub fn startOutboundTls(self: *Session, loop: *xev.Loop) void {
    // Create outbound TLS client context + stream
    var client_ctx = tls_mod.TlsContext.initClient() catch {
        self.lifecycle.close_reason = .tls_err;
        self.initiateClose(loop);
        return;
    };
    defer client_ctx.deinit();

    // Use explicit SNI from config, fallback to real target domain
    const out_sni: ?[]const u8 = if (self.outbound.config) |oc|
        (if (oc.sni_len > 0) oc.getSni() else null)
    else
        null;
    const hostname: ?[]const u8 = out_sni orelse if (self.outbound.real_target) |rt|
        (if (rt.addr_type == .domain) rt.getDomain() else null)
    else
        null;

    // Configure certificate verification and ALPN
    const skip_verify = if (self.outbound.config) |oc| oc.skip_cert_verify else false;
    client_ctx.configureOutbound(skip_verify, hostname);

    self.outbound.tls = client_ctx.newClient(hostname) catch {
        self.lifecycle.close_reason = .tls_err;
        self.initiateClose(loop);
        return;
    };

    _ = self.lifecycle.fsm.transition(.outbound_tls_handshake);

    // Drive the initial handshake (sends ClientHello)
    driveOutboundTlsHandshake(self, loop);
}

fn driveOutboundTlsHandshake(self: *Session, loop: *xev.Loop) void {
    var ttls = &(self.outbound.tls.?);

    switch (ttls.handshake()) {
        .done => {
            // TLS handshake complete, proceed to protocol header
            onOutboundTlsReady(self, loop);
        },
        .want_read => {
            // Send pending TLS data (ClientHello) to target, then read response
            const pending_n = ttls.getNetworkData(self.outbound_state.?.pending.?);
            if (pending_n > 0) {
                self.trackOp();
                self.outbound.tcp.?.write(loop, &self.outbound.write_comp, .{ .slice = self.outbound_state.?.pending.?[0..pending_n] }, Session, self, &onOutboundTlsWrite);
            } else {
                // Need more data from target
                startTargetReadForTls(self, loop);
            }
        },
        .want_write => {
            const pending_n = ttls.getNetworkData(self.outbound_state.?.pending.?);
            if (pending_n > 0) {
                self.trackOp();
                self.outbound.tcp.?.write(loop, &self.outbound.write_comp, .{ .slice = self.outbound_state.?.pending.?[0..pending_n] }, Session, self, &onOutboundTlsWrite);
            } else {
                // No data to write but TLS wants write — read more from target
                startTargetReadForTls(self, loop);
            }
        },
        .err => {
            self.lifecycle.close_reason = .tls_err;
            self.initiateClose(loop);
        },
    }
}

fn onOutboundTlsWrite(ud: ?*Session, l: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.WriteBuffer, r: xev.WriteError!usize) xev.CallbackAction {
    const self = ud.?;
    defer self.opDone();
    if (self.lifecycle.fsm.isClosingOrClosed()) return .disarm;

    _ = r catch {
        self.lifecycle.close_reason = .tls_err;
        self.initiateClose(l);
        return .disarm;
    };

    if (self.lifecycle.fsm.is(.outbound_tls_handshake)) {
        // After writing TLS data, read response from target
        startTargetReadForTls(self, l);
    }
    // In relay mode, TLS writes are handled by normal relay flow
    return .disarm;
}

fn startTargetReadForTls(self: *Session, loop: *xev.Loop) void {
    const tbuf = self.ensureTargetBuf() orelse {
        self.initiateClose(loop);
        return;
    };
    self.trackOp();
    self.outbound.tcp.?.read(loop, &self.outbound.read_comp, .{ .slice = tbuf }, Session, self, &onOutboundTlsRead);
}

fn onOutboundTlsRead(ud: ?*Session, l: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.ReadBuffer, r: xev.ReadError!usize) xev.CallbackAction {
    const self = ud.?;
    defer self.opDone();
    if (self.lifecycle.fsm.isClosingOrClosed()) return .disarm;

    const n = r catch {
        self.lifecycle.close_reason = .tls_err;
        self.initiateClose(l);
        return .disarm;
    };

    if (n == 0) {
        self.initiateClose(l);
        return .disarm;
    }

    // Feed data to TLS engine
    var ttls = &(self.outbound.tls.?);
    _ = ttls.feedNetworkData(self.outbound.target_buf.?[0..n]) catch {
        self.lifecycle.close_reason = .tls_err;
        self.initiateClose(l);
        return .disarm;
    };

    // Continue handshake
    driveOutboundTlsHandshake(self, l);
    return .disarm;
}

/// Called when outbound TLS handshake completes.
fn onOutboundTlsReady(self: *Session, loop: *xev.Loop) void {
    // For WSS transport: TLS done → WS upgrade next
    const transport: config_mod.Transport = if (self.outbound.config) |oc| oc.transport else .tcp;
    if (transport == .wss) {
        startOutboundWsUpgrade(self, loop);
        return;
    }
    proceedToProtocolHandshake(self, loop);
}

// ══════════════════════════════════════════════════════════════
//  Protocol Dispatch (thin layer — delegates to protocol handlers)
// ══════════════════════════════════════════════════════════════

/// After transport layers are ready (TCP/TLS/WS), start protocol-specific handshake.
/// Delegates to outbound_dispatch which calls pure protocol encoders.
fn proceedToProtocolHandshake(self: *Session, loop: *xev.Loop) void {
    outbound_dispatch.sendProtocolHeader(self, loop);
}

/// Write data to target, through outbound transport layers (WS + TLS).
/// Callback dispatches based on connection state (Trojan header → relay, VMess header → read response).
pub fn writeToTargetRaw(self: *Session, loop: *xev.Loop, data: []const u8) void {
    const wrapped = relay_pipeline.wrapOutboundTransport(self, data) orelse {
        self.cfg.logger.err("outbound transport wrap failed", .{});
        self.initiateClose(loop);
        return;
    };

    // Debug: log transport-wrapped output for VMess handshake
    if (self.lifecycle.fsm.is(.outbound_vmess_header)) {
        self.cfg.logger.debug("vmess out: raw={d}B wrapped={d}B ws={s} tls={s}", .{
            data.len,
            wrapped.len,
            if (self.outbound.ws_active) @as([]const u8, "yes") else @as([]const u8, "no"),
            if (self.outbound.tls != null) @as([]const u8, "yes") else @as([]const u8, "no"),
        });
    }

    self.trackOp();
    self.outbound.tcp.?.write(loop, &self.outbound.write_comp, .{ .slice = wrapped }, Session, self, &onOutboundHeaderWrite);
}

/// Generic callback for outbound header writes. Delegates protocol-specific
/// post-write logic to outbound_dispatch.handlePostHeaderWrite.
fn onOutboundHeaderWrite(ud: ?*Session, l: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.WriteBuffer, r: xev.WriteError!usize) xev.CallbackAction {
    const self = ud.?;
    defer self.opDone();
    if (self.lifecycle.fsm.isClosingOrClosed()) return .disarm;

    _ = r catch |e| {
        self.cfg.logger.err("outbound header write failed: {}", .{e});
        self.initiateClose(l);
        return .disarm;
    };

    outbound_dispatch.handlePostHeaderWrite(self, l);
    return .disarm;
}

// ══════════════════════════════════════════════════════════════
//  Outbound WebSocket Upgrade (ws/wss transport)
// ══════════════════════════════════════════════════════════════

/// Start WebSocket client upgrade handshake.
/// Called after TCP connect (ws) or after TLS ready (wss).
pub fn startOutboundWsUpgrade(self: *Session, loop: *xev.Loop) void {
    const oc = self.outbound.config orelse {
        self.cfg.logger.err("outbound WS: no config", .{});
        self.initiateClose(loop);
        return;
    };

    const path = if (oc.getWsPath().len > 0) oc.getWsPath() else "/";
    const host = if (oc.getWsHost().len > 0) oc.getWsHost() else oc.getServerHost();

    const ws_ptr = self.cfg.worker.allocator.create(ws_mod.WsStream) catch {
        self.cfg.logger.err("outbound WS: alloc failed", .{});
        self.initiateClose(loop);
        return;
    };
    ws_ptr.* = ws_mod.WsStream.initClient(path, host);
    self.outbound.ws = ws_ptr;
    self.outbound.ws_active = true;
    _ = self.lifecycle.fsm.transition(.outbound_ws_handshake);
    self.cfg.logger.debug("outbound WS: path=\"{s}\" host=\"{s}\"", .{ path, host });

    driveOutboundWsHandshake(self, loop);
}

fn driveOutboundWsHandshake(self: *Session, loop: *xev.Loop) void {
    const ws = self.outbound.ws.?;

    const hs_result = ws.handshake();
    self.cfg.logger.debug("outbound WS hs: result={s} hs_done={}", .{
        switch (hs_result) {
            .want_write => "want_write",
            .want_read => "want_read",
            .bytes => "bytes",
            .err => "err",
            .closed => "closed",
        },
        ws.handshake_done,
    });

    switch (hs_result) {
        .want_write => {
            // Get WS handshake data and send through TLS or TCP
            const ws_n = ws.getNetworkData(self.outbound_state.?.enc_buf.?);
            self.cfg.logger.debug("outbound WS hs: sending {d}B upgrade request (tls={})", .{ ws_n, self.outbound.tls != null });
            if (ws_n > 0) {
                const data = self.outbound_state.?.enc_buf.?[0..ws_n];
                // If outbound TLS is active (wss), wrap through TLS
                if (self.outbound.tls) |*ttls| {
                    switch (ttls.writeEncrypted(data)) {
                        .bytes => {},
                        else => {
                            self.cfg.logger.err("outbound WS: TLS encrypt failed", .{});
                            self.initiateClose(loop);
                            return;
                        },
                    }
                    const tls_n = ttls.getNetworkData(self.outbound_state.?.pending.?);
                    if (tls_n > 0) {
                        self.trackOp();
                        self.outbound.tcp.?.write(loop, &self.outbound.write_comp, .{ .slice = self.outbound_state.?.pending.?[0..tls_n] }, Session, self, &onOutboundWsWrite);
                    } else {
                        startTargetReadForWs(self, loop);
                    }
                } else {
                    // Plain TCP (ws without TLS)
                    self.trackOp();
                    self.outbound.tcp.?.write(loop, &self.outbound.write_comp, .{ .slice = data }, Session, self, &onOutboundWsWrite);
                }
            } else {
                startTargetReadForWs(self, loop);
            }
        },
        .want_read => {
            startTargetReadForWs(self, loop);
        },
        .bytes => {
            // Handshake complete (bytes=0 means done)
            onOutboundWsReady(self, loop);
        },
        else => {
            self.cfg.logger.err("outbound WS: handshake failed", .{});
            self.initiateClose(loop);
        },
    }
}

fn onOutboundWsWrite(ud: ?*Session, l: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.WriteBuffer, r: xev.WriteError!usize) xev.CallbackAction {
    const self = ud.?;
    defer self.opDone();
    if (self.lifecycle.fsm.isClosingOrClosed()) return .disarm;

    const written = r catch |e| {
        self.cfg.logger.err("outbound WS write failed: {}", .{e});
        self.initiateClose(l);
        return .disarm;
    };
    self.cfg.logger.debug("outbound WS hs: write done {d}B, fsm={s}", .{
        written,
        @tagName(self.lifecycle.fsm.state),
    });

    if (self.lifecycle.fsm.is(.outbound_ws_handshake)) {
        startTargetReadForWs(self, l);
    }
    return .disarm;
}

fn startTargetReadForWs(self: *Session, loop: *xev.Loop) void {
    if (self.outbound.tcp) |*tcp| {
        const tbuf = self.ensureTargetBuf() orelse {
            self.initiateClose(loop);
            return;
        };
        self.trackOp();
        tcp.read(loop, &self.outbound.read_comp, .{ .slice = tbuf }, Session, self, &onOutboundWsRead);
    }
}

fn onOutboundWsRead(ud: ?*Session, l: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.ReadBuffer, r: xev.ReadError!usize) xev.CallbackAction {
    const self = ud.?;
    defer self.opDone();
    if (self.lifecycle.fsm.isClosingOrClosed()) return .disarm;

    const n = r catch |e| {
        self.cfg.logger.err("outbound WS read failed: {}", .{e});
        self.initiateClose(l);
        return .disarm;
    };
    self.cfg.logger.debug("outbound WS hs: read {d}B from target", .{n});
    if (n == 0) {
        self.cfg.logger.err("outbound WS: server closed during handshake", .{});
        self.initiateClose(l);
        return .disarm;
    }

    // For WSS: decrypt TLS first, then feed to WS
    if (self.outbound.tls) |*ttls| {
        _ = ttls.feedNetworkData(self.outbound.target_buf.?[0..n]) catch {
            self.cfg.logger.err("outbound WS: TLS feed failed", .{});
            self.initiateClose(l);
            return .disarm;
        };
        while (true) {
            switch (ttls.readDecrypted(self.inbound.decrypt_buf.?)) {
                .bytes => |dn| {
                    _ = self.outbound.ws.?.feedNetworkData(self.inbound.decrypt_buf.?[0..dn]) catch {
                        self.cfg.logger.err("outbound WS: feed failed", .{});
                        self.initiateClose(l);
                        return .disarm;
                    };
                    continue; // drain all TLS records, not just the first
                },
                .want_read => break,
                else => {
                    self.cfg.logger.err("outbound WS: TLS read failed", .{});
                    self.initiateClose(l);
                    return .disarm;
                },
            }
        }
    } else {
        _ = self.outbound.ws.?.feedNetworkData(self.outbound.target_buf.?[0..n]) catch {
            self.cfg.logger.err("outbound WS: feed failed", .{});
            self.initiateClose(l);
            return .disarm;
        };
    }

    driveOutboundWsHandshake(self, l);
    return .disarm;
}

/// WS upgrade complete — proceed to protocol handshake.
fn onOutboundWsReady(self: *Session, loop: *xev.Loop) void {
    self.cfg.logger.info("outbound WS upgrade done", .{});
    proceedToProtocolHandshake(self, loop);
}
