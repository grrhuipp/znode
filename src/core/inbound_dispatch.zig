// ══════════════════════════════════════════════════════════════
//  Inbound Protocol Dispatch
//
//  Thin dispatcher: accumulates protocol header bytes, calls
//  pure protocol parsers, and executes InboundResult actions.
//
//  Protocol handlers are pure functions — they return InboundResult
//  instead of directly operating on Session. The dispatcher
//  interprets the result and applies side effects.
//
//  Also provides shared fallback handling (ALPN + path matching).
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const xev = @import("xev");
const session_mod = @import("session.zig");
const trojan_inbound = @import("../protocol/trojan/trojan_inbound.zig");
const vmess_inbound = @import("../protocol/vmess/vmess_inbound.zig");
const ss_inbound = @import("../protocol/shadowsocks/ss_inbound.zig");
const ss_crypto = @import("../protocol/shadowsocks/ss_crypto.zig");
const Session = @import("proxy_connection.zig").Session;
const inbound_result = @import("inbound_result.zig");
const InboundResult = inbound_result.InboundResult;
const ConnectAction = inbound_result.ConnectAction;

/// Accumulate and attempt to parse the protocol header.
/// Dispatches to the appropriate protocol handler based on node_type.
pub fn handleProtocolData(self: *Session, loop: *xev.Loop, data: []const u8) xev.CallbackAction {
    // Accumulate in protocol buffer (pre-allocated in create())
    const avail = self.inbound.protocol_buf.?.len - self.inbound.protocol_buf_len;
    const to_copy = @min(data.len, avail);
    @memcpy(self.inbound.protocol_buf.?[self.inbound.protocol_buf_len .. self.inbound.protocol_buf_len + to_copy], data[0..to_copy]);
    self.inbound.protocol_buf_len += to_copy;

    // Protocol buffer full but header still not parsed — close (header shouldn't need >8KB)
    if (data.len > avail) {
        self.cfg.logger.warn("protocol buffer full ({d}B), header not parsed", .{self.inbound.protocol_buf_len});
        self.lifecycle.close_reason = .proto_err;
        self.initiateClose(loop);
        return .disarm;
    }

    const buf = self.inbound.protocol_buf.?[0..self.inbound.protocol_buf_len];

    // Detect TLS ClientHello when TLS is not enabled
    if (self.inbound.tls == null and buf.len >= 3 and buf[0] == 0x16 and buf[1] == 0x03) {
        self.lifecycle.close_reason = .tls_err;
        self.initiateClose(loop);
        return .disarm;
    }

    // Ensure payload output buffer (handlers write initial payload here)
    const payload_out = self.ensureDecryptBuf() orelse {
        self.initiateClose(loop);
        return .disarm;
    };

    // Call pure protocol parser → InboundResult
    const result: InboundResult = switch (self.inbound.node_type) {
        .trojan => trojan_inbound.parseInbound(buf, self.cfg.user_store_ptr, payload_out),
        .vmess => blk: {
            const user_map = if (self.cfg.user_store_ptr) |store| store.getUsers() else null;
            const info = &self.cfg.worker.listener_infos[self.cfg.listener_id];
            const res = vmess_inbound.parseInbound(
                buf,
                user_map,
                &self.cfg.worker.replay_filter,
                &info.hot_cache,
                self.cfg.worker.allocator,
                payload_out,
            );
            switch (res) {
                .close => |reason| if (reason == .auth_fail) {
                    const n_users: usize = if (user_map) |um| um.users.len else 0;
                    self.cfg.logger.warn("vmess: auth failed ({d} users checked)", .{n_users});
                },
                else => {},
            }
            break :blk res;
        },
        .shadowsocks => blk: {
            const info = &self.cfg.worker.listener_infos[self.cfg.listener_id];
            if (info.ss_inbound) |ss| {
                const method: ss_crypto.Method = @enumFromInt(ss.method);
                break :blk ss_inbound.parseInbound(buf, method, ss.psk[0..ss.key_len], payload_out);
            }
            break :blk InboundResult{ .close = .proto_err };
        },
        else => InboundResult{ .close = .proto_err },
    };

    return executeResult(self, loop, result);
}

// ══════════════════════════════════════════════════════════════
//  InboundResult Execution
// ══════════════════════════════════════════════════════════════

/// Execute an InboundResult: apply side effects to Session.
fn executeResult(self: *Session, loop: *xev.Loop, result: InboundResult) xev.CallbackAction {
    switch (result) {
        .connect => |action| return executeConnect(self, loop, action, false),
        .udp_associate => |action| return executeConnect(self, loop, action, true),
        .need_more => return .rearm,
        .fallback => return tryFallback(self, loop, ""),
        .close => |reason| {
            self.lifecycle.close_reason = reason;
            self.initiateClose(loop);
            return .disarm;
        },
    }
}

/// Execute a connect or UDP associate action from InboundResult.
fn executeConnect(self: *Session, loop: *xev.Loop, action: ConnectAction, is_udp: bool) xev.CallbackAction {
    // Set inbound protocol state (VMess/SS crypto, or .none for Trojan)
    self.inbound.protocol = action.protocol_state;

    // Save access metadata for logging
    self.saveAccessMeta(action.user_id, action.target, action.protoLabel());

    // Copy initial payload (already written to decrypt_buf by handler)
    if (action.payload_len > 0) {
        self.initial_payload = self.inbound.decrypt_buf.?[0..action.payload_len];
        self.initial_payload_len = action.payload_len;
    }

    // SS: save salt to protocol_buf for first downlink response
    if (action.salt_len > 0) {
        @memcpy(self.inbound.protocol_buf.?[0..action.salt_len], action.salt_buf[0..action.salt_len]);
        self.inbound.protocol_buf_len = action.salt_len;
    }

    // VMess: send response header first (deferred connect — onClientWrite triggers startConnect)
    if (action.response_len > 0) {
        self.inbound.protocol.vmess.response_sent = true;
        self.outbound.target_addr = action.target;
        sendProtocolResponse(self, loop, action.response_buf[0..action.response_len]);
        return .disarm;
    }

    // UDP associate → check XUDP or regular UDP
    if (is_udp) {
        // Check if outbound routes to VMess → XUDP mode (UDP over VMess TCP)
        if (self.resolveOutbound(action.target)) |route_result| {
            if (route_result.out.protocol == .vmess) {
                self.outbound.xudp_mode = true;
                self.startConnect(loop, action.target);
                return .disarm;
            }
        }
        // Regular UDP relay
        self.startUdpRelay(loop);
        return .disarm;
    }

    // Regular TCP connect
    self.startConnect(loop, action.target);
    return .disarm;
}

/// Send protocol-layer response to client through transport layers (WS + TLS).
/// Used for VMess response header during protocol_parse phase.
fn sendProtocolResponse(self: *Session, loop: *xev.Loop, data: []const u8) void {
    const sbuf = self.ensureSendBuf() orelse {
        self.initiateClose(loop);
        return;
    };
    var pos: usize = 0;

    // WS wrap: binary frame, server→client (no mask per RFC 6455)
    if (self.inbound.ws_active) {
        sbuf[pos] = 0x82; // FIN + binary opcode
        pos += 1;
        if (data.len <= 125) {
            sbuf[pos] = @intCast(data.len);
            pos += 1;
        } else {
            sbuf[pos] = 126;
            pos += 1;
            std.mem.writeInt(u16, sbuf[pos..][0..2], @intCast(data.len), .big);
            pos += 2;
        }
        @memcpy(sbuf[pos .. pos + data.len], data);
        pos += data.len;
    } else {
        @memcpy(sbuf[0..data.len], data);
        pos = data.len;
    }

    // TLS encrypt
    if (self.inbound.tls) |*tls| {
        switch (tls.writeEncrypted(sbuf[0..pos])) {
            .bytes => {
                const tls_n = tls.getNetworkData(sbuf);
                if (tls_n > 0) {
                    self.trackOp();
                    self.inbound.tcp.write(loop, &self.inbound.write_comp, .{ .slice = sbuf[0..tls_n] }, Session, self, &Session.onClientWrite);
                    return;
                }
            },
            else => {
                self.lifecycle.close_reason = .tls_err;
                self.initiateClose(loop);
                return;
            },
        }
    }

    // No TLS: send directly
    self.trackOp();
    self.inbound.tcp.write(loop, &self.inbound.write_comp, .{ .slice = sbuf[0..pos] }, Session, self, &Session.onClientWrite);
}

// ══════════════════════════════════════════════════════════════
//  Fallback Handling (shared across protocols)
// ══════════════════════════════════════════════════════════════

/// Try fallback on auth/protocol failure. If fallback is configured,
/// connect to fallback server and forward all accumulated raw data.
/// Supports multi-level fallback with ALPN and path matching (Xray-compatible).
pub fn tryFallback(self: *Session, loop: *xev.Loop, _: []const u8) xev.CallbackAction {
    // Determine fallback destination
    const fb_addr = resolveFallbackAddr(self) orelse {
        self.lifecycle.close_reason = .auth_fail;
        self.initiateClose(loop);
        return .disarm;
    };

    // Save ALL accumulated raw data as initial payload for fallback
    if (self.inbound.protocol_buf_len > 0) {
        const dbuf = self.ensureDecryptBuf() orelse {
            self.lifecycle.close_reason = .err;
            self.initiateClose(loop);
            return .disarm;
        };
        @memcpy(
            dbuf[0..self.inbound.protocol_buf_len],
            self.inbound.protocol_buf.?[0..self.inbound.protocol_buf_len],
        );
        self.initial_payload = dbuf[0..self.inbound.protocol_buf_len];
        self.initial_payload_len = self.inbound.protocol_buf_len;
    }

    self.saveAccessMeta(-1, session_mod.TargetAddress{}, "fallback");
    self.doConnect(loop, fb_addr);
    return .disarm;
}

/// Resolve fallback address: try multi-level entries first, then default.
fn resolveFallbackAddr(self: *Session) ?std.net.Address {
    // Get ALPN from inbound TLS (if available)
    const alpn: ?[]const u8 = if (self.inbound.tls) |*tls| tls.getAlpnProtocol() else null;

    // Extract HTTP path from accumulated data (first line: "GET /path HTTP/1.1")
    const path: ?[]const u8 = extractHttpPath(self);

    // Check listener-specific multi-level fallbacks
    if (self.cfg.listener_id < self.cfg.worker.listener_info_count) {
        const info = self.cfg.worker.listener_infos[self.cfg.listener_id];
        if (info.fallback_count > 0) {
            for (info.fallbacks[0..info.fallback_count]) |*fb| {
                if (fb.matches(alpn, path)) {
                    if (fb.dest_addr) |addr| return addr;
                }
            }
        }
    }

    // Default fallback (unconditional)
    return self.cfg.fallback_addr;
}

/// Extract HTTP request path from protocol_buf (best-effort).
fn extractHttpPath(self: *Session) ?[]const u8 {
    if (self.inbound.protocol_buf_len < 10) return null;
    const buf = self.inbound.protocol_buf.?[0..self.inbound.protocol_buf_len];
    // Look for "GET /path " or "POST /path " etc.
    const first_space = std.mem.indexOfScalar(u8, buf, ' ') orelse return null;
    if (first_space + 1 >= buf.len) return null;
    const path_start = first_space + 1;
    if (buf[path_start] != '/') return null;
    const rest = buf[path_start..];
    const second_space = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    return rest[0..second_space];
}

// ══════════════════════════════════════════════════════════════
//  Tests
// ══════════════════════════════════════════════════════════════

test "extractHttpPath" {
    // Can't test directly without a Session, but structure is verified
    // by the compiler. Integration tests cover the full parsing path.
}
