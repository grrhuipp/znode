// ══════════════════════════════════════════════════════════════
//  Outbound Protocol Dispatcher
//
//  Analogous to inbound_dispatch.zig: protocol files are pure functions,
//  this file bridges them to Session state and async I/O.
//
//  Responsibilities:
//    1. Read protocol config from Session
//    2. Call pure encode/parse functions (trojan/vmess/ss _outbound.zig)
//    3. Install results into Session (crypto state, FSM, buffers)
//    4. Drive async I/O (TCP write callbacks, response read callbacks)
//
//  Called from:
//    - outbound_transport.proceedToProtocolHandshake → sendProtocolHeader
//    - outbound_transport.onOutboundHeaderWrite → handlePostHeaderWrite
//    - proxy_connection.onConnect (direct path) → sendProtocolHeader
//    - proxy_connection.onTargetWrite (VMess deferred) → startVMessResponseRead
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const xev = @import("xev");

const trojan_outbound = @import("../protocol/trojan/trojan_outbound.zig");
const trojan_protocol = @import("../protocol/trojan/trojan_protocol.zig");
const vmess_outbound = @import("../protocol/vmess/vmess_outbound.zig");
const vmess_protocol = @import("../protocol/vmess/vmess_protocol.zig");
const vmess_stream = @import("../protocol/vmess/vmess_stream.zig");
const vmess_relay = @import("../protocol/vmess/vmess_relay.zig");
const ss_outbound = @import("../protocol/shadowsocks/ss_outbound.zig");
const ss_crypto = @import("../protocol/shadowsocks/ss_crypto.zig");

const outbound_transport = @import("../transport/outbound_transport.zig");
const relay_pipeline = @import("relay_pipeline.zig");
const Session = @import("proxy_connection.zig").Session;

// ══════════════════════════════════════════════════════════════
//  Main dispatch entry point
// ══════════════════════════════════════════════════════════════

/// Dispatch outbound protocol handshake after transport layers (TCP/TLS/WS) are ready.
/// Called from outbound_transport.proceedToProtocolHandshake.
pub fn sendProtocolHeader(self: *Session, loop: *xev.Loop) void {
    switch (self.outbound.kind) {
        .trojan => sendTrojanHeader(self, loop),
        .vmess => sendVMessHeader(self, loop),
        .shadowsocks => sendSsFirstPacket(self, loop),
        .direct => enterRelay(self, loop),
    }
}

/// Called by outbound_transport.onOutboundHeaderWrite after the header TCP write completes.
/// Dispatches to protocol-specific post-write logic.
pub fn handlePostHeaderWrite(self: *Session, loop: *xev.Loop) void {
    switch (self.lifecycle.fsm.state) {
        .outbound_trojan_header => enterRelayAfterHeader(self, loop),
        .outbound_vmess_header => handleVMessPostWrite(self, loop),
        else => {},
    }
}

// ══════════════════════════════════════════════════════════════
//  Trojan outbound
// ══════════════════════════════════════════════════════════════

fn sendTrojanHeader(self: *Session, loop: *xev.Loop) void {
    const target = self.outbound.real_target orelse {
        self.cfg.logger.err("trojan outbound: no real target", .{});
        self.initiateClose(loop);
        return;
    };

    const command: trojan_protocol.Command = if (self.outbound.xudp_mode) .udp_associate else .connect;

    const header_len = trojan_outbound.encodeHeader(
        self.outbound_state.?.enc_buf.?,
        self.outbound.config.?.trojan_password_hash,
        command,
        &target,
    ) orelse {
        self.cfg.logger.err("trojan outbound: header encode failed", .{});
        self.initiateClose(loop);
        return;
    };

    // Append initial payload to header for single TLS record write (reduces RTT + fingerprint).
    // initial_payload lives in decrypt_buf, enc_buf is separate — safe to copy.
    var total_len = header_len;
    if (self.initial_payload) |payload| {
        if (payload.len > 0 and total_len + payload.len <= self.outbound_state.?.enc_buf.?.len) {
            @memcpy(self.outbound_state.?.enc_buf.?[total_len .. total_len + payload.len], payload);
            total_len += payload.len;
            self.initial_payload = null;
            self.initial_payload_len = 0;
        }
    }

    _ = self.lifecycle.fsm.transition(.outbound_trojan_header);

    outbound_transport.writeToTargetRaw(self, loop, self.outbound_state.?.enc_buf.?[0..total_len]);
}

fn enterRelayAfterHeader(self: *Session, loop: *xev.Loop) void {
    _ = self.lifecycle.fsm.transition(.relaying);
    _ = self.cfg.worker.conns_relay.fetchAdd(1, .monotonic);
    self.touchActivity();
    self.cfg.logger.debug("#{d} [session] RELAY_START kind={s} pending_ops={d}", .{
        self.metrics.conn_id, @tagName(self.outbound.kind), self.lifecycle.pending_ops,
    });
    self.sendInitialPayload(loop);
}

// ══════════════════════════════════════════════════════════════
//  VMess outbound — header encoding
// ══════════════════════════════════════════════════════════════

fn sendVMessHeader(self: *Session, loop: *xev.Loop) void {
    const target = self.outbound.real_target orelse {
        self.cfg.logger.err("vmess outbound: no real target", .{});
        self.initiateClose(loop);
        return;
    };

    const security: vmess_protocol.SecurityMethod = @enumFromInt(self.outbound.config.?.vmess_security);
    const command: vmess_protocol.Command = if (self.outbound.xudp_mode) .mux else .tcp;
    const uuid = self.outbound.config.?.vmess_uuid;

    const result = vmess_outbound.encodeHeader(
        self.outbound_state.?.enc_buf.?,
        uuid,
        &target,
        command,
        security,
    ) orelse {
        self.cfg.logger.err("vmess outbound: header encode failed", .{});
        self.initiateClose(loop);
        return;
    };

    // Install crypto state into outbound_state
    self.outbound_state.?.vmess.body_key = result.body_key;
    self.outbound_state.?.vmess.body_iv = result.body_iv;
    self.outbound_state.?.vmess.resp_header = result.resp_header;
    self.outbound_state.?.vmess.request_state = result.request_state;
    self.outbound_state.?.vmess.response_state = null;
    self.outbound_state.?.pending_head = 0;
    self.outbound_state.?.pending_tail = 0;

    _ = self.lifecycle.fsm.transition(.outbound_vmess_header);
    self.inbound.protocol_buf_len = 0; // reuse protocol_buf for response accumulation

    // Debug: log VMess outbound header details for interop debugging
    {
        const vmess_crypto = @import("../protocol/vmess/vmess_crypto.zig");
        const enc = self.outbound_state.?.enc_buf.?;
        const cmd_key = vmess_crypto.deriveCmdKey(uuid);
        const ts = std.time.timestamp();
        self.cfg.logger.debug("vmess out: uuid={x:0>2}{x:0>2}{x:0>2}{x:0>2} cmdkey={x:0>2}{x:0>2}{x:0>2}{x:0>2} ts={d} authid={x:0>2}{x:0>2}{x:0>2}{x:0>2} wire={d}B sec={d} opt=0x{x:0>2}", .{
            uuid[0],  uuid[1],  uuid[2],  uuid[3],
            cmd_key[0], cmd_key[1], cmd_key[2], cmd_key[3],
            ts,
            enc[0], enc[1], enc[2], enc[3],
            result.wire_len,
            @intFromEnum(security),
            @as(u8, @bitCast(vmess_protocol.OptionFlags{ .chunk_stream = true, .chunk_masking = true, .global_padding = true })),
        });

        // Self-verification: try parsing our own header to catch encoding bugs
        if (result.wire_len >= 42) {
            var temp_replay = vmess_protocol.ReplayFilter{};
            const verify_result = vmess_protocol.parseRequestWithKey(
                enc[0..result.wire_len],
                cmd_key,
                null,
                &temp_replay,
                ts,
            );
            switch (verify_result) {
                .success => self.cfg.logger.debug("vmess out: self-verify OK", .{}),
                .incomplete => self.cfg.logger.warn("vmess out: self-verify incomplete (wire={d})", .{result.wire_len}),
                .auth_failed => self.cfg.logger.err("vmess out: SELF-VERIFY FAILED: auth_failed — KDF or AuthID encoding bug!", .{}),
                .protocol_error => self.cfg.logger.err("vmess out: SELF-VERIFY FAILED: protocol_error — header encoding bug!", .{}),
                .replay_detected => {},
            }
        }
    }

    // Write header through transport layers (WS + TLS)
    outbound_transport.writeToTargetRaw(self, loop, self.outbound_state.?.enc_buf.?[0..result.wire_len]);
}

// ══════════════════════════════════════════════════════════════
//  VMess outbound — post-header-write logic
// ══════════════════════════════════════════════════════════════

fn handleVMessPostWrite(self: *Session, loop: *xev.Loop) void {
    // VMess: start response read + allow pre-response uplink.
    // Some servers only flush VMess response after receiving first payload.
    //
    // IMPORTANT: If uplink data exists, we must write it via target_write_comp.
    // We CANNOT start response read (target_read_comp) AND write uplink
    // (target_write_comp) at the same time — double-submit on write_comp.
    // Solution: if uplink write is needed, set vmess_response_pending flag
    // and defer startVMessResponseRead to onTargetWrite (after write completes).
    self.cfg.logger.debug("vmess outbound: header written, waiting for response", .{});

    const has_uplink = (self.inbound.protocol == .vmess and
        self.inbound.pending_tail > self.inbound.pending_head);
    const has_initial = if (self.initial_payload) |p| p.len > 0 else false;

    if (has_uplink) {
        // Uplink data pending — write it first, defer response read
        self.outbound.vmess_response_pending = true;
        const action = vmess_relay.processVMessUplink(self, loop, &[_]u8{});
        if (action == .rearm) {
            // No complete chunk yet — start response read now (no write conflict)
            self.outbound.vmess_response_pending = false;
            startVMessResponseRead(self, loop);
            self.startClientRead(loop);
        }
        // .disarm: writeToTarget submitted → onTargetWrite will call startVMessResponseRead
    } else if (has_initial) {
        // Initial payload — write first, defer response read
        self.outbound.vmess_response_pending = true;
        self.writeToTarget(loop, self.initial_payload.?);
        self.initial_payload = null;
        // onTargetWrite will call startVMessResponseRead
    } else {
        // No uplink data — safe to start response read immediately
        startVMessResponseRead(self, loop);
        self.startClientRead(loop);
    }
}

// ══════════════════════════════════════════════════════════════
//  VMess outbound — response read
// ══════════════════════════════════════════════════════════════

/// Start reading the VMess server response header (38 bytes).
/// Called from handleVMessPostWrite (direct) or onTargetWrite (deferred).
pub fn startVMessResponseRead(self: *Session, loop: *xev.Loop) void {
    if (self.outbound.tcp) |*tcp| {
        const tbuf = self.ensureTargetBuf() orelse {
            self.initiateClose(loop);
            return;
        };
        self.trackOp();
        tcp.read(loop, &self.outbound.read_comp, .{ .slice = tbuf }, Session, self, &onVMessResponseRead);
    }
}

fn onVMessResponseRead(
    ud: ?*Session,
    l: *xev.Loop,
    _: *xev.Completion,
    _: xev.TCP,
    _: xev.ReadBuffer,
    r: xev.ReadError!usize,
) xev.CallbackAction {
    const self = ud.?;
    var do_op_done = true;
    defer if (do_op_done) self.opDone();

    // If already in relay state, this callback was re-armed because pending
    // downlink data was incomplete at handshake→relay transition. We returned
    // .rearm instead of calling startTargetRead (which would re-arm
    // target_read_comp from within its own callback → IOCP error 996).
    // Process the new data as normal relay downlink.
    if (self.lifecycle.fsm.isRelaying()) {
        if (self.lifecycle.fsm.isClosingOrClosed()) return .disarm;
        const n = r catch {
            self.initiateClose(l);
            return .disarm;
        };
        if (n == 0) {
            self.initiateClose(l);
            return .disarm;
        }
        self.touchActivity();
        self.cfg.worker.stats.addBytesOut(n);
        self.metrics.conn_bytes_dn += n;

        // Unwrap transport and process VMess downlink (mirrors onTargetRead VMess path)
        const vout = self.outbound_state.?;
        if (self.outbound.tls) |*ttls| {
            _ = ttls.feedNetworkData(self.outbound.target_buf.?[0..n]) catch {
                self.lifecycle.close_reason = .tls_err;
                self.initiateClose(l);
                return .disarm;
            };
            switch (ttls.readDecrypted(self.inbound.decrypt_buf.?)) {
                .bytes => |dn| {
                    if (self.outbound.ws_active) {
                        const payload_len = vout.stripWsFrames(self.inbound.decrypt_buf.?[0..dn], self.outbound.target_buf.?) orelse {
                            self.initiateClose(l);
                            return .disarm;
                        };
                        if (payload_len > 0) {
                            vmess_relay.processVMessOutDownlinkData(self, l, self.outbound.target_buf.?[0..payload_len]);
                        } else {
                            self.startTargetRead(l);
                        }
                    } else {
                        vmess_relay.processVMessOutDownlinkData(self, l, self.inbound.decrypt_buf.?[0..dn]);
                    }
                },
                .want_read => self.startTargetRead(l),
                else => self.initiateClose(l),
            }
        } else if (self.outbound.ws_active) {
            const payload_len = vout.stripWsFrames(self.outbound.target_buf.?[0..n], self.inbound.decrypt_buf.?) orelse {
                self.initiateClose(l);
                return .disarm;
            };
            if (payload_len > 0) {
                vmess_relay.processVMessOutDownlinkData(self, l, self.inbound.decrypt_buf.?[0..payload_len]);
            } else {
                self.startTargetRead(l);
            }
        } else {
            vmess_relay.processVMessOutDownlinkData(self, l, self.outbound.target_buf.?[0..n]);
        }
        return .disarm;
    }

    if (self.lifecycle.fsm.isClosingOrClosed()) return .disarm;

    const n = r catch {
        self.cfg.logger.err("vmess outbound response read failed", .{});
        self.initiateClose(l);
        return .disarm;
    };
    if (n == 0) {
        self.cfg.logger.err("vmess outbound: server closed during handshake", .{});
        self.initiateClose(l);
        return .disarm;
    }

    self.cfg.logger.debug("vmess outbound: got {d}B response from target", .{n});

    // Unwrap transport layers: [TLS decrypt] → [WS unframe] → raw VMess data
    var payload: []const u8 = self.outbound.target_buf.?[0..n];

    if (self.outbound.tls) |*ttls| {
        _ = ttls.feedNetworkData(payload) catch {
            self.cfg.logger.err("vmess response: TLS feed failed", .{});
            self.initiateClose(l);
            return .disarm;
        };
        switch (ttls.readDecrypted(self.inbound.decrypt_buf.?)) {
            .bytes => |dn| {
                payload = self.inbound.decrypt_buf.?[0..dn];
            },
            .want_read => {
                startVMessResponseRead(self, l);
                return .disarm;
            },
            else => {
                self.cfg.logger.err("vmess response: TLS decrypt failed", .{});
                self.initiateClose(l);
                return .disarm;
            },
        }
    }

    if (self.outbound.ws) |ws| {
        var total_fed = ws.feedNetworkData(payload) catch {
            self.cfg.logger.err("vmess response: WS feed failed", .{});
            self.initiateClose(l);
            return .disarm;
        };
        // Drain ALL complete WS frames (TCP may contain multiple).
        const ws_out: []u8 = if (self.outbound.tls != null) self.outbound.target_buf.? else self.inbound.decrypt_buf.?;
        var total_wn: usize = 0;
        while (total_wn < ws_out.len) {
            switch (ws.readDecrypted(ws_out[total_wn..])) {
                .bytes => |wn| {
                    total_wn += wn;
                    if (total_fed < payload.len) {
                        const more = ws.feedNetworkData(payload[total_fed..]) catch break;
                        total_fed += more;
                    }
                },
                .want_read => {
                    if (total_fed < payload.len) {
                        const more = ws.feedNetworkData(payload[total_fed..]) catch break;
                        total_fed += more;
                        if (more > 0) continue;
                    }
                    break;
                },
                else => {
                    self.cfg.logger.err("vmess response: WS unframe failed (payload={d}B, decoded={d}B)", .{ payload.len, total_wn });
                    self.initiateClose(l);
                    return .disarm;
                },
            }
        }
        if (total_wn > 0) {
            payload = ws_out[0..total_wn];
        } else {
            startVMessResponseRead(self, l);
            return .disarm;
        }
    }

    // Accumulate unwrapped VMess data in protocol_buf
    const avail = self.inbound.protocol_buf.?.len - self.inbound.protocol_buf_len;
    const to_copy = @min(payload.len, avail);
    @memcpy(self.inbound.protocol_buf.?[self.inbound.protocol_buf_len .. self.inbound.protocol_buf_len + to_copy], payload[0..to_copy]);
    self.inbound.protocol_buf_len += to_copy;

    // Call pure response parser — handles 38-byte check, AEAD validation, state init
    const security: vmess_protocol.SecurityMethod = @enumFromInt(self.outbound.config.?.vmess_security);
    const parse_result = vmess_outbound.parseResponse(
        self.inbound.protocol_buf.?[0..self.inbound.protocol_buf_len],
        self.outbound_state.?.vmess.body_key,
        self.outbound_state.?.vmess.body_iv,
        self.outbound_state.?.vmess.resp_header,
        security,
    );

    switch (parse_result) {
        .need_more => {
            startVMessResponseRead(self, l);
            return .disarm;
        },
        .protocol_error => {
            self.cfg.logger.err("vmess outbound: response protocol error", .{});
            self.initiateClose(l);
            return .disarm;
        },
        .validation_failed => {
            self.cfg.logger.err("vmess outbound: response validation failed", .{});
            self.initiateClose(l);
            return .disarm;
        },
        .success => |resp| {
            // Install response (downlink decrypt) state
            // Request state was initialized before response parsing to allow
            // pre-response uplink. Keep existing state if already active.
            if (self.outbound_state.?.vmess.request_state == null) {
                const options = vmess_protocol.OptionFlags{
                    .chunk_stream = true,
                    .chunk_masking = true,
                    .global_padding = true,
                };
                const vmess_crypto = @import("../protocol/vmess/vmess_crypto.zig");
                const resp_key = vmess_crypto.deriveResponseKey(self.outbound_state.?.vmess.body_key);
                const resp_iv = vmess_crypto.deriveResponseIv(self.outbound_state.?.vmess.body_iv);
                self.outbound_state.?.vmess.request_state = vmess_stream.StreamState.init(
                    resp_key,
                    resp_iv,
                    security,
                    options,
                );
            }
            self.outbound_state.?.vmess.response_state = resp.response_state;

            _ = self.lifecycle.fsm.transition(.relaying);
            _ = self.cfg.worker.conns_relay.fetchAdd(1, .monotonic);
            self.touchActivity();
            self.cfg.logger.debug("#{d} [session] RELAY_START kind=vmess pending_ops={d}", .{
                self.metrics.conn_id, self.lifecycle.pending_ops,
            });

            // Check if we got extra data beyond the 38-byte response header
            const extra = self.inbound.protocol_buf_len - vmess_protocol.response_wire_size;
            if (extra > 0) {
                const opend = self.ensureOutPending() orelse {
                    self.initiateClose(l);
                    return .disarm;
                };
                @memcpy(opend[0..extra], self.inbound.protocol_buf.?[vmess_protocol.response_wire_size..self.inbound.protocol_buf_len]);
                self.outbound_state.?.pending_head = 0;
                self.outbound_state.?.pending_tail = extra;
            }

            // Transfer WsStream's remaining raw data (partial WS frames) to
            // OutboundState.stripWsFrames so relay frame parsing stays aligned.
            if (self.outbound.ws) |ws| {
                const ws_remaining = ws.hs_buf[ws.leftover_start..ws.hs_len];
                if (ws_remaining.len > 0) {
                    const out = self.outbound_state.?;
                    if (out.stripWsFrames(ws_remaining, self.outbound.target_buf.?)) |stripped_len| {
                        if (stripped_len > 0) {
                            const pend_avail = out.pending.?.len - out.pending_tail;
                            const copy = @min(stripped_len, pend_avail);
                            if (copy > 0) {
                                @memcpy(out.pending.?[out.pending_tail .. out.pending_tail + copy], self.outbound.target_buf.?[0..copy]);
                                out.pending_tail += copy;
                            }
                        }
                    } else {
                        self.initiateClose(l);
                        return .disarm;
                    }
                }
                self.cfg.worker.allocator.destroy(ws);
                self.outbound.ws = null;
            }

            // Drain remaining TLS BIO data into outbound pending.
            if (self.outbound.tls) |*ttls| {
                const out = self.outbound_state.?;
                while (true) {
                    switch (ttls.readDecrypted(self.inbound.decrypt_buf.?)) {
                        .bytes => |dn| {
                            if (self.outbound.ws_active) {
                                const payload_len = out.stripWsFrames(self.inbound.decrypt_buf.?[0..dn], self.outbound.target_buf.?) orelse {
                                    self.initiateClose(l);
                                    return .disarm;
                                };
                                if (payload_len > 0) {
                                    const pend_avail = out.pending.?.len - out.pending_tail;
                                    const copy = @min(payload_len, pend_avail);
                                    if (copy > 0) {
                                        @memcpy(out.pending.?[out.pending_tail .. out.pending_tail + copy], self.outbound.target_buf.?[0..copy]);
                                        out.pending_tail += copy;
                                    }
                                }
                            } else {
                                const pend_avail = out.pending.?.len - out.pending_tail;
                                const copy = @min(dn, pend_avail);
                                if (copy > 0) {
                                    @memcpy(out.pending.?[out.pending_tail .. out.pending_tail + copy], self.inbound.decrypt_buf.?[0..copy]);
                                    out.pending_tail += copy;
                                }
                            }
                        },
                        .want_read => break,
                        else => {
                            self.initiateClose(l);
                            return .disarm;
                        },
                    }
                }
            }

            // XUDP mode: handle initial payload as UDP packets
            if (self.outbound.xudp_mode) {
                if (self.initial_payload) |init_data| {
                    if (init_data.len > 0) {
                        vmess_relay.handleXudpUplink(self, l, init_data);
                    }
                    self.initial_payload = null;
                }
                self.startClientRead(l);
                do_op_done = false;
                return .rearm;
            } else {
                // Normal TCP relay entry
                const out = self.outbound_state.?;
                const has_pending = out.pending_tail > out.pending_head;
                const has_uplink = (self.inbound.node_type == .vmess and
                    self.inbound.pending_tail > self.inbound.pending_head);
                const has_initial = if (self.initial_payload) |p| p.len > 0 else false;

                if (has_pending and !has_uplink and !has_initial) {
                    // Pending downlink but no uplink. Process inline to avoid
                    // startTargetRead from within target_read_comp (IOCP error 996).
                    self.startClientRead(l);
                    const state = &(out.vmess.response_state.?);
                    const pending = out.pending.?[out.pending_head..out.pending_tail];
                    switch (vmess_stream.decryptChunk(state, pending, self.inbound.decrypt_buf.?)) {
                        .success => |result2| {
                            out.pending_head += result2.bytes_consumed;
                            if (out.pending_head == out.pending_tail) {
                                out.pending_head = 0;
                                out.pending_tail = 0;
                            }
                            if (result2.plaintext_len == 0) {
                                self.initiateClose(l);
                                return .disarm;
                            }
                            relay_pipeline.handleRelayDownlinkData(self, l, self.inbound.decrypt_buf.?[0..result2.plaintext_len]);
                        },
                        .incomplete => {
                            do_op_done = false;
                            return .rearm;
                        },
                        .integrity_error => {
                            self.initiateClose(l);
                            return .disarm;
                        },
                    }
                } else if (has_pending) {
                    self.outbound.pending_downlink_flush = true;
                    self.sendInitialPayload(l);
                } else {
                    self.sendInitialPayload(l);
                }
            }
        },
    }

    return .disarm;
}

// ══════════════════════════════════════════════════════════════
//  Shadowsocks outbound
// ══════════════════════════════════════════════════════════════

fn sendSsFirstPacket(self: *Session, loop: *xev.Loop) void {
    const target = self.outbound.real_target orelse {
        self.cfg.logger.err("ss outbound: no real target", .{});
        self.initiateClose(loop);
        return;
    };

    const method: ss_crypto.Method = @enumFromInt(self.outbound.config.?.ss_method);
    const key_len = method.keySize();

    const result = ss_outbound.encodeFirstPacket(
        self.inbound.send_buf.?,
        method,
        self.outbound.config.?.ss_psk[0..key_len],
        &target,
        self.initial_payload,
    ) orelse {
        self.cfg.logger.err("ss outbound: first packet encode failed", .{});
        self.initiateClose(loop);
        return;
    };

    // Install encrypt state
    self.outbound_state.?.ss.encrypt = result.encrypt_state;
    self.outbound_state.?.ss.first_sent = true;

    // initial_payload was included in the encrypted frame
    self.initial_payload = null;
    self.initial_payload_len = 0;

    _ = self.lifecycle.fsm.transition(.outbound_ss_header);

    // Write salt + encrypted first frame to target (SS does not use transport layers)
    self.trackOp();
    self.outbound.tcp.?.write(
        loop,
        &self.outbound.write_comp,
        .{ .slice = self.inbound.send_buf.?[0..result.total_len] },
        Session,
        self,
        &onSsFirstWrite,
    );
}

fn onSsFirstWrite(
    ud: ?*Session,
    l: *xev.Loop,
    _: *xev.Completion,
    _: xev.TCP,
    _: xev.WriteBuffer,
    r: xev.WriteError!usize,
) xev.CallbackAction {
    const self = ud.?;
    defer self.opDone();
    if (self.lifecycle.fsm.isClosingOrClosed()) return .disarm;

    _ = r catch |e| {
        self.cfg.logger.err("ss outbound first write failed: {}", .{e});
        self.initiateClose(l);
        return .disarm;
    };

    // First packet written — now enter relay phase
    _ = self.lifecycle.fsm.transition(.relaying);
    _ = self.cfg.worker.conns_relay.fetchAdd(1, .monotonic);
    self.touchActivity();
    self.cfg.logger.debug("#{d} [session] RELAY_START kind=shadowsocks pending_ops={d}", .{
        self.metrics.conn_id, self.lifecycle.pending_ops,
    });

    // send_buf is now free — safe to start both directions
    self.startClientRead(l);
    self.startTargetRead(l);
    return .disarm;
}

// ══════════════════════════════════════════════════════════════
//  Direct relay (no protocol handshake)
// ══════════════════════════════════════════════════════════════

fn enterRelay(self: *Session, loop: *xev.Loop) void {
    _ = self.lifecycle.fsm.transition(.relaying);
    _ = self.cfg.worker.conns_relay.fetchAdd(1, .monotonic);
    self.touchActivity();
    self.cfg.logger.debug("#{d} [session] RELAY_START kind=direct pending_ops={d}", .{
        self.metrics.conn_id, self.lifecycle.pending_ops,
    });
    self.sendInitialPayload(loop);
}
