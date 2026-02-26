// ══════════════════════════════════════════════════════════════
//  Relay Pipeline — Transport layer wrap/unwrap + downlink relay
//
//  Centralizes the transport layer processing (TLS ↔ WS ↔ Protocol)
//  into an iterative pipeline, eliminating duplicated unwrap logic
//  across onTargetRead and handleRelayDownlink.
//
//  Data flow:
//    Downlink: target TCP → [TLS decrypt] → [WS unframe] → protocol data
//    Uplink:   protocol data → [WS frame] → [TLS encrypt] → target TCP
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const xev = @import("xev");
const vmess_stream = @import("../protocol/vmess/vmess_stream.zig");
const vmess_relay = @import("../protocol/vmess/vmess_relay.zig");
const ss_relay = @import("../protocol/shadowsocks/ss_relay.zig");
const ss_crypto = @import("../protocol/shadowsocks/ss_crypto.zig");
const ws_mod = @import("../transport/ws_stream.zig");
const tls_mod = @import("../transport/tls_stream.zig");
const Session = @import("proxy_connection.zig").Session;

/// Result of iterative transport unwrapping.
pub const UnwrapResult = union(enum) {
    /// Unwrapped protocol-level data ready for processing.
    data: []const u8,
    /// Need more network data — issue target read.
    want_read: void,
    /// WS close frame received — initiate connection close.
    close: void,
    /// Transport error (TLS or WS) — initiate connection close.
    err: void,
};

/// Iteratively unwrap outbound transport layers: raw TCP → [TLS decrypt] → [WS unframe].
///
/// Buffer strategy (avoids aliasing):
///   - After TLS decrypt: data in `decrypt_buf`, `target_buf` is free → WS output to `target_buf`
///   - Without TLS: data in `target_buf`, `decrypt_buf` is free → WS output to `decrypt_buf`
pub fn unwrapOutboundTransport(conn: *Session, raw: []const u8) UnwrapResult {
    var data = raw;
    var data_in_decrypt = false;

    // Stage 1: TLS decrypt — drain all available records from BIO
    if (conn.outbound.tls) |*ttls| {
        _ = ttls.feedNetworkData(data) catch return .err;
        var total_decrypted: usize = 0;
        while (true) {
            switch (ttls.readDecrypted(conn.inbound.decrypt_buf.?[total_decrypted..])) {
                .bytes => |dn| {
                    total_decrypted += dn;
                    // Continue draining if there might be more records
                },
                .want_read => break,
                else => return .err,
            }
        }
        if (total_decrypted == 0) return .want_read;
        data = conn.inbound.decrypt_buf.?[0..total_decrypted];
        data_in_decrypt = true;
    }

    // Stage 2: WS unframe (server→client: unmasked)
    if (conn.outbound.ws_active) {
        const out = conn.outbound_state orelse return .err;
        if (data_in_decrypt) {
            // Input in decrypt_buf → output to target_buf (free after TLS consumed raw)
            const payload_len = out.stripWsFrames(data, conn.outbound.target_buf.?) orelse return .close;
            if (payload_len == 0) return .want_read;
            return .{ .data = conn.outbound.target_buf.?[0..payload_len] };
        } else {
            // Input in target_buf → output to decrypt_buf (free, no TLS)
            const payload_len = out.stripWsFrames(data, conn.inbound.decrypt_buf.?) orelse return .close;
            if (payload_len == 0) return .want_read;
            return .{ .data = conn.inbound.decrypt_buf.?[0..payload_len] };
        }
    }

    return .{ .data = data };
}

/// Drain remaining data from outbound TLS BIO without feeding new TCP data.
/// Used by onClientWrite to flush buffered TLS records after a write completes.
///
/// Buffer strategy: same as unwrapOutboundTransport but reads from BIO only.
pub fn drainOutboundTlsBio(conn: *Session) UnwrapResult {
    if (conn.outbound.tls) |*ttls| {
        switch (ttls.readDecrypted(conn.inbound.decrypt_buf.?)) {
            .bytes => |dn| {
                if (conn.outbound.ws_active) {
                    const out = conn.outbound_state orelse return .err;
                    // TLS output in decrypt_buf → WS output to target_buf
                    const payload_len = out.stripWsFrames(conn.inbound.decrypt_buf.?[0..dn], conn.outbound.target_buf.?) orelse return .close;
                    if (payload_len == 0) return .want_read;
                    return .{ .data = conn.outbound.target_buf.?[0..payload_len] };
                }
                return .{ .data = conn.inbound.decrypt_buf.?[0..dn] };
            },
            .want_read => return .want_read,
            else => return .err,
        }
    }
    return .want_read;
}

// ══════════════════════════════════════════════════════════════
//  Downlink Relay: target → client
// ══════════════════════════════════════════════════════════════

/// Unified downlink relay entry point.
/// Unwraps transport layers, then dispatches to protocol-specific handler.
///
/// Called from onTargetRead for all non-VMess/non-SS-outbound connections.
/// VMess/SS outbound paths call unwrapOutboundTransport directly for
/// protocol-specific accumulation handling.
pub fn handleRelayDownlink(conn: *Session, loop: *xev.Loop, n: usize) void {
    // SS outbound: raw TCP data (no transport layers — SS has its own encryption)
    if (conn.outbound.kind == .shadowsocks) {
        ss_relay.processSsOutDownlink(conn, loop, conn.outbound.target_buf.?[0..n]);
        return;
    }

    // Unwrap transport layers iteratively
    switch (unwrapOutboundTransport(conn, conn.outbound.target_buf.?[0..n])) {
        .data => |data| {
            // After WS unframe, send buffered pong immediately while
            // target_write_comp is free (we're in target_read callback).
            if (conn.outbound.ws_active) {
                if (conn.outbound_state) |out| {
                    if (out.ws.pong_len > 0) {
                        sendWsPongDirect(conn, loop);
                    }
                }
            }
            handleRelayDownlinkData(conn, loop, data);
        },
        .want_read => conn.startTargetRead(loop),
        .close, .err => conn.initiateClose(loop),
    }
}

/// Process unwrapped downlink data through the inbound protocol pipeline.
/// Applies: [VMess/SS inbound encrypt] → [WS frame] → [TLS encrypt] → client TCP write.
pub fn handleRelayDownlinkData(conn: *Session, loop: *xev.Loop, data: []const u8) void {
    var data_to_send = data;
    var out_len: usize = 0;

    // Inbound protocol: re-encrypt for the inbound client
    switch (conn.inbound.protocol) {
        .vmess => |*v| {
            if (vmess_stream.encryptChunk(&v.response_state, data_to_send, conn.inbound.send_buf.?)) |chunk_len| {
                out_len = chunk_len;
                data_to_send = conn.inbound.send_buf.?[0..chunk_len];
            } else {
                conn.cfg.logger.err("vmess chunk encrypt failed (nonce exhausted or buffer too small)", .{});
                conn.initiateClose(loop);
                return;
            }
        },
        .shadowsocks => |*v| {
            // First response: prepend server salt (stored in protocol_buf)
            var offset: usize = 0;
            if (conn.inbound.protocol_buf_len > 0) {
                @memcpy(conn.inbound.send_buf.?[0..conn.inbound.protocol_buf_len], conn.inbound.protocol_buf.?[0..conn.inbound.protocol_buf_len]);
                offset = conn.inbound.protocol_buf_len;
                conn.inbound.protocol_buf_len = 0; // salt sent once
            }
            if (v.encrypt_state.encryptFrame(data_to_send, conn.inbound.send_buf.?[offset..])) |frame_len| {
                out_len = offset + frame_len;
                data_to_send = conn.inbound.send_buf.?[0..out_len];
            } else {
                conn.cfg.logger.err("shadowsocks encrypt failed", .{});
                conn.initiateClose(loop);
                return;
            }
        },
        .none => {},
    }

    // Inbound WS: wrap in binary frame (server→client: no mask)
    if (conn.inbound.ws_active) {
        const ws_input = if (out_len > 0) conn.inbound.send_buf.?[0..out_len] else data_to_send;
        const ws_framed = wrapInboundWsFrame(conn, ws_input) orelse {
            conn.initiateClose(loop);
            return;
        };
        out_len = ws_framed.len;
        data_to_send = ws_framed;
    }

    // TLS: encrypt for sending to client
    if (conn.inbound.tls) |*tls| {
        const to_encrypt = if (out_len > 0) conn.inbound.send_buf.?[0..out_len] else data_to_send;
        switch (tls.writeEncrypted(to_encrypt)) {
            .bytes, .want_write => {
                const tls_n = tls.getNetworkData(conn.inbound.send_buf.?);
                if (tls_n > 0) {
                    conn.trackOp();
                    conn.inbound.tcp.write(loop, &conn.inbound.write_comp, .{ .slice = conn.inbound.send_buf.?[0..tls_n] }, Session, conn, &Session.onClientWrite);
                } else {
                    conn.startTargetRead(loop);
                }
            },
            else => conn.initiateClose(loop),
        }
    } else {
        // No TLS: send directly
        if (out_len > 0) {
            // Data in send_buf (protocol encrypt and/or WS framed)
            conn.trackOp();
            conn.inbound.tcp.write(loop, &conn.inbound.write_comp, .{ .slice = conn.inbound.send_buf.?[0..out_len] }, Session, conn, &Session.onClientWrite);
        } else {
            // Plain data in stable buffer (target_buf/decrypt_buf) — write directly, no copy
            conn.trackOp();
            conn.inbound.tcp.write(loop, &conn.inbound.write_comp, .{ .slice = data_to_send }, Session, conn, &Session.onClientWrite);
        }
    }
}

/// Drain pending outbound downlink data from onClientWrite.
/// Returns an action: .disarm if data was submitted, null if nothing to drain.
///
/// This is critical for multi-chunk protocols (VMess, SS):
/// Multiple protocol chunks may arrive in a single TLS record.
/// Only one chunk is processed per cycle; remaining chunks are
/// buffered in outbound_state.pending. This function drains them
/// when the previous client write completes.
pub fn drainPendingDownlink(conn: *Session, l: *xev.Loop) ?xev.CallbackAction {
    // VMess outbound: check for complete chunks in pending buffer
    if (conn.outbound_state) |out| {
        if (out.vmess.response_state) |*state| {
            const pending = out.pending.?[out.pending_head..out.pending_tail];
            if (pending.len > 0) {
                switch (vmess_stream.decryptChunk(state, pending, conn.inbound.decrypt_buf.?)) {
                    .success => |result| {
                        out.pending_head += result.bytes_consumed;
                        if (out.pending_head == out.pending_tail) {
                            out.pending_head = 0;
                            out.pending_tail = 0;
                        }
                        if (result.plaintext_len == 0) {
                            conn.initiateClose(l);
                            return .disarm;
                        }
                        if (conn.outbound.xudp_mode) {
                            vmess_relay.processXudpDownlink(conn, l, conn.inbound.decrypt_buf.?[0..result.plaintext_len]);
                        } else {
                            handleRelayDownlinkData(conn, l, conn.inbound.decrypt_buf.?[0..result.plaintext_len]);
                        }
                        return .disarm; // → onClientWrite → back here
                    },
                    .incomplete => {}, // fall through to TLS BIO drain
                    .integrity_error => {
                        conn.initiateClose(l);
                        return .disarm;
                    },
                }
            }

            // Drain outbound TLS BIO (may have buffered records)
            switch (drainOutboundTlsBio(conn)) {
                .data => |data| {
                    vmess_relay.processVMessOutDownlinkData(conn, l, data);
                    return .disarm;
                },
                .want_read => {}, // BIO drained, fall through
                .close, .err => {
                    conn.initiateClose(l);
                    return .disarm;
                },
            }

            conn.startTargetRead(l);
            return .disarm;
        }
    }

    // SS outbound: check for complete frames in pending buffer
    if (conn.outbound_state) |out| {
        if (out.ss.decrypt != null) {
            var state = &(out.ss.decrypt.?);
            if (out.pending_tail > out.pending_head) {
                const pending_data = out.pending.?[out.pending_head..out.pending_tail];
                switch (state.decryptFrame(pending_data, conn.inbound.decrypt_buf.?)) {
                    .success => |result| {
                        out.pending_head += result.bytes_consumed;
                        if (out.pending_head == out.pending_tail) {
                            out.pending_head = 0;
                            out.pending_tail = 0;
                        }
                        if (result.plaintext_len == 0) {
                            conn.initiateClose(l);
                            return .disarm;
                        }
                        handleRelayDownlinkData(conn, l, conn.inbound.decrypt_buf.?[0..result.plaintext_len]);
                        return .disarm;
                    },
                    .incomplete => {},
                    .integrity_error => {
                        conn.initiateClose(l);
                        return .disarm;
                    },
                }
            }
            conn.startTargetRead(l);
            return .disarm;
        }
    }

    // Non-VMess/SS outbound: drain TLS BIO
    switch (drainOutboundTlsBio(conn)) {
        .data => |data| {
            handleRelayDownlinkData(conn, l, data);
            return .disarm;
        },
        .want_read => return null, // nothing to drain
        .close, .err => {
            conn.initiateClose(l);
            return .disarm;
        },
    }
}

// ══════════════════════════════════════════════════════════════
//  Uplink Relay: client → target
// ══════════════════════════════════════════════════════════════

/// Drive uplink relay from client read data.
/// Handles: TLS decrypt → [WS unwrap] → inbound protocol dispatch → outbound encrypt → target write.
pub fn driveRelayUplink(conn: *Session, loop: *xev.Loop, n: usize) xev.CallbackAction {
    conn.touchActivity();
    if (conn.inbound.tls) |*tls| {
        // Feed ciphertext to inbound TLS
        _ = tls.feedNetworkData(conn.inbound.recv_buf.?[0..n]) catch {
            conn.initiateClose(loop);
            return .disarm;
        };

        // Drain TLS BIO — loop for VMess (chunks may span TLS records),
        // single pass for Trojan (one record forwarded, rest drained in onTargetWrite).
        while (true) {
            switch (tls.readDecrypted(conn.inbound.decrypt_buf.?)) {
                .bytes => |decrypted_n| {
                    conn.cfg.worker.stats.addBytesIn(decrypted_n);
                    conn.metrics.conn_bytes_up += decrypted_n;
                    // Inbound WS: unwrap frames before protocol dispatch
                    if (conn.inbound.ws_active) {
                        const action = unwrapInboundWsAndDispatch(conn, loop, conn.inbound.decrypt_buf.?[0..decrypted_n]);
                        if (action == .disarm) return .disarm;
                        continue;
                    }
                    const action = dispatchUplink(conn, loop, conn.inbound.decrypt_buf.?[0..decrypted_n]);
                    if (action == .disarm) return .disarm;
                    continue;
                },
                .want_read => return .rearm,
                .closed => {
                    conn.initiateClose(loop);
                    return .disarm;
                },
                else => {
                    conn.initiateClose(loop);
                    return .disarm;
                },
            }
        }
    } else {
        // No TLS: raw protocol data
        conn.cfg.worker.stats.addBytesIn(n);
        conn.metrics.conn_bytes_up += n;
        if (conn.inbound.ws_active) {
            return unwrapInboundWsAndDispatch(conn, loop, conn.inbound.recv_buf.?[0..n]);
        }
        return dispatchUplink(conn, loop, conn.inbound.recv_buf.?[0..n]);
    }
}

/// Dispatch uplink data to the appropriate inbound protocol handler.
fn dispatchUplink(conn: *Session, loop: *xev.Loop, data: []const u8) xev.CallbackAction {
    switch (conn.inbound.protocol) {
        .vmess => return vmess_relay.processVMessUplink(conn, loop, data),
        .shadowsocks => return ss_relay.processSsUplink(conn, loop, data),
        .none => {
            if (conn.outbound.xudp_mode) {
                vmess_relay.handleXudpUplink(conn, loop, data);
                return .disarm;
            } else {
                writeToTarget(conn, loop, data);
                return .disarm;
            }
        },
    }
}

/// Write data to target through outbound protocol + transport layers.
/// Applies: [VMess/SS outbound encrypt] → [WS frame] → [TLS encrypt] → target TCP write.
pub fn writeToTarget(conn: *Session, loop: *xev.Loop, data: []const u8) void {
    if (conn.outbound.tcp) |*tcp| {
        // VMess outbound: encrypt chunk before sending to remote server
        if (conn.outbound_state) |vout| {
            if (vout.vmess.request_state) |*state| {
                if (vmess_stream.encryptChunk(state, data, vout.enc_buf.?)) |chunk_len| {
                    // VMess chunks go through outbound transport (WS + TLS)
                    const wrapped = wrapOutboundTransport(conn, vout.enc_buf.?[0..chunk_len]) orelse {
                        conn.initiateClose(loop);
                        return;
                    };
                    conn.trackOp();
                    tcp.write(loop, &conn.outbound.write_comp, .{ .slice = wrapped }, Session, conn, &Session.onTargetWrite);
                } else {
                    conn.cfg.logger.err("vmess outbound: chunk encrypt failed", .{});
                    conn.initiateClose(loop);
                }
                return;
            }
        }
        // Shadowsocks outbound: encrypt as AEAD frame
        if (conn.outbound_state) |out_s| {
            if (out_s.ss.encrypt != null) {
                var enc = &(out_s.ss.encrypt.?);
                if (enc.encryptFrame(data, conn.inbound.send_buf.?)) |frame_len| {
                    conn.trackOp();
                    tcp.write(loop, &conn.outbound.write_comp, .{ .slice = conn.inbound.send_buf.?[0..frame_len] }, Session, conn, &Session.onTargetWrite);
                } else {
                    conn.cfg.logger.err("ss outbound: frame encrypt failed", .{});
                    conn.initiateClose(loop);
                }
                return;
            }
        }
        // Plain / Trojan relay: wrap through transport layers (WS + TLS)
        const out = wrapOutboundTransport(conn, data) orelse {
            conn.initiateClose(loop);
            return;
        };
        conn.trackOp();
        tcp.write(loop, &conn.outbound.write_comp, .{ .slice = out }, Session, conn, &Session.onTargetWrite);
    }
}

/// Wrap data through outbound transport layers: [WS frame] → [TLS encrypt].
/// Returns the wrapped data slice, or null on error.
///
/// Buffer usage: WS framing writes to recv_buf (not send_buf!) to avoid a race
/// condition: send_buf may be in use by an outstanding client write (downlink)
/// while this uplink write is being prepared. TLS output goes to enc_buf.
pub fn wrapOutboundTransport(conn: *Session, data: []const u8) ?[]const u8 {
    var current = data;

    // Stage 1: WS framing (client → server: masked per RFC 6455)
    if (conn.outbound.ws_active) {
        var offset: usize = 0;
        // Prepend pending pong response (from server ping) before data frame
        if (conn.outbound_state) |out| {
            if (out.ws.pong_len > 0) {
                @memcpy(conn.inbound.recv_buf.?[0..out.ws.pong_len], out.ws.pong_buf[0..out.ws.pong_len]);
                offset = out.ws.pong_len;
                out.ws.pong_len = 0;
            }
        }
        const ws_len = ws_mod.encodeFrame(conn.inbound.recv_buf.?[offset..], .binary, current, true) orelse return null;
        current = conn.inbound.recv_buf.?[0 .. offset + ws_len];
    }

    // Stage 2: TLS encryption (output to enc_buf, NOT pending — pending is
    // reserved for VMess downlink chunk accumulation)
    if (conn.outbound.tls) |*ttls| {
        switch (ttls.writeEncrypted(current)) {
            .bytes => {},
            else => return null,
        }
        const n = ttls.getNetworkData(conn.outbound_state.?.enc_buf.?);
        if (n == 0) return null;
        return conn.outbound_state.?.enc_buf.?[0..n];
    }

    return current;
}

/// Send a pending WS pong frame directly to the target.
/// Used from onTargetWrite when no uplink data is being processed.
pub fn sendWsPongDirect(conn: *Session, loop: *xev.Loop) void {
    const out = conn.outbound_state orelse return;
    if (out.ws.pong_len == 0) return;
    const pong_len = out.ws.pong_len;
    out.ws.pong_len = 0;

    if (conn.outbound.tls) |*ttls| {
        // WSS: TLS-encrypt the pong frame
        switch (ttls.writeEncrypted(out.ws.pong_buf[0..pong_len])) {
            .bytes => {},
            else => return,
        }
        const n = ttls.getNetworkData(out.enc_buf.?);
        if (n > 0) {
            conn.trackOp();
            conn.outbound.tcp.?.write(loop, &conn.outbound.write_comp, .{ .slice = out.enc_buf.?[0..n] }, Session, conn, &Session.onTargetWrite);
        }
    } else {
        // Plain WS: write directly from ws pong_buf
        conn.trackOp();
        conn.outbound.tcp.?.write(loop, &conn.outbound.write_comp, .{ .slice = out.ws.pong_buf[0..pong_len] }, Session, conn, &Session.onTargetWrite);
    }
}

// ══════════════════════════════════════════════════════════════
//  Inbound WebSocket: relay-phase frame unwrap/wrap
// ══════════════════════════════════════════════════════════════

/// Result of streaming inbound WS unwrap.
pub const InboundWsResult = union(enum) {
    /// Extracted payload (in recv_buf or decrypt_buf). Caller should check
    /// conn.inbound.ws_state.close_received after dispatching.
    payload: []const u8,
    /// No complete payload available, need more data.
    want_read: void,
    /// Close frame received with no preceding payload.
    close: void,
};

/// Core streaming inbound WS unwrap: strip WS frames, unmask, return payload.
///
/// Fully streaming — never buffers entire WS frames. Uses:
///   - InboundWsState.header_buf (14 bytes) for partial frame headers
///   - frame_remaining/mask_key/mask_offset for incremental payload tracking
///
/// Buffer strategy (avoid aliasing with input):
///   Input in decrypt_buf → output to recv_buf  (free after TLS feed)
///   Otherwise            → output to decrypt_buf (free when no TLS, or target_buf input)
pub fn unwrapInboundWsCore(conn: *Session, data: []const u8) InboundWsResult {
    var ws = &conn.inbound.ws_state;

    if (ws.close_received) return .close;

    // Choose output buffer based on input location (avoid aliasing)
    const input_base = @intFromPtr(data.ptr);
    const decrypt_base = @intFromPtr(conn.inbound.decrypt_buf.?.ptr);
    const in_decrypt = (input_base >= decrypt_base and input_base < decrypt_base + conn.inbound.decrypt_buf.?.len);
    const out_buf: []u8 = if (in_decrypt) conn.inbound.recv_buf.? else conn.inbound.decrypt_buf.?;
    var out_len: usize = 0;
    var pos: usize = 0;

    while (pos < data.len) {
        // ── State A: Mid data-frame payload ──
        if (ws.frame_remaining > 0 and ws.ctrl_skip == 0) {
            const frame_avail = @min(data.len - pos, @as(usize, ws.frame_remaining));
            const out_avail = out_buf.len - out_len;
            const n = @min(frame_avail, out_avail);
            if (n == 0) break; // output buffer full
            @memcpy(out_buf[out_len..][0..n], data[pos..][0..n]);
            ws_mod.applyMaskWithOffset(out_buf[out_len..][0..n], ws.mask_key, ws.mask_offset);
            ws.mask_offset = @intCast((@as(usize, ws.mask_offset) + n) % 4);
            ws.frame_remaining -= @intCast(n);
            out_len += n;
            pos += n;
            continue;
        }

        // ── State B: Skipping control frame payload ──
        if (ws.ctrl_skip > 0) {
            const avail = @min(data.len - pos, @as(usize, ws.ctrl_skip));
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

            if (ws.ctrl_skip == 0 and ws.ctrl_is_ping) {
                ws_mod.applyMask(ws.ping_payload[0..ws.ping_len], ws.mask_key);
                if (ws_mod.encodeFrame(&ws.pong_buf, .pong, ws.ping_payload[0..ws.ping_len], false)) |pong_n| {
                    ws.pong_len = @intCast(pong_n);
                }
                ws.ctrl_is_ping = false;
                ws.ping_len = 0;
            }
            continue;
        }

        // ── State C: Parse new frame header ──
        const remaining = data.len - pos;
        const header_space = @as(usize, 14) - @as(usize, ws.header_len);
        const to_copy = @min(remaining, header_space);
        @memcpy(ws.header_buf[ws.header_len..][0..to_copy], data[pos..][0..to_copy]);
        ws.header_len += @intCast(to_copy);
        pos += to_copy;

        if (ws_mod.parseFrameHeader(ws.header_buf[0..ws.header_len])) |hdr| {
            const excess = @as(usize, ws.header_len) - hdr.header_size;
            pos -= excess;

            ws.frame_remaining = @intCast(hdr.payload_len);
            ws.mask_key = hdr.mask_key;
            ws.mask_offset = 0;
            ws.header_len = 0;

            switch (hdr.opcode) {
                .close => {
                    ws.close_received = true;
                    break;
                },
                .ping => {
                    ws.ctrl_skip = ws.frame_remaining;
                    ws.ctrl_is_ping = true;
                    ws.ping_len = 0;
                },
                .pong => {
                    ws.ctrl_skip = ws.frame_remaining;
                },
                .binary, .text, .continuation => {},
            }
        } else {
            break;
        }
    }

    if (out_len > 0) return .{ .payload = out_buf[0..out_len] };
    if (ws.close_received) return .close;
    return .want_read;
}

/// Relay-phase: unwrap inbound WS frames and dispatch to uplink protocol handler.
pub fn unwrapInboundWsAndDispatch(conn: *Session, loop: *xev.Loop, data: []const u8) xev.CallbackAction {
    switch (unwrapInboundWsCore(conn, data)) {
        .payload => |payload| {
            const action = dispatchUplink(conn, loop, payload);
            if (conn.inbound.ws_state.close_received and action == .rearm) {
                conn.initiateClose(loop);
                return .disarm;
            }
            return action;
        },
        .want_read => return .rearm,
        .close => {
            conn.initiateClose(loop);
            return .disarm;
        },
    }
}

/// Wrap downlink data in an inbound WS binary frame (server→client: no mask).
/// Prepends any pending pong frame. Writes output to send_buf.
/// Returns the framed data slice, or null on error.
fn wrapInboundWsFrame(conn: *Session, payload: []const u8) ?[]const u8 {
    // Build WS binary frame header (no mask for server→client)
    var hdr: [10]u8 = undefined;
    var hdr_len: usize = 2;
    hdr[0] = 0x82; // FIN + binary opcode
    if (payload.len <= 125) {
        hdr[1] = @intCast(payload.len);
    } else if (payload.len <= 65535) {
        hdr[1] = 126;
        std.mem.writeInt(u16, hdr[2..4], @intCast(payload.len), .big);
        hdr_len = 4;
    } else {
        hdr[1] = 127;
        std.mem.writeInt(u64, hdr[2..10], @intCast(payload.len), .big);
        hdr_len = 10;
    }

    // Prepend pending pong if any
    var pong_prefix_len: usize = 0;
    if (conn.inbound.ws_state.pong_len > 0) {
        pong_prefix_len = conn.inbound.ws_state.pong_len;
    }

    const total_prefix = pong_prefix_len + hdr_len;
    if (total_prefix + payload.len > conn.inbound.send_buf.?.len) return null;

    // Check if payload is already in send_buf (from inbound protocol encrypt)
    const payload_in_send_buf = (@intFromPtr(payload.ptr) >= @intFromPtr(conn.inbound.send_buf.?.ptr) and
        @intFromPtr(payload.ptr) < @intFromPtr(conn.inbound.send_buf.?.ptr) + conn.inbound.send_buf.?.len);

    if (payload_in_send_buf) {
        // Shift payload right to make room for prefix
        std.mem.copyBackwards(u8, conn.inbound.send_buf.?[total_prefix .. total_prefix + payload.len], payload);
    } else {
        // Copy payload from external buffer
        @memcpy(conn.inbound.send_buf.?[total_prefix .. total_prefix + payload.len], payload);
    }

    // Write pong prefix
    if (pong_prefix_len > 0) {
        @memcpy(conn.inbound.send_buf.?[0..pong_prefix_len], conn.inbound.ws_state.pong_buf[0..pong_prefix_len]);
        conn.inbound.ws_state.pong_len = 0;
    }

    // Write WS frame header
    @memcpy(conn.inbound.send_buf.?[pong_prefix_len .. pong_prefix_len + hdr_len], hdr[0..hdr_len]);

    return conn.inbound.send_buf.?[0 .. total_prefix + payload.len];
}

// ══════════════════════════════════════════════════════════════
//  Tests
// ══════════════════════════════════════════════════════════════

test "UnwrapResult union" {
    const want_read: UnwrapResult = .want_read;
    try std.testing.expect(want_read == .want_read);

    const close: UnwrapResult = .close;
    try std.testing.expect(close == .close);

    const err_result: UnwrapResult = .err;
    try std.testing.expect(err_result == .err);
}
