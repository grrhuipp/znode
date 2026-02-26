const std = @import("std");
const xev = @import("xev");
const vmess_stream = @import("vmess_stream.zig");
const vmess_crypto = @import("vmess_crypto.zig");
const xudp_mux = @import("xudp_mux.zig");
const udp_packet = @import("../../udp/udp_packet.zig");
const Session = @import("../../core/proxy_connection.zig").Session;

/// VMess inbound uplink: decrypt AEAD chunks from client.
/// Uses inbound_pending buffer for accumulation (heap-allocated on-demand).
pub fn processVMessUplink(self: *Session, loop: *xev.Loop, data: []const u8) xev.CallbackAction {
    const ibuf = self.ensureInboundPending() orelse {
        self.initiateClose(loop);
        return .disarm;
    };
    // Accumulate data for VMess chunk parsing — compact only when needed
    var avail = ibuf.len - self.inbound.pending_tail;
    if (avail < data.len and self.inbound.pending_head > 0) {
        const remaining = self.inbound.pending_tail - self.inbound.pending_head;
        std.mem.copyForwards(u8, ibuf[0..remaining], ibuf[self.inbound.pending_head..self.inbound.pending_tail]);
        self.inbound.pending_head = 0;
        self.inbound.pending_tail = remaining;
        avail = ibuf.len - self.inbound.pending_tail;
    }
    if (avail < data.len) {
        self.cfg.logger.err("vmess uplink: accumulation buffer overflow", .{});
        self.initiateClose(loop);
        return .disarm;
    }
    @memcpy(ibuf[self.inbound.pending_tail .. self.inbound.pending_tail + data.len], data);
    self.inbound.pending_tail += data.len;

    // Decrypt as many chunks as possible, batching plaintext into decrypt_buf.
    // Batch limit matches Xray sliceSize (8KB): prevents downstream buffer overflow
    // when outbound is VMess+WS (enc_buf/recv_buf sized for single 8KB chunks).
    const batch_limit: usize = 8 * 1024;
    const state = &self.inbound.protocol.vmess.request_state;
    var total_plaintext: usize = 0;

    while (self.inbound.pending_tail > self.inbound.pending_head) {
        const pending = ibuf[self.inbound.pending_head..self.inbound.pending_tail];
        // Decrypt into stack buffer — max VMess chunk (18KB) for remote compatibility
        var chunk_buf: [vmess_crypto.max_chunk_size]u8 = undefined;
        switch (vmess_stream.decryptChunk(state, pending, &chunk_buf)) {
            .success => |result| {
                self.inbound.pending_head += result.bytes_consumed;
                if (self.inbound.pending_head == self.inbound.pending_tail) {
                    self.inbound.pending_head = 0;
                    self.inbound.pending_tail = 0;
                }

                if (result.plaintext_len == 0) {
                    // Empty chunk = end of stream — flush any accumulated data first
                    if (total_plaintext > 0) {
                        self.writeToTarget(loop, self.inbound.decrypt_buf.?[0..total_plaintext]);
                        // Connection will be closed when this write completes
                    } else {
                        self.initiateClose(loop);
                    }
                    return .disarm;
                }

                // Append to batch if it fits within limit
                if (total_plaintext + result.plaintext_len <= batch_limit) {
                    @memcpy(self.inbound.decrypt_buf.?[total_plaintext .. total_plaintext + result.plaintext_len], chunk_buf[0..result.plaintext_len]);
                    total_plaintext += result.plaintext_len;
                } else {
                    // Batch limit reached — flush accumulated data first
                    if (total_plaintext > 0) {
                        self.writeToTarget(loop, self.inbound.decrypt_buf.?[0..total_plaintext]);
                        return .disarm;
                    }
                    // Single chunk exceeds batch limit — write directly (large remote chunks)
                    self.writeToTarget(loop, chunk_buf[0..result.plaintext_len]);
                    return .disarm;
                }
            },
            .incomplete => break, // need more data
            .integrity_error => {
                self.cfg.logger.warn("vmess inbound integrity error: pending={d}B nonce={d} auth_len={}", .{
                    pending.len,
                    state.nonce_counter,
                    state.options.auth_length,
                });
                self.lifecycle.close_reason = .proto_err;
                self.initiateClose(loop);
                return .disarm;
            },
        }
    }

    // Write all batched plaintext in a single target write
    if (total_plaintext > 0) {
        self.writeToTarget(loop, self.inbound.decrypt_buf.?[0..total_plaintext]);
        return .disarm; // onTargetWrite → startClientRead
    }
    return .rearm; // need more client data
}

/// VMess outbound downlink: decrypt VMess chunks from target, then send plaintext to client.
pub fn processVMessOutDownlink(self: *Session, loop: *xev.Loop, n: usize) void {
    processVMessOutDownlinkData(self, loop, self.outbound.target_buf.?[0..n]);
}

pub fn processVMessOutDownlinkData(self: *Session, loop: *xev.Loop, data: []const u8) void {
    const out = self.outbound_state.?;
    const pbuf = out.pending orelse {
        self.initiateClose(loop);
        return;
    };
    // Accumulate data — compact only when needed
    var avail = pbuf.len - out.pending_tail;
    if (avail < data.len and out.pending_head > 0) {
        const remaining = out.pending_tail - out.pending_head;
        std.mem.copyForwards(u8, pbuf[0..remaining], pbuf[out.pending_head..out.pending_tail]);
        out.pending_head = 0;
        out.pending_tail = remaining;
        avail = pbuf.len - out.pending_tail;
    }
    if (avail < data.len) {
        self.cfg.logger.err("vmess outbound downlink: accumulation buffer overflow", .{});
        self.initiateClose(loop);
        return;
    }
    @memcpy(pbuf[out.pending_tail .. out.pending_tail + data.len], data);
    out.pending_tail += data.len;

    // Try to decrypt a chunk
    const state = &(out.vmess.response_state.?);
    const pending = pbuf[out.pending_head..out.pending_tail];

    switch (vmess_stream.decryptChunk(state, pending, self.inbound.decrypt_buf.?)) {
        .success => |result| {
            // Advance head past consumed bytes (no copy needed)
            out.pending_head += result.bytes_consumed;
            if (out.pending_head == out.pending_tail) {
                out.pending_head = 0;
                out.pending_tail = 0;
            }

            if (result.plaintext_len == 0) {
                // Empty chunk = end of stream
                self.initiateClose(loop);
                return;
            }

            // XUDP mode: decode XUDP frames and send as Trojan UDP to client
            if (self.outbound.xudp_mode) {
                processXudpDownlink(self, loop, self.inbound.decrypt_buf.?[0..result.plaintext_len]);
            } else {
                // Send decrypted plaintext through the inbound pipeline to client
                self.handleRelayDownlinkData(loop, self.inbound.decrypt_buf.?[0..result.plaintext_len]);
            }
        },
        .incomplete => {
            // Need more data from target
            self.startTargetRead(loop);
        },
        .integrity_error => {
            self.cfg.logger.warn("vmess outbound integrity error: pending={d}B nonce={d} auth_len={}", .{
                pending.len,
                state.nonce_counter,
                state.options.auth_length,
            });
            self.lifecycle.close_reason = .proto_err;
            self.initiateClose(loop);
        },
    }
}

/// XUDP uplink: parse Trojan UDP packets, encode as XUDP frames, write to target.
/// Batches multiple XUDP frames into a single writeToTarget call for efficiency.
pub fn handleXudpUplink(self: *Session, loop: *xev.Loop, data: []const u8) void {
    // Accumulate in target_buf (reused as pending buffer for Trojan UDP parsing)
    const avail = self.outbound.target_buf.?.len - self.udp_pending_len;
    if (data.len > avail) {
        self.cfg.logger.warn("xudp uplink: buffer overflow ({d}B data, {d}B avail), closing", .{ data.len, avail });
        self.initiateClose(loop);
        return;
    }
    @memcpy(self.outbound.target_buf.?[self.udp_pending_len .. self.udp_pending_len + data.len], data);
    self.udp_pending_len += data.len;

    // Batch multiple XUDP frames into decrypt_buf (reused as temp output buffer)
    var batch_len: usize = 0;

    // Parse and encode complete Trojan UDP packets as XUDP frames
    while (self.udp_pending_len > 0) {
        const buf = self.outbound.target_buf.?[0..self.udp_pending_len];
        switch (udp_packet.parseTrojanUdpPacket(buf)) {
            .success => |parsed| {
                const payload = buf[parsed.payload_offset .. parsed.payload_offset + parsed.payload_len];
                const target = &parsed.target;

                // Encode as XUDP frame into protocol_buf (reused since protocol_parse is done)
                const frame_len = if (!self.outbound.xudp_session_started) blk: {
                    self.outbound.xudp_session_started = true;
                    break :blk xudp_mux.encodeNewFrame(self.inbound.protocol_buf.?, 0, target, null, payload);
                } else blk: {
                    break :blk xudp_mux.encodeKeepFrame(self.inbound.protocol_buf.?, 0, target, payload);
                };

                const consumed = parsed.payload_offset + parsed.payload_len;
                if (frame_len) |flen| {
                    // Append frame to batch buffer
                    if (batch_len + flen <= self.inbound.decrypt_buf.?.len) {
                        @memcpy(self.inbound.decrypt_buf.?[batch_len .. batch_len + flen], self.inbound.protocol_buf.?[0..flen]);
                        batch_len += flen;
                    } else {
                        break; // Batch buffer full — write what we have
                    }
                } else {
                    self.cfg.logger.err("xudp: frame encode failed", .{});
                }
                // Consume the Trojan UDP packet
                const remaining = self.udp_pending_len - consumed;
                if (remaining > 0) {
                    std.mem.copyForwards(u8, self.outbound.target_buf.?[0..remaining], self.outbound.target_buf.?[consumed .. consumed + remaining]);
                }
                self.udp_pending_len = remaining;
            },
            .incomplete => break,
            .protocol_error => {
                self.cfg.logger.warn("xudp uplink: Trojan UDP protocol error, discarding {d}B", .{self.udp_pending_len});
                self.udp_pending_len = 0;
                break;
            },
        }
    }

    if (batch_len > 0) {
        // Write all batched XUDP frames in a single target write
        self.writeToTarget(loop, self.inbound.decrypt_buf.?[0..batch_len]);
        return;
    }

    // No complete Trojan UDP packet yet, wait for more client data
    self.startClientRead(loop);
}

/// XUDP downlink: VMess-decrypted data contains XUDP frames → decode → Trojan UDP → client.
/// Loops over all frames in the data, batching Trojan UDP packets into send_buf.
/// Saves incomplete trailing data for the next call (half-frame accumulation).
pub fn processXudpDownlink(self: *Session, loop: *xev.Loop, data: []const u8) void {
    // Prepend any saved half-frame from previous call
    var input = data;
    if (self.outbound.xudp_down_pending_len > 0) {
        const pbuf = self.outbound.xudp_down_pending orelse {
            self.outbound.xudp_down_pending_len = 0;
            processXudpDownlinkInner(self, loop, data);
            return;
        };
        // Combine pending + new data into protocol_buf (not used during relay)
        const total = self.outbound.xudp_down_pending_len + data.len;
        if (self.inbound.protocol_buf) |proto_buf| {
            if (total <= proto_buf.len) {
                @memcpy(proto_buf[0..self.outbound.xudp_down_pending_len], pbuf[0..self.outbound.xudp_down_pending_len]);
                @memcpy(proto_buf[self.outbound.xudp_down_pending_len .. self.outbound.xudp_down_pending_len + data.len], data);
                input = proto_buf[0..total];
            } else {
                self.cfg.logger.warn("xudp downlink: combined data too large ({d}B)", .{total});
                input = data;
            }
        } else {
            self.cfg.logger.debug("xudp downlink: no protocol_buf for pending combine", .{});
            input = data;
        }
        self.outbound.xudp_down_pending_len = 0;
    }
    processXudpDownlinkInner(self, loop, input);
}

fn processXudpDownlinkInner(self: *Session, loop: *xev.Loop, data: []const u8) void {
    var offset: usize = 0;
    var batch_len: usize = 0;

    while (offset < data.len) {
        switch (xudp_mux.decodeFrame(data[offset..])) {
            .success => |frame| {
                offset += frame.bytes_consumed;

                if (frame.status == .end) {
                    // Flush any batched data before closing
                    if (batch_len > 0) {
                        sendXudpBatchToClient(self, loop, batch_len);
                    } else {
                        self.initiateClose(loop);
                    }
                    return;
                }
                if (frame.status == .keep_alive) continue;

                // New or Keep with payload: encode as Trojan UDP
                if (frame.payload) |payload| {
                    if (frame.target) |target| {
                        const remaining = self.inbound.send_buf.?.len - batch_len;
                        const encoded_len = udp_packet.encodeTrojanUdpPacket(
                            self.inbound.send_buf.?[batch_len..],
                            &target,
                            payload,
                        ) orelse {
                            // Buffer full — flush current batch, save remaining for next drain
                            if (batch_len > 0) {
                                // Save unconsumed data as pending
                                saveXudpPending(self, data[offset - frame.bytes_consumed ..]);
                                sendXudpBatchToClient(self, loop, batch_len);
                                return;
                            }
                            self.cfg.logger.debug("xudp downlink: single frame too large for send_buf ({d}B avail)", .{remaining});
                            continue;
                        };
                        batch_len += encoded_len;
                    }
                }
            },
            .incomplete => {
                // Save incomplete frame data for next call
                saveXudpPending(self, data[offset..]);
                break;
            },
            .protocol_error => {
                self.cfg.logger.warn("xudp: frame protocol error at offset {d}", .{offset});
                self.initiateClose(loop);
                return;
            },
        }
    }

    if (batch_len > 0) {
        sendXudpBatchToClient(self, loop, batch_len);
    } else {
        self.startTargetRead(loop);
    }
}

/// Save unconsumed XUDP data for next processXudpDownlink call.
fn saveXudpPending(self: *Session, data: []const u8) void {
    if (data.len == 0) return;
    const pbuf = self.ensureXudpDownPending() orelse {
        self.cfg.logger.debug("xudp downlink: failed to allocate pending buf, dropping {d}B", .{data.len});
        return;
    };
    if (data.len > pbuf.len) {
        self.cfg.logger.warn("xudp downlink: pending data too large ({d}B > {d}B buf)", .{ data.len, pbuf.len });
        return;
    }
    @memcpy(pbuf[0..data.len], data);
    self.outbound.xudp_down_pending_len = data.len;
}

/// TLS encrypt (if needed) and write batched Trojan UDP to client.
fn sendXudpBatchToClient(self: *Session, loop: *xev.Loop, batch_len: usize) void {
    if (self.inbound.tls) |*tls| {
        switch (tls.writeEncrypted(self.inbound.send_buf.?[0..batch_len])) {
            .bytes => {
                const tls_n = tls.getNetworkData(self.inbound.send_buf.?);
                if (tls_n > 0) {
                    self.trackOp();
                    self.inbound.tcp.write(loop, &self.inbound.write_comp, .{ .slice = self.inbound.send_buf.?[0..tls_n] }, Session, self, &Session.onClientWrite);
                } else {
                    self.startTargetRead(loop);
                }
            },
            else => self.initiateClose(loop),
        }
    } else {
        self.trackOp();
        self.inbound.tcp.write(loop, &self.inbound.write_comp, .{ .slice = self.inbound.send_buf.?[0..batch_len] }, Session, self, &Session.onClientWrite);
    }
}
