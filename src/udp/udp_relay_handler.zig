const std = @import("std");
const xev = @import("xev");
const UdpSys = @import("udp_sys.zig").UdpSys;
const udp_packet = @import("udp_packet.zig");
const dns_resolver = @import("../dns/resolver.zig");
const session_mod = @import("../core/session.zig");
const Worker = @import("../core/worker.zig").Worker;
const Session = @import("../core/proxy_connection.zig").Session;

/// Start UDP relay mode: create outbound UDP socket + recv thread.
pub fn startUdpRelay(self: *Session, loop: *xev.Loop) void {
    // SendThrough for UDP: bind to same local IP as TCP (source-in-source-out)
    const per_listener_st = if (self.cfg.listener_id < self.cfg.worker.listener_info_count)
        self.cfg.worker.listener_infos[self.cfg.listener_id].send_through_addr
    else
        null;
    const udp_bind_addr = self.cfg.local_addr orelse per_listener_st;
    const udp_bind_ip4: ?[4]u8 = if (udp_bind_addr) |ba| blk: {
        if (ba.any.family == std.posix.AF.INET) {
            break :blk @as(*const [4]u8, @ptrCast(&ba.in.sa.addr)).*;
        }
        break :blk null;
    } else null;

    const sock = UdpSys.create(udp_bind_ip4) orelse {
        self.cfg.logger.err("failed to create UDP socket", .{});
        self.initiateClose(loop);
        return;
    };
    self.udp_sock = sock;
    _ = self.lifecycle.fsm.transition(.udp_relaying);
    _ = self.cfg.worker.conns_relay.fetchAdd(1, .monotonic);
    self.touchActivity();
    self.udp_closed.store(false, .release);
    self.udp_pending_len = 0;

    // Feed initial payload (data after Trojan header) to uplink
    if (self.initial_payload) |payload| {
        if (payload.len > 0) {
            handleUdpUplink(self, loop, payload);
        }
        self.initial_payload = null;
    }

    // Start recv thread for downlink (UDP responses)
    self.trackOp(); // held until recv thread exits (sentinel)
    const t = std.Thread.spawn(.{ .stack_size = 64 * 1024 }, udpRecvThread, .{self}) catch {
        self.cfg.logger.err("failed to spawn UDP recv thread", .{});
        self.opDone();
        self.initiateClose(loop);
        return;
    };
    t.detach();

    // Start reading from client for uplink
    self.startClientRead(loop);
}

/// Uplink: TLS decrypt → parse Trojan UDP packets → sendto.
pub fn driveUdpUplink(self: *Session, loop: *xev.Loop, n: usize) xev.CallbackAction {
    self.touchActivity();
    if (self.inbound.tls) |*tls| {
        _ = tls.feedNetworkData(self.inbound.recv_buf.?[0..n]) catch {
            self.initiateClose(loop);
            return .disarm;
        };
        while (true) {
            switch (tls.readDecrypted(self.inbound.decrypt_buf.?)) {
                .bytes => |dn| {
                    self.cfg.worker.stats.addBytesIn(dn);
                    self.metrics.conn_bytes_up += dn;
                    handleUdpUplink(self, loop, self.inbound.decrypt_buf.?[0..dn]);
                    continue;
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
        }
    } else {
        self.cfg.worker.stats.addBytesIn(n);
        self.metrics.conn_bytes_up += n;
        handleUdpUplink(self, loop, self.inbound.recv_buf.?[0..n]);
        return .rearm;
    }
}

/// Parse Trojan UDP packets from plaintext data and sendto via UDP socket.
pub fn handleUdpUplink(self: *Session, loop: *xev.Loop, data: []const u8) void {
    // Accumulate in target_buf (reused as UDP pending buffer)
    const avail = self.outbound.target_buf.?.len - self.udp_pending_len;
    if (data.len > avail) {
        self.cfg.logger.warn("UDP uplink: buffer overflow ({d}B data, {d}B avail), closing", .{ data.len, avail });
        self.initiateClose(loop);
        return;
    }
    @memcpy(self.outbound.target_buf.?[self.udp_pending_len .. self.udp_pending_len + data.len], data);
    self.udp_pending_len += data.len;

    // Parse and send complete Trojan UDP packets
    while (self.udp_pending_len > 0) {
        const buf = self.outbound.target_buf.?[0..self.udp_pending_len];
        switch (udp_packet.parseTrojanUdpPacket(buf)) {
            .success => |parsed| {
                const payload = buf[parsed.payload_offset .. parsed.payload_offset + parsed.payload_len];
                const target = &parsed.target;
                const port: u16 = target.port;

                switch (target.addr_type) {
                    .ipv4 => {
                        _ = UdpSys.send4(self.udp_sock, payload, target.ip4, port);
                    },
                    .ipv6 => {
                        _ = UdpSys.send6(self.udp_sock, payload, target.ip6, port);
                    },
                    .domain => {
                        // Synchronous DNS resolve (acceptable for UDP relay)
                        const domain = target.getDomain();
                        const result = dns_resolver.resolveSystem(domain) catch {
                            self.cfg.logger.debug("UDP DNS failed: {s}", .{domain});
                            const consumed = parsed.payload_offset + parsed.payload_len;
                            shiftUdpPending(self, consumed);
                            continue;
                        };
                        if (result.ip4) |resolved_ip| {
                            _ = UdpSys.send4(self.udp_sock, payload, resolved_ip, port);
                        } else if (result.ip6) |resolved_ip6| {
                            _ = UdpSys.send6(self.udp_sock, payload, resolved_ip6, port);
                        } else {
                            self.cfg.logger.debug("UDP DNS no result: {s}", .{domain});
                            const consumed = parsed.payload_offset + parsed.payload_len;
                            shiftUdpPending(self, consumed);
                            continue;
                        }
                    },
                    .none => {
                        const consumed = parsed.payload_offset + parsed.payload_len;
                        shiftUdpPending(self, consumed);
                        continue;
                    },
                }

                // Remove consumed bytes
                const consumed = parsed.payload_offset + parsed.payload_len;
                shiftUdpPending(self, consumed);
            },
            .incomplete => break,
            .protocol_error => {
                self.cfg.logger.warn("UDP uplink: Trojan UDP protocol error, discarding {d}B", .{self.udp_pending_len});
                self.udp_pending_len = 0;
                break;
            },
        }
    }
}

fn shiftUdpPending(self: *Session, consumed: usize) void {
    const remaining = self.udp_pending_len - consumed;
    if (remaining > 0) {
        std.mem.copyForwards(u8, self.outbound.target_buf.?[0..remaining], self.outbound.target_buf.?[consumed .. consumed + remaining]);
    }
    self.udp_pending_len = remaining;
}

/// Called by Worker when a UDP downlink packet is delivered from the recv thread.
pub fn onUdpDownlink(self: *Session, loop: *xev.Loop, entry: Worker.UdpDownlinkQueue.Entry) void {
    self.touchActivity();
    // Sentinel: recv thread has exited
    if (entry.data_len == 0) {
        self.opDone(); // matches trackOp in startUdpRelay
        return;
    }

    // Ignore if not in UDP relay mode or closing
    if (!self.lifecycle.fsm.isUdpRelaying()) return;

    // Drop if a client write is already pending (UDP is lossy)
    if (self.udp_write_pending) return;

    // Encode Trojan UDP response with source address
    var target = session_mod.TargetAddress{};
    if (entry.is_ipv6) {
        target.setIpv6(entry.src_ip6, entry.src_port);
    } else {
        target.setIpv4(entry.src_ip4, entry.src_port);
    }
    const payload = entry.data[0..entry.data_len];

    const encoded_len = udp_packet.encodeTrojanUdpPacket(self.inbound.send_buf.?, &target, payload) orelse {
        self.cfg.logger.debug("UDP downlink encode failed", .{});
        return;
    };

    // TLS encrypt if needed, then send to client
    if (self.inbound.tls) |*tls| {
        switch (tls.writeEncrypted(self.inbound.send_buf.?[0..encoded_len])) {
            .bytes => {
                const tls_n = tls.getNetworkData(self.inbound.send_buf.?);
                if (tls_n > 0) {
                    self.udp_write_pending = true;
                    self.trackOp();
                    self.inbound.tcp.write(loop, &self.inbound.write_comp, .{ .slice = self.inbound.send_buf.?[0..tls_n] }, Session, self, &Session.onClientWrite);
                }
            },
            else => self.initiateClose(loop),
        }
    } else {
        // No TLS: send directly
        self.udp_write_pending = true;
        self.trackOp();
        self.inbound.tcp.write(loop, &self.inbound.write_comp, .{ .slice = self.inbound.send_buf.?[0..encoded_len] }, Session, self, &Session.onClientWrite);
    }
}

/// UDP recv thread: blocking recvfrom loop, pushes to worker queue.
pub fn udpRecvThread(self: *Session) void {
    // Save references to stack locals before defer (avoid use-after-free)
    const worker = self.cfg.worker;
    const conn = self;
    const sock = self.udp_sock;

    defer {
        // Push sentinel to signal thread exit — retry until success
        const sentinel = Worker.UdpDownlinkQueue.Entry{
            .conn = conn,
            .data_len = 0,
        };
        while (true) {
            if (worker.udp_downlink.push(sentinel)) break;
            std.Thread.sleep(1_000_000); // 1ms
        }
        worker.async_notify.notify() catch {};
    }

    var buf: [1500]u8 = undefined;
    while (!self.udp_closed.load(.acquire)) {
        const result = UdpSys.recv(sock, &buf) orelse continue; // timeout or error

        // Push to worker's UDP downlink queue
        var entry = Worker.UdpDownlinkQueue.Entry{
            .conn = conn,
            .src_port = result.port,
            .data_len = @intCast(result.len),
        };
        if (result.ip6) |ip6| {
            entry.src_ip6 = ip6;
            entry.is_ipv6 = true;
        } else if (result.ip4) |ip4| {
            entry.src_ip4 = ip4;
        }
        @memcpy(entry.data[0..result.len], buf[0..result.len]);

        if (!worker.udp_downlink.push(entry)) {
            continue; // queue full, drop packet (UDP is lossy)
        }
        worker.async_notify.notify() catch {};
    }
}
