const std = @import("std");
const xev = @import("xev");
const ss_crypto = @import("ss_crypto.zig");
const Session = @import("../../core/proxy_connection.zig").Session;

/// Shadowsocks inbound uplink: decrypt AEAD frames from client.
/// Uses inbound_pending buffer for accumulation (heap-allocated on-demand, SS and VMess inbound are mutually exclusive).
pub fn processSsUplink(self: *Session, loop: *xev.Loop, data: []const u8) xev.CallbackAction {
    var state = &self.inbound.protocol.shadowsocks.decrypt_state;
    const ibuf = self.ensureInboundPending() orelse {
        self.initiateClose(loop);
        return .disarm;
    };

    // Accumulate data — compact only when needed
    var avail = ibuf.len - self.inbound.pending_tail;
    if (avail < data.len and self.inbound.pending_head > 0) {
        const remaining = self.inbound.pending_tail - self.inbound.pending_head;
        std.mem.copyForwards(u8, ibuf[0..remaining], ibuf[self.inbound.pending_head..self.inbound.pending_tail]);
        self.inbound.pending_head = 0;
        self.inbound.pending_tail = remaining;
        avail = ibuf.len - self.inbound.pending_tail;
    }
    if (avail < data.len) {
        self.cfg.logger.err("ss uplink: accumulation buffer overflow", .{});
        self.initiateClose(loop);
        return .disarm;
    }
    @memcpy(ibuf[self.inbound.pending_tail .. self.inbound.pending_tail + data.len], data);
    self.inbound.pending_tail += data.len;

    const pending = ibuf[self.inbound.pending_head..self.inbound.pending_tail];

    switch (state.decryptFrame(pending, self.inbound.decrypt_buf.?)) {
        .success => |result| {
            self.inbound.pending_head += result.bytes_consumed;
            if (self.inbound.pending_head == self.inbound.pending_tail) {
                self.inbound.pending_head = 0;
                self.inbound.pending_tail = 0;
            }

            if (result.plaintext_len == 0) {
                self.initiateClose(loop);
                return .disarm;
            }

            self.writeToTarget(loop, self.inbound.decrypt_buf.?[0..result.plaintext_len]);
            return .disarm;
        },
        .incomplete => return .rearm,
        .integrity_error => {
            self.cfg.logger.warn("shadowsocks frame integrity error", .{});
            self.initiateClose(loop);
            return .disarm;
        },
    }
}

/// Shadowsocks outbound downlink: decrypt AEAD frames from SS server.
/// Handles salt parsing on first response and frame decryption.
/// Uses outbound_state.pending (20KB) for frame accumulation — large enough
/// for max SS AEAD frame (~16.4KB). Previously used protocol_buf (4KB) which
/// caused silent data loss on responses larger than 4KB.
pub fn processSsOutDownlink(self: *Session, loop: *xev.Loop, data: []const u8) void {
    const method: ss_crypto.Method = @enumFromInt(self.outbound.config.?.ss_method);
    const key_len = method.keySize();
    const out = self.outbound_state.?;

    // First response: parse salt and init decrypt state
    if (self.outbound_state.?.ss.decrypt == null) {
        const salt_size = method.saltSize();
        // Accumulate salt bytes in protocol_buf (max 32 bytes, always fits)
        const salt_pending = self.outbound_state.?.ss.down_pending;
        const salt_need = salt_size - salt_pending;
        const salt_copy = @min(data.len, salt_need);
        @memcpy(self.inbound.protocol_buf.?[salt_pending .. salt_pending + salt_copy], data[0..salt_copy]);
        self.outbound_state.?.ss.down_pending = salt_pending + salt_copy;

        if (self.outbound_state.?.ss.down_pending < salt_size) {
            self.startTargetRead(loop);
            return;
        }

        // Extract salt and init decrypt state
        self.outbound_state.?.ss.decrypt = ss_crypto.StreamState.init(
            method,
            self.outbound.config.?.ss_psk[0..key_len],
            self.inbound.protocol_buf.?[0..salt_size],
        );
        self.outbound_state.?.ss.down_pending = 0; // done with salt

        // Any remaining data after salt goes to outbound pending buffer
        const data_after_salt = data[salt_copy..];
        if (data_after_salt.len > 0) {
            const pbuf = out.pending orelse {
                self.initiateClose(loop);
                return;
            };
            @memcpy(pbuf[0..data_after_salt.len], data_after_salt);
            out.pending_tail = data_after_salt.len;
        } else {
            self.startTargetRead(loop);
            return;
        }
    } else {
        // Subsequent reads: accumulate in outbound pending
        const pbuf = out.pending orelse {
            self.initiateClose(loop);
            return;
        };
        var avail = pbuf.len - out.pending_tail;
        if (avail < data.len and out.pending_head > 0) {
            const remaining = out.pending_tail - out.pending_head;
            std.mem.copyForwards(u8, pbuf[0..remaining], pbuf[out.pending_head..out.pending_tail]);
            out.pending_head = 0;
            out.pending_tail = remaining;
            avail = pbuf.len - out.pending_tail;
        }
        if (avail < data.len) {
            self.cfg.logger.err("ss outbound: pending buffer overflow ({d}B data, {d}B avail)", .{ data.len, avail });
            self.initiateClose(loop);
            return;
        }
        @memcpy(pbuf[out.pending_tail .. out.pending_tail + data.len], data);
        out.pending_tail += data.len;
    }

    // Try to decrypt a frame
    var state = &(self.outbound_state.?.ss.decrypt.?);
    const pending_data = (out.pending.?)[out.pending_head..out.pending_tail];

    switch (state.decryptFrame(pending_data, self.inbound.decrypt_buf.?)) {
        .success => |result| {
            out.pending_head += result.bytes_consumed;
            if (out.pending_head == out.pending_tail) {
                out.pending_head = 0;
                out.pending_tail = 0;
            }

            if (result.plaintext_len == 0) {
                self.initiateClose(loop);
                return;
            }

            // Forward decrypted plaintext to client
            self.handleRelayDownlinkData(loop, self.inbound.decrypt_buf.?[0..result.plaintext_len]);
        },
        .incomplete => {
            // Need more data
            self.startTargetRead(loop);
        },
        .integrity_error => {
            self.cfg.logger.warn("ss outbound: frame integrity error", .{});
            self.initiateClose(loop);
        },
    }
}
