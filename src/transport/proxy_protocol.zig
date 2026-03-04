const std = @import("std");

pub const ParseStatus = enum {
    success,
    not_proxy, // 数据不是 PROXY 协议，应回退
    incomplete, // 数据不完整，需要更多
    invalid, // 格式部分匹配但数据损坏
};

pub const ProxyResult = struct {
    status: ParseStatus,
    src_ip_buf: [46]u8 = undefined,
    src_ip_len: u8 = 0,
    src_port: u16 = 0,
    consumed: usize = 0,

    pub fn srcIp(self: *const ProxyResult) []const u8 {
        return self.src_ip_buf[0..self.src_ip_len];
    }
};

const v2_signature = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

/// Parse PROXY protocol header (auto-detect v1/v2).
/// 返回 not_proxy 表示数据不是 PROXY 协议（所有数据应回流）。
pub fn parse(data: []const u8) ProxyResult {
    if (data.len < 6) return .{ .status = .incomplete };

    // Check v2 signature (12 bytes)
    if (data.len >= 12 and std.mem.eql(u8, data[0..12], v2_signature)) {
        return parseV2(data);
    }

    // Check v1 prefix "PROXY "
    if (std.mem.startsWith(u8, data, "PROXY ")) {
        return parseV1(data);
    }

    // 前缀可能是 v2 签名的部分匹配
    if (data.len < 12) {
        // 检查已有数据是否是 v2 签名前缀
        if (std.mem.startsWith(u8, v2_signature, data[0..@min(data.len, 12)])) {
            return .{ .status = .incomplete };
        }
    }

    // 既不是 v1 也不是 v2 → 不是 proxy protocol
    return .{ .status = .not_proxy };
}

// ── V1: text format ───────────────────────────────────────────────────────

fn parseV1(data: []const u8) ProxyResult {
    // Find \r\n terminator
    const line_end = std.mem.indexOf(u8, data, "\r\n") orelse return .{ .status = .incomplete };
    const line = data[6..line_end]; // skip "PROXY "
    const consumed = line_end + 2;

    // "UNKNOWN\r\n" → success with empty IP
    if (std.mem.startsWith(u8, line, "UNKNOWN")) {
        return .{
            .status = .success,
            .src_port = 0,
            .consumed = consumed,
        };
    }

    // "TCP4 src_ip dst_ip src_port dst_port" or "TCP6 ..."
    var iter = std.mem.splitScalar(u8, line, ' ');
    _ = iter.next() orelse return .{ .status = .invalid }; // TCP4/TCP6
    const src_ip = iter.next() orelse return .{ .status = .invalid };
    _ = iter.next() orelse return .{ .status = .invalid }; // dst_ip
    const src_port_str = iter.next() orelse return .{ .status = .invalid };

    const port = std.fmt.parseInt(u16, src_port_str, 10) catch return .{ .status = .invalid };

    var result = ProxyResult{
        .status = .success,
        .src_port = port,
        .consumed = consumed,
    };

    const len: u8 = @intCast(@min(src_ip.len, result.src_ip_buf.len));
    @memcpy(result.src_ip_buf[0..len], src_ip[0..len]);
    result.src_ip_len = len;

    return result;
}

// ── V2: binary format ─────────────────────────────────────────────────────

fn parseV2(data: []const u8) ProxyResult {
    if (data.len < 16) return .{ .status = .incomplete };

    const ver_cmd = data[12];
    const version = ver_cmd >> 4;
    if (version != 2) return .{ .status = .invalid };
    const command = ver_cmd & 0x0F;

    const family_proto = data[13];
    const family = family_proto >> 4;

    const additional_len: u16 = (@as(u16, data[14]) << 8) | @as(u16, data[15]);
    const total = 16 + @as(usize, additional_len);

    if (data.len < total) return .{ .status = .incomplete };

    // LOCAL command (health check) → no address
    if (command == 0) {
        return .{
            .status = .success,
            .src_port = 0,
            .consumed = total,
        };
    }

    // PROXY command
    if (command != 1) return .{ .status = .invalid };

    var result = ProxyResult{
        .status = .success,
        .src_port = 0,
        .consumed = total,
    };

    const addr_data = data[16..total];

    switch (family) {
        0x1 => { // IPv4
            if (addr_data.len < 12) return .{ .status = .invalid };
            const formatted = std.fmt.bufPrint(&result.src_ip_buf, "{d}.{d}.{d}.{d}", .{
                addr_data[0], addr_data[1], addr_data[2], addr_data[3],
            }) catch return .{ .status = .invalid };
            result.src_ip_len = @intCast(formatted.len);
            result.src_port = (@as(u16, addr_data[8]) << 8) | @as(u16, addr_data[9]);
        },
        0x2 => { // IPv6
            if (addr_data.len < 36) return .{ .status = .invalid };
            const formatted = std.fmt.bufPrint(&result.src_ip_buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                addr_data[0],  addr_data[1],  addr_data[2],  addr_data[3],
                addr_data[4],  addr_data[5],  addr_data[6],  addr_data[7],
                addr_data[8],  addr_data[9],  addr_data[10], addr_data[11],
                addr_data[12], addr_data[13], addr_data[14], addr_data[15],
            }) catch return .{ .status = .invalid };
            result.src_ip_len = @intCast(formatted.len);
            result.src_port = (@as(u16, addr_data[32]) << 8) | @as(u16, addr_data[33]);
        },
        else => {
            // UNIX or UNSPEC — no network address
        },
    }

    return result;
}
