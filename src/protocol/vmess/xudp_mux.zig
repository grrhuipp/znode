const std = @import("std");
const session_mod = @import("../../core/session.zig");

/// XUDP Mux protocol: multiplexes UDP datagrams over a single TCP stream.
///
/// Frame format:
///   [2B meta_len BE][2B session_id BE][1B status][1B option]
///   [optional: 1B network + address (Port-first)]
///   [optional: 8B global_id (New frames only)]
///   [optional: 2B data_len BE + payload]

// ── Constants ──

pub const SessionStatus = enum(u8) {
    new = 0x01,
    keep = 0x02,
    end = 0x03,
    keep_alive = 0x04,
};

pub const Option = struct {
    pub const data: u8 = 0x01;
    pub const err: u8 = 0x02;
};

pub const NetworkType = enum(u8) {
    tcp = 0x01,
    udp = 0x02,
};

pub const AddressType = enum(u8) {
    ipv4 = 0x01,
    domain = 0x02,
    ipv6 = 0x03,
};

/// VMess Mux target: "v1.mux.cool" port 666 signals Single XUDP mode.
pub const mux_domain = "v1.mux.cool";
pub const mux_port_xudp: u16 = 666;
pub const mux_port_standard: u16 = 443;

/// Minimum frame header size: 2B meta_len + 2B session_id + 1B status + 1B option = 6
pub const min_header_size: usize = 6;

// ── Encoder ──

/// Encode a New frame (session creation with target address and optional global ID).
/// Returns bytes written or null if buffer too small.
pub fn encodeNewFrame(
    buf: []u8,
    session_id: u16,
    target_addr: *const session_mod.TargetAddress,
    global_id: ?[8]u8,
    payload: ?[]const u8,
) ?usize {
    var pos: usize = 2; // skip meta_len (filled later)

    // Session ID
    if (pos + 2 > buf.len) return null;
    std.mem.writeInt(u16, buf[pos..][0..2], session_id, .big);
    pos += 2;

    // Status + Option
    if (pos + 2 > buf.len) return null;
    buf[pos] = @intFromEnum(SessionStatus.new);
    buf[pos + 1] = if (payload != null) Option.data else 0;
    pos += 2;

    // Network type (UDP)
    if (pos + 1 > buf.len) return null;
    buf[pos] = @intFromEnum(NetworkType.udp);
    pos += 1;

    // Address: Port first, then ATYP + address
    pos = writeAddress(buf, pos, target_addr) orelse return null;

    // Global ID (8 bytes, only for New frames)
    if (global_id) |gid| {
        if (pos + 8 > buf.len) return null;
        @memcpy(buf[pos .. pos + 8], &gid);
        pos += 8;
    }

    // Fill meta_len: everything from session_id to here
    const meta_len: u16 = @intCast(pos - 2);
    std.mem.writeInt(u16, buf[0..2], meta_len, .big);

    // Optional payload
    if (payload) |p| {
        if (pos + 2 + p.len > buf.len) return null;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(p.len), .big);
        pos += 2;
        @memcpy(buf[pos .. pos + p.len], p);
        pos += p.len;
    }

    return pos;
}

/// Encode a Keep frame (data on existing session, with optional UDP address).
pub fn encodeKeepFrame(
    buf: []u8,
    session_id: u16,
    udp_target: ?*const session_mod.TargetAddress,
    payload: ?[]const u8,
) ?usize {
    var pos: usize = 2; // skip meta_len

    // Session ID
    if (pos + 2 > buf.len) return null;
    std.mem.writeInt(u16, buf[pos..][0..2], session_id, .big);
    pos += 2;

    // Status + Option
    if (pos + 2 > buf.len) return null;
    buf[pos] = @intFromEnum(SessionStatus.keep);
    buf[pos + 1] = if (payload != null) Option.data else 0;
    pos += 2;

    // UDP address (optional, for FullCone NAT)
    if (udp_target) |target| {
        if (pos + 1 > buf.len) return null;
        buf[pos] = @intFromEnum(NetworkType.udp);
        pos += 1;
        pos = writeAddress(buf, pos, target) orelse return null;
    }

    // Fill meta_len
    const meta_len: u16 = @intCast(pos - 2);
    std.mem.writeInt(u16, buf[0..2], meta_len, .big);

    // Optional payload
    if (payload) |p| {
        if (pos + 2 + p.len > buf.len) return null;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(p.len), .big);
        pos += 2;
        @memcpy(buf[pos .. pos + p.len], p);
        pos += p.len;
    }

    return pos;
}

/// Encode an End frame.
pub fn encodeEndFrame(buf: []u8, session_id: u16) ?usize {
    if (buf.len < 6) return null;
    std.mem.writeInt(u16, buf[0..2], 4, .big); // meta_len = 4
    std.mem.writeInt(u16, buf[2..4], session_id, .big);
    buf[4] = @intFromEnum(SessionStatus.end);
    buf[5] = 0;
    return 6;
}

/// Encode a KeepAlive frame.
pub fn encodeKeepAliveFrame(buf: []u8, session_id: u16) ?usize {
    if (buf.len < 6) return null;
    std.mem.writeInt(u16, buf[0..2], 4, .big); // meta_len = 4
    std.mem.writeInt(u16, buf[2..4], session_id, .big);
    buf[4] = @intFromEnum(SessionStatus.keep_alive);
    buf[5] = 0;
    return 6;
}

// ── Decoder ──

pub const DecodedFrame = struct {
    session_id: u16,
    status: SessionStatus,
    option: u8,
    network: ?NetworkType,
    target: ?session_mod.TargetAddress,
    global_id: ?[8]u8,
    payload: ?[]const u8,
    bytes_consumed: usize,
};

pub const DecodeResult = union(enum) {
    success: DecodedFrame,
    incomplete,
    protocol_error,
};

/// Decode a single XUDP frame from the data buffer.
pub fn decodeFrame(data: []const u8) DecodeResult {
    if (data.len < 2) return .incomplete;

    const meta_len = std.mem.readInt(u16, data[0..2], .big);
    const total_meta = 2 + @as(usize, meta_len);

    if (data.len < total_meta) return .incomplete;
    if (meta_len < 4) return .protocol_error; // need at least session_id(2) + status(1) + option(1)

    const session_id = std.mem.readInt(u16, data[2..4], .big);
    const status_byte = data[4];
    const option = data[5];

    const status: SessionStatus = std.meta.intToEnum(SessionStatus, status_byte) catch return .protocol_error;

    var pos: usize = 6; // past session_id + status + option within the meta region
    var network: ?NetworkType = null;
    var target: ?session_mod.TargetAddress = null;
    var global_id: ?[8]u8 = null;

    // Parse address for New frames or Keep frames with UDP network type
    const need_address = switch (status) {
        .new => true,
        .keep => blk: {
            // Check if there's a network type byte after the base header
            if (pos < 2 + meta_len and data[pos] == @intFromEnum(NetworkType.udp)) {
                break :blk true;
            }
            break :blk false;
        },
        else => false,
    };

    if (need_address) {
        // Network type
        if (pos >= 2 + meta_len) return .protocol_error;
        network = std.meta.intToEnum(NetworkType, data[pos]) catch return .protocol_error;
        pos += 1;

        // Address: Port(2B) + ATYP(1B) + addr(variable)
        const addr_result = readAddress(data[pos .. 2 + meta_len]);
        switch (addr_result) {
            .success => |a| {
                target = a.target;
                pos += a.bytes_consumed;
            },
            .incomplete => return .incomplete,
            .protocol_error => return .protocol_error,
        }

        // Global ID (8 bytes, only in New frames, if present)
        if (status == .new and pos + 8 <= 2 + meta_len) {
            global_id = data[pos..][0..8].*;
            pos += 8;
        }
    }

    // Move to after meta region
    var frame_end: usize = total_meta;
    var payload: ?[]const u8 = null;

    // Read payload if OptionData is set
    if (option & Option.data != 0) {
        if (data.len < frame_end + 2) return .incomplete;
        const payload_len = std.mem.readInt(u16, data[frame_end..][0..2], .big);
        frame_end += 2;
        if (data.len < frame_end + payload_len) return .incomplete;
        if (payload_len > 0) {
            payload = data[frame_end .. frame_end + payload_len];
        }
        frame_end += payload_len;
    }

    return .{ .success = .{
        .session_id = session_id,
        .status = status,
        .option = option,
        .network = network,
        .target = target,
        .global_id = global_id,
        .payload = payload,
        .bytes_consumed = frame_end,
    } };
}

// ── Address Helpers ──

/// Write address in Port-first format: [2B port BE][1B ATYP][variable addr]
fn writeAddress(buf: []u8, start: usize, target: *const session_mod.TargetAddress) ?usize {
    var pos = start;

    // Port (2 bytes, big-endian)
    if (pos + 2 > buf.len) return null;
    std.mem.writeInt(u16, buf[pos..][0..2], target.port, .big);
    pos += 2;

    switch (target.addr_type) {
        .ipv4 => {
            if (pos + 1 + 4 > buf.len) return null;
            buf[pos] = @intFromEnum(AddressType.ipv4);
            pos += 1;
            @memcpy(buf[pos .. pos + 4], &target.ip4);
            pos += 4;
        },
        .domain => {
            const domain = target.getDomain();
            if (pos + 1 + 1 + domain.len > buf.len) return null;
            buf[pos] = @intFromEnum(AddressType.domain);
            pos += 1;
            buf[pos] = @intCast(domain.len);
            pos += 1;
            @memcpy(buf[pos .. pos + domain.len], domain);
            pos += domain.len;
        },
        .ipv6 => {
            if (pos + 1 + 16 > buf.len) return null;
            buf[pos] = @intFromEnum(AddressType.ipv6);
            pos += 1;
            @memcpy(buf[pos .. pos + 16], &target.ip6);
            pos += 16;
        },
        .none => return null,
    }

    return pos;
}

const AddressReadResult = union(enum) {
    success: struct {
        target: session_mod.TargetAddress,
        bytes_consumed: usize,
    },
    incomplete,
    protocol_error,
};

/// Read address in Port-first format from data.
fn readAddress(data: []const u8) AddressReadResult {
    if (data.len < 3) return .incomplete; // port(2) + atyp(1)

    const port = std.mem.readInt(u16, data[0..2], .big);
    const atyp = data[2];
    var pos: usize = 3;

    var target = session_mod.TargetAddress{};

    switch (atyp) {
        @intFromEnum(AddressType.ipv4) => {
            if (data.len < pos + 4) return .incomplete;
            target.setIpv4(data[pos..][0..4].*, port);
            pos += 4;
        },
        @intFromEnum(AddressType.domain) => {
            if (data.len < pos + 1) return .incomplete;
            const domain_len = data[pos];
            pos += 1;
            if (data.len < pos + domain_len) return .incomplete;
            target.setDomain(data[pos .. pos + domain_len], port);
            pos += domain_len;
        },
        @intFromEnum(AddressType.ipv6) => {
            if (data.len < pos + 16) return .incomplete;
            target.setIpv6(data[pos..][0..16].*, port);
            pos += 16;
        },
        else => return .protocol_error,
    }

    return .{ .success = .{
        .target = target,
        .bytes_consumed = pos,
    } };
}

/// Create a Mux target address: "v1.mux.cool:666" for Single XUDP mode.
pub fn makeMuxTarget() session_mod.TargetAddress {
    var target = session_mod.TargetAddress{};
    target.setDomain(mux_domain, mux_port_xudp);
    return target;
}

// ── Tests ──

const testing = std.testing;

test "encodeNewFrame IPv4 with payload" {
    var target = session_mod.TargetAddress{};
    target.setIpv4(.{ 8, 8, 8, 8 }, 53);

    var buf: [256]u8 = undefined;
    const payload = "hello";
    const n = encodeNewFrame(&buf, 0, &target, null, payload) orelse return error.EncodeFailed;

    // Decode it back
    const result = decodeFrame(buf[0..n]);
    switch (result) {
        .success => |frame| {
            try testing.expectEqual(@as(u16, 0), frame.session_id);
            try testing.expectEqual(SessionStatus.new, frame.status);
            try testing.expectEqual(Option.data, frame.option);
            try testing.expectEqual(NetworkType.udp, frame.network.?);
            const t = frame.target.?;
            try testing.expectEqual(session_mod.TargetAddress.AddressType.ipv4, t.addr_type);
            try testing.expectEqual([4]u8{ 8, 8, 8, 8 }, t.ip4);
            try testing.expectEqual(@as(u16, 53), t.port);
            try testing.expect(frame.global_id == null);
            try testing.expectEqualStrings("hello", frame.payload.?);
            try testing.expectEqual(n, frame.bytes_consumed);
        },
        else => return error.DecodeFailed,
    }
}

test "encodeNewFrame domain with global_id" {
    var target = session_mod.TargetAddress{};
    target.setDomain("example.com", 443);

    const gid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    var buf: [256]u8 = undefined;
    const n = encodeNewFrame(&buf, 42, &target, gid, "data") orelse return error.EncodeFailed;

    const result = decodeFrame(buf[0..n]);
    switch (result) {
        .success => |frame| {
            try testing.expectEqual(@as(u16, 42), frame.session_id);
            try testing.expectEqual(SessionStatus.new, frame.status);
            const t = frame.target.?;
            try testing.expectEqual(session_mod.TargetAddress.AddressType.domain, t.addr_type);
            try testing.expectEqualStrings("example.com", t.getDomain());
            try testing.expectEqual(@as(u16, 443), t.port);
            try testing.expectEqual(gid, frame.global_id.?);
            try testing.expectEqualStrings("data", frame.payload.?);
        },
        else => return error.DecodeFailed,
    }
}

test "encodeKeepFrame with UDP target" {
    var target = session_mod.TargetAddress{};
    target.setIpv4(.{ 1, 2, 3, 4 }, 8080);

    var buf: [256]u8 = undefined;
    const payload = "udp data";
    const n = encodeKeepFrame(&buf, 0, &target, payload) orelse return error.EncodeFailed;

    const result = decodeFrame(buf[0..n]);
    switch (result) {
        .success => |frame| {
            try testing.expectEqual(@as(u16, 0), frame.session_id);
            try testing.expectEqual(SessionStatus.keep, frame.status);
            try testing.expectEqual(NetworkType.udp, frame.network.?);
            const t = frame.target.?;
            try testing.expectEqual([4]u8{ 1, 2, 3, 4 }, t.ip4);
            try testing.expectEqual(@as(u16, 8080), t.port);
            try testing.expectEqualStrings("udp data", frame.payload.?);
        },
        else => return error.DecodeFailed,
    }
}

test "encodeKeepFrame without target" {
    var buf: [256]u8 = undefined;
    const payload = "tcp data";
    const n = encodeKeepFrame(&buf, 5, null, payload) orelse return error.EncodeFailed;

    const result = decodeFrame(buf[0..n]);
    switch (result) {
        .success => |frame| {
            try testing.expectEqual(@as(u16, 5), frame.session_id);
            try testing.expectEqual(SessionStatus.keep, frame.status);
            try testing.expect(frame.network == null);
            try testing.expect(frame.target == null);
            try testing.expectEqualStrings("tcp data", frame.payload.?);
        },
        else => return error.DecodeFailed,
    }
}

test "encodeEndFrame" {
    var buf: [16]u8 = undefined;
    const n = encodeEndFrame(&buf, 99) orelse return error.EncodeFailed;
    try testing.expectEqual(@as(usize, 6), n);

    const result = decodeFrame(buf[0..n]);
    switch (result) {
        .success => |frame| {
            try testing.expectEqual(@as(u16, 99), frame.session_id);
            try testing.expectEqual(SessionStatus.end, frame.status);
            try testing.expect(frame.payload == null);
        },
        else => return error.DecodeFailed,
    }
}

test "encodeKeepAliveFrame" {
    var buf: [16]u8 = undefined;
    const n = encodeKeepAliveFrame(&buf, 0) orelse return error.EncodeFailed;
    try testing.expectEqual(@as(usize, 6), n);

    const result = decodeFrame(buf[0..n]);
    switch (result) {
        .success => |frame| {
            try testing.expectEqual(@as(u16, 0), frame.session_id);
            try testing.expectEqual(SessionStatus.keep_alive, frame.status);
        },
        else => return error.DecodeFailed,
    }
}

test "decodeFrame incomplete" {
    try testing.expect(decodeFrame(&[_]u8{0}) == .incomplete);
    try testing.expect(decodeFrame(&[_]u8{ 0, 10, 0, 0 }) == .incomplete); // meta_len=10 but only 4 bytes
}

test "decodeFrame protocol error" {
    // meta_len=1 (too small for session_id + status + option)
    try testing.expect(decodeFrame(&[_]u8{ 0, 1, 0xFF }) == .protocol_error);
}

test "encodeNewFrame IPv6" {
    var target = session_mod.TargetAddress{};
    target.setIpv6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 8443);

    var buf: [256]u8 = undefined;
    const n = encodeNewFrame(&buf, 0, &target, null, "v6") orelse return error.EncodeFailed;

    const result = decodeFrame(buf[0..n]);
    switch (result) {
        .success => |frame| {
            const t = frame.target.?;
            try testing.expectEqual(session_mod.TargetAddress.AddressType.ipv6, t.addr_type);
            try testing.expectEqual(@as(u16, 8443), t.port);
            try testing.expectEqual(@as(u8, 0x20), t.ip6[0]);
            try testing.expectEqual(@as(u8, 0x01), t.ip6[1]);
            try testing.expectEqualStrings("v6", frame.payload.?);
        },
        else => return error.DecodeFailed,
    }
}

test "multi-frame decode" {
    var buf: [512]u8 = undefined;
    var total: usize = 0;

    // Frame 1: New
    var target = session_mod.TargetAddress{};
    target.setIpv4(.{ 1, 1, 1, 1 }, 53);
    const n1 = encodeNewFrame(buf[total..], 0, &target, null, "dns query") orelse return error.EncodeFailed;
    total += n1;

    // Frame 2: Keep
    const n2 = encodeKeepFrame(buf[total..], 0, &target, "more data") orelse return error.EncodeFailed;
    total += n2;

    // Frame 3: End
    const n3 = encodeEndFrame(buf[total..], 0) orelse return error.EncodeFailed;
    total += n3;

    // Decode all three
    var offset: usize = 0;

    const r1 = decodeFrame(buf[offset..total]);
    try testing.expect(r1 == .success);
    offset += r1.success.bytes_consumed;

    const r2 = decodeFrame(buf[offset..total]);
    try testing.expect(r2 == .success);
    try testing.expectEqual(SessionStatus.keep, r2.success.status);
    offset += r2.success.bytes_consumed;

    const r3 = decodeFrame(buf[offset..total]);
    try testing.expect(r3 == .success);
    try testing.expectEqual(SessionStatus.end, r3.success.status);
    offset += r3.success.bytes_consumed;

    try testing.expectEqual(total, offset);
}

test "encodeNewFrame no payload" {
    var target = session_mod.TargetAddress{};
    target.setIpv4(.{ 10, 0, 0, 1 }, 80);

    var buf: [256]u8 = undefined;
    const n = encodeNewFrame(&buf, 1, &target, null, null) orelse return error.EncodeFailed;

    const result = decodeFrame(buf[0..n]);
    switch (result) {
        .success => |frame| {
            try testing.expectEqual(SessionStatus.new, frame.status);
            try testing.expectEqual(@as(u8, 0), frame.option); // no OptionData
            try testing.expect(frame.payload == null);
        },
        else => return error.DecodeFailed,
    }
}

test "makeMuxTarget" {
    const t = makeMuxTarget();
    try testing.expectEqual(session_mod.TargetAddress.AddressType.domain, t.addr_type);
    try testing.expectEqualStrings("v1.mux.cool", t.getDomain());
    try testing.expectEqual(@as(u16, 666), t.port);
}

test "buffer too small" {
    var target = session_mod.TargetAddress{};
    target.setIpv4(.{ 1, 2, 3, 4 }, 80);

    var tiny: [4]u8 = undefined;
    try testing.expect(encodeNewFrame(&tiny, 0, &target, null, "data") == null);
    try testing.expect(encodeKeepFrame(&tiny, 0, &target, "data") == null);

    var small: [3]u8 = undefined;
    try testing.expect(encodeEndFrame(&small, 0) == null);
}
