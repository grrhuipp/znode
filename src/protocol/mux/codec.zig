/// Mux.Cool frame codec — Xray-core compatible multiplexing.
///
/// Frame format:
///   [MetaLen: 2 BE] [SessionID: 2 BE] [Status: 1] [Option: 1]
///   [... address ...] [DataLen: 2 BE] [Payload]
const std = @import("std");
const types = @import("../../common/types.zig");

pub const Status = enum(u8) {
    new = 0x01,
    keep = 0x02,
    end = 0x03,
    keepalive = 0x04,
};

pub const NetworkType = enum(u8) {
    tcp = 0x01,
    udp = 0x02,
};

pub const OptionFlag = struct {
    pub const data: u8 = 0x01;
    pub const err: u8 = 0x02;
};

/// Mux address type (differs from SOCKS5: 1=IPv4, 2=Domain, 3=IPv6)
pub const MuxAddrType = enum(u8) {
    ipv4 = 1,
    domain = 2,
    ipv6 = 3,
};

pub const FrameHeader = struct {
    session_id: u16,
    status: Status,
    option: u8,
    network: ?NetworkType = null,
    target: ?types.TargetAddress = null,
    global_id: ?u64 = null,
    payload: ?[]const u8 = null,
    frame_size: usize = 0,
};

pub const DecodeError = error{
    NeedMoreData,
    InvalidFrame,
};

/// Decode a single Mux.Cool frame from buffer.
pub fn decodeFrame(data: []const u8) DecodeError!FrameHeader {
    if (data.len < 2) return error.NeedMoreData;

    const meta_len = readU16BE(data[0..2]);
    if (meta_len < 4) return error.InvalidFrame;
    if (data.len < 2 + meta_len) return error.NeedMoreData;

    const meta = data[2 .. 2 + meta_len];
    const session_id = readU16BE(meta[0..2]);
    const status: Status = @enumFromInt(meta[2]);
    const option = meta[3];

    var result = FrameHeader{
        .session_id = session_id,
        .status = status,
        .option = option,
    };

    var mpos: usize = 4;

    // Parse address for NEW frames, or KEEP+UDP
    const parse_addr = blk: {
        if (status == .new) break :blk true;
        if (status == .keep and mpos < meta.len and meta[mpos] == @intFromEnum(NetworkType.udp))
            break :blk true;
        break :blk false;
    };

    if (parse_addr and mpos < meta.len) {
        const net_byte = meta[mpos];
        result.network = @enumFromInt(net_byte);
        mpos += 1;

        // Port (2 bytes BE) — Mux uses Port-then-Address order
        if (mpos + 2 > meta.len) return error.InvalidFrame;
        const port = readU16BE(meta[mpos..][0..2]);
        mpos += 2;

        // Address type
        if (mpos >= meta.len) return error.InvalidFrame;
        const addr_type: MuxAddrType = @enumFromInt(meta[mpos]);
        mpos += 1;

        switch (addr_type) {
            .ipv4 => {
                if (mpos + 4 > meta.len) return error.InvalidFrame;
                var buf: [16]u8 = undefined;
                const host = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{
                    meta[mpos], meta[mpos + 1], meta[mpos + 2], meta[mpos + 3],
                }) catch return error.InvalidFrame;
                mpos += 4;
                result.target = types.TargetAddress.init(host, port, .ipv4);
            },
            .domain => {
                if (mpos >= meta.len) return error.InvalidFrame;
                const dlen = meta[mpos];
                mpos += 1;
                if (mpos + dlen > meta.len) return error.InvalidFrame;
                result.target = types.TargetAddress.init(meta[mpos .. mpos + dlen], port, .domain);
                mpos += dlen;
            },
            .ipv6 => {
                if (mpos + 16 > meta.len) return error.InvalidFrame;
                // Store raw hex for IPv6
                var buf: [46]u8 = undefined;
                const d = meta[mpos..];
                const host = std.fmt.bufPrint(&buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
                    d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15],
                }) catch return error.InvalidFrame;
                mpos += 16;
                result.target = types.TargetAddress.init(host, port, .ipv6);
            },
        }

        // GlobalID for NEW+UDP with 8 bytes remaining
        if (status == .new and result.network == .udp and mpos + 8 <= meta.len) {
            result.global_id = std.mem.readInt(u64, meta[mpos..][0..8], .big);
            mpos += 8;
        }
    }

    var total_consumed: usize = 2 + meta_len;

    // Data payload
    if (option & OptionFlag.data != 0) {
        if (total_consumed + 2 > data.len) return error.NeedMoreData;
        const data_len = readU16BE(data[total_consumed..][0..2]);
        total_consumed += 2;

        if (total_consumed + data_len > data.len) return error.NeedMoreData;
        result.payload = data[total_consumed .. total_consumed + data_len];
        total_consumed += data_len;
    }

    result.frame_size = total_consumed;
    return result;
}

// ── Encoding functions ────────────────────────────────────────────────────

/// Encode KeepAlive frame: fixed 6 bytes.
pub fn encodeKeepAlive(out: []u8) usize {
    const frame = [6]u8{ 0x00, 0x04, 0x00, 0x00, 0x04, 0x00 };
    @memcpy(out[0..6], &frame);
    return 6;
}

/// Encode End frame for a session.
pub fn encodeEnd(session_id: u16, is_error: bool, out: []u8) usize {
    var pos: usize = 0;
    writeU16BE(out[pos..][0..2], 4); // MetaLen
    pos += 2;
    writeU16BE(out[pos..][0..2], session_id);
    pos += 2;
    out[pos] = @intFromEnum(Status.end);
    pos += 1;
    out[pos] = if (is_error) OptionFlag.err else 0;
    pos += 1;
    return pos;
}

/// Encode Keep+Data frame for TCP sub-session.
pub fn encodeKeepData(session_id: u16, payload: []const u8, out: []u8) usize {
    var pos: usize = 0;
    writeU16BE(out[pos..][0..2], 4); // MetaLen
    pos += 2;
    writeU16BE(out[pos..][0..2], session_id);
    pos += 2;
    out[pos] = @intFromEnum(Status.keep);
    pos += 1;
    out[pos] = OptionFlag.data;
    pos += 1;
    writeU16BE(out[pos..][0..2], @intCast(payload.len));
    pos += 2;
    @memcpy(out[pos..][0..payload.len], payload);
    pos += payload.len;
    return pos;
}

fn readU16BE(bytes: *const [2]u8) u16 {
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}

fn writeU16BE(bytes: *[2]u8, val: u16) void {
    bytes[0] = @intCast(val >> 8);
    bytes[1] = @intCast(val & 0xFF);
}
