const std = @import("std");

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,

    pub fn isControl(self: Opcode) bool {
        return @intFromEnum(self) >= 0x8;
    }
};

pub const FrameHeader = struct {
    fin: bool,
    opcode: Opcode,
    masked: bool,
    payload_len: u64,
    mask_key: [4]u8 = .{ 0, 0, 0, 0 },

    /// Minimum header size needed to determine full header length.
    pub const min_header_size = 2;

    /// Parse frame header from buffer. Returns header and bytes consumed, or null if need more data.
    pub fn parse(data: []const u8) ?struct { header: FrameHeader, consumed: usize } {
        if (data.len < 2) return null;

        const fin = (data[0] & 0x80) != 0;
        const opcode: Opcode = @enumFromInt(@as(u4, @truncate(data[0] & 0x0F)));
        const masked = (data[1] & 0x80) != 0;
        const len7: u7 = @truncate(data[1] & 0x7F);

        var offset: usize = 2;
        var payload_len: u64 = undefined;

        if (len7 <= 125) {
            payload_len = len7;
        } else if (len7 == 126) {
            if (data.len < offset + 2) return null;
            payload_len = readU16BE(data[offset..]);
            offset += 2;
        } else { // 127
            if (data.len < offset + 8) return null;
            payload_len = readU64BE(data[offset..]);
            offset += 8;
        }

        var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
        if (masked) {
            if (data.len < offset + 4) return null;
            @memcpy(&mask_key, data[offset .. offset + 4]);
            offset += 4;
        }

        return .{
            .header = .{
                .fin = fin,
                .opcode = opcode,
                .masked = masked,
                .payload_len = payload_len,
                .mask_key = mask_key,
            },
            .consumed = offset,
        };
    }

    /// Encode frame header into buffer. Returns bytes written.
    pub fn encode(self: *const FrameHeader, buf: []u8) usize {
        var pos: usize = 0;

        buf[pos] = @as(u8, if (self.fin) 0x80 else 0x00) | @as(u8, @intFromEnum(self.opcode));
        pos += 1;

        const mask_bit: u8 = if (self.masked) 0x80 else 0x00;
        if (self.payload_len <= 125) {
            buf[pos] = mask_bit | @as(u8, @intCast(self.payload_len));
            pos += 1;
        } else if (self.payload_len <= 0xFFFF) {
            buf[pos] = mask_bit | 126;
            pos += 1;
            writeU16BE(buf[pos..], @intCast(self.payload_len));
            pos += 2;
        } else {
            buf[pos] = mask_bit | 127;
            pos += 1;
            writeU64BE(buf[pos..], self.payload_len);
            pos += 8;
        }

        if (self.masked) {
            @memcpy(buf[pos .. pos + 4], &self.mask_key);
            pos += 4;
        }

        return pos;
    }

    /// Maximum encoded header size (2 + 8 + 4 = 14).
    pub const max_header_size = 14;
};

/// XOR mask/unmask data in-place (symmetric operation).
pub fn maskData(data: []u8, mask_key: [4]u8, offset: usize) void {
    for (data, 0..) |*byte, i| {
        byte.* ^= mask_key[(offset + i) % 4];
    }
}

/// Encode a close frame payload: 2-byte status code (big-endian).
pub fn encodeClosePayload(buf: []u8, status_code: u16) []u8 {
    writeU16BE(buf, status_code);
    return buf[0..2];
}

fn readU16BE(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | @as(u16, data[1]);
}

fn readU64BE(data: []const u8) u64 {
    var result: u64 = 0;
    inline for (0..8) |i| {
        result = (result << 8) | @as(u64, data[i]);
    }
    return result;
}

fn writeU16BE(buf: []u8, val: u16) void {
    buf[0] = @intCast(val >> 8);
    buf[1] = @intCast(val & 0xFF);
}

fn writeU64BE(buf: []u8, val: u64) void {
    inline for (0..8) |i| {
        buf[i] = @intCast((val >> @intCast(56 - i * 8)) & 0xFF);
    }
}
