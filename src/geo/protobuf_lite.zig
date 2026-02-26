const std = @import("std");

/// Lightweight protobuf wire format parser.
/// Only supports the three wire types needed for geoip.dat/geosite.dat:
///   - varint (type 0)
///   - length-delimited (type 2)
///   - fixed32 (type 5) / fixed64 (type 1)
pub const ProtobufReader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) ProtobufReader {
        return .{ .data = data };
    }

    pub fn remaining(self: *const ProtobufReader) usize {
        return if (self.pos < self.data.len) self.data.len - self.pos else 0;
    }

    pub fn isEof(self: *const ProtobufReader) bool {
        return self.pos >= self.data.len;
    }

    /// Read a field tag (field_number << 3 | wire_type).
    pub fn readTag(self: *ProtobufReader) !Tag {
        const v = try self.readVarint();
        return .{
            .field_number = @intCast(v >> 3),
            .wire_type = @intCast(v & 0x07),
        };
    }

    pub const Tag = struct {
        field_number: u32,
        wire_type: u3,

        pub const VARINT: u3 = 0;
        pub const FIXED64: u3 = 1;
        pub const LENGTH_DELIMITED: u3 = 2;
        pub const FIXED32: u3 = 5;
    };

    /// Read a varint (LEB128).
    pub fn readVarint(self: *ProtobufReader) !u64 {
        var result: u64 = 0;
        var shift: u6 = 0;
        while (shift < 64) {
            if (self.pos >= self.data.len) return error.UnexpectedEof;
            const byte = self.data[self.pos];
            self.pos += 1;
            result |= @as(u64, byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) return result;
            shift += 7;
        }
        return error.VarintTooLong;
    }

    /// Read a varint as u32.
    pub fn readVarintU32(self: *ProtobufReader) !u32 {
        const v = try self.readVarint();
        return @intCast(@min(v, std.math.maxInt(u32)));
    }

    /// Read a length-delimited field (bytes/string/embedded message).
    pub fn readBytes(self: *ProtobufReader) ![]const u8 {
        const len = try self.readVarintU32();
        if (self.pos + len > self.data.len) return error.UnexpectedEof;
        const result = self.data[self.pos .. self.pos + len];
        self.pos += len;
        return result;
    }

    /// Read a fixed32 value.
    pub fn readFixed32(self: *ProtobufReader) !u32 {
        if (self.pos + 4 > self.data.len) return error.UnexpectedEof;
        const result = std.mem.readInt(u32, self.data[self.pos..][0..4], .little);
        self.pos += 4;
        return result;
    }

    /// Read a fixed64 value.
    pub fn readFixed64(self: *ProtobufReader) !u64 {
        if (self.pos + 8 > self.data.len) return error.UnexpectedEof;
        const result = std.mem.readInt(u64, self.data[self.pos..][0..8], .little);
        self.pos += 8;
        return result;
    }

    /// Skip a field based on its wire type.
    pub fn skipField(self: *ProtobufReader, wire_type: u3) !void {
        switch (wire_type) {
            Tag.VARINT => {
                _ = try self.readVarint();
            },
            Tag.FIXED64 => {
                if (self.pos + 8 > self.data.len) return error.UnexpectedEof;
                self.pos += 8;
            },
            Tag.LENGTH_DELIMITED => {
                const len = try self.readVarintU32();
                if (self.pos + len > self.data.len) return error.UnexpectedEof;
                self.pos += len;
            },
            Tag.FIXED32 => {
                if (self.pos + 4 > self.data.len) return error.UnexpectedEof;
                self.pos += 4;
            },
            else => return error.UnknownWireType,
        }
    }

    /// Create a sub-reader for an embedded message.
    pub fn subReader(self: *ProtobufReader) !ProtobufReader {
        const bytes = try self.readBytes();
        return ProtobufReader.init(bytes);
    }
};

test "ProtobufReader varint" {
    // Varint encoding of 300 = 0xAC 0x02
    const data = [_]u8{ 0xAC, 0x02 };
    var reader = ProtobufReader.init(&data);
    const val = try reader.readVarint();
    try std.testing.expectEqual(@as(u64, 300), val);
    try std.testing.expect(reader.isEof());
}

test "ProtobufReader tag" {
    // Tag for field 1, wire type 2 (length-delimited): (1 << 3) | 2 = 0x0A
    const data = [_]u8{ 0x0A, 0x03, 'a', 'b', 'c' };
    var reader = ProtobufReader.init(&data);
    const tag = try reader.readTag();
    try std.testing.expectEqual(@as(u32, 1), tag.field_number);
    try std.testing.expectEqual(@as(u3, 2), tag.wire_type);
    const bytes = try reader.readBytes();
    try std.testing.expectEqualStrings("abc", bytes);
}

test "ProtobufReader fixed32" {
    const data = [_]u8{ 0x78, 0x56, 0x34, 0x12 };
    var reader = ProtobufReader.init(&data);
    const val = try reader.readFixed32();
    try std.testing.expectEqual(@as(u32, 0x12345678), val);
}

test "ProtobufReader skipField" {
    // varint field + length-delimited field
    const data = [_]u8{ 0x08, 0x96, 0x01, 0x12, 0x02, 'h', 'i' };
    var reader = ProtobufReader.init(&data);
    // Skip varint field (tag 1, type 0)
    const tag1 = try reader.readTag();
    try reader.skipField(tag1.wire_type);
    // Read length-delimited field
    const tag2 = try reader.readTag();
    try std.testing.expectEqual(@as(u32, 2), tag2.field_number);
    const bytes = try reader.readBytes();
    try std.testing.expectEqualStrings("hi", bytes);
}
