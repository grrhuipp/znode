/// Trojan outbound — encode client handshake header.
///
/// After the header is sent over TLS, data flows transparently.
const std = @import("std");
const codec = @import("codec.zig");
const types = @import("../../common/types.zig");

pub const TrojanOutbound = struct {
    password_hash: [codec.hash_len]u8,

    pub fn init(password: []const u8) TrojanOutbound {
        var self = TrojanOutbound{ .password_hash = undefined };
        codec.hashPassword(password, &self.password_hash);
        return self;
    }

    /// Encode Trojan request header into buf. Returns bytes written or null if buf too small.
    pub fn encodeHandshake(
        self: *const TrojanOutbound,
        target: types.TargetAddress,
        command: codec.Command,
        buf: []u8,
    ) ?usize {
        return codec.encodeRequest(&self.password_hash, command, target, buf);
    }
};
