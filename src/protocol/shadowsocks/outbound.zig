/// Shadowsocks AEAD outbound — client-side salt + address encoding.
///
/// Flow: generate salt → derive subkey → encode [salt][AEAD(addr+data)] → wrap SsStream
const std = @import("std");
const protocol = @import("protocol.zig");
const types = @import("../../common/types.zig");
const aead_mod = @import("../../infra/crypto/aead.zig");
const rand_mod = @import("../../infra/crypto/rand.zig");

pub const SsOutbound = struct {
    cipher_info: protocol.CipherInfo,
    master_key: [protocol.max_key_len]u8,
    master_key_len: usize,

    pub fn init(password: []const u8, method: []const u8) ?SsOutbound {
        const info = protocol.CipherInfo.fromString(method) orelse return null;
        var self = SsOutbound{
            .cipher_info = info,
            .master_key = undefined,
            .master_key_len = info.key_len,
        };
        protocol.deriveMasterKey(password, info.key_len, &self.master_key) catch return null;
        return self;
    }

    /// Generate write salt and derive write subkey for outbound direction.
    /// Returns the salt (to be sent as first bytes) and subkey (for SsStream).
    pub fn generateWriteKeys(
        self: *const SsOutbound,
    ) !WriteKeys {
        var result = WriteKeys{
            .salt = undefined,
            .salt_len = self.cipher_info.salt_len,
            .subkey = undefined,
            .subkey_len = self.cipher_info.key_len,
        };

        try protocol.generateSalt(result.salt[0..self.cipher_info.salt_len]);
        try protocol.deriveSessionKey(
            self.master_key[0..self.master_key_len],
            result.salt[0..self.cipher_info.salt_len],
            result.subkey[0..self.cipher_info.key_len],
        );
        return result;
    }

    /// Encode SOCKS5 address for the target (used as first plaintext in SS stream).
    pub fn encodeAddress(target: types.TargetAddress, buf: []u8) ?usize {
        return protocol.encodeAddress(target, buf);
    }
};

pub const WriteKeys = struct {
    salt: [protocol.max_salt_len]u8,
    salt_len: usize,
    subkey: [protocol.max_key_len]u8,
    subkey_len: usize,
};
