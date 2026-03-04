/// Shadowsocks user manager — salt trial authentication.
///
/// Unlike Trojan (hash lookup), SS uses trial decryption:
/// for each user, derive subkey from master_key + salt, attempt to decrypt
/// the first length chunk. If AEAD auth succeeds and length is valid → match.
const std = @import("std");
const protocol = @import("protocol.zig");
const aead_mod = @import("../../infra/crypto/aead.zig");

pub const UserInfo = struct {
    user_id: i64,
    email: []const u8,
    speed_limit_bytes: u64,
    cipher_info: protocol.CipherInfo,
    master_key: [protocol.max_key_len]u8,
    master_key_len: usize,
};

pub const AuthResult = struct {
    user: *const UserInfo,
    subkey: [protocol.max_key_len]u8,
    subkey_len: usize,
};

pub const UserManager = struct {
    users: []const UserInfo,

    pub fn init(users: []const UserInfo) UserManager {
        return .{ .users = users };
    }

    /// Try decrypting the first length chunk with each user's master key + salt.
    /// Returns the matched user and derived subkey on success.
    ///
    /// `salt`: the salt read from the stream (cipher.salt_len bytes)
    /// `first_chunk`: the first encrypted length chunk (2 + 16 = 18 bytes)
    pub fn trialDecrypt(
        self: *const UserManager,
        salt: []const u8,
        first_chunk: []const u8,
    ) ?AuthResult {
        const len_chunk_size = 2 + protocol.tag_len;
        if (first_chunk.len < len_chunk_size) return null;

        for (self.users) |*user| {
            // Derive session subkey
            var subkey: [protocol.max_key_len]u8 = undefined;
            protocol.deriveSessionKey(
                user.master_key[0..user.master_key_len],
                salt,
                subkey[0..user.master_key_len],
            ) catch continue;

            // Try decrypting the length chunk
            var len_plain: [2]u8 = undefined;
            const nonce = aead_mod.ssNonce(0); // first nonce is always 0
            _ = aead_mod.decrypt(
                user.cipher_info.cipher_type,
                subkey[0..user.master_key_len],
                &nonce,
                first_chunk[0..len_chunk_size],
                &.{},
                &len_plain,
            ) catch continue; // AEAD auth failed → wrong key

            // Verify length is valid
            const payload_len = (@as(u16, len_plain[0]) << 8) | @as(u16, len_plain[1]);
            if (payload_len == 0 or payload_len > protocol.max_payload_size) continue;

            return .{
                .user = user,
                .subkey = subkey,
                .subkey_len = user.master_key_len,
            };
        }
        return null;
    }

    /// Replace all users (for panel sync). Caller owns the old slice.
    pub fn replaceUsers(self: *UserManager, new_users: []const UserInfo) void {
        self.users = new_users;
    }
};
