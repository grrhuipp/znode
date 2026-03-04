/// VMess user manager — UUID-based users with AuthID brute-force decryption.
///
/// Key derivation per user:
///   uuid_bytes = parseUUID(uuid_string)
///   cmd_key = MD5(uuid_bytes || vmess_magic)
///   auth_key = KDF16(cmd_key, ["AES Auth ID Encryption"])
///
/// AuthID authentication:
///   AES-128-ECB decrypt AuthID with each user's auth_key
///   Validate timestamp (±60s) and CRC32 checksum
const std = @import("std");
const crypto = @import("crypto.zig");
const hash_mod = @import("../../infra/crypto/hash.zig");

pub const VMessUser = struct {
    user_id: i64,
    email: []const u8,
    speed_limit_bytes: u64,
    uuid_bytes: [16]u8,
    cmd_key: [16]u8,
    auth_key: [16]u8,
};

pub const AuthResult = struct {
    user: *const VMessUser,
    timestamp: i64,
};

pub const UserManager = struct {
    users: []const VMessUser,

    pub fn init(users: []const VMessUser) UserManager {
        return .{ .users = users };
    }

    /// Create a VMessUser from UUID string.
    pub fn createUser(
        uuid_str: []const u8,
        user_id: i64,
        email: []const u8,
        speed_limit_bytes: u64,
    ) !VMessUser {
        const uuid_bytes = crypto.parseUuid(uuid_str) orelse
            return error.InvalidUuid;

        const cmd_key = try crypto.deriveCmdKey(&uuid_bytes);
        const auth_key = try crypto.deriveAuthKey(&cmd_key);

        return .{
            .user_id = user_id,
            .email = email,
            .speed_limit_bytes = speed_limit_bytes,
            .uuid_bytes = uuid_bytes,
            .cmd_key = cmd_key,
            .auth_key = auth_key,
        };
    }

    /// Authenticate by brute-force decrypting AuthID with each user's auth_key.
    pub fn authenticate(self: *const UserManager, auth_id: *const [16]u8) ?AuthResult {
        const now = std.time.timestamp();
        for (self.users) |*user| {
            if (crypto.tryDecryptAuthId(&user.auth_key, auth_id, now)) |timestamp| {
                return .{
                    .user = user,
                    .timestamp = timestamp,
                };
            }
        }
        return null;
    }

    /// Replace users (for panel sync).
    pub fn replaceUsers(self: *UserManager, new_users: []const VMessUser) void {
        self.users = new_users;
    }
};
