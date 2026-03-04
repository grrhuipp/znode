const std = @import("std");
const codec = @import("codec.zig");

pub const UserInfo = struct {
    user_id: i64,
    email: []const u8,
    password_hash: []const u8, // 56-char hex
    speed_limit_bytes: u64,
};

/// Trojan user manager — HashMap<password_hash, UserInfo> for O(1) lookup.
pub const UserManager = struct {
    /// hash → UserInfo
    users: std.StringHashMap(UserInfo),

    pub fn init(allocator: std.mem.Allocator) UserManager {
        return .{
            .users = std.StringHashMap(UserInfo).init(allocator),
        };
    }

    pub fn deinit(self: *UserManager) void {
        self.users.deinit();
    }

    /// Add a user by plaintext password (hashes it internally).
    pub fn addUser(
        self: *UserManager,
        allocator: std.mem.Allocator,
        password: []const u8,
        user_id: i64,
        email: []const u8,
        speed_limit_bytes: u64,
    ) !void {
        const hash = try codec.hashPasswordAlloc(allocator, password);
        try self.users.put(hash, .{
            .user_id = user_id,
            .email = email,
            .password_hash = hash,
            .speed_limit_bytes = speed_limit_bytes,
        });
    }

    /// Add a user with pre-computed hash.
    pub fn addUserWithHash(
        self: *UserManager,
        hash: []const u8,
        user_id: i64,
        email: []const u8,
        speed_limit_bytes: u64,
    ) !void {
        try self.users.put(hash, .{
            .user_id = user_id,
            .email = email,
            .password_hash = hash,
            .speed_limit_bytes = speed_limit_bytes,
        });
    }

    /// Validate a 56-byte hex hash. Returns UserInfo if found.
    pub fn validate(self: *const UserManager, auth_hash: []const u8) ?UserInfo {
        // Try exact match first (lowercase)
        if (self.users.get(auth_hash)) |info| return info;

        // Fallback: iterate for case-insensitive match
        var iter = self.users.iterator();
        while (iter.next()) |entry| {
            if (constantTimeEq(auth_hash, entry.key_ptr.*)) {
                return entry.value_ptr.*;
            }
        }
        return null;
    }

    /// Convert user list to a slice of codec.User for parseRequest().
    pub fn toCodecUsers(self: *const UserManager, allocator: std.mem.Allocator) ![]const codec.User {
        var list = std.ArrayList(codec.User).init(allocator);
        var iter = self.users.iterator();
        while (iter.next()) |entry| {
            const info = entry.value_ptr.*;
            try list.append(.{
                .user_id = info.user_id,
                .email = info.email,
                .password_hash = info.password_hash,
                .speed_limit_bytes = info.speed_limit_bytes,
            });
        }
        return try list.toOwnedSlice();
    }

    /// Replace all users (panel sync).
    pub fn replaceUsers(
        self: *UserManager,
        allocator: std.mem.Allocator,
        new_users: []const UserInfo,
    ) !void {
        self.users.clearRetainingCapacity();
        for (new_users) |user| {
            const hash = try allocator.dupe(u8, user.password_hash);
            try self.users.put(hash, .{
                .user_id = user.user_id,
                .email = user.email,
                .password_hash = hash,
                .speed_limit_bytes = user.speed_limit_bytes,
            });
        }
    }

    pub fn count(self: *const UserManager) usize {
        return self.users.count();
    }
};

fn constantTimeEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |ca, cb| {
        diff |= std.ascii.toLower(ca) ^ std.ascii.toLower(cb);
    }
    return diff == 0;
}
