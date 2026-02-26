const std = @import("std");
const vmess_crypto = @import("../protocol/vmess/vmess_crypto.zig");

/// Read-Copy-Update (RCU) shared user store with 2-generation deferred free.
/// Readers access data lock-free via atomic pointer load.
/// Writers create a new copy, atomically swap the pointer, and free the
/// generation before last (guaranteeing all readers have moved on).
///
/// Safety invariant: update() is called from a single writer (panel sync thread).
/// Readers (Worker threads) only call getUsers() + read the returned map.
/// The previous generation is kept alive until the *next* update(), by which
/// point all readers have observed at least the current generation.
pub const UserStore = struct {
    current: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    /// Previous generation — freed on the *next* update, not immediately.
    prev: usize = 0,
    allocator: std.mem.Allocator,

    pub const UserInfo = struct {
        id: i64 = -1,
        email: [128]u8 = [_]u8{0} ** 128,
        email_len: u8 = 0,
        uuid: [16]u8 = [_]u8{0} ** 16,
        password_hash: [56]u8 = [_]u8{0} ** 56, // SHA224 hex for Trojan
        rate_limit: u64 = 0, // bytes/sec, 0 = unlimited
        enabled: bool = true,
        device_limit: u32 = 0, // 0 = unlimited
        // Pre-cached VMess keys (deterministic from uuid, computed in UserStore.update)
        cached_cmd_key: [16]u8 = [_]u8{0} ** 16,
        cached_auth_key: [16]u8 = [_]u8{0} ** 16,

        pub fn getEmail(self: *const UserInfo) []const u8 {
            return self.email[0..self.email_len];
        }

        pub fn setEmail(self: *UserInfo, em: []const u8) void {
            const len = @min(em.len, self.email.len);
            @memcpy(self.email[0..len], em[0..len]);
            self.email_len = @intCast(len);
        }
    };

    pub const UserMap = struct {
        users: []UserInfo,
        allocator: std.mem.Allocator,
        // O(1) lookup indexes (built in UserStore.update)
        password_hash_index: std.AutoHashMapUnmanaged([56]u8, u32) = .{},
        id_index: std.AutoHashMapUnmanaged(i64, u32) = .{},

        pub fn init(allocator: std.mem.Allocator) UserMap {
            return .{ .users = &.{}, .allocator = allocator };
        }

        pub fn deinit(self: *UserMap) void {
            self.password_hash_index.deinit(self.allocator);
            self.id_index.deinit(self.allocator);
            if (self.users.len > 0) {
                self.allocator.free(self.users);
            }
        }

        /// Build O(1) lookup indexes from users array.
        /// Called once during UserStore.update() after copying users.
        pub fn buildIndexes(self: *UserMap) void {
            self.password_hash_index.ensureTotalCapacity(self.allocator, @intCast(self.users.len)) catch return;
            self.id_index.ensureTotalCapacity(self.allocator, @intCast(self.users.len)) catch return;

            const zero_hash: [56]u8 = [_]u8{0} ** 56;
            for (self.users, 0..) |*user, i| {
                const idx: u32 = @intCast(i);
                if (!std.mem.eql(u8, &user.password_hash, &zero_hash)) {
                    self.password_hash_index.putAssumeCapacity(user.password_hash, idx);
                }
                if (user.id >= 0) {
                    self.id_index.putAssumeCapacity(user.id, idx);
                }
            }
        }

        pub fn findByUuid(self: *const UserMap, uuid: [16]u8) ?*const UserInfo {
            for (self.users) |*user| {
                if (std.mem.eql(u8, &user.uuid, &uuid)) return user;
            }
            return null;
        }

        pub fn findByPasswordHash(self: *const UserMap, hash: []const u8) ?*const UserInfo {
            if (hash.len != 56) return null;
            const idx = self.password_hash_index.get(hash[0..56].*) orelse return null;
            return &self.users[idx];
        }

        pub fn findById(self: *const UserMap, id: i64) ?*const UserInfo {
            const idx = self.id_index.get(id) orelse return null;
            return &self.users[idx];
        }
    };

    pub fn init(allocator: std.mem.Allocator) UserStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *UserStore) void {
        // Free previous generation
        self.freeMaybeMap(self.prev);
        // Free current generation
        self.freeMaybeMap(self.current.load(.acquire));
    }

    /// Lock-free read: atomically load the current user map pointer.
    pub fn getUsers(self: *const UserStore) ?*const UserMap {
        const ptr_val = self.current.load(.acquire);
        if (ptr_val == 0) return null;
        return @ptrFromInt(ptr_val);
    }

    /// Update users: create new map, atomically swap the pointer.
    /// The generation before last (prev) is freed here, guaranteeing
    /// all readers have moved past it by now.
    pub fn update(self: *UserStore, new_users: []const UserInfo) !void {
        const new_map = try self.allocator.create(UserMap);
        new_map.* = UserMap.init(self.allocator);

        if (new_users.len > 0) {
            new_map.users = try self.allocator.alloc(UserInfo, new_users.len);
            @memcpy(new_map.users, new_users);

            // Pre-cache VMess CmdKey/AuthKey (deterministic from UUID)
            for (new_map.users) |*user| {
                user.cached_cmd_key = vmess_crypto.deriveCmdKey(user.uuid);
                user.cached_auth_key = vmess_crypto.deriveAuthKey(user.cached_cmd_key);
            }
        }

        // Build O(1) lookup indexes
        new_map.buildIndexes();

        const new_ptr: usize = @intFromPtr(new_map);
        const old_ptr = self.current.swap(new_ptr, .acq_rel);

        // Free the generation *before* old (2 generations back).
        // `old` is kept alive as `prev` until the next update().
        self.freeMaybeMap(self.prev);
        self.prev = old_ptr;
    }

    /// Get the number of registered users.
    pub fn count(self: *const UserStore) usize {
        const map = self.getUsers() orelse return 0;
        return map.users.len;
    }

    fn freeMaybeMap(self: *UserStore, ptr_val: usize) void {
        if (ptr_val != 0) {
            const map: *UserMap = @ptrFromInt(ptr_val);
            map.deinit();
            self.allocator.destroy(map);
        }
    }
};

test "UserStore basic operations" {
    const allocator = std.testing.allocator;
    var store = UserStore.init(allocator);
    defer store.deinit();

    try std.testing.expectEqual(@as(usize, 0), store.count());

    // Add users
    var users = [_]UserStore.UserInfo{
        .{ .id = 1 },
        .{ .id = 2 },
    };
    users[0].setEmail("user1@test.com");
    users[1].setEmail("user2@test.com");

    try store.update(&users);
    try std.testing.expectEqual(@as(usize, 2), store.count());

    // Look up user
    const map = store.getUsers().?;
    const user1 = map.findById(1).?;
    try std.testing.expectEqualStrings("user1@test.com", user1.getEmail());
}

test "UserStore update preserves previous generation" {
    const allocator = std.testing.allocator;
    var store = UserStore.init(allocator);
    defer store.deinit();

    // Gen 1
    var users1 = [_]UserStore.UserInfo{.{ .id = 1 }};
    try store.update(&users1);
    try std.testing.expectEqual(@as(usize, 1), store.count());

    // Gen 2 — gen 1 kept alive as prev
    var users2 = [_]UserStore.UserInfo{ .{ .id = 2 }, .{ .id = 3 } };
    try store.update(&users2);
    try std.testing.expectEqual(@as(usize, 2), store.count());

    // Gen 3 — gen 1 freed, gen 2 becomes prev
    var users3 = [_]UserStore.UserInfo{.{ .id = 4 }};
    try store.update(&users3);
    try std.testing.expectEqual(@as(usize, 1), store.count());

    const map = store.getUsers().?;
    const user = map.findById(4).?;
    try std.testing.expectEqual(@as(i64, 4), user.id);
}

test "UserStore update pre-caches VMess keys" {
    const allocator = std.testing.allocator;
    var store = UserStore.init(allocator);
    defer store.deinit();

    const uuid = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01 };
    var users = [_]UserStore.UserInfo{.{ .id = 1, .uuid = uuid }};
    try store.update(&users);

    const map = store.getUsers().?;
    const found = map.findById(1).?;
    const expected_cmd = vmess_crypto.deriveCmdKey(uuid);
    const expected_auth = vmess_crypto.deriveAuthKey(expected_cmd);
    try std.testing.expectEqual(expected_cmd, found.cached_cmd_key);
    try std.testing.expectEqual(expected_auth, found.cached_auth_key);
}

test "UserMap password_hash_index O(1) lookup" {
    const allocator = std.testing.allocator;
    var store = UserStore.init(allocator);
    defer store.deinit();

    var users = [_]UserStore.UserInfo{
        .{ .id = 1, .password_hash = [_]u8{'a'} ** 56 },
        .{ .id = 2, .password_hash = [_]u8{'b'} ** 56 },
    };
    try store.update(&users);

    const map = store.getUsers().?;
    const user_a = map.findByPasswordHash(&([_]u8{'a'} ** 56)).?;
    try std.testing.expectEqual(@as(i64, 1), user_a.id);
    const user_b = map.findByPasswordHash(&([_]u8{'b'} ** 56)).?;
    try std.testing.expectEqual(@as(i64, 2), user_b.id);
    try std.testing.expect(map.findByPasswordHash(&([_]u8{'c'} ** 56)) == null);
}

test "UserMap id_index O(1) lookup" {
    const allocator = std.testing.allocator;
    var store = UserStore.init(allocator);
    defer store.deinit();

    var users = [_]UserStore.UserInfo{
        .{ .id = 100 },
        .{ .id = 200 },
    };
    try store.update(&users);

    const map = store.getUsers().?;
    try std.testing.expectEqual(@as(i64, 100), map.findById(100).?.id);
    try std.testing.expectEqual(@as(i64, 200), map.findById(200).?.id);
    try std.testing.expect(map.findById(999) == null);
}
