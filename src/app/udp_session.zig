/// UDP session manager — Full Cone NAT with session tracking.
///
/// Each UDP session owns a local UDP socket. Incoming replies are dispatched
/// back to the original client via callback.
const std = @import("std");
const types = @import("../common/types.zig");

pub const UdpPacket = struct {
    target: types.TargetAddress,
    payload: []const u8,
};

/// Reply callback: called when a UDP reply arrives from the remote target.
pub const ReplyCallback = *const fn (
    sender_ip: []const u8,
    sender_port: u16,
    payload: []const u8,
    user_ctx: *anyopaque,
) void;

/// A single UDP session with its own socket.
pub const UdpSession = struct {
    socket_fd: std.posix.socket_t,
    callback: ReplyCallback,
    user_ctx: *anyopaque,
    last_active: i64,
    sent_targets: std.StringHashMap(void),

    pub fn init(
        allocator: std.mem.Allocator,
        callback: ReplyCallback,
        user_ctx: *anyopaque,
    ) !UdpSession {
        const fd = try std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK,
            0,
        );
        errdefer std.posix.close(fd);

        // Bind to ephemeral port
        var addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);
        try std.posix.bind(fd, &addr.any, addr.getOsSockLen());

        return .{
            .socket_fd = fd,
            .callback = callback,
            .user_ctx = user_ctx,
            .last_active = std.time.timestamp(),
            .sent_targets = std.StringHashMap(void).init(allocator),
        };
    }

    pub fn deinit(self: *UdpSession) void {
        std.posix.close(self.socket_fd);
        self.sent_targets.deinit();
    }

    pub fn touch(self: *UdpSession) void {
        self.last_active = std.time.timestamp();
    }

    pub fn isExpired(self: *const UdpSession, now: i64, timeout: i64) bool {
        return now - self.last_active > timeout;
    }
};

/// Manages multiple UDP sessions keyed by client endpoint.
pub const UdpSessionManager = struct {
    allocator: std.mem.Allocator,
    sessions: std.StringHashMap(*UdpSession),
    session_timeout: i64,
    last_cleanup: i64,

    pub fn init(allocator: std.mem.Allocator, timeout: i64) UdpSessionManager {
        return .{
            .allocator = allocator,
            .sessions = std.StringHashMap(*UdpSession).init(allocator),
            .session_timeout = timeout,
            .last_cleanup = std.time.timestamp(),
        };
    }

    pub fn deinit(self: *UdpSessionManager) void {
        var iter = self.sessions.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.sessions.deinit();
    }

    /// Get or create a session for the given client key.
    pub fn getOrCreate(
        self: *UdpSessionManager,
        client_key: []const u8,
        callback: ReplyCallback,
        user_ctx: *anyopaque,
    ) !*UdpSession {
        // Lazy cleanup every 30 seconds
        const now = std.time.timestamp();
        if (now - self.last_cleanup > 30) {
            self.cleanup(now);
            self.last_cleanup = now;
        }

        if (self.sessions.get(client_key)) |session| {
            session.touch();
            return session;
        }

        const session = try self.allocator.create(UdpSession);
        session.* = try UdpSession.init(self.allocator, callback, user_ctx);
        const owned_key = try self.allocator.dupe(u8, client_key);
        try self.sessions.put(owned_key, session);
        return session;
    }

    fn cleanup(self: *UdpSessionManager, now: i64) void {
        var to_remove: [64][]const u8 = undefined;
        var remove_count: usize = 0;

        var iter = self.sessions.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.*.isExpired(now, self.session_timeout)) {
                if (remove_count < 64) {
                    to_remove[remove_count] = entry.key_ptr.*;
                    remove_count += 1;
                }
            }
        }

        for (to_remove[0..remove_count]) |key| {
            if (self.sessions.fetchRemove(key)) |kv| {
                kv.value.deinit();
                self.allocator.destroy(kv.value);
            }
        }
    }
};

/// Format client endpoint key: "ip:port"
pub fn makeClientKey(buf: []u8, ip: []const u8, port: u16) []const u8 {
    const n = std.fmt.bufPrint(buf, "{s}:{d}", .{ ip, port }) catch return "";
    return buf[0..n.len];
}
