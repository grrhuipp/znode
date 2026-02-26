const std = @import("std");
const Session = @import("../core/session.zig");
const TargetAddress = Session.TargetAddress;

/// Maximum number of concurrent UDP sessions.
pub const MAX_SESSIONS: usize = 4096;

/// Session timeout in microseconds (120 seconds).
pub const SESSION_TIMEOUT_US: i64 = 120 * std.time.us_per_s;

/// A single UDP session tracking a (connection, target) mapping.
pub const UdpSession = struct {
    active: bool = false,
    conn_id: u64 = 0,
    target: TargetAddress = .{},
    created_us: i64 = 0,
    last_active_us: i64 = 0,
    packets_sent: u64 = 0,
    packets_recv: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_recv: u64 = 0,

    /// Touch the session to refresh its last-active timestamp.
    pub fn touch(self: *UdpSession, now_us: i64) void {
        self.last_active_us = now_us;
    }

    /// Record a sent packet.
    pub fn recordSent(self: *UdpSession, bytes: usize) void {
        self.packets_sent += 1;
        self.bytes_sent += bytes;
    }

    /// Record a received packet.
    pub fn recordRecv(self: *UdpSession, bytes: usize) void {
        self.packets_recv += 1;
        self.bytes_recv += bytes;
    }

    /// Check if the session has expired relative to the given time.
    pub fn isExpired(self: *const UdpSession, now_us: i64, timeout_us: i64) bool {
        if (!self.active) return true;
        const elapsed = now_us - self.last_active_us;
        return elapsed > timeout_us;
    }
};

/// Fixed-size UDP session table. No heap allocation.
///
/// Sessions are identified by (conn_id, target) pair.
/// Uses linear scan - efficient for <4096 entries with cache-friendly access.
pub const UdpSessionTable = struct {
    sessions: [MAX_SESSIONS]UdpSession = [_]UdpSession{.{}} ** MAX_SESSIONS,
    count: u32 = 0,

    /// Find an existing session matching (conn_id, target).
    pub fn find(self: *UdpSessionTable, conn_id: u64, target: *const TargetAddress) ?*UdpSession {
        for (&self.sessions) |*s| {
            if (s.active and s.conn_id == conn_id and addressMatch(&s.target, target)) {
                return s;
            }
        }
        return null;
    }

    /// Find an existing session or create a new one.
    /// Returns null if the table is full.
    pub fn findOrCreate(self: *UdpSessionTable, conn_id: u64, target: *const TargetAddress, now_us: i64) ?*UdpSession {
        // Try to find existing
        if (self.find(conn_id, target)) |existing| {
            existing.touch(now_us);
            return existing;
        }

        // Find a free slot
        for (&self.sessions) |*s| {
            if (!s.active) {
                s.* = .{
                    .active = true,
                    .conn_id = conn_id,
                    .target = target.*,
                    .created_us = now_us,
                    .last_active_us = now_us,
                };
                self.count += 1;
                return s;
            }
        }

        return null; // Table full
    }

    /// Remove all sessions for a given connection ID.
    /// Returns number of sessions removed.
    pub fn removeByConnId(self: *UdpSessionTable, conn_id: u64) u32 {
        var removed: u32 = 0;
        for (&self.sessions) |*s| {
            if (s.active and s.conn_id == conn_id) {
                s.active = false;
                removed += 1;
            }
        }
        self.count -|= removed;
        return removed;
    }

    /// Expire sessions that have been inactive for longer than timeout_us.
    /// Returns number of sessions expired.
    pub fn expireOld(self: *UdpSessionTable, now_us: i64, timeout_us: i64) u32 {
        var expired: u32 = 0;
        for (&self.sessions) |*s| {
            if (s.active and s.isExpired(now_us, timeout_us)) {
                s.active = false;
                expired += 1;
            }
        }
        self.count -|= expired;
        return expired;
    }

    /// Get the number of active sessions.
    pub fn getCount(self: *const UdpSessionTable) u32 {
        return self.count;
    }

    /// Get total bytes sent across all active sessions.
    pub fn totalBytesSent(self: *const UdpSessionTable) u64 {
        var total: u64 = 0;
        for (&self.sessions) |*s| {
            if (s.active) total += s.bytes_sent;
        }
        return total;
    }

    /// Get total bytes received across all active sessions.
    pub fn totalBytesRecv(self: *const UdpSessionTable) u64 {
        var total: u64 = 0;
        for (&self.sessions) |*s| {
            if (s.active) total += s.bytes_recv;
        }
        return total;
    }
};

/// Compare two TargetAddresses for equality (type + address + port).
fn addressMatch(a: *const TargetAddress, b: *const TargetAddress) bool {
    if (a.addr_type != b.addr_type or a.port != b.port) return false;
    return switch (a.addr_type) {
        .ipv4 => std.mem.eql(u8, &a.ip4, &b.ip4),
        .ipv6 => std.mem.eql(u8, &a.ip6, &b.ip6),
        .domain => {
            if (a.domain_len != b.domain_len) return false;
            return std.mem.eql(u8, a.domain[0..a.domain_len], b.domain[0..b.domain_len]);
        },
        .none => true,
    };
}

// ── Tests ──

const testing = std.testing;

test "UdpSession touch and expire" {
    var s = UdpSession{
        .active = true,
        .conn_id = 1,
        .last_active_us = 1000,
    };
    try testing.expect(!s.isExpired(1000 + SESSION_TIMEOUT_US - 1, SESSION_TIMEOUT_US));
    try testing.expect(s.isExpired(1000 + SESSION_TIMEOUT_US + 1, SESSION_TIMEOUT_US));

    s.touch(2000);
    try testing.expectEqual(@as(i64, 2000), s.last_active_us);
}

test "UdpSession record stats" {
    var s = UdpSession{ .active = true };
    s.recordSent(100);
    s.recordSent(200);
    s.recordRecv(50);
    try testing.expectEqual(@as(u64, 2), s.packets_sent);
    try testing.expectEqual(@as(u64, 300), s.bytes_sent);
    try testing.expectEqual(@as(u64, 1), s.packets_recv);
    try testing.expectEqual(@as(u64, 50), s.bytes_recv);
}

test "UdpSessionTable findOrCreate and find" {
    var table = UdpSessionTable{};
    var target = TargetAddress{};
    target.setIpv4(.{ 8, 8, 8, 8 }, 53);

    const now: i64 = 1000000;

    // Create a new session
    const s1 = table.findOrCreate(1, &target, now).?;
    try testing.expect(s1.active);
    try testing.expectEqual(@as(u64, 1), s1.conn_id);
    try testing.expectEqual(@as(u32, 1), table.getCount());

    // Find the same session
    const s2 = table.findOrCreate(1, &target, now + 100).?;
    try testing.expect(s1 == s2); // Same pointer
    try testing.expectEqual(@as(u32, 1), table.getCount());

    // Create a different session (different target)
    var target2 = TargetAddress{};
    target2.setIpv4(.{ 1, 1, 1, 1 }, 53);
    const s3 = table.findOrCreate(1, &target2, now).?;
    try testing.expect(s3 != s1);
    try testing.expectEqual(@as(u32, 2), table.getCount());

    // Create session for different connection
    const s4 = table.findOrCreate(2, &target, now).?;
    try testing.expect(s4 != s1);
    try testing.expectEqual(@as(u32, 3), table.getCount());
}

test "UdpSessionTable find returns null for missing" {
    var table = UdpSessionTable{};
    var target = TargetAddress{};
    target.setIpv4(.{ 8, 8, 8, 8 }, 53);
    try testing.expect(table.find(1, &target) == null);
}

test "UdpSessionTable removeByConnId" {
    var table = UdpSessionTable{};
    const now: i64 = 1000000;

    var t1 = TargetAddress{};
    t1.setIpv4(.{ 8, 8, 8, 8 }, 53);
    var t2 = TargetAddress{};
    t2.setIpv4(.{ 1, 1, 1, 1 }, 53);

    // Create 3 sessions: 2 for conn 1, 1 for conn 2
    _ = table.findOrCreate(1, &t1, now);
    _ = table.findOrCreate(1, &t2, now);
    _ = table.findOrCreate(2, &t1, now);
    try testing.expectEqual(@as(u32, 3), table.getCount());

    // Remove all for conn 1
    const removed = table.removeByConnId(1);
    try testing.expectEqual(@as(u32, 2), removed);
    try testing.expectEqual(@as(u32, 1), table.getCount());

    // Conn 2's session still exists
    try testing.expect(table.find(2, &t1) != null);
    // Conn 1's sessions are gone
    try testing.expect(table.find(1, &t1) == null);
    try testing.expect(table.find(1, &t2) == null);
}

test "UdpSessionTable expireOld" {
    var table = UdpSessionTable{};
    var target = TargetAddress{};
    target.setIpv4(.{ 8, 8, 8, 8 }, 53);

    const base: i64 = 1000000;
    _ = table.findOrCreate(1, &target, base);
    _ = table.findOrCreate(2, &target, base + 60_000_000); // 60s later

    try testing.expectEqual(@as(u32, 2), table.getCount());

    // Expire at base + 130s. Session 1 (at base) should expire, session 2 (at base+60s) should not
    const expired = table.expireOld(base + 130_000_000, SESSION_TIMEOUT_US);
    try testing.expectEqual(@as(u32, 1), expired);
    try testing.expectEqual(@as(u32, 1), table.getCount());

    // Session 2 still exists
    try testing.expect(table.find(2, &target) != null);
    try testing.expect(table.find(1, &target) == null);
}

test "UdpSessionTable domain target" {
    var table = UdpSessionTable{};
    var target = TargetAddress{};
    target.setDomain("dns.google", 443);

    const s = table.findOrCreate(1, &target, 0).?;
    try testing.expectEqualStrings("dns.google", s.target.getDomain());

    // Find by same domain
    var target2 = TargetAddress{};
    target2.setDomain("dns.google", 443);
    try testing.expect(table.find(1, &target2) != null);

    // Different domain should not match
    var target3 = TargetAddress{};
    target3.setDomain("other.com", 443);
    try testing.expect(table.find(1, &target3) == null);
}

test "UdpSessionTable total stats" {
    var table = UdpSessionTable{};
    var t1 = TargetAddress{};
    t1.setIpv4(.{ 1, 2, 3, 4 }, 80);
    var t2 = TargetAddress{};
    t2.setIpv4(.{ 5, 6, 7, 8 }, 80);

    const s1 = table.findOrCreate(1, &t1, 0).?;
    s1.recordSent(100);
    s1.recordRecv(200);

    const s2 = table.findOrCreate(2, &t2, 0).?;
    s2.recordSent(300);
    s2.recordRecv(400);

    try testing.expectEqual(@as(u64, 400), table.totalBytesSent());
    try testing.expectEqual(@as(u64, 600), table.totalBytesRecv());
}

test "addressMatch" {
    var a = TargetAddress{};
    a.setIpv4(.{ 1, 2, 3, 4 }, 80);
    var b = TargetAddress{};
    b.setIpv4(.{ 1, 2, 3, 4 }, 80);
    try testing.expect(addressMatch(&a, &b));

    var c = TargetAddress{};
    c.setIpv4(.{ 1, 2, 3, 5 }, 80);
    try testing.expect(!addressMatch(&a, &c));

    var d = TargetAddress{};
    d.setIpv4(.{ 1, 2, 3, 4 }, 81);
    try testing.expect(!addressMatch(&a, &d));
}
