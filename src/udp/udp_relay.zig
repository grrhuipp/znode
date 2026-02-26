const std = @import("std");
const xev = @import("xev");
const Session = @import("../core/session.zig");
const TargetAddress = Session.TargetAddress;
const udp_session = @import("udp_session.zig");
const UdpSessionTable = udp_session.UdpSessionTable;
/// Maximum UDP datagram size (standard MTU safe).
pub const MAX_UDP_PAYLOAD: usize = 1500;

/// UDP receive buffer size (larger for reassembly margin).
pub const RECV_BUF_SIZE: usize = 2048;

/// Full Cone NAT UDP relay.
///
/// Manages a single outbound UDP socket that can send to any destination
/// and receive from any source (Full Cone behavior). Each relay is
/// associated with a single TCP proxy connection.
///
/// Lifecycle:
///   1. init() - create and bind UDP socket
///   2. sendTo() - forward datagrams to targets
///   3. startRecv() - begin async receive loop
///   4. deinit() - close socket and clean up
///
/// The relay's lifecycle is managed by the owning Session's FSM.
pub const UdpRelay = struct {
    /// Outbound UDP socket.
    udp: xev.UDP,

    /// xev async state for read operations.
    read_state: xev.UDP.State,

    /// xev async state for write operations.
    write_state: xev.UDP.State,

    /// Completion token for pending read.
    read_completion: xev.Completion,

    /// Completion token for pending write.
    write_completion: xev.Completion,

    /// Receive buffer for incoming datagrams.
    recv_buf: [RECV_BUF_SIZE]u8,

    /// Associated connection ID (for session lookup).
    conn_id: u64,

    /// Session table (shared, not owned).
    session_table: ?*UdpSessionTable,

    /// Whether the relay has been closed.
    closed: bool,

    /// Packets forwarded (outbound).
    packets_out: u64,

    /// Packets received (inbound responses).
    packets_in: u64,

    /// Bytes forwarded (outbound).
    bytes_out: u64,

    /// Bytes received (inbound responses).
    bytes_in: u64,

    /// Initialize a UDP relay bound to a wildcard address.
    /// Uses port 0 for OS-assigned ephemeral port.
    pub fn init(conn_id: u64) !UdpRelay {
        const bind_addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);
        const udp_sock = try xev.UDP.init(bind_addr);

        return UdpRelay{
            .udp = udp_sock,
            .read_state = undefined,
            .write_state = undefined,
            .read_completion = .{},
            .write_completion = .{},
            .recv_buf = undefined,
            .conn_id = conn_id,
            .session_table = null,
            .closed = false,
            .packets_out = 0,
            .packets_in = 0,
            .bytes_out = 0,
            .bytes_in = 0,
        };
    }

    /// Clean up the relay. Closes the UDP socket if not already closed.
    pub fn deinit(self: *UdpRelay) void {
        if (!self.closed) {
            self.closed = true;
            // In actual usage, close would be async via xev.
            // For cleanup, we do a synchronous fd close.
            const fd = self.udp.fd;
            std.posix.close(fd);
        }
    }

    /// Bind the UDP socket (call after init, before send/recv).
    pub fn bind(self: *UdpRelay) !void {
        const bind_addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);
        try self.udp.bind(bind_addr);
    }

    /// Record an outbound packet in stats.
    pub fn recordSent(self: *UdpRelay, bytes: usize) void {
        self.packets_out += 1;
        self.bytes_out += bytes;
    }

    /// Record an inbound packet in stats.
    pub fn recordRecv(self: *UdpRelay, bytes: usize) void {
        self.packets_in += 1;
        self.bytes_in += bytes;
    }

    /// Check if the relay is still active.
    pub fn isActive(self: *const UdpRelay) bool {
        return !self.closed;
    }

    /// Get stats summary.
    pub fn getStats(self: *const UdpRelay) RelayStats {
        return .{
            .conn_id = self.conn_id,
            .packets_out = self.packets_out,
            .packets_in = self.packets_in,
            .bytes_out = self.bytes_out,
            .bytes_in = self.bytes_in,
        };
    }

    /// Convert a TargetAddress to std.net.Address for xev.UDP.write.
    /// Returns null for domain targets (must be resolved first).
    pub fn targetToNetAddress(target: *const TargetAddress) ?std.net.Address {
        return switch (target.addr_type) {
            .ipv4 => std.net.Address.initIp4(target.ip4, target.port),
            .ipv6 => std.net.Address.initIp6(target.ip6, target.port, 0, 0),
            .domain, .none => null, // Domain needs DNS resolution first
        };
    }
};

/// Stats snapshot for a relay instance.
pub const RelayStats = struct {
    conn_id: u64,
    packets_out: u64,
    packets_in: u64,
    bytes_out: u64,
    bytes_in: u64,

    pub fn totalPackets(self: *const RelayStats) u64 {
        return self.packets_out + self.packets_in;
    }

    pub fn totalBytes(self: *const RelayStats) u64 {
        return self.bytes_out + self.bytes_in;
    }
};

// ── Tests ──

const testing = std.testing;

test "UdpRelay struct size" {
    // Verify the struct is reasonably sized (stack-allocatable)
    const size = @sizeOf(UdpRelay);
    try testing.expect(size < 4096); // Should fit comfortably on stack
    try testing.expect(size >= RECV_BUF_SIZE); // At minimum contains recv buffer
}

test "UdpRelay initial state" {
    // Test that we can construct the struct with default values
    // (without actually creating a socket)
    var relay = UdpRelay{
        .udp = undefined,
        .read_state = undefined,
        .write_state = undefined,
        .read_completion = .{},
        .write_completion = .{},
        .recv_buf = undefined,
        .conn_id = 42,
        .session_table = null,
        .closed = false,
        .packets_out = 0,
        .packets_in = 0,
        .bytes_out = 0,
        .bytes_in = 0,
    };

    try testing.expect(relay.isActive());
    try testing.expectEqual(@as(u64, 42), relay.conn_id);
    try testing.expectEqual(@as(u64, 0), relay.packets_out);
    try testing.expectEqual(@as(u64, 0), relay.bytes_out);

    relay.closed = true;
    try testing.expect(!relay.isActive());
}

test "UdpRelay stats tracking" {
    var relay = UdpRelay{
        .udp = undefined,
        .read_state = undefined,
        .write_state = undefined,
        .read_completion = .{},
        .write_completion = .{},
        .recv_buf = undefined,
        .conn_id = 1,
        .session_table = null,
        .closed = false,
        .packets_out = 0,
        .packets_in = 0,
        .bytes_out = 0,
        .bytes_in = 0,
    };

    relay.recordSent(100);
    relay.recordSent(200);
    relay.recordRecv(50);

    try testing.expectEqual(@as(u64, 2), relay.packets_out);
    try testing.expectEqual(@as(u64, 300), relay.bytes_out);
    try testing.expectEqual(@as(u64, 1), relay.packets_in);
    try testing.expectEqual(@as(u64, 50), relay.bytes_in);

    const stats = relay.getStats();
    try testing.expectEqual(@as(u64, 3), stats.totalPackets());
    try testing.expectEqual(@as(u64, 350), stats.totalBytes());
}

test "RelayStats" {
    const stats = RelayStats{
        .conn_id = 10,
        .packets_out = 100,
        .packets_in = 50,
        .bytes_out = 10000,
        .bytes_in = 5000,
    };
    try testing.expectEqual(@as(u64, 150), stats.totalPackets());
    try testing.expectEqual(@as(u64, 15000), stats.totalBytes());
}

test "targetToNetAddress IPv4" {
    var target = TargetAddress{};
    target.setIpv4(.{ 8, 8, 8, 8 }, 53);
    const addr = UdpRelay.targetToNetAddress(&target).?;
    try testing.expectEqual(@as(u16, 53), addr.getPort());
}

test "targetToNetAddress IPv6" {
    var target = TargetAddress{};
    var ip6: [16]u8 = [_]u8{0} ** 16;
    ip6[15] = 1; // ::1
    target.setIpv6(ip6, 8080);
    const addr = UdpRelay.targetToNetAddress(&target).?;
    try testing.expectEqual(@as(u16, 8080), addr.getPort());
}

test "targetToNetAddress domain returns null" {
    var target = TargetAddress{};
    target.setDomain("example.com", 443);
    try testing.expect(UdpRelay.targetToNetAddress(&target) == null);
}

test "targetToNetAddress none returns null" {
    const target = TargetAddress{};
    try testing.expect(UdpRelay.targetToNetAddress(&target) == null);
}

