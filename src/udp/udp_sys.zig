const std = @import("std");
const builtin = @import("builtin");

/// Platform-specific raw UDP socket operations (dual-stack: IPv4 + IPv6).
pub const UdpSys = if (builtin.os.tag == .windows) struct {
    pub const INVALID_SOCKET: usize = ~@as(usize, 0);
    const SOCKET_ERROR: c_int = -1;
    const AF_INET: c_int = 2;
    const AF_INET6: c_int = 23;
    const SOCK_DGRAM: c_int = 2;
    const SOL_SOCKET: c_int = 0xFFFF;
    const SO_RCVTIMEO: c_int = 0x1006;
    const IPPROTO_IPV6: c_int = 41;
    const IPV6_V6ONLY: c_int = 27;

    extern "ws2_32" fn socket(af: c_int, sock_type: c_int, protocol: c_int) callconv(.winapi) usize;
    extern "ws2_32" fn bind(s: usize, name: [*]const u8, namelen: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn sendto(s: usize, buf_ptr: [*]const u8, len: c_int, flags: c_int, to: [*]const u8, tolen: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn recvfrom(s: usize, buf_ptr: [*]u8, len: c_int, flags: c_int, from: [*]u8, fromlen: *c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn closesocket(s: usize) callconv(.winapi) c_int;
    extern "ws2_32" fn setsockopt(s: usize, level: c_int, optname: c_int, optval: [*]const u8, optlen: c_int) callconv(.winapi) c_int;

    /// Create a dual-stack (IPv6 + IPv4 mapped) UDP socket.
    /// If bind_ip4 is provided, bind to that specific IPv4 address (for send_through).
    pub fn create(bind_ip4: ?[4]u8) ?usize {
        // Try IPv6 dual-stack first (handles both v4 and v6)
        const s6 = socket(AF_INET6, SOCK_DGRAM, 0);
        if (s6 != INVALID_SOCKET) {
            // Disable IPV6_V6ONLY to allow IPv4-mapped addresses
            const v6only: c_int = 0;
            _ = setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, @ptrCast(&v6only), @sizeOf(c_int));
            // Bind to [::]:0 or [::ffff:x.x.x.x]:0 for send_through
            var sa6: [28]u8 = std.mem.zeroes([28]u8);
            sa6[0] = AF_INET6; // sin6_family (little-endian on Windows)
            if (bind_ip4) |ip4| {
                // IPv4-mapped IPv6: ::ffff:x.x.x.x
                sa6[18] = 0xFF;
                sa6[19] = 0xFF;
                sa6[20] = ip4[0];
                sa6[21] = ip4[1];
                sa6[22] = ip4[2];
                sa6[23] = ip4[3];
            }
            if (bind(s6, &sa6, 28) == 0) {
                const timeout: c_int = 1000;
                _ = setsockopt(s6, SOL_SOCKET, SO_RCVTIMEO, @ptrCast(&timeout), @sizeOf(c_int));
                return s6;
            }
            _ = closesocket(s6);
        }

        // Fallback to IPv4-only
        const s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s == INVALID_SOCKET) return null;
        var sa: [16]u8 = std.mem.zeroes([16]u8);
        sa[0] = 2; // AF_INET
        if (bind_ip4) |ip4| {
            sa[4] = ip4[0];
            sa[5] = ip4[1];
            sa[6] = ip4[2];
            sa[7] = ip4[3];
        }
        if (bind(s, &sa, 16) != 0) {
            _ = closesocket(s);
            return null;
        }
        const timeout: c_int = 1000;
        _ = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, @ptrCast(&timeout), @sizeOf(c_int));
        return s;
    }

    pub fn close(s: usize) void {
        _ = closesocket(s);
    }

    pub fn send4(s: usize, data: []const u8, ip4: [4]u8, port: u16) bool {
        // Use IPv4-mapped IPv6 address (::ffff:x.x.x.x) on dual-stack socket
        var sa6: [28]u8 = std.mem.zeroes([28]u8);
        sa6[0] = AF_INET6; // sin6_family
        sa6[2] = @intCast(port >> 8); // sin6_port big-endian
        sa6[3] = @intCast(port & 0xFF);
        // IPv4-mapped: ::ffff:x.x.x.x at offset 8 (sin6_addr)
        sa6[18] = 0xFF;
        sa6[19] = 0xFF;
        @memcpy(sa6[20..24], &ip4);
        const r = sendto(s, data.ptr, @intCast(data.len), 0, &sa6, 28);
        if (r != SOCKET_ERROR) return true;
        // Fallback: try as plain IPv4 sockaddr_in (if socket is v4-only)
        var sa4: [16]u8 = std.mem.zeroes([16]u8);
        sa4[0] = 2; // AF_INET
        sa4[2] = @intCast(port >> 8);
        sa4[3] = @intCast(port & 0xFF);
        @memcpy(sa4[4..8], &ip4);
        return sendto(s, data.ptr, @intCast(data.len), 0, &sa4, 16) != SOCKET_ERROR;
    }

    pub fn send6(s: usize, data: []const u8, ip6: [16]u8, port: u16) bool {
        var sa6: [28]u8 = std.mem.zeroes([28]u8);
        sa6[0] = AF_INET6; // sin6_family
        sa6[2] = @intCast(port >> 8); // sin6_port big-endian
        sa6[3] = @intCast(port & 0xFF);
        @memcpy(sa6[8..24], &ip6); // sin6_addr at offset 8
        const r = sendto(s, data.ptr, @intCast(data.len), 0, &sa6, 28);
        return r != SOCKET_ERROR;
    }

    pub const RecvResult = struct {
        len: usize,
        ip4: ?[4]u8 = null,
        ip6: ?[16]u8 = null,
        port: u16 = 0,
    };

    pub fn recv(s: usize, buf: []u8) ?RecvResult {
        var sa: [28]u8 = std.mem.zeroes([28]u8);
        var sa_len: c_int = 28;
        const r = recvfrom(s, buf.ptr, @intCast(buf.len), 0, &sa, &sa_len);
        if (r == SOCKET_ERROR or r <= 0) return null;
        const family = sa[0];
        if (family == AF_INET6) {
            // Check if it's an IPv4-mapped address (::ffff:x.x.x.x)
            const addr = sa[8..24];
            if (std.mem.eql(u8, addr[0..10], &([_]u8{0} ** 10)) and addr[10] == 0xFF and addr[11] == 0xFF) {
                // IPv4-mapped
                return RecvResult{
                    .len = @intCast(r),
                    .ip4 = addr[12..16].*,
                    .port = @as(u16, sa[2]) << 8 | @as(u16, sa[3]),
                };
            }
            // Native IPv6
            return RecvResult{
                .len = @intCast(r),
                .ip6 = addr[0..16].*,
                .port = @as(u16, sa[2]) << 8 | @as(u16, sa[3]),
            };
        } else {
            // AF_INET
            return RecvResult{
                .len = @intCast(r),
                .ip4 = sa[4..8].*,
                .port = @as(u16, sa[2]) << 8 | @as(u16, sa[3]),
            };
        }
    }
} else struct {
    // POSIX (Linux/macOS)
    pub const INVALID_SOCKET: usize = ~@as(usize, 0);
    const posix = std.posix;

    pub fn create(bind_ip4: ?[4]u8) ?usize {
        // Try IPv6 dual-stack first
        const s6 = std.posix.socket(std.posix.AF.INET6, std.posix.SOCK.DGRAM, 0) catch blk: {
            break :blk null;
        };
        if (s6) |sock6| {
            const fd6: usize = @intCast(sock6);
            // Disable IPV6_V6ONLY for dual-stack
            const v6only: c_int = 0;
            std.posix.setsockopt(sock6, std.posix.IPPROTO.IPV6, std.os.linux.IPV6.V6ONLY, std.mem.asBytes(&v6only)) catch {};
            // Set recv timeout 1 second
            const tv = std.posix.timeval{ .sec = 1, .usec = 0 };
            std.posix.setsockopt(sock6, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};

            var sa6 = std.mem.zeroes(std.posix.sockaddr.in6);
            sa6.family = std.posix.AF.INET6;
            if (bind_ip4) |ip4| {
                // IPv4-mapped IPv6: ::ffff:x.x.x.x
                sa6.addr[10] = 0xFF;
                sa6.addr[11] = 0xFF;
                sa6.addr[12] = ip4[0];
                sa6.addr[13] = ip4[1];
                sa6.addr[14] = ip4[2];
                sa6.addr[15] = ip4[3];
            }
            std.posix.bind(sock6, @ptrCast(&sa6), @sizeOf(std.posix.sockaddr.in6)) catch {
                std.posix.close(sock6);
                return null;
            };
            return fd6;
        }

        // Fallback to IPv4-only
        const s4 = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return null;
        const fd4: usize = @intCast(s4);
        const tv = std.posix.timeval{ .sec = 1, .usec = 0 };
        std.posix.setsockopt(s4, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};

        var sa4 = std.mem.zeroes(std.posix.sockaddr.in);
        sa4.family = std.posix.AF.INET;
        if (bind_ip4) |ip4| {
            sa4.addr = @bitCast(ip4);
        }
        std.posix.bind(s4, @ptrCast(&sa4), @sizeOf(std.posix.sockaddr.in)) catch {
            std.posix.close(s4);
            return null;
        };
        return fd4;
    }

    pub fn close(s: usize) void {
        std.posix.close(@intCast(s));
    }

    pub fn send4(s: usize, data: []const u8, ip4: [4]u8, port: u16) bool {
        var sa6 = std.mem.zeroes(std.posix.sockaddr.in6);
        sa6.family = std.posix.AF.INET6;
        sa6.port = std.mem.nativeToBig(u16, port);
        // IPv4-mapped: ::ffff:x.x.x.x
        sa6.addr[10] = 0xFF;
        sa6.addr[11] = 0xFF;
        sa6.addr[12] = ip4[0];
        sa6.addr[13] = ip4[1];
        sa6.addr[14] = ip4[2];
        sa6.addr[15] = ip4[3];
        const r = std.posix.sendto(@intCast(s), data, 0, @ptrCast(&sa6), @sizeOf(std.posix.sockaddr.in6)) catch {
            // Fallback: try as plain IPv4
            var sa4 = std.mem.zeroes(std.posix.sockaddr.in);
            sa4.family = std.posix.AF.INET;
            sa4.port = std.mem.nativeToBig(u16, port);
            sa4.addr = @bitCast(ip4);
            _ = std.posix.sendto(@intCast(s), data, 0, @ptrCast(&sa4), @sizeOf(std.posix.sockaddr.in)) catch return false;
            return true;
        };
        _ = r;
        return true;
    }

    pub fn send6(s: usize, data: []const u8, ip6: [16]u8, port: u16) bool {
        var sa6 = std.mem.zeroes(std.posix.sockaddr.in6);
        sa6.family = std.posix.AF.INET6;
        sa6.port = std.mem.nativeToBig(u16, port);
        sa6.addr = ip6;
        _ = std.posix.sendto(@intCast(s), data, 0, @ptrCast(&sa6), @sizeOf(std.posix.sockaddr.in6)) catch return false;
        return true;
    }

    pub const RecvResult = struct {
        len: usize,
        ip4: ?[4]u8 = null,
        ip6: ?[16]u8 = null,
        port: u16 = 0,
    };

    pub fn recv(s: usize, buf: []u8) ?RecvResult {
        var sa_storage: std.posix.sockaddr.storage = std.mem.zeroes(std.posix.sockaddr.storage);
        var sa_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
        const r = std.posix.recvfrom(@intCast(s), buf, 0, @ptrCast(&sa_storage), &sa_len) catch return null;
        if (r == 0) return null;
        const sa: *const [128]u8 = @ptrCast(&sa_storage);
        const family = sa_storage.family;
        if (family == std.posix.AF.INET6) {
            const addr = sa[8..24];
            const port_bytes = sa[2..4];
            const port = @as(u16, port_bytes[0]) << 8 | @as(u16, port_bytes[1]);
            // Check IPv4-mapped (::ffff:x.x.x.x)
            if (std.mem.eql(u8, addr[0..10], &([_]u8{0} ** 10)) and addr[10] == 0xFF and addr[11] == 0xFF) {
                return RecvResult{
                    .len = r,
                    .ip4 = addr[12..16].*,
                    .port = port,
                };
            }
            return RecvResult{
                .len = r,
                .ip6 = addr[0..16].*,
                .port = port,
            };
        } else {
            // AF_INET
            const port_bytes = sa[2..4];
            return RecvResult{
                .len = r,
                .ip4 = sa[4..8].*,
                .port = @as(u16, port_bytes[0]) << 8 | @as(u16, port_bytes[1]),
            };
        }
    }
};
