const std = @import("std");
const TlsStream = @import("tls/stream.zig").TlsStream;
const ws = @import("ws/stream.zig");
const SslContext = @import("tls/context.zig").SslContext;

/// Placeholder for the actual zio TCP stream type.
/// Will be replaced with zio.net.Stream when integrating with zio.
pub const TcpStream = struct {
    fd: i32 = -1,

    pub fn read(self: *TcpStream, buf: []u8) !usize {
        _ = self;
        _ = buf;
        return error.NotImplemented;
    }

    pub fn write(self: *TcpStream, data: []const u8) !usize {
        _ = self;
        _ = data;
        return error.NotImplemented;
    }

    pub fn close(self: *TcpStream) void {
        _ = self;
    }

    const NotImplemented = error{NotImplemented};
};

/// Transport layer stream — comptime-composed layers, runtime-switched via tagged union.
///
/// Replaces C++ `unique_ptr<AsyncStream>` chain with zero heap allocation.
///
/// Each variant is a comptime-composed stack:
///   tcp:        raw TCP
///   tcp_tls:    TCP → TLS
///   tcp_ws:     TCP → WS (server)
///   tcp_tls_ws: TCP → TLS → WS (server)
///
/// For outbound (client-side WS), use OutboundTransportStream.
pub const TransportStream = union(enum) {
    tcp: TcpStream,
    tcp_tls: TlsStream(TcpStream),
    tcp_ws: ws.WsStream(TcpStream, false),
    tcp_tls_ws: ws.WsStream(TlsStream(TcpStream), false),

    pub fn read(self: *TransportStream, buf: []u8) !usize {
        return switch (self.*) {
            inline else => |*s| s.read(buf),
        };
    }

    pub fn write(self: *TransportStream, data: []const u8) !usize {
        return switch (self.*) {
            inline else => |*s| s.write(data),
        };
    }

    pub fn writeAll(self: *TransportStream, data: []const u8) !void {
        var sent: usize = 0;
        while (sent < data.len) {
            const n = try self.write(data[sent..]);
            if (n == 0) return error.BrokenPipe;
            sent += n;
        }
    }

    pub fn close(self: *TransportStream) void {
        switch (self.*) {
            inline else => |*s| s.close(),
        }
    }
};

/// Outbound transport stream (client-side WS uses masking).
pub const OutboundTransportStream = union(enum) {
    tcp: TcpStream,
    tcp_tls: TlsStream(TcpStream),
    tcp_ws: ws.WsStream(TcpStream, true),
    tcp_tls_ws: ws.WsStream(TlsStream(TcpStream), true),

    pub fn read(self: *OutboundTransportStream, buf: []u8) !usize {
        return switch (self.*) {
            inline else => |*s| s.read(buf),
        };
    }

    pub fn write(self: *OutboundTransportStream, data: []const u8) !usize {
        return switch (self.*) {
            inline else => |*s| s.write(data),
        };
    }

    pub fn writeAll(self: *OutboundTransportStream, data: []const u8) !void {
        var sent: usize = 0;
        while (sent < data.len) {
            const n = try self.write(data[sent..]);
            if (n == 0) return error.BrokenPipe;
            sent += n;
        }
    }

    pub fn close(self: *OutboundTransportStream) void {
        switch (self.*) {
            inline else => |*s| s.close(),
        }
    }
};
