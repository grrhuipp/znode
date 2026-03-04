const std = @import("std");
const config = @import("../infra/config.zig");
const tls_ctx = @import("tls/context.zig");
const tls_stream = @import("tls/stream.zig");
const ws_stream = @import("ws/stream.zig");
const ws_handshake = @import("ws/handshake.zig");
const stream_types = @import("stream.zig");
const TcpStream = stream_types.TcpStream;
const TransportStream = stream_types.TransportStream;
const OutboundTransportStream = stream_types.OutboundTransportStream;

pub const BuildError = error{
    TlsSetupFailed,
    WsHandshakeFailed,
};

/// Build inbound (server-side) transport stack from raw TCP.
///
/// Layer composition based on config:
///   tcp + none  → TransportStream.tcp
///   tcp + tls   → TransportStream.tcp_tls
///   ws  + none  → TransportStream.tcp_ws
///   ws  + tls   → TransportStream.tcp_tls_ws
pub fn buildInbound(
    raw: TcpStream,
    settings: *const config.StreamSettings,
    server_ssl_ctx: ?*const tls_ctx.SslContext,
    real_ip_out: *[46]u8,
    real_ip_len: *u8,
) BuildError!TransportStream {
    const use_tls = settings.isTls();
    const use_ws = settings.isWs();

    if (use_tls and use_ws) {
        // TCP → TLS → WS (server)
        const ctx = server_ssl_ctx orelse return error.TlsSetupFailed;
        var tls = tls_stream.TlsStream(TcpStream).init(raw, ctx, true) catch
            return error.TlsSetupFailed;
        tls.handshake() catch return error.TlsSetupFailed;

        const hs = ws_handshake.serverHandshake(
            tls_stream.TlsStream(TcpStream),
            &tls,
            settings.ws.path,
            settings.ws.real_ip_header,
            real_ip_out,
            real_ip_len,
        ) catch return error.WsHandshakeFailed;

        var ws = ws_stream.WsStream(tls_stream.TlsStream(TcpStream), false).initWithPending(
            tls,
            hs.pending_buf[0..hs.pending_len],
        );
        _ = &ws;

        return .{ .tcp_tls_ws = ws };
    } else if (use_tls) {
        // TCP → TLS
        const ctx = server_ssl_ctx orelse return error.TlsSetupFailed;
        var tls = tls_stream.TlsStream(TcpStream).init(raw, ctx, true) catch
            return error.TlsSetupFailed;
        tls.handshake() catch return error.TlsSetupFailed;
        return .{ .tcp_tls = tls };
    } else if (use_ws) {
        // TCP → WS (server, no TLS)
        var tcp = raw;
        const hs = ws_handshake.serverHandshake(
            TcpStream,
            &tcp,
            settings.ws.path,
            settings.ws.real_ip_header,
            real_ip_out,
            real_ip_len,
        ) catch return error.WsHandshakeFailed;

        var ws_s = ws_stream.WsStream(TcpStream, false).initWithPending(
            tcp,
            hs.pending_buf[0..hs.pending_len],
        );
        _ = &ws_s;

        return .{ .tcp_ws = ws_s };
    } else {
        // Raw TCP
        return .{ .tcp = raw };
    }
}

/// Build outbound (client-side) transport stack from raw TCP.
pub fn buildOutbound(
    raw: TcpStream,
    settings: *const config.StreamSettings,
    client_ssl_ctx: ?*const tls_ctx.SslContext,
    server_name: []const u8,
) BuildError!OutboundTransportStream {
    const use_tls = settings.isTls();
    const use_ws = settings.isWs();

    if (use_tls and use_ws) {
        // TCP → TLS → WS (client)
        const ctx = client_ssl_ctx orelse return error.TlsSetupFailed;
        var tls = tls_stream.TlsStream(TcpStream).init(raw, ctx, false) catch
            return error.TlsSetupFailed;

        // Set SNI
        const sni = if (server_name.len > 0) server_name else settings.tls.server_name;
        if (sni.len > 0 and sni.len < 255) {
            var sni_buf: [256]u8 = undefined;
            @memcpy(sni_buf[0..sni.len], sni);
            sni_buf[sni.len] = 0;
            tls.setServerName(@ptrCast(sni_buf[0..sni.len :0]));
        }

        if (settings.tls.alpn.len > 0) {
            tls.setAlpn(settings.tls.alpn) catch {};
        }

        tls.handshake() catch return error.TlsSetupFailed;

        const host = if (server_name.len > 0) server_name else settings.tls.server_name;
        var tcp_tls = tls;
        const hs = ws_handshake.clientHandshake(
            tls_stream.TlsStream(TcpStream),
            &tcp_tls,
            host,
            settings.ws.path,
        ) catch return error.WsHandshakeFailed;

        var ws = ws_stream.WsStream(tls_stream.TlsStream(TcpStream), true).initWithPending(
            tcp_tls,
            hs.pending_buf[0..hs.pending_len],
        );
        _ = &ws;

        return .{ .tcp_tls_ws = ws };
    } else if (use_tls) {
        // TCP → TLS
        const ctx = client_ssl_ctx orelse return error.TlsSetupFailed;
        var tls = tls_stream.TlsStream(TcpStream).init(raw, ctx, false) catch
            return error.TlsSetupFailed;

        const sni = if (server_name.len > 0) server_name else settings.tls.server_name;
        if (sni.len > 0 and sni.len < 255) {
            var sni_buf: [256]u8 = undefined;
            @memcpy(sni_buf[0..sni.len], sni);
            sni_buf[sni.len] = 0;
            tls.setServerName(@ptrCast(sni_buf[0..sni.len :0]));
        }

        if (settings.tls.alpn.len > 0) {
            tls.setAlpn(settings.tls.alpn) catch {};
        }

        tls.handshake() catch return error.TlsSetupFailed;
        return .{ .tcp_tls = tls };
    } else if (use_ws) {
        // TCP → WS (client, no TLS)
        var tcp = raw;
        const hs = ws_handshake.clientHandshake(
            TcpStream,
            &tcp,
            server_name,
            settings.ws.path,
        ) catch return error.WsHandshakeFailed;

        var ws = ws_stream.WsStream(TcpStream, true).initWithPending(
            tcp,
            hs.pending_buf[0..hs.pending_len],
        );
        _ = &ws;

        return .{ .tcp_ws = ws };
    } else {
        return .{ .tcp = raw };
    }
}
