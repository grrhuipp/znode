// ══════════════════════════════════════════════════════════════
//  Transport Interface — Comptime Duck-Typing Verification
//
//  Formalizes the "mirror API" pattern already used by TlsStream
//  and WsStream. Any new transport layer (e.g., gRPC, QUIC) must
//  satisfy this interface to plug into the relay pipeline.
//
//  Required methods (the "mirror API"):
//    feedNetworkData(*Self, []const u8) !usize
//    readDecrypted(*Self, []u8) TransportResult
//    writeEncrypted(*Self, []const u8) TransportResult
//    getNetworkData(*Self, []u8) usize
// ══════════════════════════════════════════════════════════════

const tls_mod = @import("tls_stream.zig");
const ws_mod = @import("ws_stream.zig");

/// Verify that T satisfies the Transport interface (mirror API).
///
/// Required methods:
///   - feedNetworkData(*T, []const u8) !usize
///   - readDecrypted(*T, []u8) TransportResult-like
///   - writeEncrypted(*T, []const u8) TransportResult-like
///   - getNetworkData(*T, []u8) usize
pub fn Transport(comptime T: type) void {
    comptime {
        if (!@hasDecl(T, "feedNetworkData")) {
            @compileError(@typeName(T) ++ ": Transport requires feedNetworkData(*Self, []const u8) !usize");
        }
        if (!@hasDecl(T, "readDecrypted")) {
            @compileError(@typeName(T) ++ ": Transport requires readDecrypted(*Self, []u8) TransportResult");
        }
        if (!@hasDecl(T, "writeEncrypted")) {
            @compileError(@typeName(T) ++ ": Transport requires writeEncrypted(*Self, []const u8) TransportResult");
        }
        if (!@hasDecl(T, "getNetworkData")) {
            @compileError(@typeName(T) ++ ": Transport requires getNetworkData(*Self, []u8) usize");
        }
    }
}

// ── Static compile-time verification of existing transports ──
comptime {
    Transport(tls_mod.TlsStream);
    Transport(ws_mod.WsStream);
}
