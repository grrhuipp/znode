// ══════════════════════════════════════════════════════════════
//  VMess Outbound — Pure Encoding / Decoding
//
//  Pure functions only. No Session dependency, no I/O.
//  The dispatcher (outbound_dispatch.zig) calls these functions,
//  reads/writes Session fields, and performs I/O.
// ══════════════════════════════════════════════════════════════

const vmess_protocol = @import("vmess_protocol.zig");
const vmess_stream = @import("vmess_stream.zig");
const vmess_crypto = @import("vmess_crypto.zig");
const config_mod = @import("../../core/config.zig");
const session_mod = @import("../../core/session.zig");

pub const protocol_tag: config_mod.Protocol = .vmess;

// ══════════════════════════════════════════════════════════════
//  Outbound header encoding
// ══════════════════════════════════════════════════════════════

pub const HeaderEncodeResult = struct {
    wire_len: usize,
    body_key: [16]u8,
    body_iv: [16]u8,
    resp_header: u8,
    /// Initialized request stream state (uplink encryption).
    /// Initialized immediately so uplink can proceed before server response arrives.
    request_state: vmess_stream.StreamState,
};

/// Encode VMess AEAD request header into buf and initialize the uplink stream state.
/// Returns null if buf is too small or encoding fails.
pub fn encodeHeader(
    buf: []u8,
    uuid: [16]u8,
    target: *const session_mod.TargetAddress,
    command: vmess_protocol.Command,
    security: vmess_protocol.SecurityMethod,
) ?HeaderEncodeResult {
    const options = vmess_protocol.OptionFlags{
        .chunk_stream = true,
        .chunk_masking = true,
        .global_padding = true,
    };

    const result = vmess_protocol.encodeRequestFull(buf, uuid, target, command, security, options) orelse
        return null;

    const request_state = vmess_stream.StreamState.init(result.body_key, result.body_iv, security, options);

    return .{
        .wire_len = result.wire_len,
        .body_key = result.body_key,
        .body_iv = result.body_iv,
        .resp_header = result.response_header,
        .request_state = request_state,
    };
}

// ══════════════════════════════════════════════════════════════
//  Response parsing
// ══════════════════════════════════════════════════════════════

pub const ResponseParseResult = union(enum) {
    /// Response parsed and downlink stream state initialized.
    success: struct {
        response_state: vmess_stream.StreamState,
    },
    /// Need more data (< 38 bytes accumulated).
    need_more: void,
    /// Server sent an invalid response header.
    protocol_error: void,
    /// Response AEAD tag validation failed (wrong key or tampered).
    validation_failed: void,
};

/// Parse the 38-byte VMess AEAD response header and initialize the downlink stream state.
/// `accumulated` must contain at least vmess_protocol.response_wire_size bytes.
/// Returns need_more if not enough data yet.
pub fn parseResponse(
    accumulated: []const u8,
    body_key: [16]u8,
    body_iv: [16]u8,
    resp_header: u8,
    security: vmess_protocol.SecurityMethod,
) ResponseParseResult {
    const options = vmess_protocol.OptionFlags{
        .chunk_stream = true,
        .chunk_masking = true,
        .global_padding = true,
    };

    switch (vmess_protocol.parseResponse(accumulated, body_key, body_iv, resp_header)) {
        .success => {
            const resp_key = vmess_crypto.deriveResponseKey(body_key);
            const resp_iv = vmess_crypto.deriveResponseIv(body_iv);
            const response_state = vmess_stream.StreamState.init(resp_key, resp_iv, security, options);
            return .{ .success = .{ .response_state = response_state } };
        },
        .incomplete => return .need_more,
        .protocol_error => return .protocol_error,
        .validation_failed => return .validation_failed,
    }
}
