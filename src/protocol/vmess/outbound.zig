/// VMess AEAD outbound — encode client handshake and read server response.
///
/// Flow: generate keys → encode AEAD header → write to transport → read response → wrap VMessStream
const std = @import("std");
const crypto = @import("crypto.zig");
const types = @import("../../common/types.zig");
const aead_mod = @import("../../infra/crypto/aead.zig");
const hash_mod = @import("../../infra/crypto/hash.zig");
const rand_mod = @import("../../infra/crypto/rand.zig");

pub const HandshakeError = error{
    CryptoFailed,
    BufferTooSmall,
    InvalidResponse,
    AuthenticationFailed,
    NeedMoreData,
    InnerStreamError,
};

/// Result of encoding the handshake — contains wire bytes + session keys.
pub const HandshakeResult = struct {
    /// Wire bytes to send
    data: [512]u8 = undefined,
    data_len: usize = 0,

    /// Session keys for VMessStream
    request_key: [16]u8,
    request_iv: [16]u8,
    response_key: [16]u8,
    response_iv: [16]u8,
    response_header: u8,
    options: u8,
    security: crypto.Security,
};

pub const VMessOutbound = struct {
    uuid_bytes: [16]u8,
    security: crypto.Security,

    pub fn init(uuid_str: []const u8, security_str: []const u8) ?VMessOutbound {
        const uuid = crypto.parseUuid(uuid_str) orelse return null;
        const sec = parseSecurity(security_str);
        return .{ .uuid_bytes = uuid, .security = sec };
    }

    /// Encode VMess AEAD handshake header. Returns session keys + wire data.
    pub fn encodeHandshake(
        self: *const VMessOutbound,
        target: types.TargetAddress,
        command: crypto.Command,
    ) HandshakeError!HandshakeResult {
        var result = HandshakeResult{
            .request_key = undefined,
            .request_iv = undefined,
            .response_key = undefined,
            .response_iv = undefined,
            .response_header = 0,
            .options = crypto.Option.chunk_stream | crypto.Option.chunk_masking | crypto.Option.global_padding,
            .security = self.security,
        };

        // Resolve "auto" to aes-128-gcm
        if (result.security == .auto) result.security = .aes_128_gcm;

        // Generate random session keys
        rand_mod.randomBytes(&result.request_key) catch return error.CryptoFailed;
        rand_mod.randomBytes(&result.request_iv) catch return error.CryptoFailed;
        var resp_header_buf: [1]u8 = undefined;
        rand_mod.randomBytes(&resp_header_buf) catch return error.CryptoFailed;
        result.response_header = resp_header_buf[0];

        // Derive response keys
        result.response_key = hash_mod.sha256(&result.request_key)[0..16].*;
        result.response_iv = hash_mod.sha256(&result.request_iv)[0..16].*;

        // Build request header plaintext
        var header: [256]u8 = undefined;
        var hpos: usize = 0;

        header[hpos] = 0x01; // version
        hpos += 1;
        @memcpy(header[hpos..][0..16], &result.request_iv);
        hpos += 16;
        @memcpy(header[hpos..][0..16], &result.request_key);
        hpos += 16;
        header[hpos] = result.response_header;
        hpos += 1;
        header[hpos] = result.options;
        hpos += 1;
        // padding_len(high nibble) | security(low nibble)
        header[hpos] = @intFromEnum(result.security);
        hpos += 1;
        header[hpos] = 0x00; // reserved
        hpos += 1;
        header[hpos] = @intFromEnum(command);
        hpos += 1;

        // Port (big-endian)
        header[hpos] = @intCast(target.port >> 8);
        hpos += 1;
        header[hpos] = @intCast(target.port & 0xFF);
        hpos += 1;

        // Address
        hpos = encodeAddress(target, &header, hpos) orelse return error.BufferTooSmall;

        // FNV-1a checksum
        const checksum = fnv1a32(header[0..hpos]);
        std.mem.writeInt(u32, header[hpos..][0..4], checksum, .big);
        hpos += 4;

        // Now build wire format:
        // [AuthID(16)] [EncLen(18)] [Nonce(8)] [EncHeader(N+16)]
        const cmd_key = crypto.deriveCmdKey(&self.uuid_bytes) catch return error.CryptoFailed;
        const auth_key = crypto.deriveAuthKey(&cmd_key) catch return error.CryptoFailed;

        const now = std.time.timestamp();
        const auth_id = crypto.generateAuthId(&auth_key, now) catch return error.CryptoFailed;

        var connection_nonce: [8]u8 = undefined;
        rand_mod.randomBytes(&connection_nonce) catch return error.CryptoFailed;

        const hdr_keys = crypto.deriveHeaderKeys(&cmd_key, &auth_id, &connection_nonce) catch
            return error.CryptoFailed;

        var pos: usize = 0;

        // AuthID (16 bytes)
        @memcpy(result.data[pos..][0..16], &auth_id);
        pos += 16;

        // EncLen: encrypt header length (2 bytes → 18 bytes)
        const header_len_bytes = [2]u8{
            @intCast(hpos >> 8),
            @intCast(hpos & 0xFF),
        };
        const enc_len = aead_mod.encrypt(
            .aes_128_gcm,
            &hdr_keys.len_key,
            &hdr_keys.len_iv,
            &header_len_bytes,
            &auth_id,
            result.data[pos..],
        ) catch return error.CryptoFailed;
        pos += enc_len;

        // Connection nonce (8 bytes)
        @memcpy(result.data[pos..][0..8], &connection_nonce);
        pos += 8;

        // EncHeader: encrypt header payload
        const enc_header = aead_mod.encrypt(
            .aes_128_gcm,
            &hdr_keys.payload_key,
            &hdr_keys.payload_iv,
            header[0..hpos],
            &auth_id,
            result.data[pos..],
        ) catch return error.CryptoFailed;
        pos += enc_header;

        result.data_len = pos;
        return result;
    }

    /// Read and validate VMess AEAD response header from stream.
    pub fn readResponse(
        comptime Stream: type,
        stream: *Stream,
        response_key: *const [16]u8,
        response_iv: *const [16]u8,
        expected_response_header: u8,
    ) HandshakeError!void {
        // Read response: EncRespLen(18) + EncRespHeader(at least 4+16=20)
        var buf: [256]u8 = undefined;
        var filled: usize = 0;

        // Read at least 38 bytes (18 + 20)
        while (filled < 38) {
            const n = stream.read(buf[filled..]) catch return error.InnerStreamError;
            if (n == 0) return error.InnerStreamError;
            filled += n;
        }

        const resp = crypto.decryptResponseHeader(
            response_key,
            response_iv,
            buf[0..filled],
        ) catch return error.AuthenticationFailed;

        if (resp.response_header != expected_response_header) {
            return error.InvalidResponse;
        }
    }
};

fn encodeAddress(target: types.TargetAddress, buf: []u8, start: usize) ?usize {
    var pos = start;
    const h = target.host();

    switch (target.address_type) {
        .ipv4 => {
            buf[pos] = 0x01; // IPv4
            pos += 1;
            const addr = std.net.Address.parseIp4(h, 0) catch return null;
            const bytes = std.mem.asBytes(&addr.in.sa.addr);
            @memcpy(buf[pos..][0..4], bytes[0..4]);
            pos += 4;
        },
        .domain => {
            buf[pos] = 0x02; // Domain
            pos += 1;
            buf[pos] = @intCast(h.len);
            pos += 1;
            @memcpy(buf[pos..][0..h.len], h);
            pos += h.len;
        },
        .ipv6 => {
            buf[pos] = 0x03; // IPv6
            pos += 1;
            const addr = std.net.Address.parseIp6(h, 0) catch return null;
            @memcpy(buf[pos..][0..16], &addr.in6.sa.addr);
            pos += 16;
        },
    }
    return pos;
}

fn fnv1a32(data: []const u8) u32 {
    var hash: u32 = 0x811c9dc5;
    for (data) |byte| {
        hash ^= byte;
        hash *%= 0x01000193;
    }
    return hash;
}

fn parseSecurity(s: []const u8) crypto.Security {
    if (std.ascii.eqlIgnoreCase(s, "aes-128-gcm")) return .aes_128_gcm;
    if (std.ascii.eqlIgnoreCase(s, "chacha20-poly1305") or
        std.ascii.eqlIgnoreCase(s, "chacha20-ietf-poly1305")) return .chacha20_poly1305;
    if (std.ascii.eqlIgnoreCase(s, "none")) return .none;
    if (std.ascii.eqlIgnoreCase(s, "zero")) return .zero;
    return .auto; // default
}
