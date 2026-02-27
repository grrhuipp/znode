const std = @import("std");
const Session = @import("../../core/session.zig");
const user_store = @import("../../core/user_store.zig");
const vmess_crypto = @import("vmess_crypto.zig");
const vmess_hot_cache = @import("vmess_hot_cache.zig");
const boringssl = @import("../../crypto/boringssl_crypto.zig");
const Aes128Gcm = boringssl.Aes128Gcm;
/// Constant-time comparison to prevent timing side-channels.
fn constantTimeEql(comptime T: type, a: T, b: T) bool {
    const a_bytes: []const u8 = std.mem.asBytes(&a);
    const b_bytes: []const u8 = std.mem.asBytes(&b);
    if (a_bytes.len != b_bytes.len) return false;
    var diff: u8 = 0;
    for (a_bytes, b_bytes) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
}

pub const SecurityMethod = enum(u4) {
    aes_128_gcm = 0x03,
    chacha20_poly1305 = 0x04,
    none = 0x05,
    aes_256_gcm = 0x06,
};

pub const Command = enum(u8) {
    tcp = 0x01,
    udp = 0x02,
    mux = 0x03,
};

pub const AddressType = enum(u8) {
    ipv4 = 0x01,
    domain = 0x02,
    ipv6 = 0x03,
};

pub const OptionFlags = packed struct(u8) {
    chunk_stream: bool = false,
    _reserved1: bool = false,
    chunk_masking: bool = false,
    global_padding: bool = false,
    auth_length: bool = false,
    _reserved5: bool = false,
    _reserved6: bool = false,
    _reserved7: bool = false,
};

/// Decoded VMess AEAD request header.
pub const VMessRequest = struct {
    version: u8,
    request_body_iv: [16]u8,
    request_body_key: [16]u8,
    response_header: u8,
    options: OptionFlags,
    padding_len: u4,
    security: SecurityMethod,
    command: Command,
    target: Session.TargetAddress,
    header_len: usize,
    cmd_key: vmess_crypto.CmdKey,
    connection_nonce: [8]u8,
    matched_user: ?*const user_store.UserStore.UserInfo,
};

pub const ParseResult = union(enum) {
    success: VMessRequest,
    incomplete,
    protocol_error,
    auth_failed,
    replay_detected,
};

/// Response header (4 bytes plaintext, matching acppnode).
pub const ResponseHeader = struct {
    response_header: u8,
    options: u8,
    command: u8,
    command_len: u8,
    bytes_consumed: usize,
};

pub const ResponseParseResult = union(enum) {
    success: ResponseHeader,
    incomplete,
    protocol_error,
    validation_failed,
};

/// Response wire size: EncLen(18B) + EncHeader(20B) = 38B.
pub const response_wire_size: usize = 38;

// ── Replay Filter ──

pub const ReplayFilter = struct {
    entries: std.AutoHashMapUnmanaged(vmess_crypto.AuthID, i64) = .{},
    last_cleanup: i64 = 0,

    const cleanup_interval: i64 = 30;

    pub fn deinit(self: *ReplayFilter, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
    }

    /// Check if AuthID is a replay. If not, record it.
    /// Returns true if duplicate detected.
    /// On OOM, conservatively returns true (rejects the connection).
    /// Caller must hold replay_mutex.
    pub fn isDuplicate(self: *ReplayFilter, auth_id: vmess_crypto.AuthID, now: i64, allocator: std.mem.Allocator) bool {
        if (now - self.last_cleanup >= cleanup_interval) {
            self.evictExpired(allocator, now);
            self.last_cleanup = now;
        }

        const gop = self.entries.getOrPut(allocator, auth_id) catch return true;
        if (gop.found_existing) return true;
        gop.value_ptr.* = now;
        return false;
    }

    fn evictExpired(self: *ReplayFilter, allocator: std.mem.Allocator, now: i64) void {
        var victims: std.ArrayListUnmanaged(vmess_crypto.AuthID) = .{};
        defer victims.deinit(allocator);

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (now - entry.value_ptr.* > vmess_crypto.auth_id_window) {
                victims.append(allocator, entry.key_ptr.*) catch continue;
            }
        }
        for (victims.items) |key| {
            _ = self.entries.remove(key);
        }
    }
};

// ── Request Parsing (Inbound) ──

/// Parse a VMess AEAD request from wire data.
///
/// Wire format: AuthID(16B) + EncryptedLength(18B) + connectionNonce(8B) + EncryptedHeader(N+16B)
///
/// Minimum: 16 + 18 + 8 = 42 bytes before we can read the header length.
pub fn parseRequest(
    data: []const u8,
    user_map: *const user_store.UserStore.UserMap,
    replay_filter: *ReplayFilter,
    hot_cache: ?*vmess_hot_cache.HotCache,
    allocator: std.mem.Allocator,
) ParseResult {
    if (data.len < 42) return .incomplete;

    const auth_id: vmess_crypto.AuthID = data[0..16].*;
    const enc_length_block = data[16..34];
    const connection_nonce: [8]u8 = data[34..42].*;

    const now = std.time.timestamp();

    // ── Fast path: try hot cache first ──
    if (hot_cache) |cache| {
        if (cache.tryAuth(auth_id, now, allocator)) |hit| {
            // Verify user still exists in current UserMap
            if (user_map.findById(hit.user_id)) |user| {
                if (user.enabled) {
                    if (tryDecryptHeader(data, hit.cmd_key, auth_id, enc_length_block, connection_nonce, replay_filter, now, user, allocator)) |result| {
                        return result;
                    }
                }
            }
            // User removed or decrypt failed → evict from cache
            cache.evictUser(hit.user_id, allocator);
        }
    }

    // ── Slow path: full scan with pre-cached keys ──
    for (user_map.users) |*user| {
        if (!user.enabled) continue;

        // Use pre-cached keys (computed in UserStore.update, avoids MD5 + KDF per attempt)
        const cmd_key = user.cached_cmd_key;
        const auth_key = user.cached_auth_key;

        // Validate AuthID: AES-ECB decrypt + CRC32 + timestamp check
        const ts = vmess_crypto.validateAuthId(auth_id, auth_key, now) orelse continue;
        _ = ts;

        if (tryDecryptHeader(data, cmd_key, auth_id, enc_length_block, connection_nonce, replay_filter, now, user, allocator)) |result| {
            // Record in hot cache on successful auth from slow path
            if (hot_cache) |cache| {
                cache.recordAuth(user.id, cmd_key, auth_key, now, allocator, @max(1, user_map.users.len / 10));
            }
            return result;
        }
    }

    return .auth_failed;
}

/// Try to decrypt VMess header (length + payload) with a given CmdKey.
/// Returns ParseResult on success, null if GCM decryption fails (wrong key).
fn tryDecryptHeader(
    data: []const u8,
    cmd_key: vmess_crypto.CmdKey,
    auth_id: vmess_crypto.AuthID,
    enc_length_block: *const [18]u8,
    connection_nonce: [8]u8,
    replay_filter: *ReplayFilter,
    now: i64,
    user: *const user_store.UserStore.UserInfo,
    allocator: std.mem.Allocator,
) ?ParseResult {
    const length_key = vmess_crypto.deriveHeaderLengthKey(cmd_key, auth_id, connection_nonce);
    const length_nonce = vmess_crypto.deriveHeaderLengthNonce(cmd_key, auth_id, connection_nonce);

    var length_plain: [2]u8 = undefined;
    Aes128Gcm.decrypt(
        &length_plain,
        enc_length_block[0..2],
        enc_length_block[2..18].*,
        &auth_id,
        length_nonce,
        length_key,
    ) catch return null; // GCM auth failed → wrong key

    const header_len = std.mem.readInt(u16, &length_plain, .big);
    const total_len: usize = 42 + header_len + 16;
    if (data.len < total_len) return .incomplete;

    const header_key = vmess_crypto.deriveHeaderKey(cmd_key, auth_id, connection_nonce);
    const header_nonce = vmess_crypto.deriveHeaderNonce(cmd_key, auth_id, connection_nonce);

    var header_plain: [512]u8 = undefined;
    if (header_len > header_plain.len) return .protocol_error;

    const enc_header = data[42 .. 42 + header_len];
    const header_tag = data[42 + header_len .. total_len];

    Aes128Gcm.decrypt(
        header_plain[0..header_len],
        enc_header,
        header_tag[0..16].*,
        &auth_id,
        header_nonce,
        header_key,
    ) catch return .protocol_error;

    if (replay_filter.isDuplicate(auth_id, now, allocator)) return .replay_detected;

    return parseDecryptedHeader(header_plain[0..header_len], total_len, cmd_key, connection_nonce, user);
}

/// Parse a VMess AEAD request using a specific CmdKey (for testing).
pub fn parseRequestWithKey(
    data: []const u8,
    cmd_key: vmess_crypto.CmdKey,
    user: ?*const user_store.UserStore.UserInfo,
    replay_filter: *ReplayFilter,
    timestamp: i64,
    allocator: std.mem.Allocator,
) ParseResult {
    if (data.len < 42) return .incomplete;

    const auth_id: vmess_crypto.AuthID = data[0..16].*;
    const enc_length_block = data[16..34];
    const connection_nonce: [8]u8 = data[34..42].*;

    // Derive auth_key from cmd_key for AuthID validation
    const auth_key = vmess_crypto.deriveAuthKey(cmd_key);

    // Validate AuthID using auth_key
    _ = vmess_crypto.validateAuthId(auth_id, auth_key, timestamp) orelse return .auth_failed;

    // Decrypt header length (uses cmd_key for KDF)
    const length_key = vmess_crypto.deriveHeaderLengthKey(cmd_key, auth_id, connection_nonce);
    const length_nonce = vmess_crypto.deriveHeaderLengthNonce(cmd_key, auth_id, connection_nonce);

    var length_plain: [2]u8 = undefined;
    Aes128Gcm.decrypt(
        &length_plain,
        enc_length_block[0..2],
        enc_length_block[2..18].*,
        &auth_id,
        length_nonce,
        length_key,
    ) catch return .auth_failed;

    const header_len = std.mem.readInt(u16, &length_plain, .big);
    const total_len: usize = 42 + header_len + 16;
    if (data.len < total_len) return .incomplete;

    // Decrypt header
    const header_key = vmess_crypto.deriveHeaderKey(cmd_key, auth_id, connection_nonce);
    const header_nonce = vmess_crypto.deriveHeaderNonce(cmd_key, auth_id, connection_nonce);

    var header_plain: [512]u8 = undefined;
    if (header_len > header_plain.len) return .protocol_error;

    const enc_header = data[42 .. 42 + header_len];
    const header_tag = data[42 + header_len .. total_len];

    Aes128Gcm.decrypt(
        header_plain[0..header_len],
        enc_header,
        header_tag[0..16].*,
        &auth_id,
        header_nonce,
        header_key,
    ) catch return .protocol_error;

    if (replay_filter.isDuplicate(auth_id, timestamp, allocator)) return .replay_detected;

    return parseDecryptedHeader(header_plain[0..header_len], total_len, cmd_key, connection_nonce, user);
}

fn parseDecryptedHeader(
    plain: []const u8,
    total_wire_len: usize,
    cmd_key: vmess_crypto.CmdKey,
    connection_nonce: [8]u8,
    user: ?*const user_store.UserStore.UserInfo,
) ParseResult {
    // Minimum: Version(1) + IV(16) + Key(16) + RespH(1) + Opt(1) + PadSec(1) + Rsv(1) + Cmd(1) + Port(2) + ATyp(1) + FNV(4) = 45
    if (plain.len < 45) return .protocol_error;

    // Verify FNV1a checksum (last 4 bytes)
    const payload = plain[0 .. plain.len - 4];
    const stored_fnv = plain[plain.len - 4 ..][0..4].*;
    const computed_fnv = vmess_crypto.fnv1a32(payload);
    if (!constantTimeEql([4]u8, stored_fnv, computed_fnv)) {
        return .protocol_error;
    }

    var pos: usize = 0;

    const version = payload[pos];
    if (version != 0x01) return .protocol_error;
    pos += 1;

    var body_iv: [16]u8 = undefined;
    @memcpy(&body_iv, payload[pos .. pos + 16]);
    pos += 16;

    var body_key: [16]u8 = undefined;
    @memcpy(&body_key, payload[pos .. pos + 16]);
    pos += 16;

    const response_header = payload[pos];
    pos += 1;

    const options: OptionFlags = @bitCast(payload[pos]);
    pos += 1;

    const pad_sec = payload[pos];
    const padding_len: u4 = @intCast(pad_sec >> 4);
    const security_val: u4 = @intCast(pad_sec & 0x0F);
    const security: SecurityMethod = std.meta.intToEnum(SecurityMethod, security_val) catch return .protocol_error;
    pos += 1;

    // Reserved byte
    pos += 1;

    const cmd_byte = payload[pos];
    const command: Command = switch (cmd_byte) {
        0x01 => .tcp,
        0x02 => .udp,
        0x03 => .mux,
        else => return .protocol_error,
    };
    pos += 1;

    if (pos + 2 > payload.len) return .protocol_error;
    const port = std.mem.readInt(u16, payload[pos..][0..2], .big);
    pos += 2;

    if (pos >= payload.len) return .protocol_error;
    const atyp_byte = payload[pos];
    pos += 1;

    var target = Session.TargetAddress{};

    switch (atyp_byte) {
        0x01 => { // IPv4
            if (pos + 4 > payload.len) return .protocol_error;
            target.setIpv4(payload[pos..][0..4].*, port);
            pos += 4;
        },
        0x02 => { // Domain
            if (pos >= payload.len) return .protocol_error;
            const domain_len = payload[pos];
            pos += 1;
            if (domain_len == 0 or pos + domain_len > payload.len) return .protocol_error;
            target.setDomain(payload[pos .. pos + domain_len], port);
            pos += domain_len;
        },
        0x03 => { // IPv6
            if (pos + 16 > payload.len) return .protocol_error;
            target.setIpv6(payload[pos..][0..16].*, port);
            pos += 16;
        },
        else => return .protocol_error,
    }

    // Skip padding
    pos += padding_len;

    // Verify we consumed everything except the FNV1a checksum
    if (pos != payload.len) return .protocol_error;

    return .{ .success = .{
        .version = version,
        .request_body_iv = body_iv,
        .request_body_key = body_key,
        .response_header = response_header,
        .options = options,
        .padding_len = padding_len,
        .security = security,
        .command = command,
        .target = target,
        .header_len = total_wire_len,
        .cmd_key = cmd_key,
        .connection_nonce = connection_nonce,
        .matched_user = user,
    } };
}

// ── Request Encoding (Outbound) ──

/// Result of encoding a VMess request — includes the body key/IV needed
/// for constructing stream states and parsing the response.
pub const EncodeRequestResult = struct {
    wire_len: usize,
    body_key: [16]u8,
    body_iv: [16]u8,
    response_header: u8,
};

/// Encode a VMess AEAD request header and return the body key/IV/response_header.
/// Used by VMess outbound to build the request and later parse the response.
pub fn encodeRequestFull(
    buf: []u8,
    uuid: [16]u8,
    target: *const Session.TargetAddress,
    command: Command,
    security: SecurityMethod,
    options: OptionFlags,
) ?EncodeRequestResult {
    var body_iv: [16]u8 = undefined;
    boringssl.random.bytes(&body_iv);
    var body_key: [16]u8 = undefined;
    boringssl.random.bytes(&body_key);
    const resp_header = boringssl.random.int(u8);

    const len = encodeRequestWithParams(buf, uuid, target, command, security, options, null, null, body_iv, body_key, resp_header) orelse return null;

    return .{
        .wire_len = len,
        .body_key = body_key,
        .body_iv = body_iv,
        .response_header = resp_header,
    };
}

/// Encode a VMess AEAD request header.
/// Returns the number of bytes written, or null if buffer too small.
pub fn encodeRequest(
    buf: []u8,
    uuid: [16]u8,
    target: *const Session.TargetAddress,
    command: Command,
    security: SecurityMethod,
    options: OptionFlags,
) ?usize {
    return encodeRequestWithParams(buf, uuid, target, command, security, options, null, null, null, null, null);
}

/// Encode with explicit parameters (for testing determinism).
pub fn encodeRequestWithParams(
    buf: []u8,
    uuid: [16]u8,
    target: *const Session.TargetAddress,
    command: Command,
    security: SecurityMethod,
    options: OptionFlags,
    opt_timestamp: ?i64,
    opt_random: ?u32,
    opt_body_iv: ?[16]u8,
    opt_body_key: ?[16]u8,
    opt_resp_header: ?u8,
) ?usize {
    const cmd_key = vmess_crypto.deriveCmdKey(uuid);
    // Derive auth_key for AuthID generation (matches acppnode)
    const auth_key = vmess_crypto.deriveAuthKey(cmd_key);
    const timestamp = opt_timestamp orelse std.time.timestamp();
    const random_val = opt_random orelse boringssl.random.int(u32);

    // Generate AuthID using auth_key (NOT cmd_key!)
    const auth_id = vmess_crypto.generateAuthIdWithRandom(auth_key, timestamp, random_val);

    // Generate connection nonce
    var connection_nonce: [8]u8 = undefined;
    if (opt_random) |_| {
        @memset(&connection_nonce, 0x42); // Deterministic for testing
    } else {
        boringssl.random.bytes(&connection_nonce);
    }

    // Build plaintext header
    var header: [512]u8 = undefined;
    var pos: usize = 0;

    header[pos] = 0x01; // Version
    pos += 1;

    const body_iv = opt_body_iv orelse blk: {
        var iv: [16]u8 = undefined;
        boringssl.random.bytes(&iv);
        break :blk iv;
    };
    @memcpy(header[pos .. pos + 16], &body_iv);
    pos += 16;

    const body_key = opt_body_key orelse blk: {
        var k: [16]u8 = undefined;
        boringssl.random.bytes(&k);
        break :blk k;
    };
    @memcpy(header[pos .. pos + 16], &body_key);
    pos += 16;

    const resp_header: u8 = opt_resp_header orelse if (opt_random != null) @as(u8, 0xAB) else boringssl.random.int(u8);
    header[pos] = resp_header;
    pos += 1;

    header[pos] = @bitCast(options);
    pos += 1;

    const padding_len: u4 = 0;
    header[pos] = (@as(u8, padding_len) << 4) | @as(u8, @intFromEnum(security));
    pos += 1;

    header[pos] = 0x00; // Reserved
    pos += 1;

    header[pos] = @intFromEnum(command);
    pos += 1;

    std.mem.writeInt(u16, header[pos..][0..2], target.port, .big);
    pos += 2;

    switch (target.addr_type) {
        .ipv4 => {
            header[pos] = 0x01;
            pos += 1;
            @memcpy(header[pos .. pos + 4], &target.ip4);
            pos += 4;
        },
        .domain => {
            header[pos] = 0x02;
            pos += 1;
            header[pos] = target.domain_len;
            pos += 1;
            @memcpy(header[pos .. pos + target.domain_len], target.domain[0..target.domain_len]);
            pos += target.domain_len;
        },
        .ipv6 => {
            header[pos] = 0x03;
            pos += 1;
            @memcpy(header[pos .. pos + 16], &target.ip6);
            pos += 16;
        },
        .none => return null,
    }

    // FNV1a checksum
    const fnv = vmess_crypto.fnv1a32(header[0..pos]);
    @memcpy(header[pos .. pos + 4], &fnv);
    pos += 4;

    const header_len: u16 = @intCast(pos);

    // Wire format: AuthID(16) + EncLen(18) + Nonce(8) + EncHeader(N+16)
    const wire_len: usize = 16 + 18 + 8 + pos + 16;
    if (buf.len < wire_len) return null;

    var out_pos: usize = 0;

    // AuthID
    @memcpy(buf[out_pos .. out_pos + 16], &auth_id);
    out_pos += 16;

    // Encrypt header length (2B -> 2B ciphertext + 16B tag = 18B)
    const len_key = vmess_crypto.deriveHeaderLengthKey(cmd_key, auth_id, connection_nonce);
    const len_nonce = vmess_crypto.deriveHeaderLengthNonce(cmd_key, auth_id, connection_nonce);
    var len_plain: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_plain, header_len, .big);
    var len_tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(
        buf[out_pos .. out_pos + 2],
        &len_tag,
        &len_plain,
        &auth_id,
        len_nonce,
        len_key,
    );
    out_pos += 2;
    @memcpy(buf[out_pos .. out_pos + 16], &len_tag);
    out_pos += 16;

    // Connection nonce
    @memcpy(buf[out_pos .. out_pos + 8], &connection_nonce);
    out_pos += 8;

    // Encrypt header payload
    const hdr_key = vmess_crypto.deriveHeaderKey(cmd_key, auth_id, connection_nonce);
    const hdr_nonce = vmess_crypto.deriveHeaderNonce(cmd_key, auth_id, connection_nonce);
    var hdr_tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(
        buf[out_pos .. out_pos + pos],
        &hdr_tag,
        header[0..pos],
        &auth_id,
        hdr_nonce,
        hdr_key,
    );
    out_pos += pos;
    @memcpy(buf[out_pos .. out_pos + 16], &hdr_tag);
    out_pos += 16;

    return out_pos;
}

// ── Response Encoding/Parsing ──
//
// Response wire format (matches acppnode):
//   EncLen(18B): length(2B) + GCM tag(16B)  -- length plaintext = 0x0004
//   EncHeader(20B): header(4B) + GCM tag(16B)
//   Total: 38 bytes
//
// Response plaintext (4 bytes):
//   [0] response_header  -- echo back from request
//   [1] options           -- 0x00
//   [2] command           -- 0x00
//   [3] command_len       -- 0x00

/// Encode VMess AEAD response header (38 bytes).
/// Two-layer encryption matching acppnode:
///   Layer 1: Encrypt length (2B -> 18B) with resp_header_len key/nonce
///   Layer 2: Encrypt header payload (4B -> 20B) with resp_header key/nonce
pub fn encodeResponse(buf: []u8, request: *const VMessRequest) ?usize {
    if (buf.len < response_wire_size) return null;

    const resp_key = vmess_crypto.deriveResponseKey(request.request_body_key);
    const resp_iv = vmess_crypto.deriveResponseIv(request.request_body_iv);

    // Layer 1: Encrypt length = 4 (response payload size)
    const len_aead_key = vmess_crypto.kdfKey16(&resp_key, &.{vmess_crypto.kdf_salt_resp_header_len_key});
    const len_aead_nonce = vmess_crypto.kdfNonce12(&resp_iv, &.{vmess_crypto.kdf_salt_resp_header_len_nonce});
    var len_plain: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_plain, 4, .big); // Response payload is always 4 bytes
    var len_tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(buf[0..2], &len_tag, &len_plain, &[_]u8{}, len_aead_nonce, len_aead_key);
    @memcpy(buf[2..18], &len_tag);

    // Layer 2: Encrypt response header payload (4 bytes)
    const hdr_aead_key = vmess_crypto.kdfKey16(&resp_key, &.{vmess_crypto.kdf_salt_resp_header_key});
    const hdr_aead_nonce = vmess_crypto.kdfNonce12(&resp_iv, &.{vmess_crypto.kdf_salt_resp_header_nonce});
    var hdr_plain: [4]u8 = undefined;
    hdr_plain[0] = request.response_header;
    hdr_plain[1] = 0x00; // options
    hdr_plain[2] = 0x00; // command
    hdr_plain[3] = 0x00; // command_len
    var hdr_tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(buf[18..22], &hdr_tag, &hdr_plain, &[_]u8{}, hdr_aead_nonce, hdr_aead_key);
    @memcpy(buf[22..38], &hdr_tag);

    return response_wire_size;
}

/// Parse VMess AEAD response header (38 bytes, two-layer decryption).
pub fn parseResponse(
    data: []const u8,
    request_body_key: [16]u8,
    request_body_iv: [16]u8,
    expected_response_header: u8,
) ResponseParseResult {
    if (data.len < response_wire_size) return .incomplete;

    const resp_key = vmess_crypto.deriveResponseKey(request_body_key);
    const resp_iv = vmess_crypto.deriveResponseIv(request_body_iv);

    // Layer 1: Decrypt length
    const len_aead_key = vmess_crypto.kdfKey16(&resp_key, &.{vmess_crypto.kdf_salt_resp_header_len_key});
    const len_aead_nonce = vmess_crypto.kdfNonce12(&resp_iv, &.{vmess_crypto.kdf_salt_resp_header_len_nonce});
    var len_plain: [2]u8 = undefined;
    Aes128Gcm.decrypt(
        &len_plain,
        data[0..2],
        data[2..18].*,
        &[_]u8{},
        len_aead_nonce,
        len_aead_key,
    ) catch return .protocol_error;

    const payload_len = std.mem.readInt(u16, &len_plain, .big);
    if (payload_len != 4) return .protocol_error; // Response payload is always 4 bytes

    // Layer 2: Decrypt header payload
    const hdr_aead_key = vmess_crypto.kdfKey16(&resp_key, &.{vmess_crypto.kdf_salt_resp_header_key});
    const hdr_aead_nonce = vmess_crypto.kdfNonce12(&resp_iv, &.{vmess_crypto.kdf_salt_resp_header_nonce});
    var hdr_plain: [4]u8 = undefined;
    Aes128Gcm.decrypt(
        &hdr_plain,
        data[18..22],
        data[22..38].*,
        &[_]u8{},
        hdr_aead_nonce,
        hdr_aead_key,
    ) catch return .protocol_error;

    // Verify response header byte
    if (hdr_plain[0] != expected_response_header) return .validation_failed;

    return .{ .success = .{
        .response_header = hdr_plain[0],
        .options = hdr_plain[1],
        .command = hdr_plain[2],
        .command_len = hdr_plain[3],
        .bytes_consumed = response_wire_size,
    } };
}

// ── Streaming Parse Helpers ──

/// Result of streaming step 1: user authenticated + header length decoded.
/// Replay check is deferred to step 2 (after reading the full header).
pub const StreamStep1Result = struct {
    header_len: u16,
    cmd_key: vmess_crypto.CmdKey,
    auth_id: vmess_crypto.AuthID,
    connection_nonce: [8]u8,
    user: ?*const user_store.UserStore.UserInfo,
};

/// Streaming step 1: scan users + decode header length from the 42-byte preamble.
/// Returns null if no user matches (auth failed).
/// HotCache locking is handled internally by HotCache.tryAuth / recordAuth / evictUser;
/// callers do NOT need to hold any external lock for this function.
pub fn streamStep1(
    preamble: *const [42]u8,
    user_map: *const user_store.UserStore.UserMap,
    hot_cache: ?*vmess_hot_cache.HotCache,
    allocator: std.mem.Allocator,
    now: i64,
) ?StreamStep1Result {
    const auth_id: vmess_crypto.AuthID = preamble[0..16].*;
    const enc_length_block = preamble[16..34];
    const connection_nonce: [8]u8 = preamble[34..42].*;

    // Fast path: hot cache
    if (hot_cache) |cache| {
        if (cache.tryAuth(auth_id, now, allocator)) |hit| {
            if (user_map.findById(hit.user_id)) |user| {
                if (user.enabled) {
                    if (tryPeekHeaderLen(enc_length_block, hit.cmd_key, auth_id, connection_nonce)) |header_len| {
                        return .{ .header_len = header_len, .cmd_key = hit.cmd_key, .auth_id = auth_id, .connection_nonce = connection_nonce, .user = user };
                    }
                }
            }
            cache.evictUser(hit.user_id, allocator);
        }
    }

    // Slow path: full user scan
    for (user_map.users) |*user| {
        if (!user.enabled) continue;
        const auth_key = user.cached_auth_key;
        _ = vmess_crypto.validateAuthId(auth_id, auth_key, now) orelse continue;
        const cmd_key = user.cached_cmd_key;
        if (tryPeekHeaderLen(enc_length_block, cmd_key, auth_id, connection_nonce)) |header_len| {
            if (hot_cache) |cache| cache.recordAuth(user.id, cmd_key, auth_key, now, allocator, @max(1, user_map.users.len / 10));
            return .{ .header_len = header_len, .cmd_key = cmd_key, .auth_id = auth_id, .connection_nonce = connection_nonce, .user = user };
        }
    }

    return null;
}

/// Peek header length: decrypt only the 18-byte length block without consuming it.
/// Returns null if GCM auth fails (wrong key).
fn tryPeekHeaderLen(
    enc_length_block: []const u8,
    cmd_key: vmess_crypto.CmdKey,
    auth_id: vmess_crypto.AuthID,
    connection_nonce: [8]u8,
) ?u16 {
    const length_key = vmess_crypto.deriveHeaderLengthKey(cmd_key, auth_id, connection_nonce);
    const length_nonce = vmess_crypto.deriveHeaderLengthNonce(cmd_key, auth_id, connection_nonce);

    var length_plain: [2]u8 = undefined;
    Aes128Gcm.decrypt(
        &length_plain,
        enc_length_block[0..2],
        enc_length_block[2..18].*,
        &auth_id,
        length_nonce,
        length_key,
    ) catch return null;

    return std.mem.readInt(u16, &length_plain, .big);
}

/// Streaming step 2: decrypt VMess header + replay check using step1 result.
/// full_data must span bytes [0 .. 42 + step1.header_len + 16].
/// Call with replay_mutex held.
pub fn streamStep2(
    full_data: []const u8,
    step1: StreamStep1Result,
    replay_filter: *ReplayFilter,
    now: i64,
    allocator: std.mem.Allocator,
) ParseResult {
    const total_len: usize = 42 + @as(usize, step1.header_len) + 16;
    if (full_data.len < total_len) return .incomplete;

    const header_key = vmess_crypto.deriveHeaderKey(step1.cmd_key, step1.auth_id, step1.connection_nonce);
    const header_nonce = vmess_crypto.deriveHeaderNonce(step1.cmd_key, step1.auth_id, step1.connection_nonce);

    var header_plain: [512]u8 = undefined;
    if (step1.header_len > header_plain.len) return .protocol_error;

    const enc_header = full_data[42 .. 42 + step1.header_len];
    const header_tag = full_data[42 + step1.header_len .. total_len];

    Aes128Gcm.decrypt(
        header_plain[0..step1.header_len],
        enc_header,
        header_tag[0..16].*,
        &step1.auth_id,
        header_nonce,
        header_key,
    ) catch return .protocol_error;

    if (replay_filter.isDuplicate(step1.auth_id, now, allocator)) return .replay_detected;

    return parseDecryptedHeader(
        header_plain[0..step1.header_len],
        total_len,
        step1.cmd_key,
        step1.connection_nonce,
        step1.user,
    );
}

// ── Tests ──

const testing = std.testing;

fn makeTestTarget(comptime addr_type: Session.TargetAddress.AddressType) Session.TargetAddress {
    var t = Session.TargetAddress{};
    switch (addr_type) {
        .ipv4 => t.setIpv4(.{ 1, 2, 3, 4 }, 443),
        .domain => t.setDomain("example.com", 80),
        .ipv6 => t.setIpv6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }, 8443),
        .none => {},
    }
    return t;
}

test "encodeRequest and parseRequest roundtrip IPv4" {
    const uuid = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01 };
    const cmd_key = vmess_crypto.deriveCmdKey(uuid);
    const target = makeTestTarget(.ipv4);
    const timestamp: i64 = 1700000000;
    const body_iv = [_]u8{0x11} ** 16;
    const body_key = [_]u8{0x22} ** 16;
    const options = OptionFlags{ .chunk_stream = true, .chunk_masking = true };

    var buf: [1024]u8 = undefined;
    const n = encodeRequestWithParams(
        &buf,
        uuid,
        &target,
        .tcp,
        .aes_128_gcm,
        options,
        timestamp,
        0x12345678,
        body_iv,
        body_key,
        null,
    ) orelse return error.EncodeFailed;

    var replay = ReplayFilter{};
    defer replay.deinit(std.testing.allocator);
    const result = parseRequestWithKey(buf[0..n], cmd_key, null, &replay, timestamp, std.testing.allocator);

    switch (result) {
        .success => |req| {
            try testing.expectEqual(@as(u8, 0x01), req.version);
            try testing.expectEqual(body_iv, req.request_body_iv);
            try testing.expectEqual(body_key, req.request_body_key);
            try testing.expectEqual(Command.tcp, req.command);
            try testing.expectEqual(SecurityMethod.aes_128_gcm, req.security);
            try testing.expectEqual(Session.TargetAddress.AddressType.ipv4, req.target.addr_type);
            try testing.expectEqual(@as(u16, 443), req.target.port);
            try testing.expectEqual([_]u8{ 1, 2, 3, 4 }, req.target.ip4);
        },
        else => return error.UnexpectedResult,
    }
}

test "encodeRequest and parseRequest roundtrip domain" {
    const uuid = [_]u8{0xAA} ** 16;
    const cmd_key = vmess_crypto.deriveCmdKey(uuid);
    const target = makeTestTarget(.domain);
    const timestamp: i64 = 1700000000;

    var buf: [1024]u8 = undefined;
    const n = encodeRequestWithParams(
        &buf,
        uuid,
        &target,
        .udp,
        .chacha20_poly1305,
        .{ .chunk_stream = true },
        timestamp,
        0,
        [_]u8{0x33} ** 16,
        [_]u8{0x44} ** 16,
        null,
    ) orelse return error.EncodeFailed;

    var replay = ReplayFilter{};
    defer replay.deinit(std.testing.allocator);
    const result = parseRequestWithKey(buf[0..n], cmd_key, null, &replay, timestamp, std.testing.allocator);

    switch (result) {
        .success => |req| {
            try testing.expectEqual(Command.udp, req.command);
            try testing.expectEqual(SecurityMethod.chacha20_poly1305, req.security);
            try testing.expectEqual(Session.TargetAddress.AddressType.domain, req.target.addr_type);
            try testing.expectEqual(@as(u16, 80), req.target.port);
            try testing.expectEqualStrings("example.com", req.target.domain[0..req.target.domain_len]);
        },
        else => return error.UnexpectedResult,
    }
}

test "encodeRequest and parseRequest roundtrip IPv6" {
    const uuid = [_]u8{0xBB} ** 16;
    const cmd_key = vmess_crypto.deriveCmdKey(uuid);
    const target = makeTestTarget(.ipv6);
    const timestamp: i64 = 1700000000;

    var buf: [1024]u8 = undefined;
    const n = encodeRequestWithParams(&buf, uuid, &target, .tcp, .none, .{}, timestamp, 0, [_]u8{0x55} ** 16, [_]u8{0x66} ** 16, null) orelse return error.EncodeFailed;

    var replay = ReplayFilter{};
    defer replay.deinit(std.testing.allocator);
    const result = parseRequestWithKey(buf[0..n], cmd_key, null, &replay, timestamp, std.testing.allocator);

    switch (result) {
        .success => |req| {
            try testing.expectEqual(Session.TargetAddress.AddressType.ipv6, req.target.addr_type);
            try testing.expectEqual(@as(u16, 8443), req.target.port);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseRequest incomplete data" {
    const cmd_key = [_]u8{0x01} ** 16;
    var replay = ReplayFilter{};
    defer replay.deinit(std.testing.allocator);
    const result = parseRequestWithKey(&[_]u8{0} ** 20, cmd_key, null, &replay, 0, std.testing.allocator);
    try testing.expect(result == .incomplete);
}

test "parseRequest wrong key" {
    const uuid = [_]u8{0xCC} ** 16;
    const wrong_key = [_]u8{0xDD} ** 16;
    const target = makeTestTarget(.ipv4);
    const timestamp: i64 = 1700000000;

    var buf: [1024]u8 = undefined;
    const n = encodeRequestWithParams(&buf, uuid, &target, .tcp, .aes_128_gcm, .{}, timestamp, 0, [_]u8{0} ** 16, [_]u8{0} ** 16, null) orelse return error.EncodeFailed;

    var replay = ReplayFilter{};
    defer replay.deinit(std.testing.allocator);
    const result = parseRequestWithKey(buf[0..n], wrong_key, null, &replay, timestamp, std.testing.allocator);
    try testing.expect(result == .auth_failed);
}

test "parseRequest replay detection" {
    const uuid = [_]u8{0xEE} ** 16;
    const cmd_key = vmess_crypto.deriveCmdKey(uuid);
    const target = makeTestTarget(.ipv4);
    const timestamp: i64 = 1700000000;

    var buf: [1024]u8 = undefined;
    const n = encodeRequestWithParams(&buf, uuid, &target, .tcp, .aes_128_gcm, .{}, timestamp, 0x42, [_]u8{0} ** 16, [_]u8{0} ** 16, null) orelse return error.EncodeFailed;

    var replay = ReplayFilter{};
    defer replay.deinit(std.testing.allocator);

    // First parse should succeed
    const r1 = parseRequestWithKey(buf[0..n], cmd_key, null, &replay, timestamp, std.testing.allocator);
    try testing.expect(r1 == .success);

    // Second parse with same data should detect replay
    const r2 = parseRequestWithKey(buf[0..n], cmd_key, null, &replay, timestamp, std.testing.allocator);
    try testing.expect(r2 == .replay_detected);
}

test "cross-implementation: full wire output matches Xray-core Go reference" {
    // UUID: bf417eb3-d283-5487-b6ad-9a9be278be8a
    const uuid = [_]u8{ 0xbf, 0x41, 0x7e, 0xb3, 0xd2, 0x83, 0x54, 0x87, 0xb6, 0xad, 0x9a, 0x9b, 0xe2, 0x78, 0xbe, 0x8a };
    const timestamp: i64 = 1700000000;
    const random_val: u32 = 0xDEADBEEF;
    const body_iv = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
    const body_key = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
    const resp_header: u8 = 0xAB;

    // Target: 1.2.3.4:443 (IPv4)
    var target = Session.TargetAddress{};
    target.setIpv4(.{ 1, 2, 3, 4 }, 443);

    const options = OptionFlags{ .chunk_stream = true, .chunk_masking = true };

    var buf: [1024]u8 = undefined;
    const wire_len = encodeRequestWithParams(
        &buf, uuid, &target, .tcp, .aes_128_gcm, options,
        timestamp, random_val, body_iv, body_key, resp_header,
    ) orelse return error.EncodeFailed;

    // Go reference: wire_len=107
    try testing.expectEqual(@as(usize, 107), wire_len);

    // Go reference wire (hex): aecdf507eff0267642c5d072917f7aaec80cb364...
    const expected_wire = [_]u8{
        0xae, 0xcd, 0xf5, 0x07, 0xef, 0xf0, 0x26, 0x76, 0x42, 0xc5, 0xd0, 0x72, 0x91, 0x7f, 0x7a, 0xae,
        0xc8, 0x0c, 0xb3, 0x64, 0xde, 0x0c, 0xbb, 0xfc, 0xbb, 0x5f, 0x66, 0x6e, 0xac, 0xeb, 0x8d, 0xdc,
        0x2e, 0xd3, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0xa4, 0x3c, 0x01, 0x19, 0xf3, 0xbd,
        0xca, 0x46, 0xee, 0xcd, 0xad, 0x80, 0x70, 0x9b, 0xbb, 0x08, 0x66, 0xcc, 0xae, 0xf4, 0xac, 0x15,
        0x0f, 0xe0, 0xdc, 0xd7, 0x7a, 0xf0, 0xcd, 0x83, 0x13, 0x7f, 0x63, 0x5e, 0x1e, 0xe2, 0xc6, 0xbf,
        0x82, 0xce, 0x95, 0x10, 0x05, 0xcc, 0x16, 0x95, 0xd3, 0xa1, 0x25, 0xb5, 0x86, 0xe2, 0x1f, 0x3d,
        0x73, 0xf2, 0x44, 0x1f, 0x61, 0xf7, 0x6f, 0x54, 0x3f, 0x27, 0xc5,
    };

    try testing.expectEqualSlices(u8, &expected_wire, buf[0..wire_len]);
}

test "encodeResponse and parseResponse roundtrip" {
    const body_key = [_]u8{0x77} ** 16;
    const body_iv = [_]u8{0x88} ** 16;
    const resp_header: u8 = 0xAB;

    const req = VMessRequest{
        .version = 0x01,
        .request_body_iv = body_iv,
        .request_body_key = body_key,
        .response_header = resp_header,
        .options = .{},
        .padding_len = 0,
        .security = .aes_128_gcm,
        .command = .tcp,
        .target = .{},
        .header_len = 0,
        .cmd_key = [_]u8{0} ** 16,
        .connection_nonce = [_]u8{0} ** 8,
        .matched_user = null,
    };

    var buf: [64]u8 = undefined;
    const n = encodeResponse(&buf, &req) orelse return error.EncodeFailed;
    try testing.expectEqual(@as(usize, 38), n); // 18 + 20 = 38B

    const result = parseResponse(buf[0..n], body_key, body_iv, resp_header);
    switch (result) {
        .success => |resp| {
            try testing.expectEqual(resp_header, resp.response_header);
            try testing.expectEqual(@as(u8, 0x00), resp.options);
            try testing.expectEqual(@as(u8, 0x00), resp.command);
            try testing.expectEqual(@as(u8, 0x00), resp.command_len);
            try testing.expectEqual(@as(usize, 38), resp.bytes_consumed);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseResponse validation byte mismatch" {
    const body_key = [_]u8{0x77} ** 16;
    const body_iv = [_]u8{0x88} ** 16;

    const req = VMessRequest{
        .version = 0x01,
        .request_body_iv = body_iv,
        .request_body_key = body_key,
        .response_header = 0xAB,
        .options = .{},
        .padding_len = 0,
        .security = .aes_128_gcm,
        .command = .tcp,
        .target = .{},
        .header_len = 0,
        .cmd_key = [_]u8{0} ** 16,
        .connection_nonce = [_]u8{0} ** 8,
        .matched_user = null,
    };

    var buf: [64]u8 = undefined;
    const n = encodeResponse(&buf, &req) orelse return error.EncodeFailed;

    // Parse with wrong expected header byte
    const result = parseResponse(buf[0..n], body_key, body_iv, 0xFF);
    try testing.expect(result == .validation_failed);
}

test "parseResponse incomplete" {
    const result = parseResponse(&[_]u8{0} ** 10, [_]u8{0} ** 16, [_]u8{0} ** 16, 0);
    try testing.expect(result == .incomplete);
}

test "OptionFlags packing" {
    const flags = OptionFlags{ .chunk_stream = true, .chunk_masking = true };
    const byte: u8 = @bitCast(flags);
    try testing.expectEqual(@as(u8, 0x05), byte); // bit 0 + bit 2
}

test "SecurityMethod enum values" {
    try testing.expectEqual(@as(u4, 0x03), @intFromEnum(SecurityMethod.aes_128_gcm));
    try testing.expectEqual(@as(u4, 0x04), @intFromEnum(SecurityMethod.chacha20_poly1305));
    try testing.expectEqual(@as(u4, 0x05), @intFromEnum(SecurityMethod.none));
    try testing.expectEqual(@as(u4, 0x06), @intFromEnum(SecurityMethod.aes_256_gcm));
}

test "ReplayFilter deduplication" {
    var filter = ReplayFilter{};
    defer filter.deinit(std.testing.allocator);
    const auth_id = [_]u8{0xAA} ** 16;
    const now: i64 = 1700000000;

    try testing.expect(!filter.isDuplicate(auth_id, now, std.testing.allocator)); // First time: not duplicate
    try testing.expect(filter.isDuplicate(auth_id, now, std.testing.allocator)); // Second time: duplicate
}

test "ReplayFilter expiration" {
    var filter = ReplayFilter{};
    defer filter.deinit(std.testing.allocator);
    const auth_id = [_]u8{0xBB} ** 16;
    const now: i64 = 1700000000;

    try testing.expect(!filter.isDuplicate(auth_id, now, std.testing.allocator));

    // After expiration window, should not be detected as duplicate
    try testing.expect(!filter.isDuplicate(auth_id, now + vmess_crypto.auth_id_window + 1, std.testing.allocator));
}

test "encodeRequest buffer too small" {
    const uuid = [_]u8{0xFF} ** 16;
    const target = makeTestTarget(.ipv4);
    var buf: [10]u8 = undefined; // Way too small
    const result = encodeRequest(&buf, uuid, &target, .tcp, .aes_128_gcm, .{});
    try testing.expect(result == null);
}

test "encodeRequest invalid target" {
    const uuid = [_]u8{0xFF} ** 16;
    const target = Session.TargetAddress{}; // addr_type = .none
    var buf: [1024]u8 = undefined;
    const result = encodeRequest(&buf, uuid, &target, .tcp, .aes_128_gcm, .{});
    try testing.expect(result == null);
}
