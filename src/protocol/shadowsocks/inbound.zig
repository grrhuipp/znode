/// Shadowsocks AEAD inbound handler.
///
/// Flow:
/// 1. Read salt (cipher.salt_len bytes)
/// 2. Read first length chunk (18 bytes)
/// 3. Trial decrypt with each user's master key (salt trial auth)
/// 4. Decrypt first payload chunk → extract SOCKS5 address header
/// 5. Return ParsedAction with target + SsStream wrapping
const std = @import("std");
const types = @import("../../common/types.zig");
const session = @import("../../app/session.zig");
const protocol = @import("protocol.zig");
const user_manager_mod = @import("user_manager.zig");
const stream_mod = @import("stream.zig");
const aead_mod = @import("../../infra/crypto/aead.zig");

pub const ParsedAction = struct {
    target: types.TargetAddress,
    network: types.Network,
    initial_payload: []const u8, // leftover data after address header
    // Subkey and cipher info needed to construct SsStream
    read_subkey: [protocol.max_key_len]u8,
    read_subkey_len: usize,
    cipher_type: aead_mod.CipherType,
    // Master key for generating write subkey (server→client direction)
    master_key: [protocol.max_key_len]u8,
    master_key_len: usize,
    // First chunk already decrypted data (address + maybe payload)
    first_dec_buf: [protocol.max_payload_size]u8,
    first_dec_len: usize,
    // Remaining raw bytes after length chunk + data chunk already consumed
    first_chunk_nonce: u64, // nonce counter after consuming first chunks
};

pub const InboundError = error{
    AuthFailed,
    InvalidProtocol,
    NeedMoreData,
    BufferOverflow,
    InnerStreamError,
    CryptoFailed,
};

pub const SsInboundHandler = struct {
    user_manager: *const user_manager_mod.UserManager,

    pub fn init(um: *const user_manager_mod.UserManager) SsInboundHandler {
        return .{ .user_manager = um };
    }

    /// Read salt + first chunk from transport, authenticate via trial decryption,
    /// parse SOCKS5 address from decrypted payload.
    pub fn parseStream(
        self: *const SsInboundHandler,
        comptime Transport: type,
        transport: *Transport,
        ctx: *session.SessionContext,
    ) InboundError!ParsedAction {
        // Determine salt and chunk sizes from first user (all users share same cipher)
        if (self.user_manager.users.len == 0) return error.AuthFailed;
        const cipher_info = self.user_manager.users[0].cipher_info;
        const salt_len = cipher_info.salt_len;
        const len_chunk_size = 2 + protocol.tag_len; // 18

        // Read salt
        var salt_buf: [protocol.max_salt_len]u8 = undefined;
        var salt_filled: usize = 0;
        while (salt_filled < salt_len) {
            const n = transport.read(salt_buf[salt_filled..salt_len]) catch
                return error.InnerStreamError;
            if (n == 0) return error.InvalidProtocol;
            salt_filled += n;
        }
        const salt = salt_buf[0..salt_len];

        // Read first length chunk
        var first_len_chunk: [2 + protocol.tag_len]u8 = undefined; // 18 bytes
        var len_filled: usize = 0;
        while (len_filled < len_chunk_size) {
            const n = transport.read(first_len_chunk[len_filled..len_chunk_size]) catch
                return error.InnerStreamError;
            if (n == 0) return error.InvalidProtocol;
            len_filled += n;
        }

        // Trial decrypt to authenticate
        const auth = self.user_manager.trialDecrypt(salt, &first_len_chunk) orelse
            return error.AuthFailed;

        // Fill session context
        ctx.user_id = auth.user.user_id;
        ctx.setUserEmail(auth.user.email);
        ctx.speed_limit = auth.user.speed_limit_bytes;
        ctx.inbound_protocol = .shadowsocks;

        // We already know the length is valid (trialDecrypt verified it)
        // Re-decrypt to get actual length value
        var len_plain: [2]u8 = undefined;
        const nonce0 = aead_mod.ssNonce(0);
        _ = aead_mod.decrypt(
            cipher_info.cipher_type,
            auth.subkey[0..auth.subkey_len],
            &nonce0,
            &first_len_chunk,
            &.{},
            &len_plain,
        ) catch return error.CryptoFailed;
        const payload_len: usize = (@as(u16, len_plain[0]) << 8) | @as(u16, len_plain[1]);

        // Read first data chunk (payload_len + tag_len bytes)
        const data_chunk_size = payload_len + protocol.tag_len;
        var data_chunk_buf: [protocol.max_payload_size + protocol.tag_len]u8 = undefined;
        var data_filled: usize = 0;
        while (data_filled < data_chunk_size) {
            const n = transport.read(data_chunk_buf[data_filled..data_chunk_size]) catch
                return error.InnerStreamError;
            if (n == 0) return error.InvalidProtocol;
            data_filled += n;
        }

        // Decrypt first data chunk
        var result: ParsedAction = undefined;
        const nonce1 = aead_mod.ssNonce(1);
        const dec_len = aead_mod.decrypt(
            cipher_info.cipher_type,
            auth.subkey[0..auth.subkey_len],
            &nonce1,
            data_chunk_buf[0..data_chunk_size],
            &.{},
            &result.first_dec_buf,
        ) catch return error.CryptoFailed;
        result.first_dec_len = dec_len;
        result.cipher_type = cipher_info.cipher_type;
        result.read_subkey = auth.subkey;
        result.read_subkey_len = auth.subkey_len;
        result.master_key = auth.user.master_key;
        result.master_key_len = auth.user.master_key_len;
        result.first_chunk_nonce = 2; // consumed nonces 0 (length) and 1 (data)

        // Parse SOCKS5 address from decrypted payload
        const dec_data = result.first_dec_buf[0..dec_len];
        var addr_index: usize = 0;
        const target = protocol.parseAddress(dec_data, &addr_index) catch
            return error.InvalidProtocol;

        ctx.target = target;
        ctx.network = .tcp; // SS TCP stream
        result.target = target;
        result.network = .tcp;

        // Data after address header is initial payload
        if (addr_index < dec_len) {
            result.initial_payload = result.first_dec_buf[addr_index..dec_len];
            ctx.setFirstPacket(result.first_dec_buf[addr_index..dec_len]);
        } else {
            result.initial_payload = &.{};
        }

        return result;
    }
};
