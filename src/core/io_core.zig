// ══════════════════════════════════════════════════════════════
//  I/O Core — Sub-struct for Session
//
//  TCP handles, TLS/WS transport, xev Completion objects,
//  pool-borrowed buffers, and I/O state flags.
// ══════════════════════════════════════════════════════════════

const xev = @import("xev");
const tls_mod = @import("../transport/tls_stream.zig");
const ws_mod = @import("../transport/ws_stream.zig");
const buffer_pool = @import("buffer_pool.zig");

pub const pool_medium = buffer_pool.BufferPool.medium_size; // 8KB
pub const pool_iodata = buffer_pool.BufferPool.iodata_size; // 20KB

/// I/O core: TCP handles, transport layers, completions, buffers.
/// Embedded in Session as `io` field.
pub const IoCore = struct {
    // ── TCP handles ──
    client_tcp: xev.TCP,
    target_tcp: ?xev.TCP = null,

    // ── Transport layers ──
    tls: ?tls_mod.TlsStream = null, // inbound TLS
    target_tls: ?tls_mod.TlsStream = null, // outbound TLS
    outbound_ws: ?*ws_mod.WsStream = null, // outbound WS (heap, freed after handshake)
    outbound_ws_active: bool = false, // WS transport persistent flag

    // ── xev Completion objects (one per pending I/O) ──
    client_read_comp: xev.Completion = .{},
    client_write_comp: xev.Completion = .{},
    target_read_comp: xev.Completion = .{},
    target_write_comp: xev.Completion = .{},
    connect_comp: xev.Completion = .{},
    client_close_comp: xev.Completion = .{},
    target_close_comp: xev.Completion = .{},

    // ── I/O state flags ──
    client_read_pending: bool = false, // client_read_comp has pending I/O
    early_detect_active: bool = false, // early disconnect detection read active
    pending_downlink_flush: bool = false, // VMess outbound: pending flush at relay start
    vmess_response_pending: bool = false, // VMess outbound: response read deferred

    // ── Buffers (pool-borrowed slices, null when not in use) ──
    recv_buf: ?[]u8 = null, // client TCP recv (8KB medium)
    decrypt_buf: ?[]u8 = null, // TLS decrypted / protocol plaintext (20KB iodata)
    target_buf: ?[]u8 = null, // target TCP recv — downlink (8KB medium)
    send_buf: ?[]u8 = null, // encrypt output → client TCP write (20KB iodata)
    protocol_buf: ?[]u8 = null, // protocol header accumulation (8KB medium)
    protocol_buf_len: usize = 0,
    // Inbound chunk accumulation (VMess/SS, chunks may span TCP segments)
    inbound_pending: ?[]u8 = null, // pool large (32KB iodata)
    inbound_pending_head: usize = 0,
    inbound_pending_tail: usize = 0,

    // ── Buffer pool helpers: lazy acquire ──

    pub fn ensureRecvBuf(self: *IoCore, pool: *buffer_pool.BufferPool) ?[]u8 {
        if (self.recv_buf) |b| return b;
        self.recv_buf = pool.acquire(pool_medium) catch return null;
        return self.recv_buf;
    }

    pub fn ensureDecryptBuf(self: *IoCore, pool: *buffer_pool.BufferPool) ?[]u8 {
        if (self.decrypt_buf) |b| return b;
        self.decrypt_buf = pool.acquire(pool_iodata) catch return null;
        return self.decrypt_buf;
    }

    pub fn ensureTargetBuf(self: *IoCore, pool: *buffer_pool.BufferPool) ?[]u8 {
        if (self.target_buf) |b| return b;
        self.target_buf = pool.acquire(pool_medium) catch return null;
        return self.target_buf;
    }

    pub fn ensureSendBuf(self: *IoCore, pool: *buffer_pool.BufferPool) ?[]u8 {
        if (self.send_buf) |b| return b;
        self.send_buf = pool.acquire(pool_iodata) catch return null;
        return self.send_buf;
    }

    pub fn ensureProtocolBuf(self: *IoCore, pool: *buffer_pool.BufferPool) ?[]u8 {
        if (self.protocol_buf) |b| return b;
        self.protocol_buf = pool.acquire(pool_medium) catch return null;
        return self.protocol_buf;
    }

    pub fn ensureInboundPending(self: *IoCore, pool: *buffer_pool.BufferPool) ?[]u8 {
        if (self.inbound_pending) |b| return b;
        self.inbound_pending = pool.acquire(pool_iodata) catch return null;
        return self.inbound_pending;
    }

    /// Release protocol_buf back to pool (called at handshake→relay transition).
    pub fn releaseProtocolBuf(self: *IoCore, pool: *buffer_pool.BufferPool) void {
        if (self.protocol_buf) |b| {
            pool.release(b);
            self.protocol_buf = null;
            self.protocol_buf_len = 0;
        }
    }

    /// Release all pool-borrowed buffers (called in destroy).
    pub fn releaseAllBuffers(self: *IoCore, pool: *buffer_pool.BufferPool, allocator: std.mem.Allocator) void {
        if (self.tls) |*tls| tls.deinit();
        if (self.target_tls) |*ttls| ttls.deinit();
        if (self.outbound_ws) |ws| allocator.destroy(ws);
        if (self.recv_buf) |b| pool.release(b);
        if (self.decrypt_buf) |b| pool.release(b);
        if (self.target_buf) |b| pool.release(b);
        if (self.send_buf) |b| pool.release(b);
        if (self.protocol_buf) |b| pool.release(b);
        if (self.inbound_pending) |b| pool.release(b);
    }
};

const std = @import("std");
