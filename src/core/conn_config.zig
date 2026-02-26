// ══════════════════════════════════════════════════════════════
//  Connection Config — Sub-struct for Session
//
//  Per-connection immutable configuration, set at create() time
//  from listener info. Pure data container.
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const log = @import("log.zig");
const tls_mod = @import("../transport/tls_stream.zig");
const user_store_mod = @import("user_store.zig");
const Worker = @import("worker.zig").Worker;

/// Per-connection configuration (immutable after create()).
/// Embedded in Session as `cfg` field.
pub const ConnConfig = struct {
    worker: *Worker,
    logger: log.ScopedLogger,
    listener_id: u8 = 0,
    tls_ctx_ptr: ?*tls_mod.TlsContext = null,
    user_store_ptr: ?*user_store_mod.UserStore = null,
    enable_routing: bool = false,
    fallback_addr: ?std.net.Address = null,
    local_addr: ?std.net.Address = null,
    inbound_tag_buf: [64]u8 = [_]u8{0} ** 64,
    inbound_tag_len: u8 = 0,
};
