// ══════════════════════════════════════════════════════════════
//  Connection Lifecycle — Sub-struct for Session
//
//  FSM state, pending_ops ref counting, and close tracking.
// ══════════════════════════════════════════════════════════════

const conn_fsm = @import("connection_fsm.zig");
const conn_types = @import("conn_types.zig");

pub const ConnFSM = conn_fsm.ConnFSM;
pub const CloseReason = conn_types.CloseReason;

/// Connection lifecycle state: FSM, ref counting, close tracking.
/// Embedded in Session as `lifecycle` field.
pub const Lifecycle = struct {
    fsm: ConnFSM = .{},
    pending_ops: u16 = 0,
    close_count: u8 = 0,
    sockets_to_close: u8 = 1, // 1 for client only, 2 when target connected
    close_reason: CloseReason = .none,
    half_close_start_ms: u64 = 0, // timestamp when half-close began (0 = not in half-close)

    pub fn trackOp(self: *Lifecycle) void {
        self.pending_ops += 1;
    }
};
