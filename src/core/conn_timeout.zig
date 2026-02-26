// ══════════════════════════════════════════════════════════════
//  Timeout Manager — Sub-struct for Session
//
//  Manages handshake, idle, and half-close timeouts via xev Timer.
//  Uses @fieldParentPtr("timeout", self) to access Session.
// ══════════════════════════════════════════════════════════════

const std = @import("std");
const xev = @import("xev");

/// Timeout management state: timer, scheduling, and activity tracking.
/// Embedded in Session as `timeout` field.
pub const TimeoutManager = struct {
    timer: ?xev.Timer = null,
    comp: xev.Completion = .{},
    cancel_comp: xev.Completion = .{},
    active: bool = false, // timer run is pending
    due_ms: u64 = 0, // absolute due timestamp for the pending timeout run
    rearm_ms: u64 = 0, // cancel-confirmed rearm delay (0 = no rearm)
    last_activity_ms: u64 = 0, // timestamp for idle check

    /// Update last activity timestamp (call on relay data transfer).
    pub fn touchActivity(self: *TimeoutManager) void {
        self.last_activity_ms = currentMs();
    }

    /// Deinitialize timer resource.
    pub fn deinitTimer(self: *TimeoutManager) void {
        if (self.timer) |*t| t.deinit();
    }

    pub fn currentMs() u64 {
        return @intCast(@max(0, std.time.milliTimestamp()));
    }
};
