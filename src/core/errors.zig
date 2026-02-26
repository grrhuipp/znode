const std = @import("std");

/// Unified error set for the znode proxy server.
/// Maps to the C++ acppnode error categories.
pub const Error = error{
    // Connection errors
    ConnectionReset,
    ConnectionRefused,
    ConnectionTimeout,
    ConnectionClosed,

    // Protocol errors
    ProtocolViolation,
    UnsupportedProtocol,
    UnsupportedCommand,
    InvalidAddress,
    InvalidHeader,

    // Authentication errors
    AuthenticationFailed,
    UserNotFound,
    UserDisabled,
    ReplayDetected,

    // TLS errors
    TlsHandshakeFailed,
    TlsCertificateError,
    TlsAlertReceived,

    // DNS errors
    DnsResolutionFailed,
    DnsTimeout,
    DnsNxDomain,

    // Resource errors
    BufferExhausted,
    ConnectionLimitReached,
    RateLimitExceeded,
    OutOfMemory,

    // I/O errors
    ReadFailed,
    WriteFailed,
    Timeout,
    WouldBlock,

    // Router errors
    NoRouteFound,
    OutboundNotFound,

    // Panel errors
    PanelApiError,
    PanelSyncFailed,
};

/// Log severity levels (matching log.zig).
pub const Severity = enum { debug, info, warn, err };

/// Error context for logging and debugging.
pub const ErrorContext = struct {
    err: Error,
    message: []const u8 = "",
    conn_id: u64 = 0,
    worker_id: u16 = 0,

    pub fn format(self: ErrorContext, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("[conn={d} worker={d}] {s}", .{ self.conn_id, self.worker_id, @errorName(self.err) });
        if (self.message.len > 0) {
            try writer.print(": {s}", .{self.message});
        }
    }

    /// Classify the error severity for log routing.
    pub fn severity(self: ErrorContext) Severity {
        return switch (self.err) {
            // Expected flow — debug level
            error.ConnectionReset, error.ConnectionClosed => .debug,
            // Security events — warn level
            error.AuthenticationFailed, error.ReplayDetected,
            error.UserNotFound, error.UserDisabled,
            error.RateLimitExceeded, error.ConnectionLimitReached,
            => .warn,
            // Resource exhaustion — error level
            error.OutOfMemory, error.BufferExhausted => .err,
            // Everything else — info
            else => .info,
        };
    }

    /// Check if the error is transient and the operation may succeed on retry.
    pub fn isRetryable(self: ErrorContext) bool {
        return switch (self.err) {
            error.DnsTimeout,
            error.ConnectionTimeout,
            error.Timeout,
            error.WouldBlock,
            error.PanelApiError,
            => true,
            else => false,
        };
    }

    /// Create an ErrorContext with a message.
    pub fn init(err: Error, message: []const u8, conn_id: u64, worker_id: u16) ErrorContext {
        return .{
            .err = err,
            .message = message,
            .conn_id = conn_id,
            .worker_id = worker_id,
        };
    }
};

// ── Tests ──

test "ErrorContext format" {
    const ctx = ErrorContext{
        .err = error.ConnectionReset,
        .message = "peer closed",
        .conn_id = 42,
        .worker_id = 3,
    };
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try ctx.format("", .{}, fbs.writer());
    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "conn=42") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "peer closed") != null);
}

test "ErrorContext severity classification" {
    try std.testing.expectEqual(Severity.debug, (ErrorContext{ .err = error.ConnectionReset }).severity());
    try std.testing.expectEqual(Severity.debug, (ErrorContext{ .err = error.ConnectionClosed }).severity());
    try std.testing.expectEqual(Severity.warn, (ErrorContext{ .err = error.AuthenticationFailed }).severity());
    try std.testing.expectEqual(Severity.warn, (ErrorContext{ .err = error.ReplayDetected }).severity());
    try std.testing.expectEqual(Severity.err, (ErrorContext{ .err = error.OutOfMemory }).severity());
    try std.testing.expectEqual(Severity.err, (ErrorContext{ .err = error.BufferExhausted }).severity());
    try std.testing.expectEqual(Severity.info, (ErrorContext{ .err = error.DnsResolutionFailed }).severity());
}

test "ErrorContext isRetryable" {
    try std.testing.expect((ErrorContext{ .err = error.DnsTimeout }).isRetryable());
    try std.testing.expect((ErrorContext{ .err = error.ConnectionTimeout }).isRetryable());
    try std.testing.expect((ErrorContext{ .err = error.WouldBlock }).isRetryable());
    try std.testing.expect((ErrorContext{ .err = error.PanelApiError }).isRetryable());
    try std.testing.expect(!(ErrorContext{ .err = error.AuthenticationFailed }).isRetryable());
    try std.testing.expect(!(ErrorContext{ .err = error.OutOfMemory }).isRetryable());
}

test "ErrorContext init helper" {
    const ctx = ErrorContext.init(error.TlsHandshakeFailed, "bad cert", 100, 5);
    try std.testing.expectEqual(error.TlsHandshakeFailed, ctx.err);
    try std.testing.expectEqualStrings("bad cert", ctx.message);
    try std.testing.expectEqual(@as(u64, 100), ctx.conn_id);
    try std.testing.expectEqual(@as(u16, 5), ctx.worker_id);
}
