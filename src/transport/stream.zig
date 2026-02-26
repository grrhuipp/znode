const std = @import("std");

/// Common result type for transport layer operations (TLS, WebSocket, etc.).
/// Used by readDecrypted, writeEncrypted, handshake, and similar functions.
pub const TransportResult = union(enum) {
    bytes: usize,
    want_read,
    want_write,
    closed,
    err,
};
