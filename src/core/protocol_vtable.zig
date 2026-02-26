// ══════════════════════════════════════════════════════════════
//  Protocol VTable — Removed
//
//  OutboundVTable is no longer applicable:
//  Outbound protocols are now pure functions with per-protocol
//  signatures (encodeHeader / encodeFirstPacket). Session-level
//  orchestration is in outbound_dispatch.zig.
//
//  InboundVTable was removed earlier for the same reason.
// ══════════════════════════════════════════════════════════════
