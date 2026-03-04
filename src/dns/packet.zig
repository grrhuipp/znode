/// DNS wire format encoding/decoding.
///
/// Supports: A (IPv4) and AAAA (IPv6) record queries/responses.
/// Handles name compression pointers (0xC0).
const std = @import("std");

pub const RecordType = enum(u16) {
    a = 1,
    aaaa = 28,
};

pub const RCode = enum(u4) {
    ok = 0,
    format_error = 1,
    server_failure = 2,
    name_error = 3, // NXDOMAIN
    not_implemented = 4,
    refused = 5,
    _,
};

pub const DnsAddress = struct {
    buf: [46]u8 = undefined, // max IPv6 text length
    len: u8 = 0,
    is_ipv6: bool = false,

    pub fn text(self: *const DnsAddress) []const u8 {
        return self.buf[0..self.len];
    }
};

pub const QueryResult = struct {
    addresses: [16]DnsAddress = undefined, // up to 16 records
    count: u8 = 0,
    ttl: u32 = 0,
    rcode: RCode = .ok,

    pub fn addrs(self: *const QueryResult) []const DnsAddress {
        return self.addresses[0..self.count];
    }
};

/// Build a DNS query packet for the given domain and record type.
/// Returns number of bytes written to `out`.
pub fn buildQuery(domain: []const u8, rtype: RecordType, txid: u16, out: []u8) ?usize {
    if (out.len < 512) return null; // ensure enough space

    var pos: usize = 0;

    // Header (12 bytes)
    writeU16(out[pos..], txid); // Transaction ID
    pos += 2;
    writeU16(out[pos..], 0x0100); // Flags: RD=1 (recursion desired)
    pos += 2;
    writeU16(out[pos..], 1); // QDCOUNT
    pos += 2;
    writeU16(out[pos..], 0); // ANCOUNT
    pos += 2;
    writeU16(out[pos..], 0); // NSCOUNT
    pos += 2;
    writeU16(out[pos..], 0); // ARCOUNT
    pos += 2;

    // Question: domain name in wire format
    const name_len = encodeDomainName(domain, out[pos..]) orelse return null;
    pos += name_len;

    // QTYPE
    writeU16(out[pos..], @intFromEnum(rtype));
    pos += 2;
    // QCLASS = IN (1)
    writeU16(out[pos..], 1);
    pos += 2;

    return pos;
}

/// Parse a DNS response packet.
pub fn parseResponse(data: []const u8, expected_txid: u16) ?QueryResult {
    if (data.len < 12) return null;

    // Verify transaction ID
    const txid = readU16(data[0..2]);
    if (txid != expected_txid) return null;

    // Verify QR bit (response)
    const flags = readU16(data[2..4]);
    if (flags & 0x8000 == 0) return null;

    const rcode: RCode = @enumFromInt(@as(u4, @intCast(flags & 0x000F)));

    var result = QueryResult{
        .rcode = rcode,
        .ttl = std.math.maxInt(u32),
    };

    if (rcode != .ok and rcode != .name_error) return result;
    if (rcode == .name_error) {
        result.ttl = 60; // negative cache TTL
        return result;
    }

    const qdcount = readU16(data[4..6]);
    const ancount = readU16(data[6..8]);

    // Skip question section
    var pos: usize = 12;
    for (0..qdcount) |_| {
        pos = skipDomainName(data, pos) orelse return null;
        pos += 4; // QTYPE + QCLASS
        if (pos > data.len) return null;
    }

    // Parse answer section
    for (0..ancount) |_| {
        if (pos >= data.len) break;

        pos = skipDomainName(data, pos) orelse break;
        if (pos + 10 > data.len) break;

        const record_type = readU16(data[pos..]);
        pos += 2;
        pos += 2; // CLASS
        const ttl = readU32(data[pos..]);
        pos += 4;
        const rdlength = readU16(data[pos..]);
        pos += 2;

        if (pos + rdlength > data.len) break;

        if (record_type == @intFromEnum(RecordType.a) and rdlength == 4) {
            if (result.count < 16) {
                var addr = DnsAddress{};
                const text = std.fmt.bufPrint(&addr.buf, "{d}.{d}.{d}.{d}", .{
                    data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                }) catch break;
                addr.len = @intCast(text.len);
                result.addresses[result.count] = addr;
                result.count += 1;
                result.ttl = @min(result.ttl, ttl);
            }
        } else if (record_type == @intFromEnum(RecordType.aaaa) and rdlength == 16) {
            if (result.count < 16) {
                var addr = DnsAddress{ .is_ipv6 = true };
                const d = data[pos..];
                const text = std.fmt.bufPrint(&addr.buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
                    d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15],
                }) catch break;
                addr.len = @intCast(text.len);
                result.addresses[result.count] = addr;
                result.count += 1;
                result.ttl = @min(result.ttl, ttl);
            }
        }

        pos += rdlength;
    }

    if (result.ttl == std.math.maxInt(u32)) result.ttl = 60;
    return result;
}

// ── Internal helpers ─────────────────────────────────────────────────────

fn encodeDomainName(domain: []const u8, out: []u8) ?usize {
    var pos: usize = 0;
    var iter = std.mem.splitScalar(u8, domain, '.');

    while (iter.next()) |label| {
        if (label.len == 0 or label.len > 63) return null;
        if (pos + 1 + label.len > out.len) return null;
        out[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(out[pos..][0..label.len], label);
        pos += label.len;
    }

    if (pos >= out.len) return null;
    out[pos] = 0; // terminator
    pos += 1;
    return pos;
}

fn skipDomainName(data: []const u8, start: usize) ?usize {
    var pos = start;
    while (pos < data.len) {
        const len = data[pos];
        if (len == 0) {
            return pos + 1;
        }
        if ((len & 0xC0) == 0xC0) {
            // Compression pointer
            return pos + 2;
        }
        pos += 1 + len;
    }
    return null;
}

fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}

fn readU32(bytes: []const u8) u32 {
    return (@as(u32, bytes[0]) << 24) | (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) | @as(u32, bytes[3]);
}

fn writeU16(buf: []u8, val: u16) void {
    buf[0] = @intCast(val >> 8);
    buf[1] = @intCast(val & 0xFF);
}
