const std = @import("std");

/// Lock-free client IP affinity table.
/// Maps client IP hashes to worker IDs for connection locality.
/// 65536 entries, cache-line aligned, using linear probing.
pub const AffinityTable = struct {
    entries: [table_size]Entry = [_]Entry{.{}} ** table_size,

    pub const table_size: usize = 65536;
    const max_probe: usize = 16;
    const ttl_seconds: i64 = 600; // 10 minutes

    /// Cache-line aligned affinity entry.
    pub const Entry = extern struct {
        ip_hash: std.atomic.Value(u64) align(64) = std.atomic.Value(u64).init(0),
        worker_id: std.atomic.Value(u16) = std.atomic.Value(u16).init(0),
        last_seen: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
        _padding: [64 - 8 - 2 - 8]u8 = [_]u8{0} ** (64 - 8 - 2 - 8),
    };

    /// Look up the worker ID for a given client IP hash.
    /// Returns null if no affinity exists or the entry has expired.
    pub fn lookup(self: *AffinityTable, ip_hash: u64) ?u16 {
        if (ip_hash == 0) return null;
        const now = std.time.timestamp();
        const start_idx = ip_hash & (table_size - 1);

        for (0..max_probe) |probe| {
            const idx = (start_idx + probe) & (table_size - 1);
            const entry = &self.entries[idx];
            const stored_hash = entry.ip_hash.load(.acquire);

            if (stored_hash == 0) return null; // Empty slot, stop probing
            if (stored_hash == ip_hash) {
                const last = entry.last_seen.load(.acquire);
                if (now - last > ttl_seconds) return null; // Expired
                // Update last_seen
                entry.last_seen.store(now, .release);
                return entry.worker_id.load(.acquire);
            }
        }
        return null;
    }

    /// Update or insert an affinity entry.
    /// Uses CAS to avoid overwriting active entries from other threads.
    pub fn update(self: *AffinityTable, ip_hash: u64, worker_id: u16) void {
        if (ip_hash == 0) return;
        const now = std.time.timestamp();
        const start_idx = ip_hash & (table_size - 1);

        for (0..max_probe) |probe| {
            const idx = (start_idx + probe) & (table_size - 1);
            const entry = &self.entries[idx];
            const stored_hash = entry.ip_hash.load(.acquire);

            if (stored_hash == ip_hash) {
                // Existing entry, update
                entry.worker_id.store(worker_id, .release);
                entry.last_seen.store(now, .release);
                return;
            }

            if (stored_hash == 0) {
                // Empty slot, try to claim it with CAS
                if (entry.ip_hash.cmpxchgStrong(0, ip_hash, .acq_rel, .acquire)) |_| {
                    // CAS failed, another thread claimed it; continue probing
                    continue;
                }
                entry.worker_id.store(worker_id, .release);
                entry.last_seen.store(now, .release);
                return;
            }

            // Check if this slot is expired and can be reused
            const last = entry.last_seen.load(.acquire);
            if (now - last > ttl_seconds) {
                entry.ip_hash.store(ip_hash, .release);
                entry.worker_id.store(worker_id, .release);
                entry.last_seen.store(now, .release);
                return;
            }
        }
        // All probe slots occupied, entry not inserted (acceptable loss)
    }

    /// Remove expired entries. Called periodically from a cleanup task.
    pub fn cleanup(self: *AffinityTable) usize {
        const now = std.time.timestamp();
        var removed: usize = 0;
        for (&self.entries) |*entry| {
            const stored_hash = entry.ip_hash.load(.acquire);
            if (stored_hash == 0) continue;
            const last = entry.last_seen.load(.acquire);
            if (now - last > ttl_seconds) {
                entry.ip_hash.store(0, .release);
                removed += 1;
            }
        }
        return removed;
    }

    /// FNV-1a hash for client IP strings.
    pub fn hashIp(ip: []const u8) u64 {
        var hash: u64 = 0xcbf29ce484222325;
        for (ip) |byte| {
            hash ^= byte;
            hash *%= 0x100000001b3;
        }
        // Ensure non-zero (0 means empty slot)
        return if (hash == 0) 1 else hash;
    }
};

test "AffinityTable basic operations" {
    var table = AffinityTable{};

    const hash1 = AffinityTable.hashIp("192.168.1.1");
    const hash2 = AffinityTable.hashIp("10.0.0.1");

    // Initially empty
    try std.testing.expectEqual(@as(?u16, null), table.lookup(hash1));

    // Insert and lookup
    table.update(hash1, 0);
    try std.testing.expectEqual(@as(?u16, 0), table.lookup(hash1));

    table.update(hash2, 3);
    try std.testing.expectEqual(@as(?u16, 3), table.lookup(hash2));

    // Update existing
    table.update(hash1, 2);
    try std.testing.expectEqual(@as(?u16, 2), table.lookup(hash1));
}

test "AffinityTable hashIp produces non-zero" {
    const h1 = AffinityTable.hashIp("");
    try std.testing.expect(h1 != 0);

    const h2 = AffinityTable.hashIp("127.0.0.1");
    try std.testing.expect(h2 != 0);

    // Different IPs produce different hashes
    const h3 = AffinityTable.hashIp("192.168.0.1");
    try std.testing.expect(h2 != h3);
}
