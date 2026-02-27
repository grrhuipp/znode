const std = @import("std");
const zio = @import("zio");

// ── Log Level (API unchanged) ──

pub const Level = enum {
    debug,
    info,
    warn,
    err,

    pub fn toStdLevel(self: Level) std.log.Level {
        return switch (self) {
            .debug => .debug,
            .info => .info,
            .warn => .warn,
            .err => .err,
        };
    }

    pub fn fromString(s: []const u8) Level {
        if (std.mem.eql(u8, s, "debug")) return .debug;
        if (std.mem.eql(u8, s, "info")) return .info;
        if (std.mem.eql(u8, s, "warn") or std.mem.eql(u8, s, "warning")) return .warn;
        if (std.mem.eql(u8, s, "error") or std.mem.eql(u8, s, "err")) return .err;
        return .info;
    }
};

// ── Atomic min level ──

var min_level: std.atomic.Value(u8) = std.atomic.Value(u8).init(@intFromEnum(Level.info));

pub fn setLevel(level: Level) void {
    min_level.store(@intFromEnum(level), .release);
}

pub fn getLevel() Level {
    return @enumFromInt(min_level.load(.acquire));
}

pub fn isEnabled(level: Level) bool {
    return @intFromEnum(level) >= @intFromEnum(getLevel());
}

/// Enable console output on all log channels (access + error).
/// App channel always writes to console; this enables it for the others too.
pub fn setConsoleAll(enabled: bool) void {
    g_state.access_ch.write_console = enabled;
    g_state.error_ch.write_console = enabled;
}

fn levelStr(level: Level) []const u8 {
    return switch (level) {
        .debug => "DBG",
        .info => "INF",
        .warn => "WRN",
        .err => "ERR",
    };
}

// ── Time Helpers ──

const TimeParts = struct {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    ms: u16,
    epoch_day: i32,
};

const TimeCache = struct {
    valid: bool = false,
    unix_ms: u64 = 0,
    parts: TimeParts = .{
        .year = 1970,
        .month = 1,
        .day = 1,
        .hour = 0,
        .minute = 0,
        .second = 0,
        .ms = 0,
        .epoch_day = 0,
    },
    text: [23]u8 = "1970-01-01 00:00:00.000".*,
};

threadlocal var g_time_cache: TimeCache = .{};

fn getTimePartsFromMs(total_ms: u64) TimeParts {
    const secs = total_ms / 1000;
    const ms: u16 = @intCast(total_ms % 1000);

    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const epoch_day = es.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = es.getDaySeconds();

    const month_raw: u8 = @intCast(@intFromEnum(month_day.month));
    const month_1: u8 = if (comptime @intFromEnum(std.time.epoch.Month.jan) == 0) month_raw + 1 else month_raw;

    return .{
        .year = @intCast(year_day.year),
        .month = month_1,
        .day = month_day.day_index + 1,
        .hour = @intCast(day_secs.getHoursIntoDay()),
        .minute = @intCast(day_secs.getMinutesIntoHour()),
        .second = @intCast(day_secs.getSecondsIntoMinute()),
        .ms = ms,
        .epoch_day = @intCast(@as(u64, epoch_day.day)),
    };
}

fn getTimeParts() TimeParts {
    const ms_ts = std.time.milliTimestamp();
    const total_ms: u64 = @intCast(@max(ms_ts, 0));
    return getTimePartsFromMs(total_ms);
}

fn formatTimestamp(buf: *[23]u8, parts: TimeParts) void {
    _ = std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}", .{
        parts.year, parts.month, parts.day,
        parts.hour, parts.minute, parts.second, parts.ms,
    }) catch {};
}

fn getTimestamp(parts_out: *TimeParts, ts_out: *[23]u8) void {
    const ms_ts = std.time.milliTimestamp();
    const total_ms: u64 = @intCast(@max(ms_ts, 0));

    if (g_time_cache.valid and g_time_cache.unix_ms == total_ms) {
        parts_out.* = g_time_cache.parts;
        ts_out.* = g_time_cache.text;
        return;
    }

    const parts = getTimePartsFromMs(total_ms);
    var ts_buf: [23]u8 = "0000-00-00 00:00:00.000".*;
    formatTimestamp(&ts_buf, parts);

    g_time_cache.valid = true;
    g_time_cache.unix_ms = total_ms;
    g_time_cache.parts = parts;
    g_time_cache.text = ts_buf;

    parts_out.* = parts;
    ts_out.* = ts_buf;
}

fn currentDay() i32 {
    const ts = std.time.timestamp();
    return @intCast(@divFloor(ts, 86400));
}

/// Convert Y-M-D to epoch day number (days since 1970-01-01).
/// Uses Howard Hinnant's algorithm.
fn ymdToEpochDay(y_in: u16, m_in: u8, d_in: u8) i32 {
    var y: i32 = @intCast(y_in);
    var m: i32 = @intCast(m_in);
    const d: i32 = @intCast(d_in);
    // March-based year adjustment
    if (m <= 2) {
        y -= 1;
        m += 9;
    } else {
        m -= 3;
    }
    const era: i32 = @divFloor(y, 400);
    const yoe: i32 = y - era * 400;
    const doy: i32 = @divFloor(153 * m + 2, 5) + d - 1;
    const doe: i32 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

// ── Channel (per-log-channel state) ──

const Channel = struct {
    mutex: std.Thread.Mutex = .{},
    file: ?std.fs.File = null,
    current_day: i32 = 0,
    prefix_buf: [16]u8 = [_]u8{0} ** 16,
    prefix_len: u8 = 0,
    write_console: bool = false,

    fn writeLine(self: *Channel, line: []const u8, parts: TimeParts) void {
        const write_console = self.write_console;

        self.mutex.lock();

        // Write to file (rotate if needed)
        if (g_state.log_dir_len > 0) {
            self.ensureFile(parts);
            if (self.file) |f| {
                f.writeAll(line) catch {};
            }
        }
        self.mutex.unlock();

        // Keep file lock free from slow console I/O.
        if (write_console) {
            g_console_mutex.lock();
            defer g_console_mutex.unlock();
            std.debug.print("{s}", .{line});
        }
    }

    fn ensureFile(self: *Channel, parts: TimeParts) void {
        if (self.file != null and self.current_day == parts.epoch_day) return;

        // Close old file
        if (self.file) |f| {
            f.close();
            self.file = null;
        }

        // Build path: {log_dir}/{prefix}_YYYY-MM-DD.log
        var path_buf: [512]u8 = undefined;
        const dir_path = g_state.log_dir_buf[0..g_state.log_dir_len];
        const prefix = self.prefix_buf[0..self.prefix_len];
        const path = std.fmt.bufPrint(&path_buf, "{s}/{s}_{d:0>4}-{d:0>2}-{d:0>2}.log", .{
            dir_path, prefix, parts.year, parts.month, parts.day,
        }) catch return;

        // Open in append mode
        self.file = openAppendFile(path);
        self.current_day = parts.epoch_day;
    }

    fn flushFile(self: *Channel) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.file) |f| {
            f.sync() catch {};
        }
    }

    fn closeFile(self: *Channel) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.file) |f| {
            f.close();
            self.file = null;
        }
    }
};

// ── Global State ──

fn comptimePad(comptime s: []const u8, comptime n: usize) [n]u8 {
    var buf = [_]u8{0} ** n;
    for (s, 0..) |c, i| buf[i] = c;
    return buf;
}

var g_state = struct {
    initialized: bool = false,
    log_dir_buf: [256]u8 = [_]u8{0} ** 256,
    log_dir_len: u16 = 0,
    max_days: u16 = 7,
    app: Channel = .{
        .prefix_buf = comptimePad("app", 16),
        .prefix_len = 3,
        .write_console = true,
    },
    access_ch: Channel = .{
        .prefix_buf = comptimePad("access", 16),
        .prefix_len = 6,
        .write_console = false,
    },
    error_ch: Channel = .{
        .prefix_buf = comptimePad("error", 16),
        .prefix_len = 5,
        .write_console = false,
    },
}{};
var g_console_mutex: std.Thread.Mutex = .{};

// ── File Operations ──

fn openAppendFile(path: []const u8) ?std.fs.File {
    const file = std.fs.cwd().createFile(path, .{ .truncate = false }) catch return null;
    const end_pos = file.getEndPos() catch 0;
    file.seekTo(end_pos) catch {};
    return file;
}

fn parseDateFromFilename(name: []const u8) ?i32 {
    // Format: "prefix_YYYY-MM-DD.log"
    if (!std.mem.endsWith(u8, name, ".log")) return null;
    const underscore_pos = std.mem.lastIndexOfScalar(u8, name, '_') orelse return null;
    const rest = name[underscore_pos + 1 ..];
    if (rest.len < 14) return null; // "YYYY-MM-DD.log" = 14 chars
    const date_only = rest[0..10]; // "YYYY-MM-DD"
    if (date_only[4] != '-' or date_only[7] != '-') return null;

    const year = std.fmt.parseInt(u16, date_only[0..4], 10) catch return null;
    const month = std.fmt.parseInt(u8, date_only[5..7], 10) catch return null;
    const day = std.fmt.parseInt(u8, date_only[8..10], 10) catch return null;

    if (month < 1 or month > 12 or day < 1 or day > 31) return null;
    return ymdToEpochDay(year, month, day);
}

fn cleanupOldLogs() void {
    const dir_path = g_state.log_dir_buf[0..g_state.log_dir_len];
    if (dir_path.len == 0) return;

    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch return;
    defer dir.close();

    const today = currentDay();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        const file_day = parseDateFromFilename(entry.name) orelse continue;
        if (today - file_day > g_state.max_days) {
            dir.deleteFile(entry.name) catch {};
        }
    }
}

// ── Public API: Lifecycle ──

/// Enable file-based logging. Call once from main before spawning workers.
/// When not called, log output goes to stderr only (backward compatible).
pub fn init(log_dir: []const u8, max_days: u16, clean_on_start: bool) void {
    const len: u16 = @intCast(@min(log_dir.len, g_state.log_dir_buf.len));
    @memcpy(g_state.log_dir_buf[0..len], log_dir[0..len]);
    g_state.log_dir_len = len;
    g_state.max_days = if (max_days == 0) 7 else max_days;

    // Create log directory if needed
    std.fs.cwd().makePath(log_dir) catch {};

    if (clean_on_start) {
        cleanupAllLogs();
    } else {
        cleanupOldLogs();
    }

    g_state.initialized = true;
}

fn cleanupAllLogs() void {
    const dir_path = g_state.log_dir_buf[0..g_state.log_dir_len];
    if (dir_path.len == 0) return;

    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.endsWith(u8, entry.name, ".log")) {
            dir.deleteFile(entry.name) catch {};
        }
    }
}

/// Flush and close all log files. Call from main on shutdown.
pub fn shutdown() void {
    if (!g_state.initialized) return;
    g_state.app.closeFile();
    g_state.access_ch.closeFile();
    g_state.error_ch.closeFile();
    g_state.initialized = false;
}

/// Force flush all log files to disk.
pub fn flush() void {
    if (!g_state.initialized) return;
    g_state.app.flushFile();
    g_state.access_ch.flushFile();
    g_state.error_ch.flushFile();
}

// ── Public API: Access / Error Logs ──

/// Write an access log entry (access channel, file only).
pub fn access(
    client_ip: []const u8,
    target: []const u8,
    port: u16,
    bytes_up: u64,
    bytes_down: u64,
    duration_ms: u64,
    status: []const u8,
) void {
    if (!g_state.initialized) return;

    var parts: TimeParts = undefined;
    var ts_buf: [23]u8 = undefined;
    getTimestamp(&parts, &ts_buf);

    var buf: [2048]u8 = undefined;
    const ts_str: []const u8 = &ts_buf;
    const line = std.fmt.bufPrint(&buf, "{s} [ACC] {s} -> {s}:{d} up={d} down={d} time={d}ms {s}\n", .{
        ts_str, client_ip, target, port, bytes_up, bytes_down, duration_ms, status,
    }) catch return;

    g_state.access_ch.writeLine(line, parts);
}

/// Write a connection failure entry (error channel, file only).
pub fn connFail(
    client_ip: []const u8,
    target: []const u8,
    port: u16,
    reason: []const u8,
) void {
    if (!g_state.initialized) return;

    var parts: TimeParts = undefined;
    var ts_buf: [23]u8 = undefined;
    getTimestamp(&parts, &ts_buf);

    var buf: [2048]u8 = undefined;
    const ts_str: []const u8 = &ts_buf;
    const line = std.fmt.bufPrint(&buf, "{s} [ERR] {s} -> {s}:{d} {s}\n", .{
        ts_str, client_ip, target, port, reason,
    }) catch return;

    g_state.error_ch.writeLine(line, parts);
}

// ── Per-thread log batch buffer ──

/// Per-worker log buffer. Accumulates log lines locally (no lock) and
/// flushes them to the Channel in a single mutex acquisition.
/// Reduces lock contention by ~100x under high-throughput logging.
pub const LogBatch = struct {
    buf: [BATCH_SIZE]u8 = undefined,
    len: usize = 0,
    last_parts: TimeParts = .{
        .year = 0, .month = 0, .day = 0,
        .hour = 0, .minute = 0, .second = 0,
        .ms = 0, .epoch_day = 0,
    },
    /// Route to app channel (for worker/panel loggers). Default is access channel.
    to_app: bool = false,

    const BATCH_SIZE: usize = 4096;

    /// Append a formatted line to the batch. Flushes if buffer would overflow.
    pub fn append(self: *LogBatch, line: []const u8, parts: TimeParts) void {
        if (self.len + line.len > BATCH_SIZE) {
            self.flushToChannel();
        }
        if (line.len > BATCH_SIZE) {
            // Oversized line — write directly
            const ch = if (self.to_app) &g_state.app else &g_state.access_ch;
            ch.writeLine(line, parts);
            return;
        }
        @memcpy(self.buf[self.len..][0..line.len], line);
        self.len += line.len;
        self.last_parts = parts;
    }

    /// Flush accumulated data to the appropriate channel.
    pub fn flushToChannel(self: *LogBatch) void {
        if (self.len == 0) return;
        const ch = if (self.to_app) &g_state.app else &g_state.access_ch;
        ch.writeLine(self.buf[0..self.len], self.last_parts);
        self.len = 0;
    }
};

// ── Existing API (signatures unchanged, batch support added) ──

/// Scoped logger with worker_id prefix.
/// When `batch` is set, log lines accumulate in a per-worker buffer
/// and flush in bulk, reducing Channel mutex contention.
pub const ScopedLogger = struct {
    worker_id: u16,
    scope: []const u8,
    batch: ?*LogBatch = null,
    conn_id: u64 = 0,
    src_buf: [46]u8 = [_]u8{0} ** 46,
    src_len: u8 = 0,
    /// Route to app channel (worker/panel). Connection loggers use access channel.
    to_app: bool = false,

    pub fn init(worker_id: u16, scope: []const u8) ScopedLogger {
        return .{ .worker_id = worker_id, .scope = scope };
    }

    pub fn withBatch(worker_id: u16, scope: []const u8, b: *LogBatch) ScopedLogger {
        return .{ .worker_id = worker_id, .scope = scope, .batch = b };
    }

    /// Set the client source from a zio.net.IpAddress (accept result).
    pub fn setSource(self: *ScopedLogger, addr: zio.net.IpAddress) void {
        const s = switch (addr.getFamily()) {
            .ipv4 => blk: {
                const ip_bytes: [4]u8 = @bitCast(addr.in.addr);
                break :blk std.fmt.bufPrint(&self.src_buf, "{d}.{d}.{d}.{d}:{d}", .{
                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], addr.getPort(),
                }) catch return;
            },
            .ipv6 => std.fmt.bufPrint(&self.src_buf, "[ipv6]:{d}", .{addr.getPort()}) catch return,
        };
        self.src_len = @intCast(s.len);
    }

    /// Set source string directly (e.g. when resolved from PROXY protocol).
    pub fn setSourceText(self: *ScopedLogger, src: []const u8) void {
        const n: usize = @min(src.len, self.src_buf.len);
        if (n == 0) {
            self.src_len = 0;
            return;
        }
        @memcpy(self.src_buf[0..n], src[0..n]);
        self.src_len = @intCast(n);
    }

    pub fn debug(self: ScopedLogger, comptime fmt: []const u8, args: anytype) void {
        self.log(.debug, fmt, args);
    }

    pub fn info(self: ScopedLogger, comptime fmt: []const u8, args: anytype) void {
        self.log(.info, fmt, args);
    }

    pub fn warn(self: ScopedLogger, comptime fmt: []const u8, args: anytype) void {
        self.log(.warn, fmt, args);
    }

    pub fn err(self: ScopedLogger, comptime fmt: []const u8, args: anytype) void {
        self.log(.err, fmt, args);
    }

    /// Write an info-level line to the access channel (file only, no console).
    pub fn accessInfo(self: ScopedLogger, comptime fmt: []const u8, args: anytype) void {
        if (!isEnabled(.info)) return;

        var parts: TimeParts = undefined;
        var ts_buf: [23]u8 = undefined;
        getTimestamp(&parts, &ts_buf);

        var buf: [2048]u8 = undefined;
        const ts_str: []const u8 = &ts_buf;
        const line = std.fmt.bufPrint(&buf, "{s} [{s}] [W{d}] [{s}] " ++ fmt ++ "\n", .{ts_str} ++ .{levelStr(.info)} ++ .{self.worker_id} ++ .{self.scope} ++ args) catch return;

        if (g_state.initialized) {
            g_state.access_ch.writeLine(line, parts);
        }
    }

    pub fn enabled(self: ScopedLogger, level: Level) bool {
        _ = self;
        return isEnabled(level);
    }

    fn log(self: ScopedLogger, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (!isEnabled(level)) return;

        var parts: TimeParts = undefined;
        var ts_buf: [23]u8 = undefined;
        getTimestamp(&parts, &ts_buf);

        var buf: [2048]u8 = undefined;
        const ts_str: []const u8 = &ts_buf;
        // Connection loggers (conn_id > 0) include #{id} {src} prefix in access log.
        // App-level loggers (conn_id == 0, e.g. worker/panel) use plain format in app log.
        const line = if (self.conn_id != 0) blk: {
            const src: []const u8 = if (self.src_len > 0) self.src_buf[0..self.src_len] else "-";
            break :blk std.fmt.bufPrint(&buf, "{s} [{s}] [W{d}] [{s}] #{d} {s} " ++ fmt ++ "\n", .{ts_str} ++ .{levelStr(level)} ++ .{self.worker_id} ++ .{self.scope} ++ .{self.conn_id} ++ .{src} ++ args) catch return;
        } else blk: {
            break :blk std.fmt.bufPrint(&buf, "{s} [{s}] [W{d}] [{s}] " ++ fmt ++ "\n", .{ts_str} ++ .{levelStr(level)} ++ .{self.worker_id} ++ .{self.scope} ++ args) catch return;
        };

        const channel = if (self.to_app) &g_state.app else &g_state.access_ch;
        if (g_state.initialized) {
            if (self.batch) |b| {
                b.append(line, parts);
                // Flush immediately on error/warn for timely visibility
                if (level == .err or level == .warn) b.flushToChannel();
            } else {
                channel.writeLine(line, parts);
            }
        } else {
            std.debug.print("{s}", .{line});
        }
    }
};

/// Global logger (no worker scope).
pub fn debug(comptime fmt: []const u8, args: anytype) void {
    logGlobal(.debug, fmt, args);
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    logGlobal(.info, fmt, args);
}

pub fn warn(comptime fmt: []const u8, args: anytype) void {
    logGlobal(.warn, fmt, args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    logGlobal(.err, fmt, args);
}

fn logGlobal(level: Level, comptime fmt: []const u8, args: anytype) void {
    if (!isEnabled(level)) return;

    var parts: TimeParts = undefined;
    var ts_buf: [23]u8 = undefined;
    getTimestamp(&parts, &ts_buf);

    var buf: [2048]u8 = undefined;
    const ts_str: []const u8 = &ts_buf;
    const line = std.fmt.bufPrint(&buf, "{s} [{s}] " ++ fmt ++ "\n", .{ts_str} ++ .{levelStr(level)} ++ args) catch return;

    if (g_state.initialized) {
        g_state.app.writeLine(line, parts);
    } else {
        std.debug.print("{s}", .{line});
    }
}

// ── Tests ──

test "Level fromString" {
    try std.testing.expectEqual(Level.debug, Level.fromString("debug"));
    try std.testing.expectEqual(Level.info, Level.fromString("info"));
    try std.testing.expectEqual(Level.warn, Level.fromString("warn"));
    try std.testing.expectEqual(Level.warn, Level.fromString("warning"));
    try std.testing.expectEqual(Level.err, Level.fromString("error"));
    try std.testing.expectEqual(Level.err, Level.fromString("err"));
    try std.testing.expectEqual(Level.info, Level.fromString("unknown"));
}

test "Level toStdLevel" {
    try std.testing.expectEqual(std.log.Level.debug, Level.debug.toStdLevel());
    try std.testing.expectEqual(std.log.Level.err, Level.err.toStdLevel());
}

test "setLevel and getLevel" {
    const old = getLevel();
    defer setLevel(old);

    setLevel(.debug);
    try std.testing.expectEqual(Level.debug, getLevel());
    setLevel(.err);
    try std.testing.expectEqual(Level.err, getLevel());
}

test "ymdToEpochDay known dates" {
    // 1970-01-01 = day 0
    try std.testing.expectEqual(@as(i32, 0), ymdToEpochDay(1970, 1, 1));
    // 2000-01-01 = day 10957
    try std.testing.expectEqual(@as(i32, 10957), ymdToEpochDay(2000, 1, 1));
    // 2024-01-01 = day 19723
    try std.testing.expectEqual(@as(i32, 19723), ymdToEpochDay(2024, 1, 1));
}

test "ymdToEpochDay ordering" {
    const day1 = ymdToEpochDay(2026, 2, 20);
    const day2 = ymdToEpochDay(2026, 2, 21);
    const day3 = ymdToEpochDay(2026, 2, 28);
    try std.testing.expect(day1 < day2);
    try std.testing.expect(day2 < day3);
    try std.testing.expectEqual(@as(i32, 1), day2 - day1);
}

test "parseDateFromFilename valid" {
    const d1 = parseDateFromFilename("app_2026-02-21.log");
    try std.testing.expect(d1 != null);
    try std.testing.expectEqual(ymdToEpochDay(2026, 2, 21), d1.?);

    const d2 = parseDateFromFilename("access_2024-01-01.log");
    try std.testing.expect(d2 != null);
    try std.testing.expectEqual(ymdToEpochDay(2024, 1, 1), d2.?);

    const d3 = parseDateFromFilename("error_2025-12-31.log");
    try std.testing.expect(d3 != null);
}

test "parseDateFromFilename invalid" {
    try std.testing.expect(parseDateFromFilename("nodate.log") == null);
    try std.testing.expect(parseDateFromFilename("app_2026-13-01.log") == null); // month > 12
    try std.testing.expect(parseDateFromFilename("app_2026-02-00.log") == null); // day 0
    try std.testing.expect(parseDateFromFilename("app_short.log") == null);
    try std.testing.expect(parseDateFromFilename("app_2026-02-21.txt") == null); // wrong ext
    try std.testing.expect(parseDateFromFilename("nounderscorelog") == null);
}

test "formatTimestamp length" {
    const parts = TimeParts{
        .year = 2026,
        .month = 2,
        .day = 21,
        .hour = 8,
        .minute = 30,
        .second = 15,
        .ms = 42,
        .epoch_day = 0,
    };
    var buf: [23]u8 = undefined;
    formatTimestamp(&buf, parts);
    const expected = "2026-02-21 08:30:15.042";
    try std.testing.expectEqualStrings(expected, &buf);
}

test "formatTimestamp zero padding" {
    const parts = TimeParts{
        .year = 2026,
        .month = 1,
        .day = 5,
        .hour = 0,
        .minute = 3,
        .second = 9,
        .ms = 7,
        .epoch_day = 0,
    };
    var buf: [23]u8 = undefined;
    formatTimestamp(&buf, parts);
    const expected = "2026-01-05 00:03:09.007";
    try std.testing.expectEqualStrings(expected, &buf);
}

test "getTimeParts returns reasonable values" {
    const parts = getTimeParts();
    try std.testing.expect(parts.year >= 2024 and parts.year <= 2100);
    try std.testing.expect(parts.month >= 1 and parts.month <= 12);
    try std.testing.expect(parts.day >= 1 and parts.day <= 31);
    try std.testing.expect(parts.hour <= 23);
    try std.testing.expect(parts.minute <= 59);
    try std.testing.expect(parts.second <= 59);
    try std.testing.expect(parts.ms <= 999);
    try std.testing.expect(parts.epoch_day > 19000); // after 2022
}

test "ScopedLogger creation" {
    const logger = ScopedLogger.init(3, "relay");
    try std.testing.expectEqual(@as(u16, 3), logger.worker_id);
    try std.testing.expectEqualStrings("relay", logger.scope);
}

test "levelStr values" {
    try std.testing.expectEqualStrings("DBG", levelStr(.debug));
    try std.testing.expectEqualStrings("INF", levelStr(.info));
    try std.testing.expectEqualStrings("WRN", levelStr(.warn));
    try std.testing.expectEqualStrings("ERR", levelStr(.err));
}

test "currentDay is consistent with getTimeParts" {
    const parts = getTimeParts();
    const day = currentDay();
    // Should be same day or at most 1 day apart (midnight edge case)
    try std.testing.expect(@abs(day - parts.epoch_day) <= 1);
}

test "init and shutdown cycle" {
    // Use a temporary directory for testing
    const tmp_dir = "zig-test-logs";
    std.fs.cwd().makePath(tmp_dir) catch {};
    defer std.fs.cwd().deleteTree(tmp_dir) catch {};

    init(tmp_dir, 7, false);
    try std.testing.expect(g_state.initialized);
    try std.testing.expectEqual(@as(u16, 7), g_state.max_days);
    try std.testing.expectEqualStrings(tmp_dir, g_state.log_dir_buf[0..g_state.log_dir_len]);

    shutdown();
    try std.testing.expect(!g_state.initialized);
}

test "comptimePad" {
    const padded = comptimePad("test", 8);
    try std.testing.expectEqualStrings("test", padded[0..4]);
    try std.testing.expectEqual(@as(u8, 0), padded[4]);
    try std.testing.expectEqual(@as(u8, 0), padded[7]);
}
