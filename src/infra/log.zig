const std = @import("std");

pub const Level = enum {
    trace,
    debug,
    info,
    warn,
    err,

    pub fn string(self: Level) []const u8 {
        return switch (self) {
            .trace => "trace",
            .debug => "debug",
            .info => "info",
            .warn => "warn",
            .err => "error",
        };
    }

    pub fn fromString(s: []const u8) Level {
        if (std.ascii.eqlIgnoreCase(s, "trace")) return .trace;
        if (std.ascii.eqlIgnoreCase(s, "debug")) return .debug;
        if (std.ascii.eqlIgnoreCase(s, "info")) return .info;
        if (std.ascii.eqlIgnoreCase(s, "warn")) return .warn;
        if (std.ascii.eqlIgnoreCase(s, "error")) return .err;
        return .info;
    }
};

/// 带独立锁的日志通道。
/// 每个通道持有自己的 Mutex，不同通道之间写入互不阻塞。
/// 格式化到栈缓冲区后一次性 writeAll，保证单条日志原子性。
const Channel = struct {
    mu: std.Thread.Mutex = .{},
    file: ?std.fs.File = null,

    fn open(self: *Channel, dir: []const u8, name: []const u8) void {
        self.file = openLogFile(dir, name);
    }

    fn close(self: *Channel) void {
        if (self.file) |f| f.close();
        self.file = null;
    }

    /// 带 level 前缀写入（app.log 用）。
    fn writeFormatted(self: *Channel, level: Level, comptime fmt: []const u8, args: anytype) void {
        self.mu.lock();
        defer self.mu.unlock();
        const f = self.file orelse return;

        var buf: [4096]u8 = undefined;
        var pos: usize = 0;
        pos = appendTimestamp(&buf, pos);
        pos = appendFmt(&buf, pos, " [{s}] ", .{level.string()});
        pos = appendFmt(&buf, pos, fmt ++ "\n", args);
        f.writeAll(buf[0..pos]) catch {};
    }

    /// 无 level 前缀写入（access.log / error.log 用）。
    fn writeRaw(self: *Channel, comptime fmt: []const u8, args: anytype) void {
        self.mu.lock();
        defer self.mu.unlock();
        const f = self.file orelse return;

        var buf: [4096]u8 = undefined;
        var pos: usize = 0;
        pos = appendTimestamp(&buf, pos);
        pos = appendFmt(&buf, pos, " " ++ fmt ++ "\n", args);
        f.writeAll(buf[0..pos]) catch {};
    }
};

/// Multi-channel logger: app.log, access.log, error.log + console.
///
/// - app.log:    程序日志（按 level 过滤）
/// - access.log: 连接访问记录
/// - error.log:  连接失败日志
/// - console:    stdout 状态输出
///
/// 并发设计：每个通道独立 Mutex，多 worker 写不同通道零争用。
pub const Logger = struct {
    min_level: std.atomic.Value(u8),
    log_dir: []const u8,
    max_days: u16,

    app_ch: Channel = .{},
    access_ch: Channel = .{},
    error_ch: Channel = .{},
    console_mu: std.Thread.Mutex = .{},

    initialized: bool = false,
    init_mu: std.Thread.Mutex = .{},

    pub fn init(log_dir: []const u8, level: Level, max_days: u16) Logger {
        return .{
            .min_level = std.atomic.Value(u8).init(@intFromEnum(level)),
            .log_dir = log_dir,
            .max_days = max_days,
        };
    }

    pub fn start(self: *Logger) !void {
        self.init_mu.lock();
        defer self.init_mu.unlock();

        if (self.initialized) return;

        if (self.log_dir.len > 0) {
            std.fs.cwd().makePath(self.log_dir) catch {};
        }

        self.app_ch.open(self.log_dir, "app.log");
        self.access_ch.open(self.log_dir, "access.log");
        self.error_ch.open(self.log_dir, "error.log");
        self.initialized = true;

        self.writeConsole("日志系统已启动", .{});
    }

    pub fn deinit(self: *Logger) void {
        self.init_mu.lock();
        defer self.init_mu.unlock();
        self.app_ch.close();
        self.access_ch.close();
        self.error_ch.close();
        self.initialized = false;
    }

    /// 写入 app.log（按 level 过滤）。
    pub fn app(self: *Logger, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(level) < self.min_level.load(.acquire)) return;
        self.app_ch.writeFormatted(level, fmt, args);
    }

    /// 写入 access.log。
    pub fn access(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.access_ch.writeRaw(fmt, args);
    }

    /// 写入 error.log。
    pub fn connError(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.error_ch.writeRaw(fmt, args);
    }

    /// 写入 stdout。
    pub fn console(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.console_mu.lock();
        defer self.console_mu.unlock();
        self.writeConsole(fmt, args);
    }

    /// 动态调整日志级别（线程安全）。
    pub fn setLevel(self: *Logger, level: Level) void {
        self.min_level.store(@intFromEnum(level), .release);
    }

    fn writeConsole(_: *Logger, comptime fmt: []const u8, args: anytype) void {
        var buf: [4096]u8 = undefined;
        var pos: usize = 0;
        pos = appendTimestamp(&buf, pos);
        pos = appendFmt(&buf, pos, " [info] " ++ fmt ++ "\n", args);
        std.fs.File.stdout().writeAll(buf[0..pos]) catch {};
    }
};

fn openLogFile(dir: []const u8, name: []const u8) ?std.fs.File {
    if (dir.len == 0) {
        return std.fs.cwd().createFile(name, .{ .truncate = false }) catch null;
    }
    var d = std.fs.cwd().openDir(dir, .{}) catch return null;
    defer d.close();
    const f = d.createFile(name, .{ .truncate = false }) catch return null;
    f.seekFromEnd(0) catch {};
    return f;
}

/// 格式化时间戳到 buf[pos..]，返回新 pos。
fn appendTimestamp(buf: []u8, pos: usize) usize {
    const ts = std.time.timestamp();
    const epoch_secs: u64 = @intCast(ts);
    const es = std.time.epoch.EpochSeconds{ .secs = epoch_secs };
    const day = es.getDaySeconds();
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();

    const s = std.fmt.bufPrint(buf[pos..], "[{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}]", .{
        yd.year,
        md.month.numeric(),
        md.day_index + 1,
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
        day.getSecondsIntoMinute(),
    }) catch return pos;
    return pos + s.len;
}

/// 格式化到 buf[pos..]，返回新 pos。
fn appendFmt(buf: []u8, pos: usize, comptime fmt: []const u8, args: anytype) usize {
    const s = std.fmt.bufPrint(buf[pos..], fmt, args) catch return pos;
    return pos + s.len;
}

// 全局 logger 实例
var global_logger: Logger = Logger.init("", .info, 15);

pub fn getLogger() *Logger {
    return &global_logger;
}

/// 初始化全局 logger。必须在任何 worker 启动前调用。
pub fn initGlobal(log_dir: []const u8, level: Level, max_days: u16) !void {
    global_logger = Logger.init(log_dir, level, max_days);
    try global_logger.start();
}
