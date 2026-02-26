const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── Dependencies ──
    const xev_dep = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });

    // ── xev backend wrapper (epoll on Linux, IOCP on Windows) ──
    const xev_raw = xev_dep.module("xev");
    const xev_mod = b.createModule(.{
        .root_source_file = b.path("src/xev_backend.zig"),
        .target = target,
        .optimize = optimize,
    });
    xev_mod.addImport("xev_raw", xev_raw);

    // ── Helper: configure a compile step with all dependencies ──
    const configureStep = struct {
        fn apply(
            step: *std.Build.Step.Compile,
            xev: *std.Build.Module,
            t: std.Build.ResolvedTarget,
        ) void {
            step.root_module.addImport("xev", xev);

            // BoringSSL (NASM-accelerated prebuilt: AES-NI, SHA, GHASH, ChaCha20, P256, etc.)
            step.addIncludePath(.{ .cwd_relative = "deps/boringssl/include" });
            // Select prebuilt library path based on target OS
            if (t.result.os.tag == .linux) {
                step.addLibraryPath(.{ .cwd_relative = "deps/boringssl/build-linux" });
            } else {
                step.addLibraryPath(.{ .cwd_relative = "deps/boringssl/build-windows" });
            }
            step.linkSystemLibrary("ssl");
            step.linkSystemLibrary("crypto");
            step.linkLibCpp(); // BoringSSL's ssl/ is C++
            step.linkLibC();

            // fast_hash.c (Keccak/SHAKE128, CRC32, FNV1a32)
            step.addIncludePath(.{ .cwd_relative = "src/crypto" });
            step.addCSourceFile(.{
                .file = .{ .cwd_relative = "src/crypto/fast_hash.c" },
                .flags = &.{ "-O3", "-std=c11" },
            });

            // System libraries
            if (t.result.os.tag == .windows) {
                step.linkSystemLibrary("ws2_32");
                step.linkSystemLibrary("mswsock");
                step.linkSystemLibrary("advapi32");
                step.linkSystemLibrary("bcrypt");
            }
        }
    }.apply;

    // ── Main executable ──
    const strip = b.option(bool, "strip", "Strip debug info from binary") orelse false;
    const profile = b.option(bool, "profile", "Keep frame pointers for perf profiling") orelse false;
    const exe = b.addExecutable(.{
        .name = "znode",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = if (strip) true else null,
            .omit_frame_pointer = if (profile) false else null,
            .unwind_tables = if (profile) .@"async" else null,
        }),
    });
    configureStep(exe, xev_mod, target);
    b.installArtifact(exe);

    // ── Run step ──
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the proxy server");
    run_step.dependOn(&run_cmd.step);

    // ── Unit tests ──
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    configureStep(unit_tests, xev_mod, target);

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
