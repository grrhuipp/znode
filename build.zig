const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- zio dependency (force epoll on Linux) ---
    const zio_dep = b.dependency("zio", .{
        .target = target,
        .optimize = optimize,
        .backend = "epoll",
    });
    const zio_mod = zio_dep.module("zio");

    // --- aws-lc: include 共享，lib 按目标平台选择 ---
    const awslc_include: std.Build.LazyPath = .{ .cwd_relative = b.pathFromRoot("deps/aws-lc/include") };
    const awslc_lib_dir = awslcLibDir(b, target.result);

    // --- main executable ---
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zio", .module = zio_mod },
        },
    });
    exe_mod.addIncludePath(awslc_include);
    exe_mod.link_libc = true;

    const exe = b.addExecutable(.{
        .name = "znode",
        .root_module = exe_mod,
    });

    linkAwsLc(b, exe, awslc_lib_dir);
    b.installArtifact(exe);

    // --- run step ---
    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run znode");
    run_step.dependOn(&run_cmd.step);

    // --- tests ---
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zio", .module = zio_mod },
        },
    });
    test_mod.addIncludePath(awslc_include);
    test_mod.link_libc = true;

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });

    linkAwsLc(b, unit_tests, awslc_lib_dir);

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // --- crypto tests (independent of zio, runs on any platform) ---
    const crypto_test_mod = b.createModule(.{
        .root_source_file = b.path("src/infra/crypto/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    crypto_test_mod.addIncludePath(awslc_include);
    crypto_test_mod.link_libc = true;

    const crypto_tests = b.addTest(.{
        .root_module = crypto_test_mod,
    });

    linkAwsLc(b, crypto_tests, awslc_lib_dir);

    const run_crypto_tests = b.addRunArtifact(crypto_tests);
    const crypto_test_step = b.step("test-crypto", "Run crypto unit tests");
    crypto_test_step.dependOn(&run_crypto_tests.step);

    // --- check step (compile-only, no linking — works without aws-lc libs) ---
    const check_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zio", .module = zio_mod },
        },
    });
    check_mod.addIncludePath(awslc_include);
    check_mod.link_libc = true;

    const check_obj = b.addObject(.{
        .name = "znode-check",
        .root_module = check_mod,
    });
    const check_step = b.step("check", "Check compilation (no linking)");
    check_step.dependOn(&check_obj.step);
}

/// 根据目标平台返回预编译库路径，找不到返回 null。
fn awslcLibDir(b: *std.Build, resolved: std.Target) ?[]const u8 {
    if (resolved.os.tag != .linux) return null;
    const arch = switch (resolved.cpu.arch) {
        .x86_64 => "x86_64",
        else => return null,
    };
    const dir = b.fmt("deps/aws-lc/lib/{s}-linux-musl", .{arch});
    const crypto_path = b.fmt("{s}/libcrypto.a", .{dir});
    std.fs.cwd().access(b.pathFromRoot(crypto_path), .{}) catch return null;
    return dir;
}

/// 链接 aws-lc 预编译库（libcrypto.a + libssl.a）。
fn linkAwsLc(b: *std.Build, step: *std.Build.Step.Compile, lib_dir: ?[]const u8) void {
    const dir = lib_dir orelse return;
    step.addObjectFile(.{ .cwd_relative = b.pathFromRoot(b.fmt("{s}/libcrypto.a", .{dir})) });
    step.addObjectFile(.{ .cwd_relative = b.pathFromRoot(b.fmt("{s}/libssl.a", .{dir})) });
    step.linkLibCpp();
}
