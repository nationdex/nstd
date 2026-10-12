const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Native CPU target optimization for ReleaseFast builds when compiling CLI/bench
    const cpu_target = if (optimize == .ReleaseFast)
        b.resolveTargetQuery(.{ .cpu_model = .native })
    else
        target;

    // Shared core module used by both the CLI and the C ABI.
    const core_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = cpu_target,
        .optimize = optimize,
        .pic = true,
    });

    // ---- Static + shared C ABI drop-in library ----
    const lib = b.addLibrary(.{
        .name = "nstd",
        .root_module = core_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    const lib_shared = b.addLibrary(.{
        .name = "nstd",
        .root_module = core_mod,
        .linkage = .dynamic,
    });
    b.installArtifact(lib_shared);

    // ---- CLI tool ----
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = cpu_target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "nstd", .module = core_mod },
        },
    });
    const exe = b.addExecutable(.{
        .name = "nstd",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    // ---- C ABI conformance test (real libzstd/zlib headers, linked to libnstd) ----
    const c_mod = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true });
    c_mod.addCSourceFile(.{ .file = b.path("tests/c_abi_test.c"), .flags = &.{"-Wall"} });
    c_mod.addIncludePath(b.path("zstd/lib"));
    c_mod.addIncludePath(b.path("include"));
    c_mod.linkLibrary(lib);
    const c_test = b.addExecutable(.{ .name = "c_abi_test", .root_module = c_mod });
    // Streaming zlib driver (used by tests/interop.sh against the system zlib).
    const zt_mod = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true });
    zt_mod.addCSourceFile(.{ .file = b.path("tests/zstream_tool.c"), .flags = &.{"-Wall"} });
    zt_mod.linkLibrary(lib);
    const zt = b.addExecutable(.{ .name = "zstream_tool", .root_module = zt_mod });
    b.installArtifact(zt);
    const run_c = b.addRunArtifact(c_test);
    const c_step = b.step("test-c", "Run the C ABI conformance test");
    c_step.dependOn(&run_c.step);

    // ---- Tests ----
    const tests = b.addTest(.{
        .root_module = core_mod,
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_tests.step);
}
