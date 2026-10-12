//! Portable SIMD / wildcard copy primitives.
//!
//! All hot decompression match-copy paths use `wildcopy` semantics: copy in
//! fixed 8/16/32-byte units, allowing overrun up to the next unit boundary.
//! Works on every architecture (scalar loads), with optional vector width chosen
//! at comptime based on the target.

const std = @import("std");
const builtin = @import("builtin");

const cpu = builtin.cpu;

/// Vector width chosen for the active target: 32 bytes where AVX2 is present,
/// 16 for SSE/NEON-class targets, otherwise fall back to 8-byte scalar units.
const VEC_LEN: comptime_int = blk: {
    if (cpu.arch.isX86()) {
        if (std.Target.x86.featureSetHas(cpu.features, .avx2)) break :blk 32;
        break :blk 16;
    }
    if (cpu.arch == .aarch64 or cpu.arch == .arm) break :blk 16;
    break :blk 8;
};

pub const Vec = @Vector(VEC_LEN, u8);

/// Overlapping-safe forward match copy. `dst` must have room for `len` bytes.
/// May write up to `VEC_LEN - 1` bytes past `dst + len` (caller reserves slack).
pub fn wildcopy(dst: [*]u8, src: [*]const u8, len: usize) void {
    var i: usize = 0;
    if (VEC_LEN == 8) {
        while (i + 8 <= len) : (i += 8) {
            @as(*align(1) u64, @ptrCast(dst + i)).* =
                @as(*align(1) const u64, @ptrCast(src + i)).*;
        }
        while (i < len) : (i += 1) dst[i] = src[i];
        return;
    }
    while (i + VEC_LEN <= len) : (i += VEC_LEN) {
        const v: Vec = src[i..][0..VEC_LEN].*;
        dst[i..][0..VEC_LEN].* = v;
    }
    while (i < len) : (i += 1) dst[i] = src[i];
}

/// Byte-by-byte forward copy used when the match overlaps the output (dist < len).
/// Overwrite-safe: writes strictly left-to-right so repeats propagate correctly.
pub fn matchcopy(dst: [*]u8, dist: usize, len: usize) void {
    var i: usize = 0;
    if (dist >= 8) {
        // No byte-level overlap within an 8-byte step: do aligned 8-byte chunks
        // then finish byte-wise.
        while (i + 8 <= len) : (i += 8) {
            @as(*align(1) u64, @ptrCast(dst + i)).* =
                @as(*align(1) const u64, @ptrCast(dst + i - dist)).*;
        }
    }
    while (i < len) : (i += 1) {
        dst[i] = (dst - dist)[i];
    }
}

/// Fast non-overlapping memcpy of `len` bytes.
pub fn fastcopy(dst: [*]u8, src: [*]const u8, len: usize) void {
    if (len >= VEC_LEN) {
        wildcopy(dst, src, len);
    } else {
        var i: usize = 0;
        while (i < len) : (i += 1) dst[i] = src[i];
    }
}

test "wildcopy roundtrip" {
    var src = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };
    var dst: [64]u8 = [_]u8{0} ** 64;
    wildcopy(&dst, &src, 20);
    try std.testing.expectEqualSlices(u8, src[0..20], dst[0..20]);
}

test "matchcopy overlapping" {
    var buf: [64]u8 = [_]u8{0} ** 64;
    buf[0] = 'a';
    buf[1] = 'b';
    matchcopy(buf[2..].ptr, 2, 10); // dist 2: "ab" repeats
    try std.testing.expectEqualSlices(u8, "abababababab", buf[0..12]);
}
