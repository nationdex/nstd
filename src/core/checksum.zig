//! Checksum primitives: XXH64 (Zstd) and CRC32 (Gzip), pure Zig, table-driven
//! with slicing-by-8 style accumulation. Tables are comptime so they land in
//! .rodata with zero runtime cost.

const std = @import("std");

// ---------------------------------------------------------------------------
// CRC32 (IEEE, reflected, poly 0xEDB88320) — Gzip trailer.
// ---------------------------------------------------------------------------

/// Slicing-by-16 tables: `crc_tab[k][b]` is the CRC contribution of byte `b`
/// followed by `k` zero bytes.
const crc_tab = blk: {
    @setEvalBranchQuota(200000);
    var t: [16][256]u32 = undefined;
    for (0..256) |i| {
        var c: u32 = @intCast(i);
        for (0..8) |_| c = if (c & 1 != 0) (0xEDB88320 ^ (c >> 1)) else (c >> 1);
        t[0][i] = c;
    }
    for (0..256) |i| {
        var c = t[0][i];
        for (1..16) |k| {
            c = t[0][c & 0xFF] ^ (c >> 8);
            t[k][i] = c;
        }
    }
    break :blk t;
};

pub fn crc32(input: []const u8, seed: u32) u32 {
    var c: u32 = ~seed;
    var p = input;
    // 16 bytes per step: four independent table lookups per 32-bit lane.
    while (p.len >= 16) {
        const w0 = std.mem.readInt(u32, p[0..4], .little) ^ c;
        const w1 = std.mem.readInt(u32, p[4..8], .little);
        const w2 = std.mem.readInt(u32, p[8..12], .little);
        const w3 = std.mem.readInt(u32, p[12..16], .little);
        c = crc_tab[15][w0 & 0xFF] ^ crc_tab[14][(w0 >> 8) & 0xFF] ^ crc_tab[13][(w0 >> 16) & 0xFF] ^ crc_tab[12][w0 >> 24] ^
            crc_tab[11][w1 & 0xFF] ^ crc_tab[10][(w1 >> 8) & 0xFF] ^ crc_tab[9][(w1 >> 16) & 0xFF] ^ crc_tab[8][w1 >> 24] ^
            crc_tab[7][w2 & 0xFF] ^ crc_tab[6][(w2 >> 8) & 0xFF] ^ crc_tab[5][(w2 >> 16) & 0xFF] ^ crc_tab[4][w2 >> 24] ^
            crc_tab[3][w3 & 0xFF] ^ crc_tab[2][(w3 >> 8) & 0xFF] ^ crc_tab[1][(w3 >> 16) & 0xFF] ^ crc_tab[0][w3 >> 24];
        p = p[16..];
    }
    for (p) |b| c = crc_tab[0][(c ^ b) & 0xFF] ^ (c >> 8);
    return ~c;
}

test "crc32 matches the reference value and the byte-wise result" {
    try std.testing.expectEqual(@as(u32, 0xCBF43926), crc32("123456789", 0));
    var buf: [1000]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    for ([_]usize{ 0, 1, 15, 16, 17, 100, 999, 1000 }) |n| {
        var c: u32 = 0xFFFFFFFF;
        for (buf[0..n]) |b| c = crc_tab[0][(c ^ b) & 0xFF] ^ (c >> 8);
        try std.testing.expectEqual(~c, crc32(buf[0..n], 0));
    }
    // Chaining: crc(a ++ b) == crc(b, crc(a)).
    try std.testing.expectEqual(crc32(buf[0..500], 0), crc32(buf[0..500], 0));
    try std.testing.expectEqual(crc32(buf[0..1000], 0), crc32(buf[300..1000], crc32(buf[0..300], 0)));
}

// ---------------------------------------------------------------------------
// XXH64 — Zstd frame content checksum.
// ---------------------------------------------------------------------------

const PRIME64_1: u64 = 0x9E3779B185EBCA87;
const PRIME64_2: u64 = 0xC2B2AE3D27D4EB4F;
const PRIME64_3: u64 = 0x165667B19E3779F9;
const PRIME64_4: u64 = 0x85EBCA77C2B2AE63;
const PRIME64_5: u64 = 0x27D4EB2F165667C5;

inline fn round(acc: u64, lane: u64) u64 {
    var a = acc;
    a +%= lane *% PRIME64_2;
    a = std.math.rotl(u64, a, 31);
    a *%= PRIME64_1;
    return a;
}

inline fn mergeRound(acc: u64, val: u64) u64 {
    var v = val;
    v = round(0, v);
    var a = acc;
    a ^= v;
    return a *% PRIME64_1 +% PRIME64_4;
}

fn readU64le(p: [*]const u8) u64 {
    return std.mem.readInt(u64, p[0..8], .little);
}

fn readU32le(p: [*]const u8) u32 {
    return std.mem.readInt(u32, p[0..4], .little);
}

pub fn xxh64(input: []const u8, seed: u64) u64 {
    const len = input.len;
    const p = input.ptr;
    var h: u64 = 0;
    var off: usize = 0;

    if (len >= 32) {
        var v1 = seed +% PRIME64_1 +% PRIME64_2;
        var v2 = seed +% PRIME64_2;
        var v3 = seed;
        var v4 = seed -% PRIME64_1;

        const limit = len - 32;
        while (off <= limit) : (off += 32) {
            v1 = round(v1, readU64le(p + off));
            v2 = round(v2, readU64le(p + off + 8));
            v3 = round(v3, readU64le(p + off + 16));
            v4 = round(v4, readU64le(p + off + 24));
        }
        h = std.math.rotl(u64, v1, 1) +% std.math.rotl(u64, v2, 7) +%
            std.math.rotl(u64, v3, 12) +% std.math.rotl(u64, v4, 18);
        h = mergeRound(h, v1);
        h = mergeRound(h, v2);
        h = mergeRound(h, v3);
        h = mergeRound(h, v4);
    } else {
        h = seed +% PRIME64_5;
    }

    h +%= @as(u64, len);

    // Tail: `off` now points at the first byte past the 32-byte stride loop.
    if (len - off >= 8) {
        const limit = len - 8;
        while (off <= limit) : (off += 8) {
            const k = round(0, readU64le(p + off));
            h ^= k;
            h = std.math.rotl(u64, h, 27) *% PRIME64_1 +% PRIME64_4;
        }
    }
    if (off + 4 <= len) {
        h ^= @as(u64, readU32le(p + off)) *% PRIME64_1;
        h = std.math.rotl(u64, h, 23) *% PRIME64_2 +% PRIME64_3;
        off += 4;
    }
    while (off < len) : (off += 1) {
        h ^= @as(u64, p[off]) *% PRIME64_5;
        h = std.math.rotl(u64, h, 11) *% PRIME64_1;
    }

    h ^= h >> 33;
    h *%= PRIME64_2;
    h ^= h >> 29;
    h *%= PRIME64_3;
    h ^= h >> 32;
    return h;
}

test "crc32 known vectors" {
    try std.testing.expectEqual(@as(u32, 0), crc32("", 0));
    try std.testing.expectEqual(@as(u32, 0xCBF43926), crc32("123456789", 0));
}

test "xxh64 known vectors" {
    // XXH64("", 0) == 0xEF46DB3751D8E999
    try std.testing.expectEqual(@as(u64, 0xEF46DB3751D8E999), xxh64("", 0));
    // XXH64("xxhash", 0) == 0x32DD38952C4BC720
    try std.testing.expectEqual(@as(u64, 0x32DD38952C4BC720), xxh64("xxhash", 0));
    // XXH64("abc", 0) == 0x44BC2CF5AD770999
    try std.testing.expectEqual(@as(u64, 0x44BC2CF5AD770999), xxh64("abc", 0));
}

/// Adler-32 (zlib trailer). `seed` is the running value (1 for a fresh stream).
pub fn adler32(input: []const u8, seed: u32) u32 {
    var a: u32 = seed & 0xFFFF;
    var b: u32 = seed >> 16;
    var i: usize = 0;
    while (i < input.len) {
        const n = @min(input.len - i, 5552);
        for (input[i .. i + n]) |x| {
            a +%= x;
            b +%= a;
        }
        a %= 65521;
        b %= 65521;
        i += n;
    }
    return (b << 16) | a;
}

test "adler32 known" {
    try std.testing.expectEqual(@as(u32, 0x11E60398), adler32("Wikipedia", 1));
}
