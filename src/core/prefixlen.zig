//! Length-limited Huffman code lengths, shared by entropy coders that need a
//! prefix code with a hard maximum code length (Brotli: 15, code-length code: 5).

const std = @import("std");

pub const MAX_SYMS = 1024;

const Node = struct { freq: u64, parent: u16 = 0xFFFF };

/// Compute code lengths for `freq` capped at `max_bits`. Symbols with zero
/// frequency get length 0. With exactly one used symbol its length is 0 (the
/// caller decides how to encode a degenerate code). The resulting code is
/// complete (Kraft sum == 1) whenever two or more symbols are used.
pub fn limitedLengths(freq: []const u32, max_bits: u8, out: []u8) void {
    std.debug.assert(freq.len <= MAX_SYMS and out.len >= freq.len);
    @memset(out[0..freq.len], 0);

    var syms: [MAX_SYMS]u16 = undefined;
    var n: usize = 0;
    for (freq, 0..) |f, s| {
        if (f != 0) {
            syms[n] = @intCast(s);
            n += 1;
        }
    }
    if (n == 0) return;
    if (n == 1) return;

    const Ctx = struct {
        f: []const u32,
        fn lt(c: @This(), a: u16, b: u16) bool {
            if (c.f[a] != c.f[b]) return c.f[a] < c.f[b];
            return a < b;
        }
    };
    std.mem.sort(u16, syms[0..n], Ctx{ .f = freq }, Ctx.lt);

    var nodes: [2 * MAX_SYMS]Node = undefined;
    for (0..n) |i| nodes[i] = .{ .freq = freq[syms[i]] };
    var leaf: usize = 0;
    var inner: usize = n;
    var total: usize = n;
    while (total < 2 * n - 1) {
        var picks: [2]usize = undefined;
        for (&picks) |*p| {
            const have_leaf = leaf < n;
            const have_inner = inner < total;
            if (have_leaf and (!have_inner or nodes[leaf].freq <= nodes[inner].freq)) {
                p.* = leaf;
                leaf += 1;
            } else {
                p.* = inner;
                inner += 1;
            }
        }
        nodes[total] = .{ .freq = nodes[picks[0]].freq + nodes[picks[1]].freq };
        nodes[picks[0]].parent = @intCast(total);
        nodes[picks[1]].parent = @intCast(total);
        total += 1;
    }
    var depth: [2 * MAX_SYMS]u16 = undefined;
    depth[total - 1] = 0;
    var i: usize = total - 1;
    while (i > 0) {
        i -= 1;
        depth[i] = depth[nodes[i].parent] + 1;
    }
    for (0..n) |k| out[syms[k]] = @intCast(@min(depth[k], 255));

    // Cap at max_bits while restoring Kraft equality.
    const one: u64 = @as(u64, 1) << @intCast(max_bits);
    var kraft: u64 = 0;
    for (syms[0..n]) |s| {
        if (out[s] > max_bits) out[s] = max_bits;
        kraft += one >> @intCast(out[s]);
    }
    while (kraft > one) {
        var best: ?u16 = null;
        for (syms[0..n]) |s| {
            if (out[s] >= max_bits) continue;
            if (best == null or freq[s] < freq[best.?] or
                (freq[s] == freq[best.?] and out[s] > out[best.?])) best = s;
        }
        const b = best.?;
        kraft -= one >> @intCast(out[b] + 1);
        out[b] += 1;
    }
    while (kraft < one) {
        var best: ?u16 = null;
        for (syms[0..n]) |s| {
            if (out[s] <= 1) continue;
            const add: u64 = one >> @intCast(out[s]);
            if (kraft + add > one) continue;
            if (best == null or freq[s] > freq[best.?]) best = s;
        }
        if (best == null) break;
        const b = best.?;
        kraft += one >> @intCast(out[b]);
        out[b] -= 1;
    }
}

/// Canonical codes (MSB-first values) for `lengths`, per RFC 1951/7932.
pub fn canonicalCodes(lengths: []const u8, codes: []u16) void {
    var count: [16]u16 = .{0} ** 16;
    for (lengths) |l| count[l] += 1;
    count[0] = 0;
    var next: [16]u16 = .{0} ** 16;
    var code: u32 = 0;
    for (1..16) |l| {
        code = (code + count[l - 1]) << 1;
        next[l] = @intCast(code);
    }
    for (lengths, 0..) |l, s| {
        if (l == 0) {
            codes[s] = 0;
            continue;
        }
        codes[s] = next[l];
        next[l] += 1;
    }
}

test "limited lengths are complete" {
    var freq: [40]u32 = undefined;
    for (&freq, 0..) |*f, i| f.* = @as(u32, 1) << @intCast(@min(i, 20));
    var len: [40]u8 = undefined;
    limitedLengths(&freq, 15, &len);
    var k: u32 = 0;
    for (len) |l| {
        try std.testing.expect(l >= 1 and l <= 15);
        k += @as(u32, 1) << @intCast(15 - l);
    }
    try std.testing.expectEqual(@as(u32, 1 << 15), k);
}
