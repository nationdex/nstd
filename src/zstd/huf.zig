//! Huffman literal coding for Zstandard (RFC 8878 §4.2).

const std = @import("std");
const fse = @import("fse.zig");

pub const Error = fse.Error;
pub const MAX_BITS = 11;
pub const DEC_MAX_BITS = 12;

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

pub const DTable = struct {
    max_bits: u8 = 0,
    /// `symbol | (code_length << 8)` indexed by the next `max_bits` bits.
    ent: [1 << DEC_MAX_BITS]u16 = undefined,
    /// Double-symbol table. `x2_bits == 0` means unused.
    /// Entry: sym0 | (sym1 << 8) | (skip << 16) | (two << 24), indexed by the
    /// next `x2_bits` bits. `two == 0` emits only sym0 and skips `skip` bits.
    x2_bits: u8 = 0,
    /// Every slot emits two symbols (max_bits <= 6). Hot path has no length branch.
    x2_always2: bool = false,
    x2: [1 << DEC_MAX_BITS]u32 = undefined,
};

fn packX2(sym0: u8, sym1: u8, skip: u8, two: bool) u32 {
    return @as(u32, sym0) | (@as(u32, sym1) << 8) | (@as(u32, skip) << 16) | (@as(u32, @intFromBool(two)) << 24);
}

/// Parse a Huffman tree description from the start of `src` into `t`.
/// Returns the number of bytes consumed.
pub fn readTable(t: *DTable, src: []const u8) Error!usize {
    t.x2_bits = 0;
    t.x2_always2 = false;
    if (src.len == 0) return error.CorruptData;
    const hb = src[0];
    var weights: [256]u8 = .{0} ** 256;
    var n: usize = 0;
    var consumed: usize = undefined;

    if (hb >= 128) {
        n = hb - 127;
        const nbytes = (n + 1) / 2;
        if (1 + nbytes > src.len) return error.CorruptData;
        for (0..n) |i| {
            const b = src[1 + i / 2];
            weights[i] = if (i % 2 == 0) b >> 4 else b & 15;
        }
        consumed = 1 + nbytes;
    } else {
        if (hb == 0 or 1 + @as(usize, hb) > src.len) return error.CorruptData;
        const comp = src[1 .. 1 + @as(usize, hb)];
        const nc = try fse.readNCount(comp, 13, 6);
        const dt = try fse.DTable.build(nc.norm[0..nc.nsym], nc.log);
        var r = try fse.RevReader.init(comp[nc.consumed..]);
        var s1: usize = @intCast(r.read(@intCast(nc.log)));
        var s2: usize = @intCast(r.read(@intCast(nc.log)));
        while (true) {
            if (n + 2 > 255) return error.CorruptData;
            var e = dt.e[s1];
            weights[n] = e.sym;
            n += 1;
            s1 = e.base + @as(usize, @intCast(r.read(@intCast(e.nb))));
            if (r.overflowed()) {
                weights[n] = dt.e[s2].sym;
                n += 1;
                break;
            }
            e = dt.e[s2];
            weights[n] = e.sym;
            n += 1;
            s2 = e.base + @as(usize, @intCast(r.read(@intCast(e.nb))));
            if (r.overflowed()) {
                weights[n] = dt.e[s1].sym;
                n += 1;
                break;
            }
        }
        consumed = 1 + @as(usize, hb);
    }

    var sum: u32 = 0;
    for (weights[0..n]) |w| {
        if (w > DEC_MAX_BITS) return error.CorruptData;
        if (w > 0) sum += @as(u32, 1) << @intCast(w - 1);
    }
    if (sum == 0) return error.CorruptData;
    const max_bits: u8 = @intCast(32 - @clz(sum)); // floor(log2)+1
    if (max_bits > DEC_MAX_BITS) return error.CorruptData;
    const left: u32 = (@as(u32, 1) << @intCast(max_bits)) - sum;
    if (left == 0 or (left & (left - 1)) != 0) return error.CorruptData;
    if (n >= 256) return error.CorruptData;
    weights[n] = @intCast(32 - @clz(left)); // log2(left)+1
    n += 1;

    t.max_bits = max_bits;
    // Counting placement: lowest weight (longest code) first, symbols in order.
    var start: [DEC_MAX_BITS + 2]usize = .{0} ** (DEC_MAX_BITS + 2);
    var wcount: [DEC_MAX_BITS + 1]usize = .{0} ** (DEC_MAX_BITS + 1);
    for (weights[0..n]) |wt| wcount[wt] += 1;
    {
        var acc: usize = 0;
        var wt: usize = 1;
        while (wt <= max_bits) : (wt += 1) {
            start[wt] = acc;
            acc += wcount[wt] << @intCast(wt - 1);
        }
        if (acc != (@as(usize, 1) << @intCast(max_bits))) return error.CorruptData;
    }
    for (weights[0..n], 0..) |wt, s| {
        if (wt == 0) continue;
        const cnt: usize = @as(usize, 1) << @intCast(wt - 1);
        const nbits: u8 = max_bits + 1 - wt;
        @memset(t.ent[start[wt] .. start[wt] + cnt], @as(u16, @intCast(s)) | (@as(u16, nbits) << 8));
        start[wt] += cnt;
    }
    buildX2(t);
    return consumed;
}

/// Second symbol whose code is a prefix of the next `room` stream bits, if that
/// code fits entirely in the peeked window.
fn secondSym(t: *const DTable, rem: usize, room: u8, mb: u8) ?struct { sym: u8, nb: u8 } {
    if (room == 0) return null;
    var k: u8 = room;
    while (k >= 1) : (k -= 1) {
        const c = rem >> @intCast(room - k);
        const idx = c << @intCast(mb - k);
        const e = t.ent[idx];
        if (e >> 8 == k) return .{ .sym = @truncate(e), .nb = k };
    }
    return null;
}

/// Fill the double-symbol lookup. Short codes (binary, low-entropy literals)
/// pack two symbols into every slot; longer tables pack two wherever both codes
/// fit in a 12-bit peek, and stay on the single-symbol path if that is rare.
fn buildX2(t: *DTable) void {
    const mb = t.max_bits;
    if (mb == 0 or mb > DEC_MAX_BITS) return;
    const table_log: u8 = if (mb <= 6) mb * 2 else DEC_MAX_BITS;
    const n = @as(usize, 1) << @intCast(table_log);
    var doubles: usize = 0;
    for (0..n) |i| {
        const top: usize = i >> @intCast(table_log - mb);
        const e0 = t.ent[top];
        const nb0: u8 = @intCast(e0 >> 8);
        const sym0: u8 = @truncate(e0);
        const room: u8 = table_log - nb0;
        if (room >= mb) {
            const rem = i & ((@as(usize, 1) << @intCast(room)) - 1);
            const second: usize = rem >> @intCast(room - mb);
            const e1 = t.ent[second];
            const nb1: u8 = @intCast(e1 >> 8);
            t.x2[i] = packX2(sym0, @truncate(e1), nb0 + nb1, true);
            doubles += 1;
        } else if (secondSym(t, i & ((@as(usize, 1) << @intCast(room)) - 1), room, mb)) |s| {
            t.x2[i] = packX2(sym0, s.sym, nb0 + s.nb, true);
            doubles += 1;
        } else {
            t.x2[i] = packX2(sym0, 0, nb0, false);
        }
    }
    // A sparse double table loses to the branchless single-symbol loop.
    if (mb > 6 and doubles * 4 < n) return;
    t.x2_bits = table_log;
    t.x2_always2 = mb <= 6;
}

inline fn x2sym0(e: u32) u8 {
    return @truncate(e);
}
inline fn x2sym1(e: u32) u8 {
    return @truncate(e >> 8);
}
inline fn x2skip(e: u32) u6 {
    return @truncate(e >> 16);
}
inline fn x2two(e: u32) bool {
    return (e >> 24) != 0;
}

/// Two symbols per lookup. Valid only when `x2_always2` (every slot is a pair).
fn decodeStreamX2(t: *const DTable, data: []const u8, dst: []u8) Error!void {
    var r = try fse.FastRev.init(data);
    const pw: u6 = @intCast(t.x2_bits);
    const x2: *const [1 << DEC_MAX_BITS]u32 = &t.x2;
    var i: usize = 0;
    // 4 pair-lookups: at most 4 * 12 = 48 bits, under the 56-bit reload budget.
    while (i + 8 <= dst.len) : (i += 8) {
        r.reload();
        inline for (0..4) |k| {
            const e = x2[@intCast(r.peekFast(pw))];
            dst[i + 2 * k] = x2sym0(e);
            dst[i + 2 * k + 1] = x2sym1(e);
            r.skip(x2skip(e));
        }
    }
    while (i + 2 <= dst.len) : (i += 2) {
        r.reload();
        const e = x2[@intCast(r.peekFast(pw))];
        dst[i] = x2sym0(e);
        dst[i + 1] = x2sym1(e);
        r.skip(x2skip(e));
    }
    if (i < dst.len) {
        r.reload();
        const e = t.ent[@intCast(r.peekFast(@intCast(t.max_bits)))];
        dst[i] = @truncate(e);
        r.skip(@intCast(e >> 8));
    }
    if (r.bitsLeft() != 0) return error.CorruptData;
}

/// Mixed 1-or-2 symbol slots. Used when some but not all peeks cover two codes.
fn decodeStreamX2Hybrid(t: *const DTable, data: []const u8, dst: []u8) Error!void {
    var r = try fse.FastRev.init(data);
    const pw: u6 = @intCast(t.x2_bits);
    const x2: *const [1 << DEC_MAX_BITS]u32 = &t.x2;
    const mb: u6 = @intCast(t.max_bits);
    const ent: *const [1 << DEC_MAX_BITS]u16 = &t.ent;
    var i: usize = 0;
    while (i + 1 < dst.len) {
        r.reload();
        const e = x2[@intCast(r.peekFast(pw))];
        if (x2two(e)) {
            dst[i] = x2sym0(e);
            dst[i + 1] = x2sym1(e);
            r.skip(x2skip(e));
            i += 2;
        } else {
            dst[i] = x2sym0(e);
            r.skip(x2skip(e));
            i += 1;
        }
    }
    if (i < dst.len) {
        r.reload();
        const e = ent[@intCast(r.peekFast(mb))];
        dst[i] = @truncate(e);
        r.skip(@intCast(e >> 8));
    }
    if (r.bitsLeft() != 0) return error.CorruptData;
}

fn decode4X2(t: *const DTable, data: []const u8, dst: []u8) Error!void {
    if (data.len < 6) return error.CorruptData;
    const s1: usize = std.mem.readInt(u16, data[0..2], .little);
    const s2: usize = std.mem.readInt(u16, data[2..4], .little);
    const s3: usize = std.mem.readInt(u16, data[4..6], .little);
    if (6 + s1 + s2 + s3 >= data.len) return error.CorruptData;
    const body = data[6..];
    const seg = (dst.len + 3) / 4;
    if (seg * 3 > dst.len) return error.CorruptData;

    var r0 = try fse.FastRev.init(body[0..s1]);
    var r1 = try fse.FastRev.init(body[s1 .. s1 + s2]);
    var r2 = try fse.FastRev.init(body[s1 + s2 .. s1 + s2 + s3]);
    var r3 = try fse.FastRev.init(body[s1 + s2 + s3 ..]);
    const pw: u6 = @intCast(t.x2_bits);
    const mb: u6 = @intCast(t.max_bits);
    const x2: *const [1 << DEC_MAX_BITS]u32 = &t.x2;
    const ent: *const [1 << DEC_MAX_BITS]u16 = &t.ent;
    const n3 = dst.len - 3 * seg;
    var i: usize = 0;
    // One pair per stream per reload stays well inside the bit budget.
    while (i + 2 <= n3) : (i += 2) {
        if (r0.ptr >= 8 and r1.ptr >= 8 and r2.ptr >= 8 and r3.ptr >= 8) {
            r0.reloadFast();
            r1.reloadFast();
            r2.reloadFast();
            r3.reloadFast();
        } else {
            r0.reload();
            r1.reload();
            r2.reload();
            r3.reload();
        }
        const e0 = x2[@intCast(r0.peekFast(pw))];
        const e1 = x2[@intCast(r1.peekFast(pw))];
        const e2 = x2[@intCast(r2.peekFast(pw))];
        const e3 = x2[@intCast(r3.peekFast(pw))];
        dst[i] = x2sym0(e0);
        dst[i + 1] = x2sym1(e0);
        dst[seg + i] = x2sym0(e1);
        dst[seg + i + 1] = x2sym1(e1);
        dst[2 * seg + i] = x2sym0(e2);
        dst[2 * seg + i + 1] = x2sym1(e2);
        dst[3 * seg + i] = x2sym0(e3);
        dst[3 * seg + i + 1] = x2sym1(e3);
        r0.skip(x2skip(e0));
        r1.skip(x2skip(e1));
        r2.skip(x2skip(e2));
        r3.skip(x2skip(e3));
    }
    const rs = [_]*fse.FastRev{ &r0, &r1, &r2, &r3 };
    for (rs, 0..) |r, si| {
        const len = if (si == 3) n3 else seg;
        var j = i;
        while (j + 2 <= len) : (j += 2) {
            r.reload();
            const e = x2[@intCast(r.peekFast(pw))];
            dst[si * seg + j] = x2sym0(e);
            dst[si * seg + j + 1] = x2sym1(e);
            r.skip(x2skip(e));
        }
        if (j < len) {
            r.reload();
            const e = ent[@intCast(r.peekFast(mb))];
            dst[si * seg + j] = @truncate(e);
            r.skip(@intCast(e >> 8));
        }
        if (r.bitsLeft() != 0) return error.CorruptData;
    }
}

/// Decode exactly `dst.len` symbols from one backward Huffman stream.
pub fn decodeStream(t: *const DTable, data: []const u8, dst: []u8) Error!void {
    if (t.x2_always2) return decodeStreamX2(t, data, dst);
    if (t.x2_bits != 0) return decodeStreamX2Hybrid(t, data, dst);
    var r = try fse.FastRev.init(data);
    const mb: u6 = @intCast(t.max_bits);
    const ent: *const [1 << DEC_MAX_BITS]u16 = &t.ent;
    var i: usize = 0;
    // Each reload yields >= 56 bits: four symbols of up to 12 bits each.
    while (i + 4 <= dst.len) : (i += 4) {
        r.reload();
        inline for (0..4) |k| {
            const e = ent[@intCast(r.peekFast(mb))];
            dst[i + k] = @truncate(e);
            r.skip(@intCast(e >> 8));
        }
    }
    while (i < dst.len) : (i += 1) {
        r.reload();
        const e = ent[@intCast(r.peekFast(mb))];
        dst[i] = @truncate(e);
        r.skip(@intCast(e >> 8));
    }
    if (r.bitsLeft() != 0) return error.CorruptData;
}

/// Decode the 4-stream layout (jump table + streams) into `dst`.
pub fn decode4(t: *const DTable, data: []const u8, dst: []u8) Error!void {
    if (t.x2_always2) return decode4X2(t, data, dst);
    if (data.len < 6) return error.CorruptData;
    const s1: usize = std.mem.readInt(u16, data[0..2], .little);
    const s2: usize = std.mem.readInt(u16, data[2..4], .little);
    const s3: usize = std.mem.readInt(u16, data[4..6], .little);
    if (6 + s1 + s2 + s3 >= data.len) return error.CorruptData;
    const body = data[6..];
    const seg = (dst.len + 3) / 4;
    if (seg * 3 > dst.len) return error.CorruptData;

    var r0 = try fse.FastRev.init(body[0..s1]);
    var r1 = try fse.FastRev.init(body[s1 .. s1 + s2]);
    var r2 = try fse.FastRev.init(body[s1 + s2 .. s1 + s2 + s3]);
    var r3 = try fse.FastRev.init(body[s1 + s2 + s3 ..]);
    const mb: u6 = @intCast(t.max_bits);
    const ent: *const [1 << DEC_MAX_BITS]u16 = &t.ent;
    const n3 = dst.len - 3 * seg;
    var i: usize = 0;
    // Interleave the four streams so their table lookups overlap.
    while (i + 4 <= n3) : (i += 4) {
        if (r0.ptr >= 8 and r1.ptr >= 8 and r2.ptr >= 8 and r3.ptr >= 8) {
            r0.reloadFast();
            r1.reloadFast();
            r2.reloadFast();
            r3.reloadFast();
        } else {
            r0.reload();
            r1.reload();
            r2.reload();
            r3.reload();
        }
        inline for (0..4) |k| {
            const e0 = ent[@intCast(r0.peekFast(mb))];
            const e1 = ent[@intCast(r1.peekFast(mb))];
            const e2 = ent[@intCast(r2.peekFast(mb))];
            const e3 = ent[@intCast(r3.peekFast(mb))];
            dst[i + k] = @truncate(e0);
            dst[seg + i + k] = @truncate(e1);
            dst[2 * seg + i + k] = @truncate(e2);
            dst[3 * seg + i + k] = @truncate(e3);
            r0.skip(@intCast(e0 >> 8));
            r1.skip(@intCast(e1 >> 8));
            r2.skip(@intCast(e2 >> 8));
            r3.skip(@intCast(e3 >> 8));
        }
    }
    // Remainders (the first three streams carry up to 3 extra symbols).
    const rs = [_]*fse.FastRev{ &r0, &r1, &r2, &r3 };
    for (rs, 0..) |r, si| {
        const len = if (si == 3) n3 else seg;
        var j = i;
        while (j < len) : (j += 1) {
            r.reload();
            const e = ent[@intCast(r.peekFast(mb))];
            dst[si * seg + j] = @truncate(e);
            r.skip(@intCast(e >> 8));
        }
        if (r.bitsLeft() != 0) return error.CorruptData;
    }
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

pub const Enc = struct {
    nb: [256]u8 = .{0} ** 256,
    code: [256]u16 = .{0} ** 256,
    max_bits: u8 = 0,
    /// One past the highest symbol with a nonzero count.
    nsym: usize = 0,
};

const Node = struct { freq: u64, parent: u16 = 0xFFFF };

/// Build a length-limited canonical Huffman code. Null when fewer than two
/// distinct symbols are present.
pub fn build(freq: *const [256]u32) ?Enc {
    var syms: [256]u8 = undefined;
    var n: usize = 0;
    for (freq, 0..) |f, s| {
        if (f != 0) {
            syms[n] = @intCast(s);
            n += 1;
        }
    }
    if (n < 2) return null;

    const Ctx = struct {
        f: *const [256]u32,
        fn lt(c: @This(), a: u8, b: u8) bool {
            return c.f[a] < c.f[b];
        }
    };
    std.mem.sort(u8, syms[0..n], Ctx{ .f = freq }, Ctx.lt);

    // Two-queue Huffman construction.
    var nodes: [512]Node = undefined;
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
    var depth: [512]u8 = undefined;
    depth[total - 1] = 0;
    var i: usize = total - 1;
    while (i > 0) {
        i -= 1;
        depth[i] = depth[nodes[i].parent] + 1;
    }

    var len: [256]u8 = .{0} ** 256;
    for (0..n) |k| len[syms[k]] = depth[k];

    // Length-limit to MAX_BITS while keeping the Kraft sum exactly 1.
    var kraft: u64 = 0;
    for (syms[0..n]) |s| {
        if (len[s] > MAX_BITS) len[s] = MAX_BITS;
        kraft += @as(u64, 1) << @intCast(MAX_BITS - len[s]);
    }
    const one: u64 = @as(u64, 1) << MAX_BITS;
    while (kraft > one) {
        // lengthen the cheapest symbol that is still shorter than the limit
        var best: ?u8 = null;
        for (syms[0..n]) |s| {
            if (len[s] >= MAX_BITS) continue;
            if (best == null or freq[s] < freq[best.?] or
                (freq[s] == freq[best.?] and len[s] > len[best.?])) best = s;
        }
        const b = best.?;
        kraft -= @as(u64, 1) << @intCast(MAX_BITS - len[b] - 1);
        len[b] += 1;
    }
    while (kraft < one) {
        // shorten the most frequent symbol whose extra weight still fits
        var best: ?u8 = null;
        for (syms[0..n]) |s| {
            if (len[s] <= 1) continue;
            const add: u64 = @as(u64, 1) << @intCast(MAX_BITS - len[s]);
            if (kraft + add > one) continue;
            if (best == null or freq[s] > freq[best.?]) best = s;
        }
        if (best == null) break;
        const b = best.?;
        kraft += @as(u64, 1) << @intCast(MAX_BITS - len[b]);
        len[b] -= 1;
    }
    if (kraft != one) return null;

    var max_len: u8 = 0;
    for (syms[0..n]) |s| max_len = @max(max_len, len[s]);

    var enc = Enc{ .max_bits = max_len };
    enc.nsym = @as(usize, syms[0]) + 1;
    for (syms[0..n]) |s| enc.nsym = @max(enc.nsym, @as(usize, s) + 1);
    var idx: u32 = 0;
    var w: u8 = 1;
    while (w <= max_len) : (w += 1) {
        const nbits = max_len + 1 - w;
        const cnt: u32 = @as(u32, 1) << @intCast(w - 1);
        for (0..256) |s| {
            if (len[s] != nbits) continue;
            enc.nb[s] = nbits;
            enc.code[s] = @intCast(idx >> @intCast(w - 1));
            idx += cnt;
        }
    }
    return enc;
}

/// Estimated encoded size in bytes of the symbol stream (excludes table).
pub fn estimateSize(enc: *const Enc, freq: *const [256]u32) usize {
    var bits: u64 = 0;
    for (freq, 0..) |f, s| bits += @as(u64, f) * enc.nb[s];
    return @intCast((bits + 7) / 8);
}

/// Write the tree description into `out`. Returns bytes written, or null if
/// it cannot be represented.
pub fn writeTable(enc: *const Enc, out: []u8) ?usize {
    const n = enc.nsym - 1; // last weight is implicit
    if (n == 0) return null;
    var weights: [256]u8 = .{0} ** 256;
    for (0..n) |s| weights[s] = if (enc.nb[s] > 0) enc.max_bits + 1 - enc.nb[s] else 0;

    var best: ?usize = null;

    // FSE-compressed weights.
    var tmp: [256]u8 = undefined;
    if (compressWeights(weights[0..n], &tmp)) |clen| {
        if (clen < 128 and clen + 1 <= out.len) {
            out[0] = @intCast(clen);
            @memcpy(out[1 .. 1 + clen], tmp[0..clen]);
            best = 1 + clen;
        }
    }
    // Direct 4-bit weights.
    if (n <= 128) {
        const direct = 1 + (n + 1) / 2;
        if ((best == null or direct < best.?) and direct <= out.len) {
            out[0] = @intCast(127 + n);
            @memset(out[1..direct], 0);
            for (0..n) |i| {
                if (i % 2 == 0) out[1 + i / 2] |= weights[i] << 4 else out[1 + i / 2] |= weights[i];
            }
            best = direct;
        }
    }
    return best;
}

fn compressWeights(weights: []const u8, out: []u8) ?usize {
    const n = weights.len;
    if (n < 2) return null;
    var counts: [16]u32 = .{0} ** 16;
    for (weights) |w| counts[w] += 1;
    var present: u32 = 0;
    for (counts) |c| {
        if (c != 0) present += 1;
    }
    if (present < 2) return null;
    const log: u8 = 6;
    var norm: [16]i16 = .{0} ** 16;
    const nsym = fse.normalize(&counts, n, log, &norm);
    const ct = fse.CTable.build(norm[0..nsym], log);

    var hdr: [64]u8 = undefined;
    const hlen = fse.writeNCount(&hdr, norm[0..nsym], nsym, log) catch return null;

    var body: [512]u8 = undefined;
    var w = fse.BitW.init(&body);
    var s1: u32 = undefined;
    var s2: u32 = undefined;
    var i: usize = n;
    if (n % 2 == 1) {
        i -= 1;
        s1 = ct.initState(weights[i]); // symbol N-1 lives in state 1 (even index)
        i -= 1;
        s2 = ct.initState(weights[i]);
    } else {
        i -= 1;
        s2 = ct.initState(weights[i]);
        i -= 1;
        s1 = ct.initState(weights[i]);
    }
    while (i > 0) {
        i -= 1;
        if (i % 2 == 0) ct.encode(&w, &s1, weights[i]) else ct.encode(&w, &s2, weights[i]);
    }
    ct.flush(&w, s2);
    ct.flush(&w, s1);
    const blen = w.close() catch return null;
    if (hlen + blen > out.len) return null;
    @memcpy(out[0..hlen], hdr[0..hlen]);
    @memcpy(out[hlen .. hlen + blen], body[0..blen]);

    // Verify with the real decoder path to dodge the zero-bit tail ambiguity.
    var probe: [1 + 256]u8 = undefined;
    const total = hlen + blen;
    if (total >= 128) return null;
    probe[0] = @intCast(total);
    @memcpy(probe[1 .. 1 + total], out[0..total]);
    var dec: [256]u8 = .{0} ** 256;
    var cnt: usize = 0;
    if (decodeWeightsFse(probe[0 .. 1 + total], &dec, &cnt)) |_| {} else |_| return null;
    if (cnt != n or !std.mem.eql(u8, dec[0..n], weights)) return null;
    return total;
}

fn decodeWeightsFse(src: []const u8, weights: *[256]u8, count: *usize) Error!void {
    const hb = src[0];
    const comp = src[1 .. 1 + @as(usize, hb)];
    const nc = try fse.readNCount(comp, 13, 6);
    const dt = try fse.DTable.build(nc.norm[0..nc.nsym], nc.log);
    var r = try fse.RevReader.init(comp[nc.consumed..]);
    var s1: usize = @intCast(r.read(@intCast(nc.log)));
    var s2: usize = @intCast(r.read(@intCast(nc.log)));
    var n: usize = 0;
    while (true) {
        if (n + 2 > 255) return error.CorruptData;
        var e = dt.e[s1];
        weights[n] = e.sym;
        n += 1;
        s1 = e.base + @as(usize, @intCast(r.read(@intCast(e.nb))));
        if (r.overflowed()) {
            weights[n] = dt.e[s2].sym;
            n += 1;
            break;
        }
        e = dt.e[s2];
        weights[n] = e.sym;
        n += 1;
        s2 = e.base + @as(usize, @intCast(r.read(@intCast(e.nb))));
        if (r.overflowed()) {
            weights[n] = dt.e[s1].sym;
            n += 1;
            break;
        }
    }
    count.* = n;
}

/// Encode `src` as one backward stream into `out`. Returns byte count.
pub fn encodeStream(enc: *const Enc, src: []const u8, out: []u8) Error!usize {
    var w = fse.BitW.init(out);
    var i = src.len;
    while (i > 0) {
        i -= 1;
        const s = src[i];
        w.put(enc.code[s], @intCast(enc.nb[s]));
    }
    return w.close();
}

test "huffman roundtrip" {
    var freq: [256]u32 = .{0} ** 256;
    const text = "the quick brown fox jumps over the lazy dog, the quick brown fox";
    for (text) |c| freq[c] += 1;
    const enc = build(&freq).?;
    var tbl: [200]u8 = undefined;
    const tlen = writeTable(&enc, &tbl).?;
    var dt: DTable = undefined;
    const used = try readTable(&dt, tbl[0..tlen]);
    try std.testing.expectEqual(tlen, used);
    var buf: [256]u8 = undefined;
    const blen = try encodeStream(&enc, text, &buf);
    var back: [text.len]u8 = undefined;
    try decodeStream(&dt, buf[0..blen], &back);
    try std.testing.expectEqualStrings(text, &back);
}

test "x2 double-symbol roundtrip" {
    var freq: [256]u32 = .{0} ** 256;
    freq['a'] = 8000;
    freq['b'] = 400;
    freq['c'] = 40;
    freq['d'] = 4;
    const enc = build(&freq).?;
    var tbl: [128]u8 = undefined;
    const tlen = writeTable(&enc, &tbl).?;
    var dt: DTable = undefined;
    const used = try readTable(&dt, tbl[0..tlen]);
    try std.testing.expectEqual(tlen, used);
    if (dt.max_bits <= 6) try std.testing.expect(dt.x2_always2);

    var src: [4096]u8 = undefined;
    for (&src, 0..) |*c, i| c.* = "aaabaaac"[i % 8];
    var buf: [8192]u8 = undefined;
    const blen = try encodeStream(&enc, &src, &buf);
    var back: [4096]u8 = undefined;
    try decodeStream(&dt, buf[0..blen], &back);
    try std.testing.expectEqualSlices(u8, &src, &back);
}
