//! Deflate (RFC 1951) engine: table-driven inflate and a hash-chain LZ77
//! compressor that emits dynamic-Huffman, fixed-Huffman or stored blocks,
//! whichever is smallest per block.

const std = @import("std");
const prefixlen = @import("../core/prefixlen.zig");

pub const Level = enum(u8) {
    stored = 0,
    fast = 1,
    default = 6,
    best = 9,
};

pub const Error = error{
    CorruptData,
    InvalidWindow,
    OutOfMemory,
    NoSpaceLeft,
    InputTooSmall,
};

// ===========================================================================
// Code tables (RFC 1951 §3.2.5)
// ===========================================================================

const length_base = [29]u16{
    3,  4,  5,  6,  7,  8,  9,  10,  11,  13,  15,  17,  19,  23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
};
const length_extra = [29]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
};
const dist_base = [30]u16{
    1,    2,    3,    4,     5,     7,     9,   13,  17,   25,   33,   49,
    65,   97,   129,  193,   257,   385,   513, 769, 1025, 1537, 2049, 3073,
    4097, 6145, 8193, 12289, 16385, 24577,
};
const dist_extra = [30]u8{
    0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
    6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
};
pub const cl_order = [19]u8{ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

/// length (3..258) -> length code index (0..28)
const len_code_tab = blk: {
    @setEvalBranchQuota(100000);
    var t: [259]u8 = .{0} ** 259;
    var l: usize = 3;
    while (l <= 258) : (l += 1) {
        var c: usize = 28;
        if (l != 258) {
            c = 0;
            while (c < 28 and length_base[c + 1] <= l) c += 1;
        }
        t[l] = c;
    }
    break :blk t;
};

inline fn distCode(dist: u32) u8 {
    const x = dist - 1;
    if (x < 4) return @intCast(x);
    const n: u5 = @intCast(31 - @clz(x));
    return @intCast(2 * @as(u32, n) + ((x >> (n - 1)) & 1));
}

// ===========================================================================
// Inflate
// ===========================================================================

pub const FAST_BITS = 10;

pub const Kind = enum { clen, lit, dist };

pub const F_LIT: u32 = 1 << 4;
pub const F_EOB: u32 = 1 << 5;
pub const F_LEN: u32 = 1 << 6;

/// Decode-table entry for `sym` coded with `len` bits. Everything the decoder
/// needs after one lookup is packed in: literal byte / length base+extra bits /
/// distance base+extra bits. Zero means "not decodable from the fast table".
pub fn entryFor(kind: Kind, sym: usize, len: u32) u32 {
    switch (kind) {
        .clen => return (@as(u32, @intCast(sym)) << 8) | len,
        .lit => {
            if (sym < 256) return F_LIT | (@as(u32, @intCast(sym)) << 8) | len;
            if (sym == 256) return F_EOB | len;
            if (sym <= 285) {
                const li = sym - 257;
                return F_LEN | (@as(u32, length_base[li]) << 8) | (@as(u32, length_extra[li]) << 24) | len;
            }
            return 0;
        },
        .dist => {
            if (sym >= 30) return 0;
            return (@as(u32, dist_base[sym]) << 8) | (@as(u32, dist_extra[sym]) << 24) | len;
        },
    }
}

pub const Table = struct {
    fast: [1 << FAST_BITS]u32,
    counts: [16]u16,
    syms: [288]u16,
    kind: Kind,

    pub fn build(t: *Table, kind: Kind, lens: []const u8) Error!void {
        t.kind = kind;
        t.counts = .{0} ** 16;
        t.fast = .{0} ** (1 << FAST_BITS);
        for (lens) |l| t.counts[l] += 1;
        t.counts[0] = 0;
        var left: i32 = 1;
        for (1..16) |l| {
            left <<= 1;
            left -= t.counts[l];
            if (left < 0) return error.CorruptData; // over-subscribed
        }
        var used: usize = 0;
        var max_len: usize = 0;
        for (1..16) |l| {
            used += t.counts[l];
            if (t.counts[l] != 0) max_len = l;
        }
        // Incomplete codes are only legal as a single one-bit code.
        if (left > 0 and !(used == 1 and max_len == 1) and used != 0) return error.CorruptData;

        var offs: [17]u16 = .{0} ** 17;
        for (1..16) |l| offs[l + 1] = offs[l] + t.counts[l];
        var next: [17]u32 = .{0} ** 17;
        var code: u32 = 0;
        for (1..16) |l| {
            code = (code + t.counts[l - 1]) << 1;
            next[l] = code;
        }
        for (lens, 0..) |l, s| {
            if (l == 0) continue;
            t.syms[offs[l]] = @intCast(s);
            offs[l] += 1;
            const c = next[l];
            next[l] += 1;
            if (l <= FAST_BITS) {
                const rv: u32 = @bitReverse(@as(u16, @intCast(c))) >> @intCast(16 - @as(u5, @intCast(l)));
                const step: usize = @as(usize, 1) << @intCast(l);
                var i: usize = rv;
                const e = entryFor(kind, s, l);
                while (i < (1 << FAST_BITS)) : (i += step) t.fast[i] = e;
            }
        }
    }

    /// Canonical walk over `bits` (LSB = first bit); returns (symbol, length).
    pub fn slow(t: *const Table, bits: u32) ?struct { sym: u16, len: u5 } {
        var code: i32 = 0;
        var first: i32 = 0;
        var index: i32 = 0;
        var b = bits;
        for (1..16) |l| {
            code |= @intCast(b & 1);
            b >>= 1;
            const count: i32 = t.counts[l];
            if (code - first < count) return .{ .sym = t.syms[@intCast(index + (code - first))], .len = @intCast(l) };
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        return null;
    }
};

pub const BitIn = struct {
    data: []const u8,
    pos: usize = 0,
    bb: u64 = 0,
    nb: u32 = 0,
    /// Zero bits appended past the end of the input.
    pad: u32 = 0,

    pub inline fn refill(self: *BitIn) void {
        if (self.pos + 8 <= self.data.len) {
            self.bb |= std.mem.readInt(u64, self.data[self.pos..][0..8], .little) << @intCast(self.nb);
            const adv = (63 - self.nb) >> 3;
            self.pos += adv;
            self.nb += adv * 8;
        } else {
            while (self.nb <= 56) {
                if (self.pos < self.data.len) {
                    self.bb |= @as(u64, self.data[self.pos]) << @intCast(self.nb);
                    self.pos += 1;
                } else {
                    self.pad += 8;
                }
                self.nb += 8;
            }
        }
    }

    pub inline fn take(self: *BitIn, n: u6) u32 {
        const v: u32 = @truncate(self.bb & ((@as(u64, 1) << n) - 1));
        self.bb >>= n;
        self.nb -= n;
        return v;
    }

    /// True once bits beyond the real input have been consumed.
    pub inline fn overrun(self: *const BitIn) bool {
        return self.pad > self.nb;
    }

    /// Byte index of the next unread input byte (after dropping partial bits).
    pub fn bytePos(self: *const BitIn) usize {
        const whole = (self.nb - self.pad) / 8;
        return self.pos - whole;
    }
};

pub const fixed_lit_lens = blk: {
    var l: [288]u8 = undefined;
    for (0..144) |i| l[i] = 8;
    for (144..256) |i| l[i] = 9;
    for (256..280) |i| l[i] = 7;
    for (280..288) |i| l[i] = 8;
    break :blk l;
};

pub fn inflate(allocator: std.mem.Allocator, input: []const u8) Error![]u8 {
    const r = try inflateEx(allocator, input, 0);
    return r.data;
}

/// Inflate and report how many input bytes the deflate stream occupied.
/// `size_hint` pre-sizes the output when the caller knows it.
pub fn inflateEx(allocator: std.mem.Allocator, input: []const u8, size_hint: usize) Error!struct { data: []u8, consumed: usize } {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    if (size_hint > 0) try out.ensureTotalCapacity(size_hint + 320);

    var br = BitIn{ .data = input };
    var lit = try allocator.create(Table);
    defer allocator.destroy(lit);
    var dist = try allocator.create(Table);
    defer allocator.destroy(dist);

    while (true) {
        br.refill();
        const final = br.take(1);
        const btype: u2 = @intCast(br.take(2));
        switch (btype) {
            0 => {
                // Stored: drop to the byte boundary, then LEN / NLEN.
                br.bb >>= @intCast(br.nb % 8);
                br.nb -= br.nb % 8;
                if (br.overrun()) return error.InputTooSmall;
                const p = br.bytePos();
                if (p + 4 > input.len) return error.InputTooSmall;
                const len = std.mem.readInt(u16, input[p..][0..2], .little);
                const nlen = std.mem.readInt(u16, input[p + 2 ..][0..2], .little);
                if (len != ~nlen) return error.CorruptData;
                if (p + 4 + len > input.len) return error.InputTooSmall;
                try out.appendSlice(input[p + 4 .. p + 4 + len]);
                br.pos = p + 4 + len;
                br.bb = 0;
                br.nb = 0;
                br.pad = 0;
            },
            1 => {
                try lit.build(.lit, &fixed_lit_lens);
                try dist.build(.dist, &([_]u8{5} ** 32));
                _ = try inflateBlock(&br, &out, lit, dist, std.math.maxInt(usize), std.math.maxInt(usize));
            },
            2 => {
                try readDynamic(&br, lit, dist);
                _ = try inflateBlock(&br, &out, lit, dist, std.math.maxInt(usize), std.math.maxInt(usize));
            },
            3 => return error.CorruptData,
        }
        if (br.overrun()) return error.InputTooSmall;
        if (final == 1) break;
    }
    // Whole bytes still buffered were not consumed.
    br.bb >>= @intCast(br.nb % 8);
    br.nb -= br.nb % 8;
    const consumed = br.bytePos();
    return .{ .data = try out.toOwnedSlice(), .consumed = consumed };
}

pub fn readDynamic(br: *BitIn, lit: *Table, dist: *Table) Error!void {
    br.refill();
    const hlit: usize = br.take(5) + 257;
    const hdist: usize = br.take(5) + 1;
    const hclen: usize = br.take(4) + 4;
    if (hlit > 286 or hdist > 30) return error.CorruptData;
    var clen: [19]u8 = .{0} ** 19;
    for (0..hclen) |i| {
        if (br.nb < 3) br.refill();
        clen[cl_order[i]] = @intCast(br.take(3));
    }
    var clt: Table = undefined;
    try clt.build(.clen, &clen);

    var lens: [320]u8 = .{0} ** 320;
    var i: usize = 0;
    const total = hlit + hdist;
    while (i < total) {
        br.refill();
        if (br.overrun()) return error.InputTooSmall;
        const e = clt.fast[br.bb & ((1 << FAST_BITS) - 1)];
        var sym: u16 = undefined;
        if (e != 0) {
            sym = @intCast(e >> 8);
            _ = br.take(@intCast(e & 15));
        } else {
            const r = clt.slow(@truncate(br.bb)) orelse return error.CorruptData;
            sym = r.sym;
            _ = br.take(r.len);
        }
        if (sym < 16) {
            lens[i] = @intCast(sym);
            i += 1;
        } else {
            var rep: usize = undefined;
            var v: u8 = 0;
            if (sym == 16) {
                if (i == 0) return error.CorruptData;
                v = lens[i - 1];
                rep = 3 + br.take(2);
            } else if (sym == 17) {
                rep = 3 + br.take(3);
            } else {
                rep = 11 + br.take(7);
            }
            if (i + rep > total) return error.CorruptData;
            @memset(lens[i .. i + rep], v);
            i += rep;
        }
    }
    if (lens[256] == 0) return error.CorruptData;
    try lit.build(.lit, lens[0..hlit]);
    try dist.build(.dist, lens[hlit..total]);
}

inline fn copy16(dst: [*]u8, src: [*]const u8) void {
    dst[0..16].* = src[0..16].*;
}

pub const BlockEnd = enum { eob, stopped };

/// Decode symbols until end of block, or until input consumption reaches
/// `stop_pos` / output reaches `out_limit` (streaming callers resume afterwards).
pub fn inflateBlock(br: *BitIn, out: *std.ArrayList(u8), lit: *const Table, dist: *const Table, stop_pos: usize, out_limit: usize) Error!BlockEnd {
    var op: usize = out.items.len;
    defer out.items.len = op;
    const lfast: *const [1 << FAST_BITS]u32 = &lit.fast;
    const dfast: *const [1 << FAST_BITS]u32 = &dist.fast;
    const fmask: u64 = (1 << FAST_BITS) - 1;

    while (true) {
        if (br.pos >= stop_pos or op >= out_limit) return .stopped;
        // Room for a maximal match plus the 16-byte wild copy overshoot.
        if (op + 258 + 32 > out.capacity) {
            out.items.len = op;
            try out.ensureTotalCapacity(@max(out.capacity * 2, op + 4096));
        }
        const base: [*]u8 = out.items.ptr;
        // A length code (15) + extra (5) + distance code (15) + extra (13) fits in 56 bits.
        br.refill();
        if (br.overrun()) return error.InputTooSmall;

        var e = lfast[br.bb & fmask];
        if (e & F_LIT != 0) {
            // Up to three literals per refill: 3 x 15 bits <= the 56 buffered.
            base[op] = @truncate(e >> 8);
            op += 1;
            br.bb >>= @intCast(e & 15);
            br.nb -= e & 15;
            e = lfast[br.bb & fmask];
            if (e & F_LIT != 0) {
                base[op] = @truncate(e >> 8);
                op += 1;
                br.bb >>= @intCast(e & 15);
                br.nb -= e & 15;
                e = lfast[br.bb & fmask];
                if (e & F_LIT != 0) {
                    base[op] = @truncate(e >> 8);
                    op += 1;
                    br.bb >>= @intCast(e & 15);
                    br.nb -= e & 15;
                }
            }
            continue;
        }
        if (e == 0) {
            // A code longer than the fast table, or an invalid symbol.
            const r = lit.slow(@truncate(br.bb)) orelse return error.CorruptData;
            e = entryFor(.lit, r.sym, r.len);
            if (e == 0) return error.CorruptData;
        }
        br.bb >>= @intCast(e & 15);
        br.nb -= e & 15;
        if (e & F_LIT != 0) { // a literal whose code is longer than the fast table
            base[op] = @truncate(e >> 8);
            op += 1;
            continue;
        }
        if (e & F_EOB != 0) return .eob;

        // Length: base and extra-bit count come straight from the table entry.
        const length: usize = ((e >> 8) & 0x1FF) + br.take(@intCast((e >> 24) & 15));

        var de = dfast[br.bb & fmask];
        if (de == 0) {
            const r = dist.slow(@truncate(br.bb)) orelse return error.CorruptData;
            de = entryFor(.dist, r.sym, r.len);
            if (de == 0) return error.CorruptData;
        }
        br.bb >>= @intCast(de & 15);
        br.nb -= de & 15;
        const d: usize = ((de >> 8) & 0x7FFF) + br.take(@intCast((de >> 24) & 15));
        if (d > op) return error.InvalidWindow;
        if (br.overrun()) return error.InputTooSmall;

        var dst: [*]u8 = base + op;
        const from: [*]const u8 = dst - d;
        if (d >= 16) {
            var k: usize = 0;
            while (k < length) : (k += 16) copy16(dst + k, from + k);
        } else if (d >= 8) {
            var k: usize = 0;
            while (k < length) : (k += 8) dst[k..][0..8].* = from[k..][0..8].*;
        } else if (d == 1) {
            @memset(dst[0..length], from[0]);
        } else {
            var k: usize = 0;
            while (k < length) : (k += 1) dst[k] = from[k];
        }
        dst += length;
        op += length;
    }
}

// ===========================================================================
// Deflate
// ===========================================================================

pub const WSIZE: usize = 32768;
const WMASK: usize = WSIZE - 1;
pub const HASH_BITS = 15;
pub const TOKENS_PER_BLOCK = 1 << 15;

pub const Config = struct {
    max_lazy: u16,
    nice: u16,
    chain: u16,
    lazy: bool,
};

pub fn configFor(level: i32) Config {
    return switch (@max(1, @min(9, level))) {
        1 => .{ .max_lazy = 0, .nice = 8, .chain = 4, .lazy = false },
        2 => .{ .max_lazy = 0, .nice = 16, .chain = 8, .lazy = false },
        3 => .{ .max_lazy = 0, .nice = 32, .chain = 32, .lazy = false },
        4 => .{ .max_lazy = 4, .nice = 16, .chain = 16, .lazy = true },
        5 => .{ .max_lazy = 16, .nice = 32, .chain = 32, .lazy = true },
        6 => .{ .max_lazy = 16, .nice = 128, .chain = 128, .lazy = true },
        7 => .{ .max_lazy = 32, .nice = 128, .chain = 256, .lazy = true },
        8 => .{ .max_lazy = 128, .nice = 258, .chain = 1024, .lazy = true },
        else => .{ .max_lazy = 258, .nice = 258, .chain = 4096, .lazy = true },
    };
}

inline fn hash4(v: u32) usize {
    return (v *% 0x9E3779B1) >> (32 - HASH_BITS);
}

inline fn rd32(d: []const u8, i: usize) u32 {
    return std.mem.readInt(u32, d[i..][0..4], .little);
}

inline fn matchLen(d: []const u8, a: usize, b: usize, limit: usize) usize {
    var i: usize = 0;
    while (i + 8 <= limit) : (i += 8) {
        const x = std.mem.readInt(u64, d[a + i ..][0..8], .little) ^ std.mem.readInt(u64, d[b + i ..][0..8], .little);
        if (x != 0) return i + (@ctz(x) >> 3);
    }
    while (i < limit and d[a + i] == d[b + i]) : (i += 1) {}
    return i;
}

pub const Matcher = struct {
    head: []u32,
    prev: []u32,
    hmask: usize = (1 << HASH_BITS) - 1,
    wmask: usize = WMASK,
    /// Farthest distance a match may reach (zlib: window size - 262).
    wsize: usize = WSIZE,
    /// Positions before this are off limits (after a full flush).
    min_c: usize = 0,

    pub fn insert(self: *Matcher, d: []const u8, pos: usize) void {
        if (pos + 4 > d.len) return;
        const h = ((rd32(d, pos) *% 0x9E3779B1) >> 16) & self.hmask;
        self.prev[pos & self.wmask] = self.head[h];
        self.head[h] = @intCast(pos + 1);
    }

    /// Longest match at `pos` (> `min_len`), or length 0.
    pub fn find(self: *Matcher, d: []const u8, pos: usize, min_len: usize, cfg: Config) struct { len: usize, dist: usize } {
        if (pos + 4 > d.len) return .{ .len = 0, .dist = 0 };
        const limit = @min(258, d.len - pos);
        var best_len = min_len;
        var best_dist: usize = 0;
        const h = ((rd32(d, pos) *% 0x9E3779B1) >> 16) & self.hmask;
        var cand: usize = self.head[h];
        var chain = @min(cfg.chain, 4); // Bound chain depth to 4 for ultra-low latency web payloads
        const first = rd32(d, pos);
        while (cand != 0 and chain > 0) : (chain -= 1) {
            const c = cand - 1;
            if (c >= pos) break;
            const dist = pos - c;
            if (dist > self.wsize or c < self.min_c) break;
            if (best_len >= limit) break;
            // Cheap filters: the byte that would extend the best match, then 4 bytes.
            if (d[c + best_len] == d[pos + best_len] and rd32(d, c) == first) {
                const l = matchLen(d, c, pos, limit);
                if (l > best_len) {
                    best_len = l;
                    best_dist = dist;
                    if (l >= cfg.nice) break;
                }
            }
            const nxt: usize = self.prev[c & self.wmask];
            if (nxt == 0 or nxt - 1 >= c) break;
            cand = nxt;
        }
        if (best_dist == 0) return .{ .len = 0, .dist = 0 };
        return .{ .len = best_len, .dist = best_dist };
    }
};

pub const Tokens = struct {
    /// 0 = literal, else match length.
    len: []u16,
    /// literal byte, or distance - 1.
    val: []u16,
    n: usize = 0,
    /// Input bytes covered by the tokens.
    span: usize = 0,
};

pub const OutBuf = struct {
    list: *std.ArrayList(u8),
    acc: u64 = 0,
    n: u6 = 0,

    pub inline fn put(self: *OutBuf, v: u64, nb: u6) void {
        self.acc |= v << self.n;
        self.n += nb;
        if (self.n >= 32) {
            // two-step flush keeps `acc` below 64 bits
            const items = self.list.items;
            std.mem.writeInt(u32, items.ptr[items.len..][0..4], @truncate(self.acc), .little);
            self.list.items.len += 4;
            self.acc >>= 32;
            self.n -= 32;
        }
    }

    pub fn flushBytes(self: *OutBuf) void {
        while (self.n > 0) {
            self.list.items.ptr[self.list.items.len] = @truncate(self.acc);
            self.list.items.len += 1;
            self.acc >>= 8;
            self.n -|= 8;
        }
        self.acc = 0;
        self.n = 0;
    }
};

pub const fixed_codes = blk: {
    @setEvalBranchQuota(100000);
    var codes: [288]u16 = undefined;
    var count: [16]u16 = .{0} ** 16;
    for (fixed_lit_lens) |l| count[l] += 1;
    var next: [16]u16 = .{0} ** 16;
    var code: u16 = 0;
    for (1..16) |l| {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }
    for (fixed_lit_lens, 0..) |l, s| {
        codes[s] = next[l];
        next[l] += 1;
    }
    break :blk codes;
};

pub inline fn rev(code: u16, len: u8) u64 {
    return @bitReverse(code) >> @intCast(16 - @as(u5, @intCast(len)));
}

fn rleLens(lens: []const u8, syms: []u8, extra: []u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < lens.len) {
        const v = lens[i];
        var run: usize = 1;
        while (i + run < lens.len and lens[i + run] == v) run += 1;
        i += run;
        if (v == 0) {
            while (run >= 11) {
                const t = @min(run, 138);
                syms[n] = 18;
                extra[n] = @intCast(t - 11);
                n += 1;
                run -= t;
            }
            if (run >= 3) {
                syms[n] = 17;
                extra[n] = @intCast(run - 3);
                n += 1;
                run = 0;
            }
            while (run > 0) : (run -= 1) {
                syms[n] = 0;
                n += 1;
            }
        } else {
            syms[n] = v;
            n += 1;
            run -= 1;
            while (run >= 3) {
                const t = @min(run, 6);
                syms[n] = 16;
                extra[n] = @intCast(t - 3);
                n += 1;
                run -= t;
            }
            while (run > 0) : (run -= 1) {
                syms[n] = v;
                n += 1;
            }
        }
    }
    return n;
}

pub fn writeBlock(
    ob: *OutBuf,
    toks: *const Tokens,
    input: []const u8,
    blk_start: usize,
    is_last: bool,
) void {
    // Symbol statistics.
    var lf: [286]u32 = .{0} ** 286;
    var df: [30]u32 = .{0} ** 30;
    var extra_bits: u64 = 0;
    for (0..toks.n) |i| {
        const l = toks.len[i];
        if (l == 0) {
            lf[toks.val[i]] += 1;
        } else {
            const lc = len_code_tab[l];
            lf[257 + @as(usize, lc)] += 1;
            extra_bits += length_extra[lc];
            const dc = distCode(@as(u32, toks.val[i]) + 1);
            df[dc] += 1;
            extra_bits += dist_extra[dc];
        }
    }
    lf[256] = 1;

    var ll: [286]u8 = undefined;
    var dl: [30]u8 = undefined;
    prefixlen.limitedLengths(&lf, 15, &ll);
    prefixlen.limitedLengths(&df, 15, &dl);
    forceTwoCodes(&lf, &ll);
    forceTwoCodes(&df, &dl);

    var hlit: usize = 286;
    while (hlit > 257 and ll[hlit - 1] == 0) hlit -= 1;
    var hdist: usize = 30;
    while (hdist > 1 and dl[hdist - 1] == 0) hdist -= 1;

    var all: [316]u8 = undefined;
    @memcpy(all[0..hlit], ll[0..hlit]);
    @memcpy(all[hlit .. hlit + hdist], dl[0..hdist]);
    var syms: [320]u8 = undefined;
    var xtra: [320]u8 = .{0} ** 320;
    const nsym = rleLens(all[0 .. hlit + hdist], &syms, &xtra);
    var cf: [19]u32 = .{0} ** 19;
    for (syms[0..nsym]) |s| cf[s] += 1;
    var cl: [19]u8 = undefined;
    prefixlen.limitedLengths(&cf, 7, &cl);
    forceTwoCodes(&cf, &cl);
    // zlib rejects an incomplete code-length code, so give a lone symbol a partner.
    {
        var used: usize = 0;
        for (cl) |l| used += @intFromBool(l != 0);
        if (used == 1) {
            for (&cl) |*l| {
                if (l.* == 0) {
                    l.* = 1;
                    break;
                }
            }
        }
    }
    var hclen: usize = 19;
    while (hclen > 4 and cl[cl_order[hclen - 1]] == 0) hclen -= 1;

    // Cost of each representation in bits.
    var dyn_bits: u64 = 3 + 5 + 5 + 4 + 3 * hclen + extra_bits;
    for (syms[0..nsym]) |s| {
        dyn_bits += cl[s];
        if (s == 16) dyn_bits += 2 else if (s == 17) dyn_bits += 3 else if (s == 18) dyn_bits += 7;
    }
    var fix_bits: u64 = 3 + extra_bits;
    for (0..286) |s| {
        dyn_bits += @as(u64, lf[s]) * ll[s];
        fix_bits += @as(u64, lf[s]) * fixed_lit_lens[s];
    }
    for (0..30) |s| {
        dyn_bits += @as(u64, df[s]) * dl[s];
        fix_bits += @as(u64, df[s]) * 5;
    }
    const span = toks.span;
    const stored_bits: u64 = if (span <= 65535) (@as(u64, span) + 5) * 8 + 8 else std.math.maxInt(u64);

    if (stored_bits < dyn_bits and stored_bits < fix_bits) {
        ob.put(@intFromBool(is_last), 1);
        ob.put(0, 2);
        ob.flushBytes();
        const items = ob.list.items;
        std.mem.writeInt(u16, items.ptr[items.len..][0..2], @intCast(span), .little);
        std.mem.writeInt(u16, items.ptr[items.len + 2 ..][0..2], ~@as(u16, @intCast(span)), .little);
        @memcpy(items.ptr[items.len + 4 .. items.len + 4 + span], input[blk_start .. blk_start + span]);
        ob.list.items.len += 4 + span;
        return;
    }

    var lc: [286]u16 = undefined;
    var dc: [30]u16 = undefined;
    var lcl: [286]u8 = undefined;
    var dcl: [30]u8 = undefined;
    if (fix_bits <= dyn_bits) {
        ob.put(@intFromBool(is_last), 1);
        ob.put(1, 2);
        @memcpy(&lcl, fixed_lit_lens[0..286]);
        @memcpy(lc[0..286], fixed_codes[0..286]);
        // Fixed distance codes are the 5-bit symbol value itself, MSB first.
        for (0..30) |s| {
            dcl[s] = 5;
            dc[s] = @intCast(s);
        }
    } else {
        ob.put(@intFromBool(is_last), 1);
        ob.put(2, 2);
        ob.put(hlit - 257, 5);
        ob.put(hdist - 1, 5);
        ob.put(hclen - 4, 4);
        for (0..hclen) |i| ob.put(cl[cl_order[i]], 3);
        var ccodes: [19]u16 = undefined;
        prefixlen.canonicalCodes(&cl, &ccodes);
        for (syms[0..nsym], xtra[0..nsym]) |s, x| {
            ob.put(rev(ccodes[s], cl[s]), @intCast(cl[s]));
            if (s == 16) ob.put(x, 2) else if (s == 17) ob.put(x, 3) else if (s == 18) ob.put(x, 7);
        }
        @memcpy(&lcl, &ll);
        @memcpy(&dcl, &dl);
        prefixlen.canonicalCodes(&lcl, &lc);
        prefixlen.canonicalCodes(&dcl, &dc);
    }

    var rlc: [286]u64 = undefined;
    var rdc: [30]u64 = undefined;
    for (0..286) |s| rlc[s] = if (lcl[s] > 0) rev(lc[s], lcl[s]) else 0;
    for (0..30) |s| rdc[s] = if (dcl[s] > 0) rev(dc[s], dcl[s]) else 0;

    for (0..toks.n) |i| {
        const l = toks.len[i];
        if (l == 0) {
            const s = toks.val[i];
            ob.put(rlc[s], @intCast(lcl[s]));
        } else {
            const c = len_code_tab[l];
            const sy = 257 + @as(usize, c);
            ob.put(rlc[sy], @intCast(lcl[sy]));
            ob.put(l - length_base[c], @intCast(length_extra[c]));
            const d = @as(u32, toks.val[i]) + 1;
            const dcode = distCode(d);
            ob.put(rdc[dcode], @intCast(dcl[dcode]));
            ob.put(d - dist_base[dcode], @intCast(dist_extra[dcode]));
        }
    }
    ob.put(rlc[256], @intCast(lcl[256]));
}

/// Deflate allows a lone symbol to use a one-bit code; make sure every used
/// alphabet has at least one length-1 code (and a valid, if incomplete, shape).
fn forceTwoCodes(freq: []const u32, lens: []u8) void {
    var used: usize = 0;
    var only: usize = 0;
    for (freq, 0..) |f, s| {
        if (f != 0) {
            used += 1;
            only = s;
        }
    }
    if (used == 0) {
        lens[0] = 1;
    } else if (used == 1) {
        lens[only] = 1;
    }
}

/// Parse one literal or match starting at `pos`; returns the new position.
pub fn parseStep(m: *Matcher, cfg: Config, toks: *Tokens, input: []const u8, pos_in: usize) usize {
    var pos = pos_in;
    var best = m.find(input, pos, 3, cfg);
    if (best.len >= 4 or (best.len == 3 and best.dist <= 4096)) {
        if (cfg.lazy and best.len < cfg.max_lazy and pos + 1 < input.len) {
            m.insert(input, pos);
            const nxt = m.find(input, pos + 1, best.len, cfg);
            if (nxt.len > best.len) {
                toks.len[toks.n] = 0;
                toks.val[toks.n] = input[pos];
                toks.n += 1;
                toks.span += 1;
                pos += 1;
                best = nxt;
                m.insert(input, pos);
            }
        } else {
            m.insert(input, pos);
        }
        emitMatch(toks, best.len, best.dist);
        var q = pos + 1;
        const mend = pos + best.len;
        while (q < mend) : (q += 1) m.insert(input, q);
        return mend;
    }
    m.insert(input, pos);
    toks.len[toks.n] = 0;
    toks.val[toks.n] = input[pos];
    toks.n += 1;
    toks.span += 1;
    return pos + 1;
}

pub fn deflate(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    return deflateLevel(allocator, input, 6);
}

pub fn deflateLevel(allocator: std.mem.Allocator, input: []const u8, level: i32) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    const cfg = configFor(level);

    // Scale hash table and window buffer allocation for small payloads to avoid zeroing 1MB+ per request
    const hash_size = if (input.len < 16384) @as(usize, 4096) else if (input.len < 65536) @as(usize, 16384) else (1 << HASH_BITS);
    const w_size = if (input.len < 8192) @as(usize, 8192) else if (input.len < WSIZE) @as(usize, @intCast(input.len)) else WSIZE;
    const tok_cap = @min(TOKENS_PER_BLOCK, @max(256, input.len / 2 + 64));

    const head = try allocator.alloc(u32, hash_size);
    defer allocator.free(head);
    @memset(head, 0);
    const prev = try allocator.alloc(u32, w_size);
    defer allocator.free(prev);
    @memset(prev, 0);
    var m = Matcher{ .head = head, .prev = prev, .hmask = hash_size - 1, .wmask = w_size - 1, .wsize = w_size - 1 };

    const tl = try allocator.alloc(u16, tok_cap);
    defer allocator.free(tl);
    const tv = try allocator.alloc(u16, tok_cap);
    defer allocator.free(tv);
    var toks = Tokens{ .len = tl, .val = tv };

    var ob = OutBuf{ .list = &out };
    var blk_start: usize = 0;
    var pos: usize = 0;

    if (input.len == 0) {
        try out.ensureUnusedCapacity(16);
        ob.put(1, 1);
        ob.put(1, 2);
        ob.put(rev(fixed_codes[256], 7), 7);
        ob.flushBytes();
        return out.toOwnedSlice();
    }

    while (pos < input.len) {
        // Greedy / lazy parse until the token buffer fills.
        while (pos < input.len and toks.n < toks.len.len - 1) pos = parseStep(&m, cfg, &toks, input, pos);
        const last = pos >= input.len;
        // Worst case: every token as a 48-bit pair plus headers, or a stored block.
        try out.ensureUnusedCapacity(toks.n * 7 + toks.span + 1024);
        writeBlock(&ob, &toks, input, blk_start, last);
        blk_start = pos;
        toks.n = 0;
        toks.span = 0;
    }
    ob.flushBytes();
    return out.toOwnedSlice();
}

pub inline fn emitMatch(toks: *Tokens, len: usize, dist: usize) void {
    toks.len[toks.n] = @intCast(len);
    toks.val[toks.n] = @intCast(dist - 1);
    toks.n += 1;
    toks.span += len;
}

test "deflate round trip across levels and shapes" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(11);
    const rng = prng.random();
    const sizes = [_]usize{ 0, 1, 5, 100, 4096, 70000, 300000 };
    for (sizes) |n| {
        const buf = try a.alloc(u8, n);
        defer a.free(buf);
        for (0..3) |kind| {
            for (buf, 0..) |*b, i| {
                b.* = switch (kind) {
                    0 => rng.int(u8),
                    1 => "abcdefgh"[(i * 7 + i / 13) % 8],
                    else => if (i % 1000 < 300) @intCast(i % 251) else rng.int(u8) & 3,
                };
            }
            for ([_]i32{ 1, 3, 6, 9 }) |lvl| {
                const z = try deflateLevel(a, buf, lvl);
                defer a.free(z);
                const d = try inflate(a, z);
                defer a.free(d);
                try std.testing.expectEqualSlices(u8, buf, d);
            }
        }
    }
}

test "corrupt deflate streams never panic or over-allocate" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xDEF1A7E);
    const rng = prng.random();
    const text = "the quick brown fox jumps over the lazy dog, again and again. " ** 400;
    const z = try deflateLevel(a, text, 6);
    defer a.free(z);
    const m = try a.dupe(u8, z);
    defer a.free(m);
    for (0..500) |_| {
        @memcpy(m, z);
        const hits = rng.uintLessThan(usize, 4) + 1;
        for (0..hits) |_| m[rng.uintLessThan(usize, m.len)] = rng.int(u8);
        if (inflate(a, m)) |d| a.free(d) else |_| {}
        const cut = rng.uintLessThan(usize, m.len);
        if (inflate(a, m[0..cut])) |d| a.free(d) else |_| {}
    }
}
