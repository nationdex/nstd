//! Brotli compression (RFC 7932).
//!
//! LZ77 parse (lazy, repeat-distance aware) over a sliding window, entropy
//! coded with canonical prefix codes. Literals use context modeling: 64
//! contexts (UTF8 or LSB6 mode, whichever is cheaper) are clustered into a small
//! set of prefix trees, distances are coded with a copy-length context. Matches
//! may also reference the RFC 7932 static dictionary through its transforms.
//! Incompressible meta-blocks are stored uncompressed.

const std = @import("std");
const prefix = @import("prefix.zig");
const dec = @import("decompress.zig");
const tables = @import("tables.zig");
const dict = @import("dict_match.zig");
const prefixlen = @import("../core/prefixlen.zig");
const mfmod = @import("../core/matchfinder.zig");

pub const Error = error{ OutOfMemory, NoSpaceLeft };

const LGWIN = 22;
const WINDOW: usize = (1 << LGWIN) - 16;
const METABLOCK_MAX: usize = 1 << 20;
const MAX_LIT_TREES = 16;
pub const DEFAULT_QUALITY: i32 = 5;

// ---------------------------------------------------------------------------
// Bit writer
// ---------------------------------------------------------------------------

const Writer = struct {
    buf: std.ArrayList(u8),
    acc: u64 = 0,
    n: u7 = 0,

    fn init(a: std.mem.Allocator) Writer {
        return .{ .buf = std.ArrayList(u8).init(a) };
    }

    inline fn put(self: *Writer, v: u64, nb: u6) !void {
        if (nb == 0) return;
        self.acc |= (v & ((@as(u64, 1) << nb) - 1)) << @intCast(self.n);
        self.n += nb;
        if (self.n >= 32) {
            // Flush four bytes with one store; capacity is checked once per flush.
            try self.buf.ensureUnusedCapacity(8);
            const len = self.buf.items.len;
            std.mem.writeInt(u32, self.buf.items.ptr[len..][0..4], @truncate(self.acc), .little);
            self.buf.items.len = len + 4;
            self.acc >>= 32;
            self.n -= 32;
        }
    }

    /// Write an already bit-reversed code.
    inline fn putRev(self: *Writer, rcode: u16, len: u8) !void {
        try self.put(rcode, @intCast(len));
    }

    /// Write a canonical prefix code (MSB-first) of `len` bits.
    inline fn putCode(self: *Writer, code: u16, len: u8) !void {
        if (len == 0) return;
        try self.put(prefix.reverse(code, @intCast(len)), @intCast(len));
    }

    fn alignByte(self: *Writer) !void {
        while (self.n > 0) {
            try self.buf.append(@truncate(self.acc));
            self.acc >>= 8;
            self.n -|= 8;
        }
        self.acc = 0;
    }

    fn bitPos(self: *const Writer) usize {
        return self.buf.items.len * 8 + self.n;
    }
};

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

const Cmd = struct {
    ins: u32,
    /// Bytes copied (0 for the terminal command, whose copy is ignored).
    copy: u32,
    ic_sym: u16,
    ins_extra: u32,
    ins_bits: u8,
    copy_extra: u32,
    copy_bits: u8,
    implicit: bool,
    dsym: u16,
    dbits: u8,
    dextra: u32,
    /// Copy length that selects the distance context (2..).
    dctx_len: u32,
    /// Output bytes produced by the copy part (differs from `copy` for
    /// dictionary references; 0 for the terminal command).
    span: u32,
};

/// Insert-length code (RFC 7932 §5) in O(1).
inline fn insertCode(ins: u32) u8 {
    if (ins < 6) return @intCast(ins);
    if (ins < 130) {
        const nb: u32 = (31 - @clz(ins - 2)) - 1;
        return @intCast((nb << 1) + ((ins - 2) >> @intCast(nb)) + 2);
    }
    if (ins < 2114) return @intCast((31 - @clz(ins - 66)) + 10);
    if (ins < 6210) return 21;
    if (ins < 22594) return 22;
    return 23;
}

/// Copy-length code in O(1).
inline fn copyCode(len: u32) u8 {
    if (len < 10) return @intCast(len - 2);
    if (len < 134) {
        const nb: u32 = (31 - @clz(len - 6)) - 1;
        return @intCast((nb << 1) + ((len - 6) >> @intCast(nb)) + 4);
    }
    if (len < 2118) return @intCast((31 - @clz(len - 70)) + 12);
    return 23;
}

fn lowerCode(base: []const u32, v: u32) u8 {
    var k: usize = base.len - 1;
    while (base[k] > v) k -= 1;
    return @intCast(k);
}

fn cellFor(ic: u8, cc: u8, implicit: bool) ?u8 {
    const ir = ic / 8;
    const cr = cc / 8;
    if (implicit) {
        if (ir == 0 and cr == 0) return 0;
        if (ir == 0 and cr == 1) return 1;
        return null;
    }
    const t = [3][3]u8{ .{ 2, 3, 6 }, .{ 4, 5, 8 }, .{ 7, 9, 10 } };
    return t[ir][cr];
}

/// Distance state shared across meta-blocks (RFC 7932 §4).
const Ring = struct {
    d: [4]u32 = .{ 16, 15, 11, 4 }, // oldest..last

    /// Pick the cheapest distance symbol for `dist` and update the ring.
    fn encode(self: *Ring, dist: u32, npostfix: u2) struct { sym: u16, bits: u8, extra: u32 } {
        const last = self.d[3];
        if (dist == last) return .{ .sym = 0, .bits = 0, .extra = 0 };
        var code: u16 = 16;
        if (dist == self.d[2]) {
            code = 1;
        } else if (dist == self.d[1]) {
            code = 2;
        } else if (dist == self.d[0]) {
            code = 3;
        } else {
            const dl = @as(i64, dist) - @as(i64, last);
            const ds = @as(i64, dist) - @as(i64, self.d[2]);
            const rel = [_]u16{ 8, 6, 4, 0, 5, 7, 9 }; // index = delta + 3, delta in -3..+3
            if (dl >= -3 and dl <= 3 and dl != 0) {
                code = rel[@intCast(dl + 3)];
            } else if (ds >= -3 and ds <= 3 and ds != 0) {
                code = rel[@intCast(ds + 3)] + 6;
            }
        }
        if (code < 16) {
            self.push(dist);
            return .{ .sym = code, .bits = 0, .extra = 0 };
        }
        self.push(dist);

        // General RFC 7932 distance encoding with NPOSTFIX and NDIRECT=0.
        if (npostfix == 0) {
            const v: u32 = dist + 3;
            const hb: u5 = @intCast(31 - @clz(v));
            const nbits: u5 = hb - 1;
            const b: u32 = (v >> (hb - 1)) & 1;
            const hcode: u32 = 2 * (@as(u32, hb) - 2) + b;
            return .{ .sym = @intCast(16 + hcode), .bits = nbits, .extra = v & ((@as(u32, 1) << nbits) - 1) };
        }

        const np: u5 = npostfix;
        const postfix_mask: u32 = (@as(u32, 1) << np) - 1;
        const delta = dist - 1;
        const lcode = delta & postfix_mask;
        const hdelta = delta >> np;
        const v = hdelta + 4;
        const hb: u5 = @intCast(31 - @clz(v));
        const nbits: u5 = hb - 1;
        const b: u32 = (v >> (hb - 1)) & 1;
        const hcode: u32 = 2 * (@as(u32, hb) - 2) + b;
        const dextra = v & ((@as(u32, 1) << nbits) - 1);
        const sym: u16 = @intCast(16 + (hcode << np) + lcode);
        return .{ .sym = sym, .bits = nbits, .extra = dextra };
    }

    fn push(self: *Ring, dist: u32) void {
        self.d[0] = self.d[1];
        self.d[1] = self.d[2];
        self.d[2] = self.d[3];
        self.d[3] = dist;
    }
};

fn makeCmd(ring: *Ring, ins: u32, copy: u32, dist: u32, terminal: bool, npostfix: u2) Cmd {
    _ = npostfix;
    var c: Cmd = undefined;
    c.ins = ins;
    c.copy = if (terminal) 0 else copy;
    c.span = c.copy;
    const ic = insertCode(ins);
    c.ins_extra = ins - dec.INSERT_BASE[ic];
    c.ins_bits = dec.INSERT_EXTRA[ic];
    const eff_copy: u32 = if (terminal) 4 else copy;
    const cc = copyCode(eff_copy);
    c.copy_extra = eff_copy - dec.COPY_BASE[cc];
    c.copy_bits = dec.COPY_EXTRA[cc];
    c.dctx_len = eff_copy;
    c.dsym = 0;
    c.dbits = 0;
    c.dextra = 0;
    c.implicit = false;
    if (terminal) {
        c.ic_sym = @as(u16, cellFor(ic, cc, false).?) * 64 + @as(u16, ic & 7) * 8 + (cc & 7);
        c.implicit = true; // no distance is read after the final literals
        return c;
    }
    const r = ring.encode(dist, 0);
    var implicit = false;
    if (r.sym == 0) {
        if (cellFor(ic, cc, true)) |_| implicit = true;
    }
    const cell = cellFor(ic, cc, implicit).?;
    c.ic_sym = @as(u16, cell) * 64 + @as(u16, ic & 7) * 8 + (cc & 7);
    c.implicit = implicit;
    c.dsym = r.sym;
    c.dbits = r.bits;
    c.dextra = r.extra;
    return c;
}

// ---------------------------------------------------------------------------
// LZ parse
// ---------------------------------------------------------------------------

inline fn commonLen(data: []const u8, a: usize, b: usize) usize {
    var i: usize = 0;
    const limit = data.len - b;
    while (i + 8 <= limit) : (i += 8) {
        const x = std.mem.readInt(u64, data[a + i ..][0..8], .little) ^ std.mem.readInt(u64, data[b + i ..][0..8], .little);
        if (x != 0) return i + (@ctz(x) >> 3);
    }
    while (i < limit and data[a + i] == data[b + i]) : (i += 1) {}
    return i;
}

fn parseMetaBlock(
    allocator: std.mem.Allocator,
    mf: *mfmod.MatchFinder,
    dm: *dict.Matcher,
    data: []const u8, // src[0..end]
    start: usize,
    ring: *Ring,
    cmds: *std.ArrayList(Cmd),
    /// Dictionary matches are searched only at stream positions below this limit
    /// (their distance cost grows with position); 0 disables the dictionary.
    dict_limit: usize,
) !void {
    cmds.clearRetainingCapacity();
    _ = allocator;
    const end = data.len;
    var p = start;
    var anchor = start;
    while (p + 4 <= end) {
        var best_len: usize = 0;
        var best_dist: usize = 0;
        var dict_id: ?dict.Hit = null;

        if (mf.find(data, p)) |m| {
            best_len = m.len;
            best_dist = m.dist;
        }
        // Repeat-distance candidate.
        const last: usize = ring.d[3];
        if (p >= last and p + 4 <= end and rd32b(data, p - last) == rd32b(data, p)) {
            const rl = commonLen(data, p - last, p);
            if (rl >= 4 and rl + 2 >= best_len) {
                best_len = rl;
                best_dist = last;
            }
        }
        // Static dictionary candidate: its distance costs ~log2(window) bits, so
        // only take it when the saved literals outweigh that.
        if (p < dict_limit and best_len < 12 and p + 4 < end) {
            if (dm.find(data, p)) |h| {
                const dd: u64 = @min(WINDOW, p) + 1 + h.word_id;
                const dbits: u64 = if (dd < 4) 0 else 30 - @clz(@as(u32, @intCast(dd + 3)));
                const dict_gain: i64 = @as(i64, @intCast(h.len)) * 4 - @as(i64, @intCast(dbits)) - 14;
                const lz_bits: i64 = if (best_dist == last and best_len > 0) 0 else if (best_dist > 0) @as(i64, @intCast(std.math.log2_int(usize, best_dist))) else 0;
                const lz_gain: i64 = @as(i64, @intCast(best_len)) * 4 - lz_bits - 14;
                if (dict_gain > 0 and dict_gain > lz_gain) dict_id = h;
            }
        }

        if (best_len < 4 and dict_id == null) {
            p += 1 + ((p - anchor) >> 6);
            continue;
        }

        if (dict_id) |h| {
            // Distance beyond the window encodes the dictionary word.
            const max_dist = @min(WINDOW, p);
            const dist = max_dist + 1 + h.word_id;
            const ins: u32 = @intCast(p - anchor);
            try cmds.append(makeDictCmd(ring, ins, h.copy_len, @intCast(h.len), @intCast(dist)));
            const mend = p + h.len;
            var q = p + 1;
            while (q < mend and q + 4 <= end) : (q += 1) mf.insert(data, q);
            p = mend;
            anchor = p;
            continue;
        }

        // One-step lazy evaluation.
        if (best_len < 32 and p + 5 <= end) {
            if (mf.find(data, p + 1)) |m2| {
                if (m2.len > best_len + 1) {
                    p += 1;
                    best_len = m2.len;
                    best_dist = m2.dist;
                }
            }
        }
        const ins: u32 = @intCast(p - anchor);
        try cmds.append(makeCmd(ring, ins, @intCast(best_len), @intCast(best_dist), false, 0));
        const mend = p + best_len;
        var q = p + 2;
        const dense_end = @min(mend, q + 24);
        while (q < dense_end) : (q += 1) mf.insert(data, q);
        if (mend > dense_end + 16) q = mend - 16;
        while (q < mend) : (q += 1) mf.insert(data, q);
        p = mend;
        anchor = p;
    }
    if (anchor < end) {
        try cmds.append(makeCmd(ring, @intCast(end - anchor), 4, 0, true, 0));
    }
}

inline fn rd32b(d: []const u8, i: usize) u32 {
    return std.mem.readInt(u32, d[i..][0..4], .little);
}

inline fn rd64(d: []const u8, i: usize) u64 {
    return std.mem.readInt(u64, d[i..][0..8], .little);
}

inline fn hash5b(v: u64, log: u6) usize {
    return @intCast(((v << 24) *% 0x9E3779B185EBCA87) >> @intCast(64 - @as(u7, log)));
}

const FAST_HASH_LOG = 16;

/// Throughput-oriented parse: one 5-byte hash table, an inexpensive probe of
/// the last distance, backward match extension, no dictionary, no lazy step.
fn parseFastBr(
    tbl: []u32,
    data: []const u8,
    start: usize,
    ring: *Ring,
    cmds: *std.ArrayList(Cmd),
) !void {
    cmds.clearRetainingCapacity();
    const end = data.len;
    var ip = start;
    var anchor = start;
    while (ip + 8 <= end) {
        const v = rd64(data, ip);
        const h = hash5b(v, FAST_HASH_LOG);
        const cand: usize = tbl[h];
        tbl[h] = @intCast(ip + 1);
        var cdist: usize = 0;
        const last: usize = ring.d[3];
        if (ip >= last and @as(u32, @truncate(rd64(data, ip - last))) == @as(u32, @truncate(v))) {
            cdist = last;
        } else if (cand != 0) {
            const c = cand - 1;
            const d = ip - c;
            const max_dist = @min(WINDOW, ip);
            if (d <= max_dist and @as(u32, @truncate(rd64(data, c))) == @as(u32, @truncate(v)) and data[c + 4] == data[ip + 4]) cdist = d;
        }
        if (cdist == 0) {
            ip += 1 + ((ip - anchor) >> 4);
            continue;
        }
        var mp = ip;
        var c = ip - cdist;
        while (mp > anchor and c > 0 and data[mp - 1] == data[c - 1]) {
            mp -= 1;
            c -= 1;
        }
        const len = commonLen(data, c, mp);
        try cmds.append(makeCmd(ring, @intCast(mp - anchor), @intCast(len), @intCast(mp - c), false, 0));
        const mend = mp + len;
        if (mend + 8 <= end and len > 4) {
            tbl[hash5b(rd64(data, mp + 1), FAST_HASH_LOG)] = @intCast(mp + 2);
            tbl[hash5b(rd64(data, mend - 2), FAST_HASH_LOG)] = @intCast(mend - 1);
        }
        ip = mend;
        anchor = mend;
    }
    if (anchor < end) try cmds.append(makeCmd(ring, @intCast(end - anchor), 4, 0, true, 0));
}

// ---------------------------------------------------------------------------
// Hash-chain match search with a bit-cost score (quality >= 5)
// ---------------------------------------------------------------------------

/// Estimated bits a match saves over coding its bytes as literals.
const LIT_BITS: i64 = 6;
/// Estimated fixed cost of a command (insert/copy symbol plus extras).
const CMD_BITS: i64 = 10;

const BUCKET_BITS = 16;
const BUCKET_SLOTS = 15;

/// Cache-friendly candidate store: each 4-byte hash owns one 64-byte bucket with
/// a write cursor and the 15 most recent positions, so a lookup touches a single
/// cache line instead of chasing a linked chain through a multi-megabyte ring.
const ChainMatcher = struct {
    buckets: []u32,

    fn init(a: std.mem.Allocator) !ChainMatcher {
        const buckets = try a.alloc(u32, (@as(usize, 1) << BUCKET_BITS) * 16);
        @memset(buckets, 0);
        return .{ .buckets = buckets };
    }

    fn deinit(self: *ChainMatcher, a: std.mem.Allocator) void {
        a.free(self.buckets);
    }

    fn reset(self: *ChainMatcher) void {
        @memset(self.buckets, 0);
    }

    inline fn bucket(self: *ChainMatcher, v: u32) *[16]u32 {
        const h: usize = @intCast((v *% 0x9E3779B1) >> (32 - BUCKET_BITS));
        return self.buckets[h * 16 ..][0..16];
    }

    fn best(self: *ChainMatcher, d: []const u8, pos: usize, ring: *const Ring, max_chain: u32, nice: usize) Found {
        return chainBest(self, d, pos, ring, max_chain, nice);
    }

    fn insert(self: *ChainMatcher, d: []const u8, pos: usize) void {
        if (pos + 4 > d.len) return;
        const b = self.bucket(rd32b(d, pos));
        const i = b[0];
        b[1 + i] = @intCast(pos + 1);
        b[0] = if (i + 1 == BUCKET_SLOTS) 0 else i + 1;
    }
};

const Found = struct { len: usize = 0, dist: usize = 0, score: i64 = 0 };

/// Linked hash chains (head per 4-byte hash plus one `prev` slot per live
/// position). Deeper than a bucket but each hop is a likely cache miss, so it is
/// reserved for the slower qualities. `ring` bounds how far back chains reach.
const DeepMatcher = struct {
    head: []u32,
    prev: []u32,
    mask: usize,

    fn init(a: std.mem.Allocator, ring_bits: u5) !DeepMatcher {
        const head = try a.alloc(u32, 1 << 17);
        errdefer a.free(head);
        @memset(head, 0);
        const n = @as(usize, 1) << ring_bits;
        // Slots are written before they can be reached, so no clearing is needed.
        const prev = try a.alloc(u32, n);
        return .{ .head = head, .prev = prev, .mask = n - 1 };
    }

    fn deinit(self: *DeepMatcher, a: std.mem.Allocator) void {
        a.free(self.head);
        a.free(self.prev);
    }

    fn reset(self: *DeepMatcher) void {
        @memset(self.head, 0);
    }

    inline fn hash(v: u32) usize {
        return @intCast((v *% 0x9E3779B1) >> (32 - 17));
    }

    fn insert(self: *DeepMatcher, d: []const u8, pos: usize) void {
        if (pos + 4 > d.len) return;
        const h = hash(rd32b(d, pos));
        self.prev[pos & self.mask] = self.head[h];
        self.head[h] = @intCast(pos + 1);
    }

    fn best(self: *DeepMatcher, d: []const u8, pos: usize, ring: *const Ring, max_chain: u32, nice: usize) Found {
        var found = Found{};
        if (pos + 4 > d.len) return found;
        const limit_len = d.len - pos;
        const first = rd32b(d, pos);
        const last: usize = ring.d[3];
        if (pos >= last and rd32b(d, pos - last) == first) {
            const l = commonLen(d, pos - last, pos);
            found = .{ .len = l, .dist = last, .score = matchScore(ring, l, last) };
        }
        var cand: usize = self.head[hash(first)];
        var chain = max_chain;
        const reach = @min(WINDOW, self.mask);
        while (cand != 0 and chain > 0) : (chain -= 1) {
            const c = cand - 1;
            if (c >= pos) break;
            const dist = pos - c;
            if (dist > reach) break;
            const bl = found.len;
            if ((bl == 0 or (bl < limit_len and d[c + bl] == d[pos + bl])) and rd32b(d, c) == first) {
                const l = commonLen(d, c, pos);
                const sc = matchScore(ring, l, dist);
                if (sc > found.score) {
                    found = .{ .len = l, .dist = dist, .score = sc };
                    if (l >= nice) break;
                }
            }
            const nxt: usize = self.prev[c & self.mask];
            if (nxt == 0 or nxt - 1 >= c) break;
            cand = nxt;
        }
        if (found.len < 4 or found.score <= 0) return .{};
        return found;
    }
};

/// Approximate cost in bits of coding `dist` given the current distance ring.
inline fn distCost(ring: *const Ring, dist: usize) i64 {
    const d: u32 = @intCast(dist);
    if (d == ring.d[3]) return 1;
    if (d == ring.d[2] or d == ring.d[1] or d == ring.d[0]) return 4;
    const dl = @as(i64, d) - @as(i64, ring.d[3]);
    if (dl >= -3 and dl <= 3) return 6;
    return @as(i64, 31 - @clz(d)) + 6;
}

inline fn matchScore(ring: *const Ring, len: usize, dist: usize) i64 {
    return @as(i64, @intCast(len)) * LIT_BITS - distCost(ring, dist) - CMD_BITS;
}

fn chainBest(cm: *ChainMatcher, d: []const u8, pos: usize, ring: *const Ring, max_chain: u32, nice: usize) Found {
    var best = Found{};
    if (pos + 4 > d.len) return best;
    const limit_len = d.len - pos;
    const first = rd32b(d, pos);

    // The last distance is almost free to code: always probe it.
    const last: usize = ring.d[3];
    if (pos >= last and rd32b(d, pos - last) == first) {
        const l = commonLen(d, pos - last, pos);
        best = .{ .len = l, .dist = last, .score = matchScore(ring, l, last) };
    }

    const b = cm.bucket(first);
    var slot: u32 = b[0];
    var n: u32 = 0;
    while (n < max_chain) : (n += 1) {
        slot = if (slot == 0) BUCKET_SLOTS - 1 else slot - 1; // newest first
        const cand: usize = b[1 + slot];
        if (cand == 0) break;
        const c = cand - 1;
        if (c >= pos) continue;
        const dist = pos - c;
        if (dist > WINDOW) break;
        const bl = best.len;
        if ((bl == 0 or (bl < limit_len and d[c + bl] == d[pos + bl])) and rd32b(d, c) == first) {
            const l = commonLen(d, c, pos);
            const sc = matchScore(ring, l, dist);
            if (sc > best.score) {
                best = .{ .len = l, .dist = dist, .score = sc };
                if (l >= nice) break;
            }
        }
    }
    if (best.len < 4 or best.score <= 0) return .{};
    return best;
}

fn parseChain(
    cm: anytype,
    dm: *dict.Matcher,
    data: []const u8, // src[0..end]
    start: usize,
    ring: *Ring,
    cmds: *std.ArrayList(Cmd),
    dict_limit: usize,
    max_chain: u32,
) !void {
    cmds.clearRetainingCapacity();
    const end = data.len;
    var p = start;
    var anchor = start;
    while (p + 4 <= end) {
        var cur = cm.best(data, p, ring, max_chain, 258);

        // Static dictionary candidate, scored in the same units.
        var dict_hit: ?dict.Hit = null;
        if (p < dict_limit and cur.len < 12) {
            if (dm.find(data, p)) |h| {
                const dd: u64 = @min(WINDOW, p) + 1 + h.word_id;
                const dbits: i64 = @as(i64, 31 - @clz(@as(u32, @intCast(dd)))) + 6;
                const sc = @as(i64, @intCast(h.len)) * LIT_BITS - dbits - CMD_BITS;
                if (sc > cur.score) {
                    dict_hit = h;
                }
            }
        }

        if (dict_hit == null and cur.len == 0) {
            cm.insert(data, p);
            p += 1 + ((p - anchor) >> 7);
            continue;
        }

        if (dict_hit) |h| {
            cm.insert(data, p);
            const max_dist = @min(WINDOW, p);
            const dist = max_dist + 1 + h.word_id;
            const ins: u32 = @intCast(p - anchor);
            try cmds.append(makeDictCmd(ring, ins, h.copy_len, @intCast(h.len), @intCast(dist)));
            const mend = p + h.len;
            var q = p + 1;
            while (q < mend and q + 4 <= end) : (q += 1) cm.insert(data, q);
            p = mend;
            anchor = p;
            continue;
        }

        // One-step lazy evaluation on the score.
        cm.insert(data, p);
        if (cur.len < 64 and p + 5 <= end) {
            const nxt = cm.best(data, p + 1, ring, max_chain, 258);
            if (nxt.score > cur.score + LIT_BITS / 2) {
                p += 1;
                cur = nxt;
                cm.insert(data, p);
            }
        }
        const ins: u32 = @intCast(p - anchor);
        try cmds.append(makeCmd(ring, ins, @intCast(cur.len), @intCast(cur.dist), false, 0));
        const mend = p + cur.len;
        var q = p + 1;
        const dense_end = @min(mend, q + 32);
        while (q < dense_end) : (q += 1) cm.insert(data, q);
        if (mend > dense_end + 16) q = mend - 16;
        while (q < mend) : (q += 1) cm.insert(data, q);
        p = mend;
        anchor = p;
    }
    if (anchor < end) {
        try cmds.append(makeCmd(ring, @intCast(end - anchor), 4, 0, true, 0));
    }
}

/// Quality 5-8 search the dictionary only early in the stream, where its
/// distance codes are cheap (about 1.5x faster, ~0.4% larger on text); 9+
/// search everywhere.
fn dictLimit(q: i32) usize {
    if (q < 5) return 0;
    if (q < 7) return 1 << 16;
    if (q < 9) return 1 << 18;
    return std.math.maxInt(usize);
}

fn chainLen(q: i32) u32 {
    if (q < 5) return 4;
    if (q < 6) return 8;
    if (q < 7) return 16;
    if (q < 9) return 32;
    if (q < 10) return 64;
    return 128;
}

/// Command for a static dictionary reference: the distance is never pushed to
/// the ring and cannot use short codes.
fn makeDictCmd(ring: *Ring, ins: u32, copy: u32, span: u32, dist: u32) Cmd {
    var c: Cmd = undefined;
    c.ins = ins;
    c.copy = copy;
    c.span = span;
    const ic = insertCode(ins);
    c.ins_extra = ins - dec.INSERT_BASE[ic];
    c.ins_bits = dec.INSERT_EXTRA[ic];
    const cc = copyCode(copy);
    c.copy_extra = copy - dec.COPY_BASE[cc];
    c.copy_bits = dec.COPY_EXTRA[cc];
    c.dctx_len = copy;
    c.implicit = false;
    const cell = cellFor(ic, cc, false).?;
    c.ic_sym = @as(u16, cell) * 64 + @as(u16, ic & 7) * 8 + (cc & 7);
    // Plain distance code (no ring updates): reuse the explicit encoder on a
    // scratch ring so the real one is untouched.
    var scratch = ring.*;
    // Make sure no short code can match by perturbing the scratch ring.
    scratch.d = .{ 0, 0, 0, 0 };
    const r = scratch.encode(dist, 0);
    c.dsym = r.sym;
    c.dbits = r.bits;
    c.dextra = r.extra;
    return c;
}

// ---------------------------------------------------------------------------
// Optimal parsing (quality >= 10)
// ---------------------------------------------------------------------------

const OPT_WINDOW: usize = 1024;

const OptNode = struct {
    cost: f32 = std.math.inf(f32),
    from: usize = 0,
    len: u32 = 0,
    dist: u32 = 0,
};

fn parseOptimal(
    allocator: std.mem.Allocator,
    cm: anytype,
    dm: *dict.Matcher,
    data: []const u8,
    start: usize,
    ring: *Ring,
    cmds: *std.ArrayList(Cmd),
    dict_limit: usize,
) !void {
    cmds.clearRetainingCapacity();
    const end = data.len;
    var ip = start;

    var nodes = try allocator.alloc(OptNode, OPT_WINDOW + 1);
    defer allocator.free(nodes);

    while (ip < end) {
        const chunk = @min(end - ip, OPT_WINDOW);
        nodes[0] = .{ .cost = 0 };
        for (1..chunk + 1) |i| nodes[i] = .{ .cost = std.math.inf(f32) };

        for (0..chunk) |i| {
            const cur_cost = nodes[i].cost;
            if (cur_cost >= std.math.inf(f32)) continue;

            // Option 1: literal
            if (nodes[i + 1].cost > cur_cost + 8.0) {
                nodes[i + 1] = .{ .cost = cur_cost + 8.0, .from = i, .len = 0, .dist = 0 };
            }

            const p = ip + i;
            if (p + 4 > end) continue;

            // Option 2: matches from chain matcher
            const m = cm.best(data, p, ring, 32, 128);
            if (m.len >= 4) {
                const max_k = @min(m.len, chunk - i);
                var k: usize = 4;
                while (k <= max_k) : (k += 1) {
                    const cost = cur_cost + 12.0 + @as(f32, @floatFromInt(k)) * 0.5;
                    if (nodes[i + k].cost > cost) {
                        nodes[i + k] = .{ .cost = cost, .from = i, .len = @intCast(k), .dist = @intCast(m.dist) };
                    }
                }
            }

            // Option 3: static dictionary match
            if (p < dict_limit and m.len < 12) {
                if (dm.find(data, p)) |h| {
                    if (i + h.len <= chunk) {
                        const cost = cur_cost + 14.0;
                        if (nodes[i + h.len].cost > cost) {
                            nodes[i + h.len] = .{ .cost = cost, .from = i, .len = @intCast(h.len), .dist = @intCast(h.word_id + 1) };
                        }
                    }
                }
            }
        }

        // Traceback from chunk down to 0
        var curr: usize = chunk;
        var path_len: usize = 0;
        var pbuf: [OPT_WINDOW + 1]OptNode = undefined;
        while (curr > 0) {
            const nd = nodes[curr];
            pbuf[path_len] = nd;
            path_len += 1;
            curr = nd.from;
        }

        // Emit commands forward
        var anchor = ip;
        var p_idx = path_len;
        while (p_idx > 0) {
            p_idx -= 1;
            const step_node = pbuf[p_idx];
            if (step_node.len == 0) {
                // literal accumulation
                continue;
            } else {
                const match_pos = ip + step_node.from;
                const ins: u32 = @intCast(match_pos - anchor);
                try cmds.append(makeCmd(ring, ins, step_node.len, step_node.dist, false, 0));
                anchor = match_pos + step_node.len;
            }
        }

        ip += chunk;
        if (anchor < ip) {
            try cmds.append(makeCmd(ring, @intCast(ip - anchor), 4, 0, true, 0));
            anchor = ip;
        }
    }
}

const CL_ORDER = [18]u8{ 1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
const CL_INT = [6]u8{ 0, 7, 3, 2, 1, 15 };
const CL_BITS = [6]u8{ 2, 4, 3, 2, 2, 4 };

fn alphabetBits(size: usize) u6 {
    var bits: u6 = 0;
    var v: usize = size - 1;
    while (v > 0) : (v >>= 1) bits += 1;
    return bits;
}

const ClSym = struct { sym: u8, extra: u8 = 0 };

/// Turn code lengths into code-length symbols with 16/17 run-length coding.
fn rleLengths(lengths: []const u8, out: *std.ArrayList(ClSym)) !void {
    var n = lengths.len;
    while (n > 0 and lengths[n - 1] == 0) n -= 1;
    var prev: u8 = 8;
    var i: usize = 0;
    while (i < n) {
        const v = lengths[i];
        var run: usize = 1;
        while (i + run < n and lengths[i + run] == v) run += 1;
        i += run;
        if (v == 0) {
            if (run < 3) {
                for (0..run) |_| try out.append(.{ .sym = 0 });
            } else {
                var r = run - 3;
                const start = out.items.len;
                while (true) {
                    try out.append(.{ .sym = 17, .extra = @intCast(r & 7) });
                    r >>= 3;
                    if (r == 0) break;
                    r -= 1;
                }
                std.mem.reverse(ClSym, out.items[start..]);
            }
        } else {
            var reps = run;
            if (prev != v) {
                try out.append(.{ .sym = v });
                prev = v;
                reps -= 1;
            }
            if (reps < 3) {
                for (0..reps) |_| try out.append(.{ .sym = v });
            } else {
                var r = reps - 3;
                const start = out.items.len;
                while (true) {
                    try out.append(.{ .sym = 16, .extra = @intCast(r & 3) });
                    r >>= 2;
                    if (r == 0) break;
                    r -= 1;
                }
                std.mem.reverse(ClSym, out.items[start..]);
            }
        }
    }
}

/// Write a prefix code for `lengths` (alphabet = lengths.len).
fn writeTree(w: *Writer, a: std.mem.Allocator, lengths: []const u8) !void {
    const size = lengths.len;
    var nz: usize = 0;
    var syms: [4]u16 = undefined;
    for (lengths, 0..) |l, s| {
        if (l != 0) {
            if (nz < 4) syms[nz] = @intCast(s);
            nz += 1;
        }
    }
    const abits = alphabetBits(size);
    if (nz <= 1) {
        // Simple code, one symbol (zero-length code).
        try w.put(1, 2);
        try w.put(0, 2);
        try w.put(if (nz == 1) syms[0] else 0, abits);
        return;
    }
    if (nz <= 4) {
        // Order symbols by length, then value, as the format dictates.
        var order: [4]u16 = undefined;
        @memcpy(order[0..nz], syms[0..nz]);
        const Ctx = struct {
            l: []const u8,
            fn lt(c: @This(), x: u16, y: u16) bool {
                if (c.l[x] != c.l[y]) return c.l[x] < c.l[y];
                return x < y;
            }
        };
        std.mem.sort(u16, order[0..nz], Ctx{ .l = lengths }, Ctx.lt);
        try w.put(1, 2);
        try w.put(nz - 1, 2);
        for (order[0..nz]) |s| try w.put(s, abits);
        if (nz == 4) try w.put(@intFromBool(lengths[order[0]] == 1), 1);
        return;
    }

    var seq = std.ArrayList(ClSym).init(a);
    defer seq.deinit();
    try rleLengths(lengths, &seq);

    var freq: [18]u32 = .{0} ** 18;
    for (seq.items) |s| freq[s.sym] += 1;
    var cl_len: [18]u8 = undefined;
    prefixlen.limitedLengths(&freq, 5, &cl_len);
    var used: usize = 0;
    var only: usize = 0;
    for (freq, 0..) |f, s| {
        if (f != 0) {
            used += 1;
            only = s;
        }
    }
    if (used == 1) cl_len[only] = 4; // any nonzero length; costs no bits when decoding
    var cl_code: [18]u16 = undefined;
    prefixlen.canonicalCodes(&cl_len, &cl_code);

    var hskip: u6 = 0;
    if (cl_len[CL_ORDER[0]] == 0 and cl_len[CL_ORDER[1]] == 0) {
        hskip = 2;
        if (cl_len[CL_ORDER[2]] == 0) hskip = 3;
    }
    try w.put(hskip, 2);
    var last_nz: usize = 0;
    for (CL_ORDER, 0..) |s, i| {
        if (cl_len[s] != 0) last_nz = i;
    }
    const end_idx: usize = if (used == 1) 17 else last_nz;
    var i: usize = hskip;
    while (i <= end_idx) : (i += 1) {
        const l = cl_len[CL_ORDER[i]];
        try w.put(CL_INT[l], @intCast(CL_BITS[l]));
    }
    for (seq.items) |s| {
        if (used > 1) try w.putCode(cl_code[s.sym], cl_len[s.sym]);
        if (s.sym == 16) try w.put(s.extra, 2);
        if (s.sym == 17) try w.put(s.extra, 3);
    }
}

// ---------------------------------------------------------------------------
// Context map output
// ---------------------------------------------------------------------------

fn writeVarLen(w: *Writer, v: u32) !void {
    // v in 1..256
    if (v == 1) return w.put(0, 1);
    try w.put(1, 1);
    if (v == 2) return w.put(0, 3);
    const x = v - 1;
    const n: u6 = @intCast(31 - @clz(x));
    try w.put(n, 3);
    try w.put(x - (@as(u32, 1) << @intCast(n)), n);
}

const CmSym = struct { sym: u16, nbits: u8 = 0, extra: u32 = 0 };

fn cmapSymbols(map: []const u8, rlemax: u32, imtf: bool, out: *std.ArrayList(CmSym)) !void {
    var v: [256]u8 = undefined;
    @memcpy(v[0..map.len], map);
    if (imtf) {
        var mtf: [256]u8 = undefined;
        for (&mtf, 0..) |*m, k| m.* = @intCast(k);
        for (v[0..map.len]) |*x| {
            const val = x.*;
            var idx: usize = 0;
            while (mtf[idx] != val) idx += 1;
            x.* = @intCast(idx);
            var j = idx;
            while (j > 0) : (j -= 1) mtf[j] = mtf[j - 1];
            mtf[0] = val;
        }
    }
    var i: usize = 0;
    while (i < map.len) {
        if (v[i] == 0 and rlemax > 0) {
            var run: usize = 1;
            while (i + run < map.len and v[i + run] == 0) run += 1;
            i += run;
            while (run > 0) {
                if (run == 1) {
                    try out.append(.{ .sym = 0 });
                    break;
                }
                var c: u32 = 31 - @clz(@as(u32, @intCast(run)));
                if (c > rlemax) c = rlemax;
                const take = @min(run, (@as(usize, 2) << @intCast(c)) - 1);
                try out.append(.{ .sym = @intCast(c), .nbits = @intCast(c), .extra = @intCast(take - (@as(usize, 1) << @intCast(c))) });
                run -= take;
            }
        } else {
            try out.append(.{ .sym = @intCast(v[i] + rlemax) });
            i += 1;
        }
    }
}

fn writeContextMap(w: *Writer, a: std.mem.Allocator, map: []const u8, ntrees: u32) !void {
    var best_bits: f64 = std.math.inf(f64);
    var best_r: u32 = 0;
    var best_m = false;
    var tmp = std.ArrayList(CmSym).init(a);
    defer tmp.deinit();
    for ([_]bool{ false, true }) |im| {
        var r: u32 = 0;
        while (r <= 6) : (r += 1) {
            tmp.clearRetainingCapacity();
            try cmapSymbols(map, r, im, &tmp);
            var freq: [272]u32 = .{0} ** 272;
            var total: f64 = 0;
            var extra_bits: f64 = 0;
            for (tmp.items) |s| {
                freq[s.sym] += 1;
                total += 1;
                extra_bits += @floatFromInt(s.nbits);
            }
            var h: f64 = 0;
            for (freq) |f| {
                if (f != 0) h += @as(f64, @floatFromInt(f)) * std.math.log2(total / @as(f64, @floatFromInt(f)));
            }
            const bits = h + extra_bits + 12.0 + @as(f64, @floatFromInt(ntrees + r)) * 2.0;
            if (bits < best_bits) {
                best_bits = bits;
                best_r = r;
                best_m = im;
            }
        }
    }
    tmp.clearRetainingCapacity();
    try cmapSymbols(map, best_r, best_m, &tmp);

    if (best_r == 0) {
        try w.put(0, 1);
    } else {
        try w.put(1, 1);
        try w.put(best_r - 1, 4);
    }
    const alpha: usize = ntrees + best_r;
    var freq: [272]u32 = .{0} ** 272;
    for (tmp.items) |s| freq[s.sym] += 1;
    const ts = try buildTree(a, freq[0..alpha], 15);
    defer a.free(ts.lens);
    defer a.free(ts.codes);
    defer a.free(ts.rcodes);
    try writeTreeSet(w, a, ts);
    for (tmp.items) |s| {
        try w.putCode(ts.codes[s.sym], ts.lens[s.sym]);
        try w.put(s.extra, @intCast(s.nbits));
    }
    try w.put(@intFromBool(best_m), 1);
}

// ---------------------------------------------------------------------------
// Clustering of histograms
// ---------------------------------------------------------------------------

const nlogn_cap = 4096;
const nlogn = blk: {
    @setEvalBranchQuota(1000000);
    var t: [nlogn_cap]f32 = undefined;
    t[0] = 0;
    for (1..nlogn_cap) |i| t[i] = @as(f32, @floatFromInt(i)) * @as(f32, @floatCast(@log2(@as(f64, @floatFromInt(i)))));
    break :blk t;
};

inline fn nl(c: u32) f64 {
    if (c < nlogn_cap) return nlogn[c];
    const f: f64 = @floatFromInt(c);
    return f * std.math.log2(f);
}

const Hist = struct {
    c: []u32,
    total: u32 = 0,

    fn cost(self: *const Hist) f64 {
        if (self.total == 0) return 0;
        var s: f64 = 0;
        var used: u32 = 0;
        for (self.c) |x| {
            if (x != 0) {
                s += nl(x);
                used += 1;
            }
        }
        // entropy bits + rough tree description cost
        return nl(self.total) - s + 30.0 + 3.5 * @as(f64, @floatFromInt(used));
    }
};

fn mergedCost(a: *const Hist, b: *const Hist, scratch: []u32) f64 {
    var h = Hist{ .c = scratch, .total = a.total + b.total };
    for (scratch, 0..) |*x, i| x.* = a.c[i] + b.c[i];
    return h.cost();
}

/// Greedy agglomerative clustering. `hists[i]` is context i's histogram.
/// Writes the cluster id of each context to `assign`; returns cluster count.
fn cluster(
    a: std.mem.Allocator,
    hists: []Hist,
    alpha: usize,
    max_clusters: usize,
    assign: []u8,
) !usize {
    const n = hists.len;
    var alive = try a.alloc(bool, n);
    defer a.free(alive);
    const store = try a.alloc(u32, n * alpha);
    defer a.free(store);
    const h = try a.alloc(Hist, n);
    defer a.free(h);
    var costs = try a.alloc(f64, n);
    defer a.free(costs);
    const scratch = try a.alloc(u32, alpha);
    defer a.free(scratch);
    const parent = try a.alloc(u8, n);
    defer a.free(parent);

    var count: usize = 0;
    for (0..n) |i| {
        h[i] = .{ .c = store[i * alpha .. (i + 1) * alpha], .total = hists[i].total };
        @memcpy(h[i].c, hists[i].c);
        alive[i] = hists[i].total != 0;
        if (alive[i]) count += 1;
        costs[i] = h[i].cost();
        parent[i] = @intCast(i);
    }
    if (count == 0) {
        @memset(assign, 0);
        return 1;
    }

    // Pair delta cache.
    const delta = try a.alloc(f64, n * n);
    defer a.free(delta);
    for (0..n) |i| {
        if (!alive[i]) continue;
        for (i + 1..n) |j| {
            if (!alive[j]) continue;
            delta[i * n + j] = mergedCost(&h[i], &h[j], scratch) - costs[i] - costs[j];
        }
    }
    while (count > 1) {
        var bi: usize = 0;
        var bj: usize = 0;
        var bd: f64 = std.math.inf(f64);
        for (0..n) |i| {
            if (!alive[i]) continue;
            for (i + 1..n) |j| {
                if (!alive[j]) continue;
                if (delta[i * n + j] < bd) {
                    bd = delta[i * n + j];
                    bi = i;
                    bj = j;
                }
            }
        }
        if (bd >= 0 and count <= max_clusters) break;
        // merge j into i
        for (h[bi].c, 0..) |*x, k| x.* += h[bj].c[k];
        h[bi].total += h[bj].total;
        costs[bi] = h[bi].cost();
        alive[bj] = false;
        for (0..n) |k| {
            if (parent[k] == bj) parent[k] = @intCast(bi);
        }
        count -= 1;
        for (0..n) |k| {
            if (!alive[k] or k == bi) continue;
            const lo = @min(k, bi);
            const hi = @max(k, bi);
            delta[lo * n + hi] = mergedCost(&h[lo], &h[hi], scratch) - costs[lo] - costs[hi];
        }
    }
    // Renumber clusters densely, ordered by first context so the map compresses.
    var remap: [256]i16 = .{-1} ** 256;
    var next: u8 = 0;
    for (0..n) |i| {
        const root = parent[i];
        if (!alive[root] and hists[i].total == 0) {
            assign[i] = 0;
            continue;
        }
        if (remap[root] < 0) {
            remap[root] = next;
            next += 1;
        }
        assign[i] = @intCast(remap[root]);
    }
    return @max(next, 1);
}

// ---------------------------------------------------------------------------
// Meta-block encoding
// ---------------------------------------------------------------------------

fn looksLikeText(d: []const u8) bool {
    const n: usize = @min(d.len, 65536);
    var text: usize = 0;
    for (d[0..n]) |c| {
        if ((c >= 0x20 and c < 0x7f) or c == '\n' or c == '\r' or c == '\t') text += 1;
    }
    return text * 10 >= n * 9;
}

fn litCtx(mode: u8, p1: u8, p2: u8) u8 {
    return switch (mode) {
        0 => p1 & 0x3f,
        2 => tables.lut0[p1] | tables.lut1[p2],
        else => unreachable,
    };
}

const TreeSet = struct {
    lens: []u8,
    codes: []u16,
    /// Bit-reversed codes, ready to be written LSB-first.
    rcodes: []u16,
    /// Lone used symbol of a one-symbol code (coded with zero bits).
    single: ?u16 = null,
    /// Alphabet size the tree was built for.
    size: usize = 0,
};

fn buildTree(a: std.mem.Allocator, freq: []const u32, max_bits: u8) !TreeSet {
    const lens = try a.alloc(u8, freq.len);
    errdefer a.free(lens);
    const codes = try a.alloc(u16, freq.len);
    const rcodes = try a.alloc(u16, freq.len);
    prefixlen.limitedLengths(freq, max_bits, lens);
    var ts = TreeSet{ .lens = lens, .codes = codes, .rcodes = rcodes, .size = freq.len };
    var nz: usize = 0;
    for (freq, 0..) |f, s| {
        if (f != 0) {
            nz += 1;
            ts.single = @intCast(s);
        }
    }
    if (nz != 1) ts.single = null;
    prefixlen.canonicalCodes(lens, codes);
    for (lens, codes, rcodes) |l, c, *r| r.* = @intCast(prefix.reverse(c, @intCast(l)));
    return ts;
}

fn writeTreeSet(w: *Writer, a: std.mem.Allocator, ts: TreeSet) !void {
    if (ts.single) |s| {
        try w.put(1, 2);
        try w.put(0, 2);
        try w.put(s, alphabetBits(ts.size));
        return;
    }
    try writeTree(w, a, ts.lens);
}

/// Encode one meta-block covering src[start..end]. Returns false if the
/// compressed form is not smaller (caller falls back to uncompressed).
fn writeMetaBlock(
    a: std.mem.Allocator,
    w: *Writer,
    src: []const u8,
    start: usize,
    end: usize,
    cmds: []const Cmd,
    is_last: bool,
    ctx_model: bool,
) !void {
    const mlen = end - start;
    // ---- header ----
    try w.put(@intFromBool(is_last), 1);
    if (is_last) try w.put(0, 1);
    var nibbles: u6 = 4;
    while (nibbles < 6 and (mlen - 1) >> @intCast(nibbles * 4) != 0) nibbles += 1;
    try w.put(nibbles - 4, 2);
    try w.put(mlen - 1, nibbles * 4);
    if (!is_last) try w.put(0, 1); // ISUNCOMPRESSED

    try w.put(0, 1); // NBLTYPESL = 1
    try w.put(0, 1); // NBLTYPESI = 1
    try w.put(0, 1); // NBLTYPESD = 1
    try w.put(0, 2); // NPOSTFIX
    try w.put(0, 4); // NDIRECT

    // ---- literal context modeling ----
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ta = arena.allocator();

    var best_mode: u8 = 0;
    const best_assign = try ta.alloc(u8, 64);
    var best_k: usize = 1;
    var best_cost: f64 = std.math.inf(f64);
    const nlits = blk: {
        var t: usize = 0;
        for (cmds) |c| t += c.ins;
        break :blk t;
    };
    const lit_hist_store = try ta.alloc(u32, 64 * 256);
    var lit_h = try ta.alloc(Hist, 64);
    const cand_assign = try ta.alloc(u8, 64);
    @memset(best_assign, 0);
    // Mostly-ASCII data is what the UTF8 context mode is built for; only
    // other data is worth the second (LSB6) clustering attempt.
    const modes: []const u8 = if (!ctx_model or mlen < 65536) &[_]u8{} else if (looksLikeText(src[start..end])) &[_]u8{2} else &[_]u8{ 2, 0 };
    for (modes) |mode| {
        @memset(lit_hist_store, 0);
        for (lit_h, 0..) |*h, i| h.* = .{ .c = lit_hist_store[i * 256 .. (i + 1) * 256] };
        var pos = start;
        for (cmds) |c| {
            for (0..c.ins) |k| {
                const p = pos + k;
                const p1: u8 = if (p >= 1) src[p - 1] else 0;
                const p2: u8 = if (p >= 2) src[p - 2] else 0;
                const ctx = litCtx(mode, p1, p2);
                lit_h[ctx].c[src[p]] += 1;
                lit_h[ctx].total += 1;
            }
            pos += c.ins + c.span;
        }
        const k = try cluster(ta, lit_h, 256, MAX_LIT_TREES, cand_assign);
        // total cost of this clustering
        var cost: f64 = 0;
        const merged = try ta.alloc(u32, k * 256);
        @memset(merged, 0);
        const mh = try ta.alloc(Hist, k);
        for (mh, 0..) |*h, i| h.* = .{ .c = merged[i * 256 .. (i + 1) * 256] };
        for (lit_h, 0..) |h, i| {
            if (h.total == 0) continue;
            const t = cand_assign[i];
            for (h.c, 0..) |x, s| mh[t].c[s] += x;
            mh[t].total += h.total;
        }
        for (mh) |*h| cost += h.cost();
        cost += 64.0 * 1.5; // context map
        if (cost < best_cost) {
            best_cost = cost;
            best_mode = mode;
            best_k = k;
            @memcpy(best_assign, cand_assign);
        }
    }
    _ = nlits;

    // Context mode bits (one literal block type).
    try w.put(best_mode, 2);
    // NTREESL + context map.
    try writeVarLen(w, @intCast(best_k));
    if (best_k >= 2) try writeContextMap(w, a, best_assign, @intCast(best_k));

    // ---- distance context clustering ----
    var d_store = try ta.alloc(u32, 4 * 64);
    @memset(d_store, 0);
    var d_h = try ta.alloc(Hist, 4);
    for (d_h, 0..) |*h, i| h.* = .{ .c = d_store[i * 64 .. (i + 1) * 64] };
    for (cmds) |c| {
        if (c.implicit) continue;
        const dctx: usize = if (c.dctx_len > 4) 3 else c.dctx_len - 2;
        const dsym: u16 = c.dsym;
        if (dsym >= d_h[dctx].c.len) continue;
        d_h[dctx].c[dsym] += 1;
        d_h[dctx].total += 1;
    }
    const d_assign = try ta.alloc(u8, 4);
    @memset(d_assign, 0);
    const kd: usize = if (ctx_model) try cluster(ta, d_h, 64, 4, d_assign) else 1;
    try writeVarLen(w, @intCast(kd));
    if (kd >= 2) try writeContextMap(w, a, d_assign, @intCast(kd));

    // ---- build the trees ----
    const lit_trees = try ta.alloc(TreeSet, best_k);
    {
        const merged = try ta.alloc(u32, best_k * 256);
        @memset(merged, 0);
        // recompute histograms per cluster
        var pos = start;
        if (best_k == 1) {
            // One tree: plain byte counts, no context lookups.
            for (cmds) |c| {
                for (src[pos .. pos + c.ins]) |b| merged[b] += 1;
                pos += c.ins + c.span;
            }
        } else for (cmds) |c| {
            for (0..c.ins) |k| {
                const p = pos + k;
                const p1: u8 = if (p >= 1) src[p - 1] else 0;
                const p2: u8 = if (p >= 2) src[p - 2] else 0;
                const t = best_assign[litCtx(best_mode, p1, p2)];
                merged[@as(usize, t) * 256 + src[p]] += 1;
            }
            pos += c.ins + c.span;
        }
        for (lit_trees, 0..) |*t, i| t.* = try buildTree(ta, merged[i * 256 .. (i + 1) * 256], 15);
    }
    var ic_freq: [704]u32 = .{0} ** 704;
    for (cmds) |c| ic_freq[c.ic_sym] += 1;
    const ic_tree = try buildTree(ta, &ic_freq, 15);

    const d_trees = try ta.alloc(TreeSet, kd);
    {
        const merged = try ta.alloc(u32, kd * 64);
        @memset(merged, 0);
        for (cmds) |c| {
            if (c.implicit) continue;
            const dctx: usize = if (c.dctx_len > 4) 3 else c.dctx_len - 2;
            merged[@as(usize, d_assign[dctx]) * 64 + c.dsym] += 1;
        }
        for (d_trees, 0..) |*t, i| t.* = try buildTree(ta, merged[i * 64 .. (i + 1) * 64], 15);
    }

    for (lit_trees) |t| try writeTreeSet(w, a, t);
    try writeTreeSet(w, a, ic_tree);
    for (d_trees) |t| try writeTreeSet(w, a, t);

    // ---- commands ----
    var pos = start;
    const one_tree = best_k == 1;
    const t0 = lit_trees[0];
    for (cmds) |c| {
        try w.putRev(ic_tree.rcodes[c.ic_sym], ic_tree.lens[c.ic_sym]);
        try w.put(c.ins_extra, @intCast(c.ins_bits));
        try w.put(c.copy_extra, @intCast(c.copy_bits));
        if (one_tree) {
            // Single literal tree: no context lookups, two literals per write.
            var k: usize = 0;
            while (k + 2 <= c.ins) : (k += 2) {
                const x = src[pos + k];
                const y = src[pos + k + 1];
                const lx = t0.lens[x];
                try w.put(@as(u64, t0.rcodes[x]) | (@as(u64, t0.rcodes[y]) << @intCast(lx)), @intCast(lx + t0.lens[y]));
            }
            if (k < c.ins) {
                const x = src[pos + k];
                try w.putRev(t0.rcodes[x], t0.lens[x]);
            }
        } else {
            for (0..c.ins) |k| {
                const p = pos + k;
                const p1: u8 = if (p >= 1) src[p - 1] else 0;
                const p2: u8 = if (p >= 2) src[p - 2] else 0;
                const t = lit_trees[best_assign[litCtx(best_mode, p1, p2)]];
                try w.putRev(t.rcodes[src[p]], t.lens[src[p]]);
            }
        }
        pos += c.ins;
        if (!c.implicit) {
            const dctx: usize = if (c.dctx_len > 4) 3 else c.dctx_len - 2;
            const t = d_trees[d_assign[dctx]];
            try w.putRev(t.rcodes[c.dsym], t.lens[c.dsym]);
            try w.put(c.dextra, @intCast(c.dbits));
        }
        pos += c.span;
    }
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

/// Incremental encoder. `data` passed to `encode` is the whole history (all
/// bytes since the stream start, possibly trimmed by the caller via `trim`);
/// only `[from, to)` is newly encoded.
pub const Encoder = struct {
    allocator: std.mem.Allocator,
    w: Writer,
    mf: mfmod.MatchFinder,
    chain: ?ChainMatcher,
    deep: ?DeepMatcher,
    dm: dict.Matcher,
    ring: Ring = .{},
    cmds: std.ArrayList(Cmd),
    quality: i32,
    fast_tbl: []u32,

    pub fn init(allocator: std.mem.Allocator) Error!Encoder {
        return initQuality(allocator, DEFAULT_QUALITY);
    }

    /// Quality 0-2: fast parse, single literal tree. 3-4: lazy parse with
    /// context-modeled literals. 5+: adds static-dictionary matching.
    pub fn initQuality(allocator: std.mem.Allocator, quality: i32) Error!Encoder {
        const fast_tbl = try allocator.alloc(u32, if (quality <= 3) @as(usize, 1) << FAST_HASH_LOG else 0);
        errdefer allocator.free(fast_tbl);
        @memset(fast_tbl, 0);
        var mf = try mfmod.MatchFinder.init(allocator, .{ .hash_log = 17, .max_dist = @intCast(WINDOW) });
        errdefer mf.deinit(allocator);
        var chain: ?ChainMatcher = if (quality == 4 or quality == 5) try ChainMatcher.init(allocator) else null;
        errdefer if (chain) |*c| c.deinit(allocator);
        var deep: ?DeepMatcher = if (quality >= 6) try DeepMatcher.init(allocator, if (quality >= 9) 22 else 20) else null;
        errdefer if (deep) |*c| c.deinit(allocator);
        var dm = try dict.Matcher.init(allocator);
        errdefer dm.deinit(allocator);
        var w = Writer.init(allocator);
        errdefer w.buf.deinit();
        w.put(0b1011, 4) catch return error.OutOfMemory; // WBITS = 22
        return .{ .allocator = allocator, .w = w, .mf = mf, .chain = chain, .deep = deep, .dm = dm, .cmds = std.ArrayList(Cmd).init(allocator), .quality = quality, .fast_tbl = fast_tbl };
    }

    pub fn deinit(self: *Encoder) void {
        self.w.buf.deinit();
        self.mf.deinit(self.allocator);
        if (self.chain) |*c| c.deinit(self.allocator);
        if (self.deep) |*c| c.deinit(self.allocator);
        self.dm.deinit(self.allocator);
        self.cmds.deinit();
        self.allocator.free(self.fast_tbl);
    }

    /// Encode `data[from..to]` as one or more meta-blocks (never the last).
    pub fn encode(self: *Encoder, data: []const u8, from: usize, to: usize) Error!void {
        var pos = from;
        while (pos < to) {
            const end = @min(to, pos + METABLOCK_MAX);
            const snap_len = self.w.buf.items.len;
            const snap_acc = self.w.acc;
            const snap_n = self.w.n;
            const snap_ring = self.ring;

            if (self.quality <= 2) {
                parseFastBr(self.fast_tbl, data[0..end], pos, &self.ring, &self.cmds) catch return error.OutOfMemory;
            } else if (self.chain) |*cm| {
                parseChain(cm, &self.dm, data[0..end], pos, &self.ring, &self.cmds, dictLimit(self.quality), chainLen(self.quality)) catch return error.OutOfMemory;
            } else if (self.deep) |*cm| {
                parseChain(cm, &self.dm, data[0..end], pos, &self.ring, &self.cmds, dictLimit(self.quality), chainLen(self.quality)) catch return error.OutOfMemory;
            } else {
                parseMetaBlock(self.allocator, &self.mf, &self.dm, data[0..end], pos, &self.ring, &self.cmds, dictLimit(self.quality)) catch return error.OutOfMemory;
            }
            writeMetaBlock(self.allocator, &self.w, data, pos, end, self.cmds.items, false, self.quality >= 3) catch return error.OutOfMemory;

            const used_bits = self.w.bitPos() - (snap_len * 8 + snap_n);
            const mlen = end - pos;
            if (used_bits >= (mlen + 4) * 8) {
                // Stored meta-block is cheaper.
                self.w.buf.shrinkRetainingCapacity(snap_len);
                self.w.acc = snap_acc;
                self.w.n = snap_n;
                self.ring = snap_ring;
                writeStored(&self.w, data[pos..end]) catch return error.OutOfMemory;
            }
            pos = end;
        }
    }

    /// Byte-align the output with an empty metadata meta-block so everything
    /// encoded so far can be decoded without further input.
    pub fn flush(self: *Encoder) Error!void {
        self.w.put(0, 1) catch return error.OutOfMemory; // ISLAST
        self.w.put(3, 2) catch return error.OutOfMemory; // MNIBBLES = 0 (metadata)
        self.w.put(0, 1) catch return error.OutOfMemory; // reserved
        self.w.put(0, 2) catch return error.OutOfMemory; // MSKIPBYTES = 0
        self.w.alignByte() catch return error.OutOfMemory;
    }

    /// Terminate the stream.
    pub fn finish(self: *Encoder) Error!void {
        self.w.put(1, 1) catch return error.OutOfMemory; // ISLAST
        self.w.put(1, 1) catch return error.OutOfMemory; // ISLASTEMPTY
        self.w.alignByte() catch return error.OutOfMemory;
    }

    /// Fully written bytes so far (the trailing partial byte is excluded).
    pub fn output(self: *const Encoder) []const u8 {
        return self.w.buf.items;
    }

    /// Discard the first `n` output bytes.
    pub fn consume(self: *Encoder, n: usize) void {
        self.w.buf.replaceRange(0, n, &.{}) catch unreachable;
    }

    /// Forget match-finder state (call after sliding the history buffer).
    pub fn resetHistory(self: *Encoder) void {
        self.mf.reset();
        if (self.chain) |*c| c.reset();
        if (self.deep) |*c| c.reset();
        @memset(self.fast_tbl, 0);
    }
};

/// Compress `src` into a Brotli stream.
pub fn compress(allocator: std.mem.Allocator, src: []const u8) Error![]u8 {
    return compressQuality(allocator, src, DEFAULT_QUALITY);
}

pub fn compressQuality(allocator: std.mem.Allocator, src: []const u8, quality: i32) Error![]u8 {
    var enc = try Encoder.initQuality(allocator, quality);
    defer enc.deinit();
    if (src.len > 0) try enc.encode(src, 0, src.len);
    try enc.finish();
    return enc.w.buf.toOwnedSlice();
}

fn writeStored(w: *Writer, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        const chunk = @min(data.len - off, 1 << 24);
        try w.put(0, 1); // ISLAST
        var nibbles: u6 = 4;
        while (nibbles < 6 and (chunk - 1) >> @intCast(nibbles * 4) != 0) nibbles += 1;
        try w.put(nibbles - 4, 2);
        try w.put(chunk - 1, nibbles * 4);
        try w.put(1, 1); // ISUNCOMPRESSED
        try w.alignByte();
        try w.buf.appendSlice(data[off .. off + chunk]);
        off += chunk;
    }
}

test "round trip" {
    const a = std.testing.allocator;
    const text = "the quick brown fox jumps over the lazy dog. " ** 300;
    const z = try compress(a, text);
    defer a.free(z);
    try std.testing.expect(z.len < text.len / 8);
    const d = try dec.decompress(a, z);
    defer a.free(d);
    try std.testing.expectEqualStrings(text, d);
}

fn genData(a: std.mem.Allocator, rng: std.Random, n: usize, kind: u8) ![]u8 {
    const buf = try a.alloc(u8, n);
    switch (kind) {
        0 => rng.bytes(buf),
        1 => for (buf) |*b| {
            b.* = "abcde "[rng.uintLessThan(usize, 6)];
        },
        2 => {
            const words = [_][]const u8{ "alpha ", "The ", "information ", "delta\n", "government ", "zeta, ", "Because " };
            var i: usize = 0;
            while (i < n) {
                const w = words[rng.uintLessThan(usize, words.len)];
                const k = @min(w.len, n - i);
                @memcpy(buf[i .. i + k], w[0..k]);
                i += k;
            }
        },
        else => {
            var i: usize = 0;
            while (i < n) {
                const run = @min(n - i, rng.uintLessThan(usize, 300) + 1);
                const b = rng.int(u8);
                if (rng.boolean() and i > 64) {
                    const off = rng.uintLessThan(usize, i) + 1;
                    for (0..run) |k| buf[i + k] = buf[i + k - @min(off, i + k)];
                } else @memset(buf[i .. i + run], b);
                i += run;
            }
        },
    }
    return buf;
}

test "fuzz round trip" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xB107);
    const rng = prng.random();
    const sizes = [_]usize{ 0, 1, 3, 17, 100, 1023, 5000, 70000, 300000, 1100000 };
    for (sizes) |n| {
        for (0..4) |kind| {
            const data = try genData(a, rng, n, @intCast(kind));
            defer a.free(data);
            const z = try compress(a, data);
            defer a.free(z);
            const d = try dec.decompress(a, z);
            defer a.free(d);
            try std.testing.expectEqualSlices(u8, data, d);
        }
    }
}

test "every quality level round trips" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x9A11);
    const rng = prng.random();
    for ([_]usize{ 0, 1, 77, 5000, 250000 }) |n| {
        for (0..4) |kind| {
            const data = try genData(a, rng, n, @intCast(kind));
            defer a.free(data);
            for ([_]i32{ 0, 2, 3, 5, 6, 9, 11 }) |q| {
                const z = try compressQuality(a, data, q);
                defer a.free(z);
                const d = try dec.decompress(a, z);
                defer a.free(d);
                try std.testing.expectEqualSlices(u8, data, d);
            }
        }
    }
}

test "O(1) insert/copy codes match the table search" {
    var v: u32 = 0;
    while (v < 3_000_000) : (v += 1) {
        try std.testing.expectEqual(lowerCode(&dec.INSERT_BASE, v), insertCode(v));
        if (v >= 2) try std.testing.expectEqual(lowerCode(&dec.COPY_BASE, v), copyCode(v));
    }
    for ([_]u32{ 16_799_809, 16_799_000, 22_593, 22_594, 6_209, 6_210, 16_779_333 }) |x| {
        try std.testing.expectEqual(lowerCode(&dec.INSERT_BASE, x), insertCode(x));
        try std.testing.expectEqual(lowerCode(&dec.COPY_BASE, x), copyCode(x));
    }
}
