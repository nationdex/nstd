//! Zstandard compression (RFC 8878).
//!
//! LZ77 parse (lazy, hash-chained by the shared match finder) feeding the full
//! entropy back end: Huffman-coded literals (1 or 4 streams) and FSE-coded
//! sequences with per-stream choice of predefined / RLE / custom tables and
//! repeat-offset coding. Incompressible blocks fall back to Raw / RLE.

const std = @import("std");
const frame = @import("frame.zig");
const fse = @import("fse.zig");
const huf = @import("huf.zig");
const dec = @import("decompress.zig");
const dict_mod = @import("dict.zig");
const checksum = @import("../core/checksum.zig");
const mfmod = @import("../core/matchfinder.zig");

pub const Error = error{
    OutOfMemory,
    NoSpaceLeft,
    InputTooSmall,
    CorruptData,
};

const Seq = struct { ll: u32, ml: u32, off: u32 };

const Coded = struct {
    llc: u8,
    mlc: u8,
    ofc: u8,
    llx: u32,
    mlx: u32,
    ofx: u32,
};

const WINDOW_LOG: u6 = 22;

/// Speed/ratio knobs derived from the compression level.
const Params = struct {
    hash_log: u6,
    lazy: bool,
    /// Positions indexed inside a match (dense head) before sparse tail.
    inner_dense: usize,
    /// Skip acceleration shift: step grows by (run >> accel).
    accel: u6,
    /// Use only predefined sequence tables (no per-block table build).
    predefined_only: bool,
    /// Single-table pipelined parser (levels <= 2).
    fast: bool = false,
    /// Two-table (long + short hash) parser with repeat-offset probing (level 3).
    dfast: bool = false,
    long_log: u6 = 17,
    short_log: u6 = 16,

    /// Shrink the hash tables for small inputs: zeroing megabytes of tables would
    /// otherwise dominate compressing a few hundred bytes.
    fn scaled(self: Params, len: usize) Params {
        var p = self;
        // For small web packets under 32KB, limit hash table depth to reduce cache pollution and initialization time
        const need: u6 = blk: {
            var l: u6 = 7;
            while (l < 15 and (@as(usize, 1) << l) < len * 2) l += 1;
            break :blk l;
        };
        p.hash_log = @min(p.hash_log, need);
        p.long_log = @min(p.long_log, need);
        p.short_log = @min(p.short_log, @as(u6, @max(7, need - 1)));
        return p;
    }

    fn tableSize(self: Params) usize {
        if (self.fast) return @as(usize, 1) << self.hash_log;
        if (self.dfast) return (@as(usize, 1) << self.long_log) + (@as(usize, 1) << self.short_log);
        return 0;
    }

    fn fromLevel(level: i32) Params {
        if (level <= 1) return .{ .hash_log = 15, .lazy = false, .inner_dense = 2, .accel = 7, .predefined_only = false, .fast = true };
        if (level == 2) return .{ .hash_log = 17, .lazy = false, .inner_dense = 8, .accel = 8, .predefined_only = false, .fast = true };
        if (level == 3) return .{ .hash_log = 16, .lazy = false, .inner_dense = 0, .accel = 8, .predefined_only = true, .fast = true };
        return .{ .hash_log = 17, .lazy = true, .inner_dense = 24, .accel = 5, .predefined_only = false };
    }
};

pub const DEFAULT_LEVEL: i32 = 3;

/// Compress `src` into a complete Zstandard frame at the default level.
pub fn compress(allocator: std.mem.Allocator, src: []const u8) Error![]u8 {
    return compressLevel(allocator, src, DEFAULT_LEVEL);
}

/// Compress `src` into a complete Zstandard frame. Lower levels are faster.
pub fn compressLevel(allocator: std.mem.Allocator, src: []const u8, level: i32) Error![]u8 {
    const prm = Params.fromLevel(level).scaled(src.len);
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    const single = src.len <= (@as(usize, 1) << WINDOW_LOG);
    var wlog: u6 = 10;
    if (!single) wlog = WINDOW_LOG;
    try frame.writeFrameHeader(&out, .{
        .single_segment = single,
        .content_checksum = true,
        .content_size = src.len,
        .window_log = wlog,
    });

    if (src.len == 0) {
        try frame.writeBlockHeader(&out, .{ .last = true, .type = .raw, .size = 0 });
    } else {
        var mf: mfmod.MatchFinder = undefined;
        const need_mf = !(prm.fast or prm.dfast);
        if (need_mf) {
            mf = try mfmod.MatchFinder.init(allocator, .{
                .hash_log = prm.hash_log,
                .max_dist = @as(u32, 1) << WINDOW_LOG,
            });
        }
        defer if (need_mf) mf.deinit(allocator);

        const fast_tbl = try allocator.alloc(u32, prm.tableSize());
        defer allocator.free(fast_tbl);
        @memset(fast_tbl, 0);
        var rep: [3]u32 = .{ 1, 4, 8 };
        var seqs = std.ArrayList(Seq).init(allocator);
        defer seqs.deinit();
        var lits = std.ArrayList(u8).init(allocator);
        defer lits.deinit();

        var pos: usize = 0;
        while (pos < src.len) {
            const end = @min(src.len, pos + frame.BLOCK_MAX);
            const last = end == src.len;
            try compressOneBlock(allocator, prm, &mf, fast_tbl, src, pos, end, last, &rep, &seqs, &lits, &out);
            pos = end;
        }
    }

    const c = checksum.xxh64(src, 0);
    try out.appendSlice(&std.mem.toBytes(@as(u32, @truncate(c))));
    return out.toOwnedSlice();
}

/// Symbol statistics gathered while parsing samples (dictionary training).
pub const Stats = struct {
    lit: [256]u32 = .{0} ** 256,
    ll: [36]u32 = .{0} ** 36,
    ml: [53]u32 = .{0} ** 53,
    of: [32]u32 = .{0} ** 32,
};

/// Parse `sample` against raw dictionary `content` exactly as the compressor
/// would, and add the literal / sequence-code histograms to `st`.
pub fn analyzeSample(allocator: std.mem.Allocator, sample: []const u8, content: []const u8, level: i32, st: *Stats) Error!void {
    if (sample.len == 0) return;
    const prm = Params.fromLevel(level).scaled(content.len + sample.len);
    const full_len = content.len + sample.len;
    const full_src = try allocator.alloc(u8, full_len);
    defer allocator.free(full_src);
    @memcpy(full_src[0..content.len], content);
    @memcpy(full_src[content.len..], sample);

    var mf: mfmod.MatchFinder = undefined;
    const need_mf = !(prm.fast or prm.dfast);
    if (need_mf) {
        mf = try mfmod.MatchFinder.init(allocator, .{ .hash_log = prm.hash_log, .max_dist = @as(u32, 1) << WINDOW_LOG });
    }
    defer if (need_mf) mf.deinit(allocator);

    const tbl_size = prm.tableSize();
    const tbl = try allocator.alloc(u32, tbl_size);
    defer allocator.free(tbl);
    @memset(tbl, 0);
    if (content.len >= 4) {
        if (prm.dfast) {
            prefillDfast(prm, tbl, full_src[0..content.len]);
        } else if (prm.fast) {
            prefillFast(prm.hash_log, tbl, full_src[0..content.len]);
        } else {
            var p: usize = 0;
            while (p + 8 <= content.len) : (p += 1) _ = mf.find(full_src[0..content.len], p);
        }
    }

    var rep: [3]u32 = .{ 1, 4, 8 };
    var seqs = std.ArrayList(Seq).init(allocator);
    defer seqs.deinit();
    var lits = std.ArrayList(u8).init(allocator);
    defer lits.deinit();
    var pos: usize = content.len;
    while (pos < full_len) {
        const end = @min(full_len, pos + frame.BLOCK_MAX);
        if (prm.dfast) {
            parseDfast(prm, tbl, full_src[0..end], pos, end, &rep, &seqs, &lits) catch return error.OutOfMemory;
        } else if (prm.fast) {
            parseFast(prm, tbl, full_src[0..end], pos, end, &rep, &seqs, &lits) catch return error.OutOfMemory;
        } else {
            parse(prm, &mf, full_src[0..end], pos, end, &seqs, &lits) catch return error.OutOfMemory;
        }
        for (lits.items) |b| st.lit[b] += 1;
        for (seqs.items) |q| {
            const ov = offsetValue(&rep, q.off, q.ll);
            st.of[floorLog2(ov)] += 1;
            st.ll[llCode(q.ll)] += 1;
            st.ml[mlCode(q.ml)] += 1;
        }
        pos = end;
    }
}

/// Compress `src` with an optional dictionary at default level.
pub fn compressDict(allocator: std.mem.Allocator, src: []const u8, dict_bytes: ?[]const u8) Error![]u8 {
    return compressDictLevel(allocator, src, dict_bytes, DEFAULT_LEVEL);
}

/// Compress `src` with an optional dictionary at the given level.
pub fn compressDictLevel(allocator: std.mem.Allocator, src: []const u8, dict_bytes: ?[]const u8, level: i32) Error![]u8 {
    if (dict_bytes == null or dict_bytes.?.len == 0) {
        return compressLevel(allocator, src, level);
    }
    const d = dict_mod.Dict.init(dict_bytes.?) catch return compressLevel(allocator, src, level);
    const prm = Params.fromLevel(level).scaled(d.content.len + src.len);
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    const single = (d.content.len + src.len) <= (@as(usize, 1) << WINDOW_LOG);
    var wlog: u6 = 10;
    if (!single) wlog = WINDOW_LOG;
    try frame.writeFrameHeader(&out, .{
        .single_segment = single,
        .content_checksum = true,
        .dict_id = d.dict_id,
        .content_size = src.len,
        .window_log = wlog,
    });

    if (src.len == 0) {
        try frame.writeBlockHeader(&out, .{ .last = true, .type = .raw, .size = 0 });
    } else {
        const full_len = d.content.len + src.len;
        const full_src = try allocator.alloc(u8, full_len);
        defer allocator.free(full_src);
        @memcpy(full_src[0..d.content.len], d.content);
        @memcpy(full_src[d.content.len..], src);

        var mf: mfmod.MatchFinder = undefined;
        const need_mf = !(prm.fast or prm.dfast);
        if (need_mf) {
            mf = try mfmod.MatchFinder.init(allocator, .{
                .hash_log = prm.hash_log,
                .max_dist = @as(u32, 1) << WINDOW_LOG,
            });
        }
        defer if (need_mf) mf.deinit(allocator);

        const tbl_size = prm.tableSize();
        const fast_tbl = try allocator.alloc(u32, tbl_size);
        defer allocator.free(fast_tbl);
        @memset(fast_tbl, 0);

        if (d.content.len >= 4) {
            if (prm.dfast) {
                prefillDfast(prm, fast_tbl, full_src[0..d.content.len]);
            } else if (prm.fast) {
                prefillFast(prm.hash_log, fast_tbl, full_src[0..d.content.len]);
            } else {
                var p: usize = 0;
                while (p + 8 <= d.content.len) : (p += 1) {
                    _ = mf.find(full_src[0..d.content.len], p);
                }
            }
        }

        var rep: [3]u32 = d.rep;
        var seqs = std.ArrayList(Seq).init(allocator);
        defer seqs.deinit();
        var lits = std.ArrayList(u8).init(allocator);
        defer lits.deinit();

        var pos: usize = d.content.len;
        while (pos < full_len) {
            const end = @min(full_len, pos + frame.BLOCK_MAX);
            const last = end == full_len;
            try compressOneBlock(allocator, prm, &mf, fast_tbl, full_src, pos, end, last, &rep, &seqs, &lits, &out);
            pos = end;
        }
    }

    const c = checksum.xxh64(src, 0);
    try out.appendSlice(&std.mem.toBytes(@as(u32, @truncate(c))));
    return out.toOwnedSlice();
}

fn prefillFast(log: u6, tbl: []u32, dict_data: []const u8) void {
    if (dict_data.len < 8) return;
    var i: usize = 0;
    while (i + 8 <= dict_data.len) : (i += 1) {
        const v = rd64(dict_data, i);
        const h = hash5(v, log);
        tbl[h] = @intCast(i + 1);
    }
}

fn prefillDfast(prm: Params, tbl: []u32, dict_data: []const u8) void {
    const long_log = prm.long_log;
    const short_log = prm.short_log;
    if (dict_data.len < 8) return;
    const tl = tbl[0 .. @as(usize, 1) << long_log];
    const ts = tbl[@as(usize, 1) << long_log ..][0 .. @as(usize, 1) << short_log];
    var i: usize = 0;
    while (i + 8 <= dict_data.len) : (i += 1) {
        const v = rd64(dict_data, i);
        const hl = hash8(v, long_log);
        const hs = hash5(v, short_log);
        tl[hl] = @intCast(i + 1);
        ts[hs] = @intCast(i + 1);
    }
}

/// Default chunk for multi-threaded compression: large enough that cutting the
/// match history between chunks costs well under 1% ratio.
pub const MT_CHUNK: usize = 8 << 20;

/// Compress with up to `nthreads` workers by cutting `src` into independent
/// frames of `chunk` bytes (the concatenation is a valid Zstandard stream).
/// `nthreads <= 1` or small inputs produce a single frame.
pub fn compressMt(allocator: std.mem.Allocator, src: []const u8, level: i32, nthreads: usize, chunk: usize) Error![]u8 {
    if (nthreads <= 1 or src.len <= chunk) return compressLevel(allocator, src, level);
    const n_chunks = (src.len + chunk - 1) / chunk;
    const parts = try allocator.alloc(?[]u8, n_chunks);
    defer allocator.free(parts);
    @memset(parts, null);
    var failed = std.atomic.Value(bool).init(false);
    var next = std.atomic.Value(usize).init(0);

    const Ctx = struct {
        allocator: std.mem.Allocator,
        src: []const u8,
        level: i32,
        chunk: usize,
        parts: []?[]u8,
        failed: *std.atomic.Value(bool),
        next: *std.atomic.Value(usize),

        fn run(c: @This()) void {
            while (!c.failed.load(.monotonic)) {
                const i = c.next.fetchAdd(1, .monotonic);
                if (i >= c.parts.len) return;
                const s0 = i * c.chunk;
                const e0 = @min(c.src.len, s0 + c.chunk);
                c.parts[i] = compressLevel(c.allocator, c.src[s0..e0], c.level) catch {
                    c.failed.store(true, .monotonic);
                    return;
                };
            }
        }
    };
    const ctx = Ctx{ .allocator = allocator, .src = src, .level = level, .chunk = chunk, .parts = parts, .failed = &failed, .next = &next };

    const extra = @min(nthreads, n_chunks) - 1;
    const threads = try allocator.alloc(std.Thread, extra);
    defer allocator.free(threads);
    var spawned: usize = 0;
    for (threads) |*t| {
        t.* = std.Thread.spawn(.{}, Ctx.run, .{ctx}) catch break;
        spawned += 1;
    }
    Ctx.run(ctx);
    for (threads[0..spawned]) |t| t.join();

    defer for (parts) |p| if (p) |b| allocator.free(b);
    if (failed.load(.monotonic)) return error.OutOfMemory;
    var total: usize = 0;
    for (parts) |p| total += p.?.len;
    const out = try allocator.alloc(u8, total);
    var off: usize = 0;
    for (parts) |p| {
        @memcpy(out[off .. off + p.?.len], p.?);
        off += p.?.len;
    }
    return out;
}

fn compressOneBlock(
    allocator: std.mem.Allocator,
    prm: Params,
    mf: *mfmod.MatchFinder,
    fast_tbl: []u32,
    src: []const u8,
    start: usize,
    end: usize,
    last: bool,
    rep: *[3]u32,
    seqs: *std.ArrayList(Seq),
    lits: *std.ArrayList(u8),
    out: *std.ArrayList(u8),
) Error!void {
    const block = src[start..end];

    // RLE block.
    if (block.len >= 4 and std.mem.allEqual(u8, block, block[0])) {
        try frame.writeBlockHeader(out, .{ .last = last, .type = .rle, .size = @intCast(block.len) });
        try out.append(block[0]);
        return;
    }

    if (prm.dfast) {
        parseDfast(prm, fast_tbl, src[0..end], start, end, rep, seqs, lits) catch return error.OutOfMemory;
    } else if (prm.fast) {
        parseFast(prm, fast_tbl, src[0..end], start, end, rep, seqs, lits) catch return error.OutOfMemory;
    } else {
        parse(prm, mf, src[0..end], start, end, seqs, lits) catch return error.OutOfMemory;
    }

    // Try the compressed form behind a placeholder header.
    const hdr_pos = out.items.len;
    try out.appendNTimes(0, 3);
    var tmp_rep = rep.*;
    const ok = try encodeCompressed(allocator, prm, seqs.items, lits.items, &tmp_rep, out);
    const body_len = out.items.len - hdr_pos - 3;
    if (ok and body_len < block.len and body_len <= frame.BLOCK_MAX) {
        rep.* = tmp_rep;
        var hb = std.ArrayList(u8).init(allocator);
        defer hb.deinit();
        try frame.writeBlockHeader(&hb, .{ .last = last, .type = .compressed, .size = @intCast(body_len) });
        @memcpy(out.items[hdr_pos .. hdr_pos + 3], hb.items[0..3]);
        return;
    }
    out.shrinkRetainingCapacity(hdr_pos);
    try frame.writeBlockHeader(out, .{ .last = last, .type = .raw, .size = @intCast(block.len) });
    try out.appendSlice(block);
}

inline fn hash5(v: u64, log: u6) usize {
    return @intCast(((v << 24) *% 0x9E3779B185EBCA87) >> @intCast(64 - @as(u7, log)));
}

inline fn rd64(d: []const u8, i: usize) u64 {
    return std.mem.readInt(u64, d[i..][0..8], .little);
}

/// Single-table greedy parser tuned for throughput: 5-byte hash, accelerating
/// skip over incompressible runs, backward match extension.
fn parseFast(
    prm: Params,
    tbl: []u32,
    data: []const u8,
    start: usize,
    end: usize,
    rep_in: *const [3]u32,
    seqs: *std.ArrayList(Seq),
    lits: *std.ArrayList(u8),
) !void {
    seqs.clearRetainingCapacity();
    lits.clearRetainingCapacity();
    // Every match is >= 4 bytes, so a block holds at most BLOCK_MAX/4 sequences;
    // reserving up front lets the loop write without capacity checks.
    try seqs.ensureTotalCapacity((end - start) / 4 + 2);
    try lits.ensureTotalCapacity((end - start) + 64);
    const sq: [*]Seq = seqs.items.ptr;
    const lt: [*]u8 = lits.items.ptr;
    var nseq: usize = 0;
    var nlit: usize = 0;

    const max_dist: usize = @as(usize, 1) << WINDOW_LOG;
    const log = prm.hash_log;
    var rep1: usize = rep_in[0];
    var rep2: usize = rep_in[1];
    var ip = start;
    var anchor = start;
    while (ip + 16 <= end) {
        const v = rd64(data, ip);
        const h = hash5(v, log);
        const cand: usize = tbl[h];
        tbl[h] = @intCast(ip + 1);

        var c: usize = 0;
        var found = false;
        // Repeat offset first: it is the cheapest match to code.
        if (rep1 != 0 and ip >= rep1 and @as(u32, @truncate(rd64(data, ip - rep1))) == @as(u32, @truncate(v))) {
            c = ip - rep1;
            found = true;
        } else if (cand != 0) {
            const cc = cand - 1;
            if (ip - cc <= max_dist and @as(u32, @truncate(rd64(data, cc))) == @as(u32, @truncate(v)) and data[cc + 4] == data[ip + 4]) {
                c = cc;
                found = true;
            }
        }
        if (!found) {
            ip += 1 + ((ip - anchor) >> prm.accel);
            continue;
        }

        var mp = ip;
        // extend backward into pending literals
        while (mp > anchor and c > 0 and data[mp - 1] == data[c - 1]) {
            mp -= 1;
            c -= 1;
        }
        var len = commonLen(data, c, mp, end);
        var offset: usize = mp - c;
        while (true) {
            // Literal run: 16-byte copies; the buffer has slack past BLOCK_MAX.
            const run = mp - anchor;
            var k: usize = 0;
            while (k < run) : (k += 16) {
                if (anchor + k + 16 <= data.len) {
                    lt[nlit + k ..][0..16].* = data[anchor + k ..][0..16].*;
                } else {
                    @memcpy(lt[nlit + k .. nlit + run], data[anchor + k .. anchor + run]);
                    break;
                }
            }
            nlit += run;
            sq[nseq] = .{ .ll = @intCast(run), .ml = @intCast(len), .off = @intCast(offset) };
            nseq += 1;
            if (offset != rep1) {
                rep2 = rep1;
                rep1 = offset;
            }
            const mend = mp + len;
            anchor = mend;
            ip = mend;
            if (ip + 16 > end) break;
            // index a couple of interior positions
            if (len > 4) {
                tbl[hash5(rd64(data, mp + 1), log)] = @intCast(mp + 2);
                tbl[hash5(rd64(data, mend - 2), log)] = @intCast(mend - 1);
            }
            // A repeat of the previous offset right after a match costs almost nothing.
            if (rep2 != 0 and ip >= rep2 and
                @as(u32, @truncate(rd64(data, ip))) == @as(u32, @truncate(rd64(data, ip - rep2))))
            {
                len = commonLen(data, ip - rep2, ip, end);
                mp = ip;
                offset = rep2;
                const t = rep1;
                rep1 = rep2;
                rep2 = t;
                continue;
            }
            break;
        }
    }
    @memcpy(lt[nlit .. nlit + (end - anchor)], data[anchor..end]);
    nlit += end - anchor;
    seqs.items.len = nseq;
    lits.items.len = nlit;
}

const DF_LONG_LOG = 17;
const DF_SHORT_LOG = 16;

inline fn hash8(v: u64, log: u6) usize {
    return @intCast((v *% 0x9E3779B185EBCA87) >> @intCast(64 - @as(u7, log)));
}

/// Double-hash parser: an 8-byte-keyed table finds long matches, a 5-byte-keyed
/// table finds short ones, and the previous two offsets are probed first and
/// again right after every match.
fn parseDfast(
    prm: Params,
    tbl: []u32,
    data: []const u8,
    start: usize,
    end: usize,
    rep_in: *const [3]u32,
    seqs: *std.ArrayList(Seq),
    lits: *std.ArrayList(u8),
) !void {
    const long_log = prm.long_log;
    const short_log = prm.short_log;
    seqs.clearRetainingCapacity();
    lits.clearRetainingCapacity();
    try seqs.ensureTotalCapacity((end - start) / 4 + 2);
    try lits.ensureTotalCapacity((end - start) + 64);
    const sq: [*]Seq = seqs.items.ptr;
    const lt: [*]u8 = lits.items.ptr;
    var nseq: usize = 0;
    var nlit: usize = 0;

    const tl = tbl[0 .. @as(usize, 1) << long_log];
    const ts = tbl[@as(usize, 1) << long_log ..][0 .. @as(usize, 1) << short_log];
    const max_dist: usize = @as(usize, 1) << WINDOW_LOG;

    var rep1: usize = rep_in[0];
    var rep2: usize = rep_in[1];
    var ip = start;
    var anchor = start;
    if (ip == 0) ip = 1;

    while (ip + 16 <= end) {
        const v = rd64(data, ip);
        const hl = hash8(v, long_log);
        const hs = hash5(v, short_log);
        const cl: usize = tl[hl];
        const cs: usize = ts[hs];
        tl[hl] = @intCast(ip + 1);
        ts[hs] = @intCast(ip + 1);

        var mp: usize = ip; // match start in the input
        var mc: usize = 0; // match start in the history
        var found = false;

        // Repeat offset at ip + 1.
        if (rep1 != 0 and ip + 1 >= rep1 and
            @as(u32, @truncate(rd64(data, ip + 1))) == @as(u32, @truncate(rd64(data, ip + 1 - rep1))))
        {
            mp = ip + 1;
            mc = mp - rep1;
            found = true;
        } else if (cl != 0 and ip - (cl - 1) <= max_dist and rd64(data, cl - 1) == v) {
            mc = cl - 1;
            found = true;
        } else if (cs != 0 and ip - (cs - 1) <= max_dist and
            @as(u32, @truncate(rd64(data, cs - 1))) == @as(u32, @truncate(v)))
        {
            mc = cs - 1;
            found = true;
            // A long match one byte later usually beats this short one.
            const v1 = rd64(data, ip + 1);
            const h3 = hash8(v1, long_log);
            const c3: usize = tl[h3];
            tl[h3] = @intCast(ip + 2);
            if (c3 != 0 and ip + 1 - (c3 - 1) <= max_dist and rd64(data, c3 - 1) == v1) {
                mp = ip + 1;
                mc = c3 - 1;
            }
        }
        if (!found) {
            ip += 1 + ((ip - anchor) >> 8);
            continue;
        }

        // Extend backward over pending literals, then forward.
        while (mp > anchor and mc > 0 and data[mp - 1] == data[mc - 1]) {
            mp -= 1;
            mc -= 1;
        }
        var len = commonLen(data, mc, mp, end);
        if (len < 4) { // the backward step cannot shrink a verified match
            ip += 1;
            continue;
        }
        var offset: usize = mp - mc;

        // Emit, then keep chaining zero-literal repeat matches.
        while (true) {
            const run = mp - anchor;
            var k: usize = 0;
            while (k < run) : (k += 16) {
                if (anchor + k + 16 <= data.len) {
                    lt[nlit + k ..][0..16].* = data[anchor + k ..][0..16].*;
                } else {
                    @memcpy(lt[nlit + k .. nlit + run], data[anchor + k .. anchor + run]);
                    break;
                }
            }
            nlit += run;
            sq[nseq] = .{ .ll = @intCast(run), .ml = @intCast(len), .off = @intCast(offset) };
            nseq += 1;
            if (offset != rep1) {
                rep2 = rep1;
                rep1 = offset;
            }
            const mend = mp + len;
            anchor = mend;
            ip = mend;
            if (ip + 16 > end) break;
            // Index a couple of positions inside the match.
            const p2i = mp + 2;
            const vi = rd64(data, p2i);
            tl[hash8(vi, long_log)] = @intCast(p2i + 1);
            ts[hash5(vi, short_log)] = @intCast(p2i + 1);
            const ie = mend - 2;
            const ve = rd64(data, ie);
            tl[hash8(ve, long_log)] = @intCast(ie + 1);
            ts[hash5(ve, short_log)] = @intCast(ie + 1);
            // Immediate repeat of the second-to-last offset.
            if (rep2 != 0 and ip >= rep2 and
                @as(u32, @truncate(rd64(data, ip))) == @as(u32, @truncate(rd64(data, ip - rep2))))
            {
                len = commonLen(data, ip - rep2, ip, end);
                mp = ip;
                offset = rep2;
                const t = rep1;
                rep1 = rep2;
                rep2 = t;
                continue;
            }
            break;
        }
    }
    @memcpy(lt[nlit .. nlit + (end - anchor)], data[anchor..end]);
    nlit += end - anchor;
    seqs.items.len = nseq;
    lits.items.len = nlit;
}

inline fn commonLen(data: []const u8, a: usize, b: usize, end: usize) usize {
    var i: usize = 0;
    const limit = end - b;
    while (i + 8 <= limit) : (i += 8) {
        const x = rd64(data, a + i) ^ rd64(data, b + i);
        if (x != 0) return i + (@ctz(x) >> 3);
    }
    while (i < limit and data[a + i] == data[b + i]) : (i += 1) {}
    return i;
}

/// Greedy-with-one-step-lazy LZ77 parse of `src[start..end]`.
fn parse(
    prm: Params,
    mf: *mfmod.MatchFinder,
    data: []const u8,
    start: usize,
    end: usize,
    seqs: *std.ArrayList(Seq),
    lits: *std.ArrayList(u8),
) !void {
    seqs.clearRetainingCapacity();
    lits.clearRetainingCapacity();
    var p = start;
    var anchor = start;
    while (p + 4 <= end) {
        var m = mf.find(data, p) orelse {
            p += 1 + ((p - anchor) >> 6);
            continue;
        };
        if (p + 1 + 4 <= end) {
            if (mf.find(data, p + 1)) |m2| {
                if (m2.len > m.len + 1) {
                    p += 1;
                    m = m2;
                }
            }
        }
        try lits.appendSlice(data[anchor..p]);
        try seqs.append(.{ .ll = @intCast(p - anchor), .ml = m.len, .off = m.dist });
        const mend = p + m.len;
        // Index inside the match; long matches are indexed sparsely.
        var q = p + 2;
        const dense_end = @min(mend, q + prm.inner_dense);
        while (q < dense_end) : (q += 1) mf.insert(data, q);
        if (mend > dense_end + 16) q = mend - 16;
        while (q < mend) : (q += 1) mf.insert(data, q);
        p = mend;
        anchor = p;
    }
    try lits.appendSlice(data[anchor..end]);
}

// ---------------------------------------------------------------------------
// Block body
// ---------------------------------------------------------------------------

fn encodeCompressed(
    allocator: std.mem.Allocator,
    prm: Params,
    seqs: []const Seq,
    lits: []const u8,
    rep: *[3]u32,
    out: *std.ArrayList(u8),
) Error!bool {
    try writeLiterals(allocator, lits, out);
    return writeSequences(allocator, prm, seqs, rep, out);
}

fn writeLiterals(allocator: std.mem.Allocator, lits: []const u8, out: *std.ArrayList(u8)) Error!void {
    const n = lits.len;

    if (n >= 32) {
        // RLE literals.
        if (std.mem.allEqual(u8, lits, lits[0])) {
            try writeRawHeader(out, 1, n);
            try out.append(lits[0]);
            return;
        }
        if (try writeHuffmanLiterals(allocator, lits, out)) return;
    }
    try writeRawHeader(out, 0, n);
    try out.appendSlice(lits);
}

fn writeRawHeader(out: *std.ArrayList(u8), ltype: u8, n: usize) !void {
    if (n < 32) {
        try out.append(ltype | (@as(u8, @intCast(n)) << 3));
    } else if (n < 4096) {
        const v: u16 = @intCast(ltype | (1 << 2) | (n << 4));
        try out.appendSlice(&std.mem.toBytes(v));
    } else {
        const v: u32 = @intCast(@as(usize, ltype) | (3 << 2) | (n << 4));
        try out.appendSlice(std.mem.toBytes(v)[0..3]);
    }
}

fn writeHuffmanLiterals(allocator: std.mem.Allocator, lits: []const u8, out: *std.ArrayList(u8)) Error!bool {
    const n = lits.len;
    // Fast path: skip Huffman trial when literals are small (< 256 bytes) to avoid table building overhead
    if (n < 256) return false;
    var freq: [256]u32 = .{0} ** 256;
    for (lits) |b| freq[b] += 1;
    const enc = huf.build(&freq) orelse return false;

    var tbl: [256]u8 = undefined;
    const tlen = huf.writeTable(&enc, &tbl) orelse return false;
    const est = huf.estimateSize(&enc, &freq);
    const raw_cost = n + (if (n < 4096) @as(usize, 2) else 3);
    if (tlen + est + 10 >= raw_cost) return false;

    const single = n < 1024;
    const nstreams: usize = if (single) 1 else 4;
    const seg = if (single) n else (n + 3) / 4;

    const cap = (seg * 11) / 8 + 16;
    var buf_stack: [4096]u8 = undefined;
    const buf = if (cap * nstreams <= buf_stack.len) buf_stack[0 .. cap * nstreams] else try allocator.alloc(u8, cap * nstreams);
    defer if (cap * nstreams > buf_stack.len) allocator.free(buf);
    var sizes: [4]usize = .{0} ** 4;
    var total: usize = 0;
    for (0..nstreams) |i| {
        const s = i * seg;
        const e = if (i == nstreams - 1) n else s + seg;
        sizes[i] = huf.encodeStream(&enc, lits[s..e], buf[i * cap .. (i + 1) * cap]) catch return false;
        total += sizes[i];
    }
    const comp = tlen + total + (if (single) @as(usize, 0) else 6);
    if (comp + 5 >= raw_cost) return false;

    // Header.
    var hdr_len: usize = undefined;
    var sf: u32 = undefined;
    var bits: u5 = undefined;
    if (single) {
        if (comp >= 1024) return false;
        sf = 0;
        hdr_len = 3;
        bits = 10;
    } else if (n < 16384 and comp < 16384) {
        sf = 2;
        hdr_len = 4;
        bits = 14;
    } else {
        if (comp >= (1 << 18)) return false;
        sf = 3;
        hdr_len = 5;
        bits = 18;
    }
    const v: u64 = 2 | (@as(u64, sf) << 2) | (@as(u64, n) << 4) | (@as(u64, comp) << (4 + @as(u6, bits)));
    try out.appendSlice(std.mem.toBytes(v)[0..hdr_len]);
    try out.appendSlice(tbl[0..tlen]);
    if (!single) {
        for (sizes[0..3]) |s| try out.appendSlice(&std.mem.toBytes(@as(u16, @intCast(s))));
    }
    for (0..nstreams) |i| try out.appendSlice(buf[i * cap .. i * cap + sizes[i]]);
    return true;
}

// ---------------------------------------------------------------------------
// Sequences
// ---------------------------------------------------------------------------

inline fn floorLog2(v: u32) u8 {
    return @intCast(31 - @clz(v));
}

fn linearLL(ll: u32) u8 {
    var k: usize = 35;
    while (dec.LL_BASE[k] > ll) k -= 1;
    return @intCast(k);
}

fn linearML(ml: u32) u8 {
    var k: usize = 52;
    while (dec.ML_BASE[k] > ml) k -= 1;
    return @intCast(k);
}

const ll_code_small = blk: {
    @setEvalBranchQuota(100000);
    var t: [64]u8 = undefined;
    for (&t, 0..) |*c, i| c.* = linearLL(i);
    break :blk t;
};

const ml_code_small = blk: {
    @setEvalBranchQuota(100000);
    var t: [128]u8 = undefined;
    for (&t, 0..) |*c, i| c.* = linearML(i + 3);
    break :blk t;
};

inline fn llCode(ll: u32) u8 {
    if (ll < 64) return ll_code_small[ll];
    return floorLog2(ll) + 19;
}

inline fn mlCode(ml: u32) u8 {
    const m = ml - 3;
    if (m < 128) return ml_code_small[m];
    return floorLog2(m) + 36;
}

/// Map a real offset onto Zstd's offset value, updating repeat history.
fn offsetValue(rep: *[3]u32, off: u32, ll: u32) u32 {
    var idx: ?usize = null;
    if (ll > 0) {
        if (off == rep[0]) idx = 0 else if (off == rep[1]) idx = 1 else if (off == rep[2]) idx = 2;
    } else {
        if (off == rep[1]) idx = 1 else if (off == rep[2]) idx = 2 else if (rep[0] > 1 and off == rep[0] - 1) idx = 3;
    }
    if (idx) |i| {
        const val: u32 = @intCast(i + 1 - @intFromBool(ll == 0));
        if (i != 0) {
            if (i >= 2) rep[2] = rep[1];
            rep[1] = rep[0];
            rep[0] = off;
        }
        return val;
    }
    rep[2] = rep[1];
    rep[1] = rep[0];
    rep[0] = off;
    return off + 3;
}

const Choice = struct {
    mode: u2,
    ct: fse.CTable,
    rle_sym: u8 = 0,
    hdr: [128]u8 = undefined,
    hlen: usize = 0,
};

fn chooseTable(
    predefined_only: bool,
    counts: []const u32,
    nseq: usize,
    def_norm: []const i16,
    def_log: u8,
    max_log: u8,
) Choice {
    var present: u32 = 0;
    var only: u8 = 0;
    for (counts, 0..) |c, s| {
        if (c != 0) {
            present += 1;
            only = @intCast(s);
        }
    }
    if (present == 1) {
        return .{ .mode = 1, .ct = fse.CTable.rleTable(), .rle_sym = only };
    }

    const pre_cost = fse.costBits(counts, def_norm, def_log);
    if (predefined_only and pre_cost != null) {
        return .{ .mode = 0, .ct = fse.CTable.build(def_norm, def_log) };
    }

    // Custom table.
    var log: u8 = @min(max_log, @max(5, floorLog2(@intCast(nseq)) + 0));
    while ((@as(u32, 1) << @intCast(log)) < present and log < max_log) log += 1;
    var norm: [64]i16 = .{0} ** 64;
    const nsym = fse.normalize(counts, nseq, log, &norm);
    var ch = Choice{ .mode = 2, .ct = undefined };
    const hlen = fse.writeNCount(&ch.hdr, norm[0..nsym], nsym, log) catch 0;
    const cust_cost: ?f64 = if (hlen == 0) null else if (fse.costBits(counts, norm[0..nsym], log)) |c| c + @as(f64, @floatFromInt(hlen * 8)) else null;

    if (pre_cost != null and (cust_cost == null or pre_cost.? <= cust_cost.?)) {
        return .{ .mode = 0, .ct = fse.CTable.build(def_norm, def_log) };
    }
    ch.ct = fse.CTable.build(norm[0..nsym], log);
    ch.hlen = hlen;
    return ch;
}

fn writeSequences(
    allocator: std.mem.Allocator,
    prm: Params,
    seqs: []const Seq,
    rep: *[3]u32,
    out: *std.ArrayList(u8),
) Error!bool {
    const nseq = seqs.len;
    if (nseq == 0) {
        try out.append(0);
        return true;
    }
    if (nseq < 128) {
        try out.append(@intCast(nseq));
    } else if (nseq < 0x7F00) {
        try out.append(@intCast((nseq >> 8) + 128));
        try out.append(@truncate(nseq));
    } else {
        try out.append(255);
        try out.appendSlice(&std.mem.toBytes(@as(u16, @intCast(nseq - 0x7F00))));
    }

    const coded = try allocator.alloc(Coded, nseq);
    defer allocator.free(coded);
    var llc: [36]u32 = .{0} ** 36;
    var ofc: [32]u32 = .{0} ** 32;
    var mlc: [53]u32 = .{0} ** 53;
    for (seqs, 0..) |s, i| {
        const ov = offsetValue(rep, s.off, s.ll);
        const oc = floorLog2(ov);
        const lc = llCode(s.ll);
        const mc = mlCode(s.ml);
        coded[i] = .{
            .llc = lc,
            .mlc = mc,
            .ofc = oc,
            .llx = s.ll - dec.LL_BASE[lc],
            .mlx = s.ml - dec.ML_BASE[mc],
            .ofx = ov - (@as(u32, 1) << @intCast(oc)),
        };
        llc[lc] += 1;
        ofc[oc] += 1;
        mlc[mc] += 1;
    }

    const ll_t = chooseTable(prm.predefined_only, &llc, nseq, &dec.LL_DEFAULT, dec.LL_DEFAULT_LOG, 9);
    const of_t = chooseTable(prm.predefined_only, &ofc, nseq, &dec.OF_DEFAULT, dec.OF_DEFAULT_LOG, 8);
    const ml_t = chooseTable(prm.predefined_only, &mlc, nseq, &dec.ML_DEFAULT, dec.ML_DEFAULT_LOG, 9);

    try out.append((@as(u8, ll_t.mode) << 6) | (@as(u8, of_t.mode) << 4) | (@as(u8, ml_t.mode) << 2));
    inline for (.{ ll_t, of_t, ml_t }) |t| {
        switch (t.mode) {
            1 => try out.append(t.rle_sym),
            2 => try out.appendSlice(t.hdr[0..t.hlen]),
            else => {},
        }
    }

    const cap = nseq * 16 + 64;
    const buf = try allocator.alloc(u8, cap);
    defer allocator.free(buf);
    const n = encodeSeqStream(buf, coded, &ll_t.ct, &of_t.ct, &ml_t.ct) orelse return false;
    try out.appendSlice(buf[0..n]);
    return true;
}

/// Backward FSE sequence stream. Bits are gathered in a register and flushed
/// with two unaligned 8-byte stores per sequence (<= 56 bits between flushes).
fn encodeSeqStream(
    buf: []u8,
    coded: []const Coded,
    ll_ct: *const fse.CTable,
    of_ct: *const fse.CTable,
    ml_ct: *const fse.CTable,
) ?usize {
    const nseq = coded.len;
    var acc: u64 = 0;
    var nb: u6 = 0;
    var wlen: usize = 0;

    const Add = struct {
        inline fn add(a: *u64, n_: *u6, v: u64, k: u6) void {
            a.* |= (v & ((@as(u64, 1) << k) -% 1)) << n_.*;
            n_.* += k;
        }
        inline fn flush(b: []u8, a: *u64, n_: *u6, l: *usize) void {
            std.mem.writeInt(u64, b[l.*..][0..8], a.*, .little);
            const by: u6 = n_.* >> 3;
            l.* += by;
            a.* >>= by * 8;
            n_.* &= 7;
        }
    };

    const last = nseq - 1;
    var ml_s = ml_ct.initState(coded[last].mlc);
    var of_s = of_ct.initState(coded[last].ofc);
    var ll_s = ll_ct.initState(coded[last].llc);
    Add.add(&acc, &nb, coded[last].llx, @intCast(dec.LL_BITS[coded[last].llc]));
    Add.add(&acc, &nb, coded[last].mlx, @intCast(dec.ML_BITS[coded[last].mlc]));
    Add.flush(buf, &acc, &nb, &wlen);
    Add.add(&acc, &nb, coded[last].ofx, @intCast(coded[last].ofc));

    var i = last;
    while (i > 0) {
        i -= 1;
        const c = coded[i];
        // State transitions (<= 26 bits) plus the literal-length extra (<= 16).
        if (!of_ct.is_rle) {
            const tt = of_ct.tt[c.ofc];
            const k: u32 = (of_s + tt.delta_nb) >> 16;
            Add.add(&acc, &nb, of_s, @intCast(k));
            of_s = of_ct.state_table[@intCast(@as(i32, @intCast(of_s >> @intCast(k))) + tt.delta_find)];
        }
        if (!ml_ct.is_rle) {
            const tt = ml_ct.tt[c.mlc];
            const k: u32 = (ml_s + tt.delta_nb) >> 16;
            Add.add(&acc, &nb, ml_s, @intCast(k));
            ml_s = ml_ct.state_table[@intCast(@as(i32, @intCast(ml_s >> @intCast(k))) + tt.delta_find)];
        }
        if (!ll_ct.is_rle) {
            const tt = ll_ct.tt[c.llc];
            const k: u32 = (ll_s + tt.delta_nb) >> 16;
            Add.add(&acc, &nb, ll_s, @intCast(k));
            ll_s = ll_ct.state_table[@intCast(@as(i32, @intCast(ll_s >> @intCast(k))) + tt.delta_find)];
        }
        Add.add(&acc, &nb, c.llx, @intCast(dec.LL_BITS[c.llc]));
        Add.flush(buf, &acc, &nb, &wlen);
        // Match-length (<= 16) and offset (<= 31) extras.
        Add.add(&acc, &nb, c.mlx, @intCast(dec.ML_BITS[c.mlc]));
        Add.add(&acc, &nb, c.ofx, @intCast(c.ofc));
        Add.flush(buf, &acc, &nb, &wlen);
        if (wlen + 16 > buf.len) return null;
    }
    if (!ml_ct.is_rle) Add.add(&acc, &nb, ml_s, @intCast(ml_ct.log));
    if (!of_ct.is_rle) Add.add(&acc, &nb, of_s, @intCast(of_ct.log));
    if (!ll_ct.is_rle) Add.add(&acc, &nb, ll_s, @intCast(ll_ct.log));
    Add.add(&acc, &nb, 1, 1); // sentinel
    Add.flush(buf, &acc, &nb, &wlen);
    if (nb > 0) wlen += 1;
    return wlen;
}

test "round trip text" {
    const a = std.testing.allocator;
    const text = "the quick brown fox jumps over the lazy dog. " ** 200;
    const z = try compress(a, text);
    defer a.free(z);
    try std.testing.expect(z.len < text.len / 4);
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
            const words = [_][]const u8{ "alpha ", "beta ", "gamma ", "delta\n", "epsilon ", "zeta, ", "eta; " };
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
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rng = prng.random();
    const sizes = [_]usize{ 0, 1, 3, 31, 32, 100, 1023, 1024, 5000, 70000, 131071, 131072, 131073, 400000 };
    for (sizes) |n| {
        for (0..4) |kind| {
            const data = try genData(a, rng, n, @intCast(kind));
            defer a.free(data);
            for ([_]i32{ 1, 2, 3, 5 }) |lvl| {
                const z = try compressLevel(a, data, lvl);
                defer a.free(z);
                const d = try dec.decompress(a, z);
                defer a.free(d);
                try std.testing.expectEqualSlices(u8, data, d);
            }
        }
    }
}

test "corrupt input never panics" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xBADF00D);
    const rng = prng.random();
    const data = try genData(a, rng, 60000, 2);
    defer a.free(data);
    const z = try compress(a, data);
    defer a.free(z);
    const m = try a.dupe(u8, z);
    defer a.free(m);
    for (0..300) |_| {
        @memcpy(m, z);
        const hits = rng.uintLessThan(usize, 4) + 1;
        for (0..hits) |_| m[rng.uintLessThan(usize, m.len)] = rng.int(u8);
        if (dec.decompress(a, m)) |d| a.free(d) else |_| {}
        // truncation
        const cut = rng.uintLessThan(usize, m.len);
        if (dec.decompress(a, m[0..cut])) |d| a.free(d) else |_| {}
    }
}

test "length code shortcuts match the table search" {
    var v: u32 = 0;
    // Block size caps literal runs below 2^17 and matches at 2^17.
    while (v < 131072) : (v += 1) {
        try std.testing.expectEqual(linearLL(v), llCode(v));
        if (v >= 3) try std.testing.expectEqual(linearML(v), mlCode(v));
    }
    try std.testing.expectEqual(linearML(131072), mlCode(131072));
}

test "multi-threaded frames round trip and match the single-frame result" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x3317);
    const rng = prng.random();
    const data = try genData(a, rng, 700000, 2);
    defer a.free(data);
    const z = try compressMt(a, data, 3, 4, 100000);
    defer a.free(z);
    const d1 = try dec.decompress(a, z);
    defer a.free(d1);
    try std.testing.expectEqualSlices(u8, data, d1);
    const d4 = try dec.decompressMt(a, z, 4);
    defer a.free(d4);
    try std.testing.expectEqualSlices(u8, data, d4);
}

test "dictionary compression round trip" {
    const a = std.testing.allocator;
    const dict_text = "The quick brown fox jumps over the lazy dog. Repetitive dictionary vocabulary and idioms.";
    const samples = [_][]const u8{
        "The quick brown fox went to sleep.",
        "A lazy dog barked at the quick brown fox.",
        "Repetitive dictionary phrases make compression much better on small inputs.",
    };

    for (samples) |src| {
        for ([_]i32{ 1, 2, 3, 5 }) |lvl| {
            const z = try compressDictLevel(a, src, dict_text, lvl);
            defer a.free(z);
            const dec_data = try dec.decompressDict(a, z, dict_text);
            defer a.free(dec_data);
            try std.testing.expectEqualSlices(u8, src, dec_data);
        }
    }
}
