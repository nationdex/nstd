//! Zstandard dictionary training.
//!
//! Content selection follows the COVER idea: the corpus is cut into epochs, and
//! in each epoch the fixed-size segment whose d-byte substrings occur in the most
//! samples is chosen; chosen substrings are then discounted so later segments add
//! new material. Entropy tables (literal Huffman, offset / match-length /
//! literal-length FSE) come from parsing the samples against the chosen content.
//! The parameters (segment size k, substring size d) are picked by compressing
//! held-out samples with each candidate dictionary.

const std = @import("std");
const comp = @import("compress.zig");
const dec = @import("decompress.zig");
const dict_mod = @import("dict.zig");
const fse = @import("fse.zig");
const huf = @import("huf.zig");
const checksum = @import("../core/checksum.zig");

pub const Error = comp.Error || error{ SamplesTooSmall, DictTooSmall, Unrepresentable };

pub const DICT_SIZE_MIN = 256;
const FREQ_BITS = 20;
const LEVEL = 3;

pub const Options = struct {
    /// Segment size; 0 = search.
    k: u32 = 0,
    /// Substring size; 0 = search.
    d: u32 = 0,
    /// Force the dictionary id (0 = derived from the content).
    dict_id: u32 = 0,
    /// Fraction of samples used for content selection while searching (rest scores).
    split: f64 = 0.75,
    /// Worker threads for the parameter search (1 = none; never use from the libc-less C ABI).
    threads: usize = 1,
    level: i32 = LEVEL,
};

pub const Chosen = struct { k: u32, d: u32 };

const Cand = struct { k: u32, d: u32, cost: u64 = std.math.maxInt(u64) };

fn scoreCand(allocator: std.mem.Allocator, c: *Cand, train_set: []const []const u8, test_set: []const []const u8, content_cap: usize, dict_cap: usize, level: i32) void {
    const content = selectContent(allocator, train_set, c.k, c.d, content_cap) catch return;
    defer allocator.free(content);
    const dict = assemble(allocator, content, train_set, 0, level) catch return;
    defer allocator.free(dict);
    if (dict.len > dict_cap) return;
    c.cost = evaluate(allocator, dict, test_set, level);
}

fn scoreStride(allocator: std.mem.Allocator, cands: []Cand, first: usize, stride: usize, train_set: []const []const u8, test_set: []const []const u8, content_cap: usize, dict_cap: usize, level: i32) void {
    var i = first;
    while (i < cands.len) : (i += stride) scoreCand(allocator, &cands[i], train_set, test_set, content_cap, dict_cap, level);
}

inline fn hashD(data: []const u8, i: usize, d: usize) usize {
    var v: u64 = undefined;
    if (i + 8 <= data.len) {
        v = std.mem.readInt(u64, data[i..][0..8], .little);
        if (d < 8) v &= (@as(u64, 1) << @intCast(8 * d)) - 1;
    } else {
        v = 0;
        var j: usize = 0;
        while (j < d) : (j += 1) v |= @as(u64, data[i + j]) << @intCast(8 * j);
    }
    return @intCast((v *% 0x9E3779B185EBCA87) >> (64 - FREQ_BITS));
}

/// Pick the most valuable `cap` bytes of the corpus (best content ends up last).
fn selectContent(
    allocator: std.mem.Allocator,
    samples: []const []const u8,
    k_in: usize,
    d: usize,
    cap: usize,
) Error![]u8 {
    var total: usize = 0;
    for (samples) |s| total += s.len;
    const corpus = try allocator.alloc(u8, total);
    defer allocator.free(corpus);
    {
        var off: usize = 0;
        for (samples) |s| {
            @memcpy(corpus[off .. off + s.len], s);
            off += s.len;
        }
    }

    const freq = try allocator.alloc(u32, 1 << FREQ_BITS);
    defer allocator.free(freq);
    @memset(freq, 0);
    const stamp = try allocator.alloc(u32, 1 << FREQ_BITS);
    defer allocator.free(stamp);
    @memset(stamp, 0);
    // A substring counts once per sample that contains it.
    {
        var off: usize = 0;
        for (samples, 1..) |s, id| {
            if (s.len >= d) {
                var i: usize = 0;
                while (i + d <= s.len) : (i += 1) {
                    const h = hashD(corpus, off + i, d);
                    if (stamp[h] != id) {
                        stamp[h] = @intCast(id);
                        freq[h] += 1;
                    }
                }
            }
            off += s.len;
        }
    }

    const k = @min(k_in, @max(cap, d + 1));
    const dict = try allocator.alloc(u8, cap);
    errdefer allocator.free(dict);
    var remaining: usize = cap;
    const nepochs: usize = @max(1, cap / k);
    const epoch_size: usize = @max(k, total / nepochs);
    const active = try allocator.alloc(u16, 1 << FREQ_BITS);
    defer allocator.free(active);
    @memset(active, 0);

    var epoch: usize = 0;
    var dead_epochs: usize = 0;
    while (remaining > 0 and dead_epochs < nepochs) : (epoch += 1) {
        const begin = (epoch % nepochs) * epoch_size;
        if (begin >= total) {
            dead_epochs += 1;
            continue;
        }
        const end = @min(total, begin + epoch_size);
        const seg_len = @min(k, end - begin);
        if (seg_len < d + 1) {
            dead_epochs += 1;
            continue;
        }
        // Slide a window of `seg_len` bytes; its score is the summed frequency of
        // the distinct substrings it holds.
        const nd = seg_len - d + 1; // substrings per window
        var score: u64 = 0;
        var i: usize = begin;
        while (i < begin + nd) : (i += 1) {
            const h = hashD(corpus, i, d);
            if (active[h] == 0) score += freq[h];
            active[h] += 1;
        }
        var best_score: u64 = score;
        var best_start: usize = begin;
        var s0: usize = begin;
        while (s0 + seg_len < end) : (s0 += 1) {
            const out_h = hashD(corpus, s0, d);
            active[out_h] -= 1;
            if (active[out_h] == 0) score -= freq[out_h];
            const in_h = hashD(corpus, s0 + nd, d);
            if (active[in_h] == 0) score += freq[in_h];
            active[in_h] += 1;
            if (score > best_score) {
                best_score = score;
                best_start = s0 + 1;
            }
        }
        // Clear the window state.
        {
            var j: usize = s0;
            while (j < s0 + nd) : (j += 1) active[hashD(corpus, j, d)] = 0;
        }
        if (best_score == 0) {
            dead_epochs += 1;
            continue;
        }
        dead_epochs = 0;
        const take = @min(seg_len, remaining);
        // Later picks go in front, so the first (best) picks sit at the end of
        // the dictionary where their offsets are smallest.
        const dst_end = remaining;
        @memcpy(dict[dst_end - take .. dst_end], corpus[best_start .. best_start + take]);
        remaining -= take;
        var j: usize = best_start;
        while (j + d <= best_start + take) : (j += 1) freq[hashD(corpus, j, d)] = 0;
    }
    const used = cap - remaining;
    std.mem.copyForwards(u8, dict[0..used], dict[remaining..cap]);
    return allocator.realloc(dict, used);
}

fn smooth(counts: []u32) void {
    for (counts) |*c| {
        if (c.* == 0) c.* = 1;
    }
}

/// Serialize a formatted dictionary: header + entropy tables + `content`.
fn assemble(
    allocator: std.mem.Allocator,
    content: []const u8,
    samples: []const []const u8,
    dict_id_opt: u32,
    level: i32,
) Error![]u8 {
    var st = comp.Stats{};
    for (samples) |s| try comp.analyzeSample(allocator, s, content, level, &st);

    // Every symbol stays codable: unseen ones get probability one.
    smooth(&st.lit);
    smooth(&st.ll);
    smooth(&st.ml);
    var offmax: usize = 31 - @as(usize, @clz(@as(u32, @intCast(content.len + (128 << 10)))));
    if (offmax > 30) offmax = 30;
    for (st.of[0 .. offmax + 1]) |*c| {
        if (c.* == 0) c.* = 1;
    }

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.appendSlice(&std.mem.toBytes(@as(u32, dict_mod.ZSTD_MAGIC_DICTIONARY)));
    var id = dict_id_opt;
    if (id == 0) {
        const h = checksum.xxh64(content, 0);
        id = 32768 + @as(u32, @intCast(h % ((@as(u64, 1) << 31) - 32768)));
    }
    try out.appendSlice(&std.mem.toBytes(id));

    // Literals: Huffman table.
    {
        var lit = st.lit;
        var total: u64 = 0;
        for (lit) |c| total += c;
        // Scale so a few huge counts cannot starve the rest of precision.
        while (total > (1 << 28)) {
            total = 0;
            for (&lit) |*c| {
                c.* = (c.* >> 1) + 1;
                total += c.*;
            }
        }
        var enc = huf.build(&lit) orelse return error.Unrepresentable;
        var buf: [300]u8 = undefined;
        var n = huf.writeTable(&enc, &buf);
        if (n == null) {
            // Flatten the distribution until its weight header fits.
            var tries: usize = 0;
            while (n == null and tries < 6) : (tries += 1) {
                for (&lit) |*c| c.* = (c.* >> 3) + 1;
                enc = huf.build(&lit) orelse return error.Unrepresentable;
                n = huf.writeTable(&enc, &buf);
            }
        }
        try out.appendSlice(buf[0 .. n orelse return error.Unrepresentable]);
    }

    // Offset, match-length, literal-length tables (the order the format uses).
    const Spec = struct { counts: []const u32, nsym: usize, log: u8 };
    const specs = [_]Spec{
        .{ .counts = st.of[0 .. offmax + 1], .nsym = offmax + 1, .log = 8 },
        .{ .counts = &st.ml, .nsym = 53, .log = 9 },
        .{ .counts = &st.ll, .nsym = 36, .log = 9 },
    };
    for (specs) |sp| {
        var total: u64 = 0;
        for (sp.counts) |c| total += c;
        var norm: [64]i16 = .{0} ** 64;
        const nsym = fse.normalize(sp.counts, total, sp.log, &norm);
        var hdr: [160]u8 = undefined;
        const hl = fse.writeNCount(&hdr, norm[0..nsym], nsym, sp.log) catch return error.Unrepresentable;
        try out.appendSlice(hdr[0..hl]);
    }

    // Repeat offsets (must not exceed the content size).
    const reps = [3]u32{ 1, 4, 8 };
    for (reps) |r| try out.appendSlice(&std.mem.toBytes(@as(u32, @intCast(@min(@as(usize, r), @max(content.len, 1))))));
    try out.appendSlice(content);
    return out.toOwnedSlice();
}

fn evaluate(allocator: std.mem.Allocator, dict: []const u8, samples: []const []const u8, level: i32) u64 {
    var total: u64 = 0;
    for (samples) |s| {
        const z = comp.compressDictLevel(allocator, s, dict, level) catch return std.math.maxInt(u64);
        total += z.len;
        allocator.free(z);
    }
    return total;
}

/// Train a dictionary of at most `dict_cap` bytes from `samples`.
pub fn train(allocator: std.mem.Allocator, samples: []const []const u8, dict_cap: usize, opt: Options, chosen: ?*Chosen) Error![]u8 {
    if (dict_cap < DICT_SIZE_MIN) return error.DictTooSmall;
    var total: usize = 0;
    var nonempty: usize = 0;
    for (samples) |s| {
        total += s.len;
        nonempty += @intFromBool(s.len > 0);
    }
    if (nonempty == 0 or total < 512) return error.SamplesTooSmall;

    // Room for the header; trimmed afterwards if it turns out smaller or larger.
    const header_guess: usize = 512;
    const content_cap = if (dict_cap > header_guess + 128) dict_cap - header_guess else dict_cap / 2;

    var best_k: u32 = opt.k;
    var best_d: u32 = opt.d;
    if (opt.k == 0 or opt.d == 0) {
        // Search with held-out samples when there are enough of them.
        const ntrain: usize = if (samples.len >= 8) @max(1, @as(usize, @intFromFloat(@as(f64, @floatFromInt(samples.len)) * opt.split))) else samples.len;
        const train_set = samples[0..ntrain];
        const test_set = if (ntrain < samples.len) samples[ntrain..] else samples;
        const ks = [_]u32{ 64, 128, 256, 512, 1024, 2048 };
        const ds = [_]u32{ 6, 8 };
        var cands: [ks.len * ds.len]Cand = undefined;
        var nc: usize = 0;
        for (ks) |k| {
            if (opt.k != 0 and k != opt.k) continue;
            if (k > content_cap) continue;
            for (ds) |dv| {
                if (opt.d != 0 and dv != opt.d) continue;
                cands[nc] = .{ .k = k, .d = dv };
                nc += 1;
            }
        }
        const nthreads = @min(@max(opt.threads, 1), nc);
        if (nthreads <= 1) {
            for (cands[0..nc]) |*c| scoreCand(allocator, c, train_set, test_set, content_cap, dict_cap, opt.level);
        } else {
            var threads: [32]std.Thread = undefined;
            var spawned: usize = 0;
            const nt = @min(nthreads, threads.len);
            for (0..nt) |t| {
                threads[t] = std.Thread.spawn(.{}, scoreStride, .{ allocator, cands[0..nc], t, nt, train_set, test_set, content_cap, dict_cap, opt.level }) catch break;
                spawned += 1;
            }
            // Anything a missing worker would have done runs here.
            if (spawned < nt) {
                var i: usize = spawned;
                while (i < nc) : (i += 1) {
                    if (i % nt >= spawned) scoreCand(allocator, &cands[i], train_set, test_set, content_cap, dict_cap, opt.level);
                }
            }
            for (threads[0..spawned]) |th| th.join();
        }
        var best_cost: u64 = std.math.maxInt(u64);
        for (cands[0..nc]) |c| {
            if (c.cost < best_cost) {
                best_cost = c.cost;
                best_k = c.k;
                best_d = c.d;
            }
        }
        if (best_k == 0) {
            best_k = @intCast(@min(@as(usize, 256), content_cap));
            best_d = 8;
        }
    }
    if (chosen) |c| c.* = .{ .k = best_k, .d = best_d };

    // Final dictionary from every sample.
    var content = try selectContent(allocator, samples, best_k, best_d, content_cap);
    errdefer allocator.free(content);
    var dict = try assemble(allocator, content, samples, opt.dict_id, opt.level);
    // The header size is only known now: shrink the content from the front (the
    // least valuable end) to honour the capacity, or leave the surplus unused.
    if (dict.len > dict_cap) {
        const excess = dict.len - dict_cap;
        if (excess >= content.len) return error.DictTooSmall;
        const trimmed = try allocator.dupe(u8, content[excess..]);
        allocator.free(content);
        content = trimmed;
        allocator.free(dict);
        dict = try assemble(allocator, content, samples, opt.dict_id, opt.level);
        if (dict.len > dict_cap) return error.DictTooSmall;
    }
    allocator.free(content);
    return dict;
}

test "trained dictionary round trips and helps similar data" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7A41);
    const rng = prng.random();
    // Samples share boilerplate and differ in small fields.
    const common = [_][]const u8{
        "{\"user\":\"", "\",\"status\":\"active\",\"roles\":[\"admin\",\"editor\",\"viewer\"],\"settings\":{\"theme\":\"dark\",\"lang\":\"en-US\",\"notifications\":true}}",
    };
    const nsamp = 40;
    var bufs: [nsamp][]u8 = undefined;
    var views: [nsamp][]const u8 = undefined;
    for (0..nsamp) |i| {
        const name_len = 3 + rng.uintLessThan(usize, 8);
        const b = try a.alloc(u8, common[0].len + name_len + common[1].len);
        @memcpy(b[0..common[0].len], common[0]);
        for (b[common[0].len .. common[0].len + name_len]) |*c| c.* = 'a' + rng.uintLessThan(u8, 26);
        @memcpy(b[common[0].len + name_len ..], common[1]);
        bufs[i] = b;
        views[i] = b;
    }
    defer for (bufs) |b| a.free(b);

    var chosen: Chosen = undefined;
    const dict = try train(a, &views, 1024, .{}, &chosen);
    defer a.free(dict);
    try std.testing.expect(dict.len <= 1024);
    try std.testing.expect(dict_mod.Dict.getDictID(dict) >= 32768);
    const parsed = try dict_mod.Dict.init(dict);
    try std.testing.expect(parsed.is_formatted);

    for (views[0..5]) |s| {
        const z = try comp.compressDictLevel(a, s, dict, 3);
        defer a.free(z);
        const plain = try comp.compressLevel(a, s, 3);
        defer a.free(plain);
        try std.testing.expect(z.len < plain.len);
        const back = try dec.decompressDict(a, z, dict);
        defer a.free(back);
        try std.testing.expectEqualSlices(u8, s, back);
    }
}

/// Build a formatted dictionary around caller-chosen `content` (the
/// ZDICT_finalizeDictionary contract): entropy tables are learned from `samples`.
/// When the result would exceed `cap`, the front of the content is dropped.
pub fn finalize(allocator: std.mem.Allocator, content_in: []const u8, samples: []const []const u8, cap: usize, dict_id: u32, level: i32) Error![]u8 {
    if (cap < DICT_SIZE_MIN) return error.DictTooSmall;
    var content = content_in;
    if (content.len > cap) content = content[content.len - cap ..];
    while (true) {
        const d = try assemble(allocator, content, samples, dict_id, if (level == 0) LEVEL else level);
        if (d.len <= cap) return d;
        const excess = d.len - cap;
        allocator.free(d);
        if (excess >= content.len) return error.DictTooSmall;
        content = content[excess..];
    }
}
