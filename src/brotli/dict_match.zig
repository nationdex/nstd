//! Static-dictionary matcher for the Brotli encoder (RFC 7932 §8, App. A/B).
//!
//! Finds the longest piece of upcoming text that equals
//! `prefix + T(word) + suffix` for a dictionary word and one of the 121
//! transforms. Only transforms whose prefix is empty or a single space are
//! searched (they cover the overwhelming majority of useful references).

const std = @import("std");
const dec = @import("decompress.zig");
const tables = @import("tables.zig");

pub const Hit = struct {
    /// Bytes of input consumed by the transformed word.
    len: usize,
    /// Dictionary word length (the command's copy length).
    copy_len: u32,
    /// `index | (transform_id << ndbits)`.
    word_id: u32,
};

const HASH_BITS = 15;
const MAX_CHAIN = 16;
const BLOOM_BITS = 19;

inline fn bloomIdx(key: u32) usize {
    return @intCast((@as(u64, key) *% 0x9E3779B97F4A7C15) >> (64 - BLOOM_BITS));
}

const Tf = struct { tid: u8, suffix: []const u8 };

/// Transform groups: [prefix_kind (0 = "", 1 = " ")][class (0 identity / omit-last,
/// 1 ferment-first, 2 ferment-all)][omit_last k 0..9].
const Groups = [2][3][10][]Tf;

pub const Matcher = struct {
    head: []u32,
    next: []u32,
    e_len: []u8,
    e_idx: []u16,
    /// First four bytes of each word, so chain walks never touch the dictionary.
    e_key: []u32,
    /// One bit per hashed 4-byte word prefix: rejects most non-word text cheaply.
    bloom: []u64,
    groups_store: []Tf,
    groups: Groups,

    pub fn init(a: std.mem.Allocator) !Matcher {
        var n: usize = 0;
        for (4..25) |l| n += @as(usize, 1) << @intCast(tables.ndbits[l]);
        const head = try a.alloc(u32, 1 << HASH_BITS);
        errdefer a.free(head);
        @memset(head, 0xFFFFFFFF);
        const next = try a.alloc(u32, n);
        errdefer a.free(next);
        const e_len = try a.alloc(u8, n);
        errdefer a.free(e_len);
        const e_idx = try a.alloc(u16, n);
        errdefer a.free(e_idx);
        const e_key = try a.alloc(u32, n);
        errdefer a.free(e_key);
        const bloom = try a.alloc(u64, (1 << BLOOM_BITS) / 64);
        errdefer a.free(bloom);
        @memset(bloom, 0);

        var e: usize = 0;
        for (4..25) |l| {
            const nw: usize = @as(usize, 1) << @intCast(tables.ndbits[l]);
            for (0..nw) |i| {
                const off = dec.dict_offset[l] + i * l;
                const h = hash4(dec.dictionary[off..][0..4]);
                const key = std.mem.readInt(u32, dec.dictionary[off..][0..4], .little);
                e_key[e] = key;
                const bi = bloomIdx(key);
                bloom[bi >> 6] |= @as(u64, 1) << @intCast(bi & 63);
                e_len[e] = @intCast(l);
                e_idx[e] = @intCast(i);
                next[e] = head[h];
                head[h] = @intCast(e);
                e += 1;
            }
        }

        // Group the usable transforms.
        var counts: [2][3][10]usize = std.mem.zeroes([2][3][10]usize);
        for (tables.transforms) |t| {
            if (groupOf(t)) |g| counts[g[0]][g[1]][g[2]] += 1;
        }
        var total: usize = 0;
        for (counts) |c1| for (c1) |c2| for (c2) |c3| {
            total += c3;
        };
        const store = try a.alloc(Tf, total);
        errdefer a.free(store);
        var groups: Groups = undefined;
        var cursor: usize = 0;
        for (0..2) |pk| for (0..3) |cl| for (0..10) |k| {
            groups[pk][cl][k] = store[cursor .. cursor + counts[pk][cl][k]];
            cursor += counts[pk][cl][k];
        };
        var fill: [2][3][10]usize = std.mem.zeroes([2][3][10]usize);
        for (tables.transforms, 0..) |t, tid| {
            if (groupOf(t)) |g| {
                const f = &fill[g[0]][g[1]][g[2]];
                groups[g[0]][g[1]][g[2]][f.*] = .{ .tid = @intCast(tid), .suffix = t.suffix };
                f.* += 1;
            }
        }
        return .{ .head = head, .next = next, .e_len = e_len, .e_idx = e_idx, .e_key = e_key, .bloom = bloom, .groups_store = store, .groups = groups };
    }

    pub fn deinit(self: *Matcher, a: std.mem.Allocator) void {
        a.free(self.head);
        a.free(self.next);
        a.free(self.e_len);
        a.free(self.e_idx);
        a.free(self.e_key);
        a.free(self.bloom);
        a.free(self.groups_store);
    }

    /// Best dictionary reference starting exactly at `data[p]`.
    pub fn find(self: *const Matcher, data: []const u8, p: usize) ?Hit {
        var best: ?Hit = null;
        const at_word_start = p == 0 or !isAlnum(data[p - 1]);
        if (at_word_start) self.tryAt(data, p, 0, &best);
        if (data[p] == ' ') self.tryAt(data, p + 1, 1, &best);
        return best;
    }

    fn tryAt(self: *const Matcher, data: []const u8, q: usize, pk: usize, best: *?Hit) void {
        if (q + 4 > data.len) return;
        const consumed_prefix: usize = pk;
        var key: [4]u8 = undefined;
        @memcpy(&key, data[q..][0..4]);

        // Variants of the lookup key: as-is, first letter lowered, all lowered.
        var variants: [3][4]u8 = undefined;
        var nvar: usize = 1;
        variants[0] = key;
        if (key[0] >= 'A' and key[0] <= 'Z') {
            var v = key;
            v[0] |= 32;
            variants[nvar] = v;
            nvar += 1;
            var all = key;
            for (&all) |*c| {
                if (c.* >= 'A' and c.* <= 'Z') c.* |= 32;
            }
            if (!std.mem.eql(u8, &all, &v)) {
                variants[nvar] = all;
                nvar += 1;
            }
        }

        for (variants[0..nvar], 0..) |vk, vi| {
            const k32 = std.mem.readInt(u32, &vk, .little);
            const bi = bloomIdx(k32);
            if (self.bloom[bi >> 6] & (@as(u64, 1) << @intCast(bi & 63)) == 0) continue;
            var e = self.head[hash4(&vk)];
            var steps: usize = 0;
            while (e != 0xFFFFFFFF and steps < MAX_CHAIN) : ({
                e = self.next[e];
                steps += 1;
            }) {
                if (self.e_key[e] != k32) continue;
                const l: usize = self.e_len[e];
                const idx: u32 = self.e_idx[e];
                const off = dec.dict_offset[l] + @as(usize, idx) * l;
                const word = dec.dictionary[off .. off + l];
                if (q + 4 > data.len) continue;
                self.tryWord(data, q, consumed_prefix, pk, word, @intCast(l), idx, best, vi);
            }
        }
    }

    fn tryWord(
        self: *const Matcher,
        data: []const u8,
        q: usize,
        prefix_len: usize,
        pk: usize,
        word: []const u8,
        l: u32,
        idx: u32,
        best: *?Hit,
        variant: usize,
    ) void {
        var buf: [24]u8 = undefined;
        const nbits = tables.ndbits[l];
        // The lookup variant fixes the case transform: as-is text can only be an
        // identity/omit-last form, a lowered first letter a FermentFirst form and
        // a fully lowered prefix a FermentAll form.
        const cl = variant;
        {
            @memcpy(buf[0..l], word);
            if (cl > 0) ferment(buf[0..l], cl == 2);
            // How much of the transformed word does the text reproduce?
            const text = data[q..];
            var m: usize = 0;
            const lim = @min(l, text.len);
            while (m < lim and buf[m] == text[m]) m += 1;
            if (m < 4) return;
            const kmax: usize = if (cl == 0) 9 else 0;
            var k: usize = 0;
            while (k <= kmax) : (k += 1) {
                if (l < k + 1) break;
                const body = l - k;
                if (body > m or body < 4) continue;
                for (self.groups[pk][cl][k]) |tf| {
                    const after = q + body;
                    if (after + tf.suffix.len > data.len) continue;
                    if (!std.mem.eql(u8, data[after .. after + tf.suffix.len], tf.suffix)) continue;
                    const consumed = prefix_len + body + tf.suffix.len;
                    if (best.* == null or consumed > best.*.?.len) {
                        best.* = .{
                            .len = consumed,
                            .copy_len = l,
                            .word_id = idx | (@as(u32, tf.tid) << @intCast(nbits)),
                        };
                    }
                }
            }
        }
    }
};

fn groupOf(t: tables.Transform) ?[3]usize {
    var pk: usize = undefined;
    if (t.prefix.len == 0) {
        pk = 0;
    } else if (t.prefix.len == 1 and t.prefix[0] == ' ') {
        pk = 1;
    } else return null;
    return switch (t.kind) {
        0 => .{ pk, 0, 0 },
        1 => .{ pk, 1, 0 },
        2 => .{ pk, 2, 0 },
        12...20 => .{ pk, 0, t.kind - 11 },
        else => null,
    };
}

fn ferment(w: []u8, all: bool) void {
    var i: usize = 0;
    while (i < w.len) {
        const c = w[i];
        if (c < 192) {
            if (c >= 97 and c <= 122) w[i] = c ^ 32;
            i += 1;
        } else if (c < 224) {
            if (i + 1 < w.len) w[i + 1] ^= 32;
            i += 2;
        } else {
            if (i + 2 < w.len) w[i + 2] ^= 5;
            i += 3;
        }
        if (!all) break;
    }
}

fn hash4(b: []const u8) usize {
    const v = std.mem.readInt(u32, b[0..4], .little);
    return @intCast((v *% 0x9E3779B1) >> (32 - HASH_BITS));
}

fn isAlnum(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c >= 128;
}
