//! Brotli decompression (RFC 7932): full decoder with block switching, context
//! modeling, distance parameters, and the static dictionary with all 121
//! transforms.

const std = @import("std");
const prefix = @import("prefix.zig");
const tables = @import("tables.zig");

pub const dictionary = @embedFile("dictionary.bin");

pub const Error = error{
    CorruptData,
    InputTooSmall,
    OutOfMemory,
    Unsupported,
};

const BitReader = prefix.BitReader;
const Tree = prefix.Tree;

pub const INSERT_BASE = [24]u32{ 0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594 };
pub const INSERT_EXTRA = [24]u8{ 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24 };
pub const COPY_BASE = [24]u32{ 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118 };
pub const COPY_EXTRA = [24]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24 };
pub const BLOCK_BASE = [26]u32{ 1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265, 2289, 4337, 8433, 16625 };
pub const BLOCK_EXTRA = [26]u8{ 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24 };
/// Insert/copy range base per 64-symbol cell of the command alphabet.
pub const CELL_INSERT = [11]u8{ 0, 0, 0, 0, 8, 8, 0, 16, 8, 16, 16 };
pub const CELL_COPY = [11]u8{ 0, 8, 0, 8, 0, 8, 16, 0, 16, 8, 16 };

const CmdInfo = struct { ins_base: u32, copy_base: u32, ins_bits: u8, copy_bits: u8 };

/// Insert/copy lengths for every command symbol (RFC 7932 §5), resolved at comptime.
const cmd_table = blk: {
    var t: [704]CmdInfo = undefined;
    for (&t, 0..) |*e, sym| {
        const cell = sym >> 6;
        const ic = CELL_INSERT[cell] + ((sym >> 3) & 7);
        const cc = CELL_COPY[cell] + (sym & 7);
        e.* = .{ .ins_base = INSERT_BASE[ic], .copy_base = COPY_BASE[cc], .ins_bits = INSERT_EXTRA[ic], .copy_bits = COPY_EXTRA[cc] };
    }
    break :blk t;
};

/// Short distance codes 0-15: which ring slot (3 = last) and the delta applied.
const SHORT_SLOT = [16]u8{ 3, 2, 1, 0, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2 };
const SHORT_DELTA = [16]i8{ 0, 0, 0, 0, -1, 1, -2, 2, -3, 3, -1, 1, -2, 2, -3, 3 };

/// Byte offset of the first dictionary word of each length.
pub const dict_offset = blk: {
    var o: [26]u32 = .{0} ** 26;
    var l: usize = 0;
    while (l < 25) : (l += 1) {
        const nw: u32 = if (l < 4) 0 else (@as(u32, 1) << @intCast(tables.ndbits[l]));
        o[l + 1] = o[l] + @as(u32, @intCast(l)) * nw;
    }
    break :blk o;
};

/// Apply transform `id` to dictionary `word`, appending to `out`.
pub fn applyTransform(out: *std.ArrayList(u8), word: []const u8, id: usize) !void {
    const t = tables.transforms[id];
    try out.appendSlice(t.prefix);
    const start = out.items.len;
    switch (t.kind) {
        0 => try out.appendSlice(word),
        1, 2 => {
            try out.appendSlice(word);
            const w = out.items[start..];
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
                if (t.kind == 1) break;
            }
        },
        3...11 => {
            const k: usize = t.kind - 2;
            if (word.len > k) try out.appendSlice(word[k..]);
        },
        12...20 => {
            const k: usize = t.kind - 11;
            if (word.len > k) try out.appendSlice(word[0 .. word.len - k]);
        },
        else => unreachable,
    }
    try out.appendSlice(t.suffix);
}

const BlockCat = struct {
    ntypes: u32 = 1,
    type_tree: ?*Tree = null,
    count_tree: ?*Tree = null,
    cur: u32 = 0,
    prev: u32 = 1,
    left: u32 = 1 << 24,

    inline fn readSwitch(self: *BlockCat, br: *BitReader) Error!void {
        const code = self.type_tree.?.decode(br);
        var nt: u32 = undefined;
        if (code == 0) {
            nt = self.prev;
        } else if (code == 1) {
            nt = self.cur + 1;
            if (nt >= self.ntypes) nt = 0;
        } else {
            nt = code - 2;
        }
        if (nt >= self.ntypes) return error.CorruptData;
        self.prev = self.cur;
        self.cur = nt;
        try self.readCount(br);
    }

    inline fn readCount(self: *BlockCat, br: *BitReader) Error!void {
        const c = self.count_tree.?.decode(br);
        if (c >= 26) return error.CorruptData;
        self.left = BLOCK_BASE[c] + br.read(@intCast(BLOCK_EXTRA[c]));
    }
};

fn readVarLen(br: *BitReader) u32 {
    // 1..256 encoded as in RFC 7932 §9.2.
    if (br.read(1) == 0) return 1;
    const n = br.read(3);
    if (n == 0) return 2;
    return (br.read(@intCast(n)) + (@as(u32, 1) << @intCast(n))) + 1;
}

/// Decode a context map of `size` entries with `ntrees` distinct trees.
fn readContextMap(allocator: std.mem.Allocator, br: *BitReader, size: usize, ntrees: u32, map: []u8) Error!void {
    var rlemax: u32 = 0;
    if (br.read(1) == 1) rlemax = br.read(4) + 1;
    const alpha: usize = ntrees + rlemax;
    var scratch: [272]u8 = undefined;
    const tree = try prefix.readTree(allocator, br, alpha, &scratch);
    defer prefix.freeTree(allocator, tree);

    var i: usize = 0;
    while (i < size) {
        const c = tree.decode(br);
        if (br.eof()) return error.InputTooSmall;
        if (c == 0) {
            map[i] = 0;
            i += 1;
        } else if (c <= rlemax) {
            const run = (@as(usize, 1) << @intCast(c)) + br.read(@intCast(c));
            if (i + run > size) return error.CorruptData;
            @memset(map[i .. i + run], 0);
            i += run;
        } else {
            map[i] = @intCast(c - rlemax);
            i += 1;
        }
    }
    if (br.read(1) == 1) {
        var mtf: [256]u8 = undefined;
        for (&mtf, 0..) |*m, k| m.* = @intCast(k);
        for (map[0..size]) |*v| {
            const idx = v.*;
            const val = mtf[idx];
            v.* = val;
            var j: usize = idx;
            while (j > 0) : (j -= 1) mtf[j] = mtf[j - 1];
            mtf[0] = val;
        }
    }
}

/// Incremental decoder: feed input in arbitrary pieces, then call `process`.
/// Work is resumed at meta-block granularity; a partially received meta-block
/// is re-parsed once more input arrives.
pub const Decoder = struct {
    allocator: std.mem.Allocator,
    input: std.ArrayList(u8),
    /// Bit offset (from `input[0]`) of the next unread bit at the last checkpoint.
    bitpos: usize = 0,
    out: std.ArrayList(u8),
    /// Bytes already discarded from the front of `out`.
    out_base: usize = 0,
    /// Bytes of `out` already handed to the consumer.
    out_taken: usize = 0,
    ring: [4]u32 = .{ 16, 15, 11, 4 }, // [0] = oldest ... [3] = last
    window: usize = 0,
    header_done: bool = false,
    finished: bool = false,
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: std.mem.Allocator) Decoder {
        return .{
            .allocator = allocator,
            .input = std.ArrayList(u8).init(allocator),
            .out = std.ArrayList(u8).init(allocator),
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Decoder) void {
        self.input.deinit();
        self.out.deinit();
        self.arena.deinit();
    }

    pub fn feed(self: *Decoder, bytes: []const u8) Error!void {
        try self.input.appendSlice(bytes);
    }

    /// Output produced but not yet taken.
    pub fn pending(self: *const Decoder) []const u8 {
        return self.out.items[self.out_taken..];
    }

    /// Mark `n` pending bytes as consumed (and reclaim memory when possible).
    pub fn take(self: *Decoder, n: usize) void {
        self.out_taken += n;
        if (self.out_taken > self.window + (1 << 22)) {
            const drop = self.out_taken - self.window;
            self.out.replaceRange(0, drop, &.{}) catch return;
            self.out_base += drop;
            self.out_taken -= drop;
        }
    }

    /// Decode every complete meta-block currently buffered.
    pub fn process(self: *Decoder) Error!void {
        while (!self.finished) {
            var br = BitReader.init(self.input.items);
            br.seekByte(self.bitpos / 8);
            _ = br.read(@intCast(self.bitpos % 8));
            const saved_len = self.out.items.len;
            const saved_ring = self.ring;
            const saved_hdr = self.header_done;

            const r = self.step(&br);
            if (br.bad) return error.CorruptData;
            const incomplete = br.eof() or (if (r) |_| false else |e| e == error.InputTooSmall);
            if (incomplete) {
                self.out.shrinkRetainingCapacity(saved_len);
                self.ring = saved_ring;
                self.header_done = saved_hdr;
                return;
            }
            try r;

            self.bitpos = br.bitsConsumed();
            const drop = self.bitpos / 8;
            if (drop > 0) {
                self.input.replaceRange(0, drop, &.{}) catch {};
                self.bitpos -= drop * 8;
            }
        }
    }

    /// Parse one meta-block (or the stream header).
    fn step(self: *Decoder, br: *BitReader) Error!void {
        if (!self.header_done) {
            var wbits: u32 = 16;
            if (br.read(1) == 1) {
                const n = br.read(3);
                if (n != 0) {
                    wbits = 17 + n;
                } else {
                    const m = br.read(3);
                    if (m == 1) return error.Unsupported; // large-window extension
                    wbits = if (m == 0) 17 else 8 + m;
                }
            }
            if (br.eof()) return error.InputTooSmall;
            self.window = (@as(usize, 1) << @intCast(wbits)) - 16;
            self.header_done = true;
            return;
        }

        _ = self.arena.reset(.retain_capacity);
        const ma = self.arena.allocator();
        const src = self.input.items;

        const is_last = br.read(1) == 1;
        if (is_last and br.read(1) == 1) {
            if (br.eof()) return error.InputTooSmall;
            self.finished = true;
            return;
        }
        const mnib = br.read(2);
        if (mnib == 3) {
            // Metadata block.
            if (br.read(1) != 0) return error.CorruptData;
            const skipbytes = br.read(2);
            var skiplen: usize = 0;
            if (skipbytes > 0) {
                skiplen = br.read(@intCast(skipbytes * 8)) + 1;
            }
            if (!br.alignToByte()) return error.CorruptData;
            if (br.eof()) return error.InputTooSmall;
            const bp = br.bytePos();
            if (bp + skiplen > src.len) return error.InputTooSmall;
            br.seekByte(bp + skiplen);
            if (is_last) self.finished = true;
            return;
        }
        const nibbles: u6 = @intCast(4 + mnib);
        const mlen: usize = @as(usize, br.read(nibbles * 4)) + 1;
        if (br.eof()) return error.InputTooSmall;
        if (nibbles > 4 and (mlen - 1) >> @intCast((nibbles - 1) * 4) == 0) return error.CorruptData;

        if (!is_last and br.read(1) == 1) {
            if (!br.alignToByte()) return error.CorruptData;
            const bp = br.bytePos();
            if (bp + mlen > src.len) return error.InputTooSmall;
            try self.out.appendSlice(src[bp .. bp + mlen]);
            br.seekByte(bp + mlen);
            return;
        }

        const block_end = self.out.items.len + mlen;
        try decodeMetaBlock(self.allocator, ma, br, &self.out, self.out_base, block_end, self.window, &self.ring);
        if (br.eof()) return error.InputTooSmall;
        if (is_last) self.finished = true;
    }
};

/// Decompress a complete Brotli stream.
pub fn decompress(allocator: std.mem.Allocator, src: []const u8) Error![]u8 {
    var d = Decoder.init(allocator);
    defer d.deinit();
    try d.feed(src);
    try d.process();
    if (!d.finished) return error.InputTooSmall;
    return d.out.toOwnedSlice();
}

fn decodeMetaBlock(
    allocator: std.mem.Allocator,
    ma: std.mem.Allocator,
    br: *BitReader,
    out: *std.ArrayList(u8),
    out_base: usize,
    block_end: usize,
    window: usize,
    dist_ring: *[4]u32,
) Error!void {
    var scratch: [1024 + 16 + 2048]u8 = undefined;
    _ = allocator;

    var cats: [3]BlockCat = .{ .{}, .{}, .{} }; // literal, insert&copy, distance
    for (&cats) |*c| {
        c.ntypes = readVarLen(br);
        if (c.ntypes >= 2) {
            c.type_tree = try prefix.readTree(ma, br, c.ntypes + 2, &scratch);
            c.count_tree = try prefix.readTree(ma, br, 26, &scratch);
            try c.readCount(br);
        }
    }
    if (br.eof()) return error.InputTooSmall;

    const npostfix: u32 = br.read(2);
    const ndirect: u32 = br.read(4) << @intCast(npostfix);

    const nbl = cats[0].ntypes;
    const cmodes = try ma.alloc(u8, nbl);
    for (cmodes) |*m| m.* = @intCast(br.read(2));

    // Literal context map.
    const ntrees_l = readVarLen(br);
    const cmap_l = try ma.alloc(u8, 64 * nbl);
    if (ntrees_l >= 2) {
        try readContextMap(ma, br, cmap_l.len, ntrees_l, cmap_l);
    } else @memset(cmap_l, 0);

    // Distance context map.
    const ntrees_d = readVarLen(br);
    const cmap_d = try ma.alloc(u8, 4 * cats[2].ntypes);
    if (ntrees_d >= 2) {
        try readContextMap(ma, br, cmap_d.len, ntrees_d, cmap_d);
    } else @memset(cmap_d, 0);
    if (br.eof()) return error.InputTooSmall;

    // Prefix codes.
    const lit_trees = try ma.alloc(*Tree, ntrees_l);
    for (lit_trees) |*t| t.* = try prefix.readTree(ma, br, 256, &scratch);
    const ic_trees = try ma.alloc(*Tree, cats[1].ntypes);
    for (ic_trees) |*t| t.* = try prefix.readTree(ma, br, 704, &scratch);
    const dist_alpha: usize = 16 + ndirect + (@as(usize, 48) << @intCast(npostfix));
    const dist_scratch = try ma.alloc(u8, dist_alpha);
    const dist_trees = try ma.alloc(*Tree, ntrees_d);
    for (dist_trees) |*t| t.* = try prefix.readTree(ma, br, dist_alpha, dist_scratch);
    if (br.eof()) return error.InputTooSmall;

    const postfix_mask: u32 = (@as(u32, 1) << @intCast(npostfix)) - 1;

    // Reserve the whole meta-block (plus slack for 16-byte wild copies) so the
    // hot loops write through a raw pointer without capacity checks.
    try out.ensureTotalCapacity(block_end + 64);
    var op: usize = out.items.len;

    while (op < block_end) {
        if (br.eof()) return error.InputTooSmall;
        // Command.
        if (cats[1].left == 0) try cats[1].readSwitch(br);
        cats[1].left -= 1;
        const cmd = ic_trees[cats[1].cur].decode(br);
        const ci = cmd_table[cmd];
        var ins_len: usize = ci.ins_base;
        var copy_len: usize = ci.copy_base;
        if (ci.ins_bits + ci.copy_bits <= 32) {
            // One peek covers both extra-bit fields in the common case.
            const v = br.read(@intCast(ci.ins_bits + ci.copy_bits));
            ins_len += v & ((@as(u32, 1) << @intCast(ci.ins_bits)) - 1);
            copy_len += v >> @intCast(ci.ins_bits);
        } else {
            ins_len += br.read(@intCast(ci.ins_bits));
            copy_len += br.read(@intCast(ci.copy_bits));
        }

        if (ins_len > block_end - op) return error.CorruptData;

        // Literals, in runs that stay within one literal block type.
        {
            const base: [*]u8 = out.items.ptr;
            var p1: u8 = if (out_base + op >= 1) base[op - 1] else 0;
            var p2: u8 = if (out_base + op >= 2) base[op - 2] else 0;
            var k: usize = 0;
            while (k < ins_len) {
                if (cats[0].left == 0) try cats[0].readSwitch(br);
                const bt = cats[0].cur;
                const run: usize = @min(ins_len - k, cats[0].left);
                const row = cmap_l[64 * bt ..][0..64];
                const mode = cmodes[bt];
                var j: usize = 0;
                switch (mode) {
                    inline 0, 1, 2, 3 => |m| {
                        while (j < run) : (j += 1) {
                            const ctx: usize = switch (m) {
                                0 => p1 & 0x3f,
                                1 => p1 >> 2,
                                2 => tables.lut0[p1] | tables.lut1[p2],
                                else => (@as(usize, tables.lut2[p1]) << 3) | tables.lut2[p2],
                            };
                            const lit: u8 = @intCast(lit_trees[row[ctx]].decode(br));
                            base[op + j] = lit;
                            p2 = p1;
                            p1 = lit;
                        }
                    },
                    else => unreachable,
                }
                op += run;
                k += run;
                cats[0].left -= @intCast(run);
                if (br.eof()) return error.InputTooSmall;
            }
        }
        if (op >= block_end) break;

        // Distance.
        var dist: usize = undefined;
        var from_ring_zero = false;
        if (cmd < 128) {
            dist = dist_ring[3];
            from_ring_zero = true;
        } else {
            if (cats[2].left == 0) try cats[2].readSwitch(br);
            cats[2].left -= 1;
            const dctx: usize = if (copy_len > 4) 3 else copy_len - 2;
            const dt = dist_trees[cmap_d[4 * cats[2].cur + dctx]];
            const dcode: u32 = dt.decode(br);
            if (dcode < 16) {
                const d: i64 = @as(i64, dist_ring[SHORT_SLOT[dcode]]) + SHORT_DELTA[dcode];
                if (d <= 0) return error.CorruptData;
                dist = @intCast(d);
                from_ring_zero = dcode == 0;
            } else if (dcode < 16 + ndirect) {
                dist = dcode - 15;
            } else if (npostfix == 0 and ndirect == 0) {
                // The common parameter set: no postfix bits, no direct codes.
                const off = dcode - 16;
                const nbits: u32 = 1 + (off >> 1);
                const dextra: u64 = br.read(@intCast(nbits));
                dist = @intCast((((@as(u64, 2) + (off & 1)) << @intCast(nbits)) - 4) + dextra + 1);
            } else {
                const off = dcode - ndirect - 16;
                const nbits: u32 = 1 + (off >> @intCast(npostfix + 1));
                const dextra: u64 = br.read(@intCast(nbits));
                const hcode = off >> @intCast(npostfix);
                const lcode = off & postfix_mask;
                const base: u64 = ((@as(u64, 2) + (hcode & 1)) << @intCast(nbits)) - 4;
                dist = @intCast(((base + dextra) << @intCast(npostfix)) + lcode + ndirect + 1);
            }
        }
        if (br.eof()) return error.InputTooSmall;

        const max_dist = @min(window, out_base + op);
        if (dist <= max_dist) {
            if (!from_ring_zero) {
                dist_ring[0] = dist_ring[1];
                dist_ring[1] = dist_ring[2];
                dist_ring[2] = dist_ring[3];
                dist_ring[3] = @intCast(dist);
            }
            if (copy_len > block_end - op) return error.CorruptData;
            if (dist > op) return error.CorruptData; // would reach before the retained history
            const dst: [*]u8 = out.items.ptr + op;
            const from: [*]const u8 = dst - dist;
            if (dist >= 16) {
                var k: usize = 0;
                while (k < copy_len) : (k += 16) dst[k..][0..16].* = from[k..][0..16].*;
            } else if (dist >= 8) {
                var k: usize = 0;
                while (k < copy_len) : (k += 8) dst[k..][0..8].* = from[k..][0..8].*;
            } else if (dist == 1) {
                @memset(dst[0..copy_len], from[0]);
            } else {
                var k: usize = 0;
                while (k < copy_len) : (k += 1) dst[k] = from[k];
            }
            op += copy_len;
        } else {
            // Static dictionary reference.
            if (copy_len < 4 or copy_len > 24) return error.CorruptData;
            const word_id = dist - (max_dist + 1);
            const nbits = tables.ndbits[copy_len];
            const idx = word_id & ((@as(usize, 1) << @intCast(nbits)) - 1);
            const tid = word_id >> @intCast(nbits);
            if (tid >= tables.transforms.len) return error.CorruptData;
            const off = dict_offset[copy_len] + idx * copy_len;
            const word = dictionary[off .. off + copy_len];
            out.items.len = op;
            try applyTransform(out, word, tid);
            if (out.items.len - op > block_end - op) return error.CorruptData;
            op = out.items.len;
        }
    }
    if (op != block_end) return error.CorruptData;
    out.items.len = op;
}

test "decode trivial uncompressed stream" {
    const a = std.testing.allocator;
    // Empty stream.
    const e = try decompress(a, &[_]u8{6});
    defer a.free(e);
    try std.testing.expectEqual(@as(usize, 0), e.len);
}

// Streams produced by the reference encoder (google/brotli 1.2.0).
const RefVec = struct { plain: []const u8, comp: []const u8 };
const ref_vectors = [_]RefVec{
    // small
    .{ .plain = "\x3c\x68\x74\x6d\x6c\x3e\x3c\x68\x65\x61\x64\x3e\x3c\x74\x69\x74\x6c\x65\x3e\x54\x68\x65\x20\x49\x6e\x74\x65\x72\x6e\x61\x74\x69\x6f\x6e\x61\x6c\x20\x49\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x20\x50\x61\x67\x65\x3c\x2f\x74\x69\x74\x6c\x65\x3e\x3c\x2f\x68\x65\x61\x64\x3e\x3c\x62\x6f\x64\x79\x3e\x54\x68\x69\x73\x20\x69\x73\x20\x69\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x20\x61\x62\x6f\x75\x74\x20\x74\x68\x65\x20\x77\x6f\x72\x6c\x64\x20\x61\x6e\x64\x20\x70\x65\x6f\x70\x6c\x65\x2c\x20\x77\x69\x74\x68\x20\x67\x6f\x76\x65\x72\x6e\x6d\x65\x6e\x74\x20\x65\x64\x75\x63\x61\x74\x69\x6f\x6e\x20\x61\x6e\x64\x20\x62\x75\x73\x69\x6e\x65\x73\x73\x20\x64\x65\x76\x65\x6c\x6f\x70\x6d\x65\x6e\x74\x2e\x20\x57\x65\x6c\x63\x6f\x6d\x65\x20\x74\x6f\x20\x6f\x75\x72\x20\x63\x6f\x6d\x6d\x75\x6e\x69\x74\x79\x21\x3c\x2f\x62\x6f\x64\x79\x3e\x3c\x2f\x68\x74\x6d\x6c\x3e", .comp = "\x13\xd4\x00\x00\x8d\x94\x6e\xde\x44\xf9\x46\x57\xd7\x20\x21\x3e\x72\x20\x2f\x16\x72\x77\x9e\xa4\x65\x75\x13\x41\xdd\x70\x1a\xe5\x48\xa6\x97\x60\x05\x0d\xf5\x90\x06\x77\xfd\x19\x66\xd0\xc9\x30\x81\x7a\x99\x84\x33\x77\x88\xad\x84\xe4\x33\x38\x42\xe3\xad\xbe\xa8\xf4\x5e\x21\x04\x0c\x3b\x78\xe8\x1f\xb3\x0a" },
    // repeat
    .{ .plain = "\x42\x72\x6f\x74\x6c\x69\x20\x73\x74\x61\x74\x69\x63\x20\x64\x69\x63\x74\x69\x6f\x6e\x61\x72\x79\x3a\x20\x74\x68\x65\x20\x71\x75\x69\x63\x6b\x20\x62\x72\x6f\x77\x6e\x20\x66\x6f\x78\x20\x6a\x75\x6d\x70\x73\x20\x6f\x76\x65\x72\x20\x74\x68\x65\x20\x6c\x61\x7a\x79\x20\x64\x6f\x67\x3b\x20\x69\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x2c\x20\x64\x65\x76\x65\x6c\x6f\x70\x6d\x65\x6e\x74\x2c\x20\x63\x6f\x6d\x6d\x75\x6e\x69\x74\x79\x2e\x20\x42\x72\x6f\x74\x6c\x69\x20\x73\x74\x61\x74\x69\x63\x20\x64\x69\x63\x74\x69\x6f\x6e\x61\x72\x79\x3a\x20\x74\x68\x65\x20\x71\x75\x69\x63\x6b\x20\x62\x72\x6f\x77\x6e\x20\x66\x6f\x78\x20\x6a\x75\x6d\x70\x73\x20\x6f\x76\x65\x72\x20\x74\x68\x65\x20\x6c\x61\x7a\x79\x20\x64\x6f\x67\x3b\x20\x69\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x2c\x20\x64\x65\x76\x65\x6c\x6f\x70\x6d\x65\x6e\x74\x2c\x20\x63\x6f\x6d\x6d\x75\x6e\x69\x74\x79\x2e\x20\x42\x72\x6f\x74\x6c\x69\x20\x73\x74\x61\x74\x69\x63\x20\x64\x69\x63\x74\x69\x6f\x6e\x61\x72\x79\x3a\x20\x74\x68\x65\x20\x71\x75\x69\x63\x6b\x20\x62\x72\x6f\x77\x6e\x20\x66\x6f\x78\x20\x6a\x75\x6d\x70\x73\x20\x6f\x76\x65\x72\x20\x74\x68\x65\x20\x6c\x61\x7a\x79\x20\x64\x6f\x67\x3b\x20\x69\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x2c\x20\x64\x65\x76\x65\x6c\x6f\x70\x6d\x65\x6e\x74\x2c\x20\x63\x6f\x6d\x6d\x75\x6e\x69\x74\x79\x2e\x20\x42\x72\x6f\x74\x6c\x69\x20\x73\x74\x61\x74\x69\x63\x20\x64\x69\x63\x74\x69\x6f\x6e\x61\x72\x79\x3a\x20\x74\x68\x65\x20\x71\x75\x69\x63\x6b\x20\x62\x72\x6f\x77\x6e\x20\x66\x6f\x78\x20\x6a\x75\x6d\x70\x73\x20\x6f\x76\x65\x72\x20\x74\x68\x65\x20\x6c\x61\x7a\x79\x20\x64\x6f\x67\x3b\x20\x69\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x2c\x20\x64\x65\x76\x65\x6c\x6f\x70\x6d\x65\x6e\x74\x2c\x20\x63\x6f\x6d\x6d\x75\x6e\x69\x74\x79\x2e\x20", .comp = "\x13\xaf\x01\xe8\x8c\x94\x6e\xe6\x22\x3d\x59\xaa\x2f\x99\x26\x65\x63\x36\x09\x01\x15\xf6\x06\x2d\x39\x70\x08\x9b\xe7\x01\x37\x3f\xd5\x07\xe7\x87\x0d\x38\xa4\x60\x90\x87\x65\x7a\xa4\x4e\x46\x77\x80\x94\xe9\x3f\x52\x9e\x54\xbb\xd0\x4a\x03\xbd\xd2\x1f\xb4\x73\x2e\x12\xc0\xc8\xf6\x7e\x04" },
    // mixed
    .{ .plain = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x20", .comp = "\x13\xef\x03\x00\x64\xc0\x6e\x95\x97\xf5\x92\x5e\x26\xc1\x21\x07\x0e\xdf\x2e\xa1\x47\x20\x11\x6b\x0d\x7e\x13\xb7\x40\x60\x08\x14\x06\x47\x20\xe3\x97\x01\x41\xf8\x27\x17\x40\xa1\x31\x58\x1c\x9e\x40\x24\x91\x29\x54\x1a\x1d\x3d\x03\x23\x13\x33\x0b\x2b\x1b\x3b\x07\x27\x17\x37\x0f\x2f\x1f\xbf\x80\xa0\x90\xb0\x88\xa8\x98\xb8\x84\xa4\x94\xb4\x8c\xac\x9c\xbc\x82\xa2\x92\xb2\x8a\xaa\x9a\xba\x86\xa6\x96\xb6\x8e\xae\x9e\xbe\x81\xa1\x91\xb1\x89\xa9\x99\xb9\x85\xa5\x95\xb5\x8d\xad\x9d\xbd\x83\xa3\x93\xb3\x8b\xab\x9b\xbb\x87\xa7\x97\xb7\x8f\xaf\x9f\x7f\x40\x60\x50\x70\x48\x68\x58\x78\x44\x64\x54\x74\x4c\x6c\x5c\x7c\x42\x62\x52\x72\x4a\x6a\x5a\x7a\x46\x66\x56\x76\x4e\x6e\x5e\x7e\x41\x61\x51\x71\x49\x69\x59\x79\x45\x65\x55\x75\x4d\x6d\x5d\x7d\x43\x63\x53\x73\x4b\x6b\x5b\x7b\x47\x67\x57\x77\x4f\x6f\x5f\xff\xc0\xe0\xd0\xf0\xc8\xe8\xd8\xf8\xc4\xe4\xd4\xf4\xcc\xec\xdc\xfc\xc2\xe2\xd2\xf2\xca\xea\xda\xfa\xc6\xe6\xd6\xf6\xce\xee\xde\xfe\xc1\xe1\xd1\xf1\xc9\xe9\xd9\xf9\xc5\xe5\xd5\xf5\xcd\xed\xdd\xfd\xc3\xe3\xd3\xf3\xcb\xeb\xdb\xfb\xc7\xe7\xd7\xf7\xcf\xef\xdf\x3f\xe8\x03\x4c\x0f\x50\xc3\x3c\xc0\x06" },
};

test "decodes reference-encoder streams" {
    const a = std.testing.allocator;
    for (ref_vectors) |v| {
        const d = try decompress(a, v.comp);
        defer a.free(d);
        try std.testing.expectEqualSlices(u8, v.plain, d);
    }
}

test "corrupt streams never panic" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5EED);
    const rng = prng.random();
    for (ref_vectors) |v| {
        const m = try a.dupe(u8, v.comp);
        defer a.free(m);
        for (0..400) |_| {
            @memcpy(m, v.comp);
            const hits = rng.uintLessThan(usize, 3) + 1;
            for (0..hits) |_| m[rng.uintLessThan(usize, m.len)] ^= @as(u8, 1) << rng.int(u3);
            if (decompress(a, m)) |d| a.free(d) else |_| {}
            const cut = rng.uintLessThan(usize, m.len);
            if (decompress(a, m[0..cut])) |d| a.free(d) else |_| {}
        }
    }
}
