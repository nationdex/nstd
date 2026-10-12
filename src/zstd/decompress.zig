//! Zstandard decompression (RFC 8878).
//!
//! Full block decoder: Raw/RLE/Compressed blocks, Huffman literals (1 and 4
//! streams, treeless reuse), FSE sequences (predefined / RLE / FSE / repeat
//! modes) with repeat-offset handling and content checksum verification.

const std = @import("std");
const frame = @import("frame.zig");
const fse = @import("fse.zig");
const huf = @import("huf.zig");
const dict_mod = @import("dict.zig");
const checksum = @import("../core/checksum.zig");

pub const Error = error{
    CorruptData,
    InputTooSmall,
    OutOfMemory,
    InvalidWindow,
    Unsupported,
    ChecksumMismatch,
};

// ---------------------------------------------------------------------------
// Constant tables (RFC 8878 §3.1.1.3.2.1)
// ---------------------------------------------------------------------------

pub const LL_DEFAULT = [36]i16{ 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1 };
pub const OF_DEFAULT = [29]i16{ 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1 };
pub const ML_DEFAULT = [53]i16{ 1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1 };
pub const LL_DEFAULT_LOG = 6;
pub const OF_DEFAULT_LOG = 5;
pub const ML_DEFAULT_LOG = 6;

pub const LL_BASE = [36]u32{
    0,  1,  2,   3,   4,   5,    6,    7,    8,    9,     10,    11,
    12, 13, 14,  15,  16,  18,   20,   22,   24,   28,    32,    40,
    48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
};
pub const LL_BITS = [36]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  1,  1,
    1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
};
pub const ML_BASE = [53]u32{
    3,  4,   5,   6,   7,    8,    9,    10,   11,    12,    13,    14, 15, 16,
    17, 18,  19,  20,  21,   22,   23,   24,   25,    26,    27,    28, 29, 30,
    31, 32,  33,  34,  35,   37,   39,   41,   43,    47,    51,    59, 67, 83,
    99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539,
};
pub const ML_BITS = [53]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  1,  1,  1,  1,
    2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
};

/// FSE decode entry with the symbol already resolved to its baseline value and
/// number of extra bits, so the hot loop needs a single table load per field.
pub const SeqEntry = struct {
    /// base (bits 0-15) | nb (16-23) | xbits (24-31) | val (32-63), loaded as one word.
    raw: u64,

    pub inline fn pack(b: u16, n: u8, x: u8, v: u32) SeqEntry {
        return .{ .raw = @as(u64, b) | (@as(u64, n) << 16) | (@as(u64, x) << 24) | (@as(u64, v) << 32) };
    }
    pub inline fn base(self: SeqEntry) usize {
        return @as(u16, @truncate(self.raw));
    }
    pub inline fn nb(self: SeqEntry) u6 {
        return @truncate(self.raw >> 16);
    }
    pub inline fn xbits(self: SeqEntry) u6 {
        return @truncate(self.raw >> 24);
    }
    pub inline fn val(self: SeqEntry) u32 {
        return @truncate(self.raw >> 32);
    }
};

pub const SeqTab = struct {
    log: u8,
    e: [1 << fse.MAX_LOG]SeqEntry,

    pub fn from(d: *const fse.DTable, comptime kind: enum { ll, ml, of }) Error!SeqTab {
        var t: SeqTab = undefined;
        t.log = d.log;
        const n = @as(usize, 1) << @intCast(d.log);
        for (d.e[0..n], 0..) |e, i| {
            var xb: u8 = 0;
            var vl: u32 = 0;
            switch (kind) {
                .ll => {
                    if (e.sym >= 36) return error.CorruptData;
                    vl = LL_BASE[e.sym];
                    xb = LL_BITS[e.sym];
                },
                .ml => {
                    if (e.sym >= 53) return error.CorruptData;
                    vl = ML_BASE[e.sym];
                    xb = ML_BITS[e.sym];
                },
                .of => {
                    if (e.sym > 31) return error.CorruptData;
                    vl = @as(u32, 1) << @intCast(e.sym);
                    xb = e.sym;
                },
            }
            t.e[i] = SeqEntry.pack(e.base, e.nb, xb, vl);
        }
        return t;
    }
};

// ---------------------------------------------------------------------------
// Frame decode state
// ---------------------------------------------------------------------------

const FrameState = struct {
    huf_table: huf.DTable = undefined,
    have_huf: bool = false,
    ll: SeqTab = undefined,
    of: SeqTab = undefined,
    ml: SeqTab = undefined,
    have_seq_tables: bool = false,
    rep: [3]u32 = .{ 1, 4, 8 },
    lit_buf: std.ArrayList(u8),
    dict_len: usize = 0,
};

/// Decompress every frame in `src`. Skippable frames are skipped.
pub fn decompress(allocator: std.mem.Allocator, src: []const u8) Error![]u8 {
    return decompressImpl(allocator, src, null, false);
}

/// Decompress every frame in `src` using an optional dictionary.
pub fn decompressDict(allocator: std.mem.Allocator, src: []const u8, dict_bytes: ?[]const u8) Error![]u8 {
    return decompressImpl(allocator, src, dict_bytes, false);
}

/// Like `decompress`, but single frames of several blocks run as a two-thread
/// pipeline (literal decoding ahead of sequence execution). Spawns a thread, so
/// it must not be used from the C ABI: a libc-less static library cannot start
/// threads inside a libc-linked host program.
pub fn decompressPipelined(allocator: std.mem.Allocator, src: []const u8) Error![]u8 {
    return decompressImpl(allocator, src, null, true);
}

fn decompressImpl(allocator: std.mem.Allocator, src: []const u8, dict_bytes: ?[]const u8, pipeline: bool) Error![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    var pos: usize = 0;

    const parsed_dict: ?dict_mod.Dict = if (dict_bytes) |db|
        dict_mod.Dict.init(db) catch return error.CorruptData
    else
        null;

    while (pos < src.len) {
        if (frame.isSkippable(src[pos..])) {
            if (pos + 8 > src.len) return error.InputTooSmall;
            const sz = std.mem.readInt(u32, src[pos + 4 ..][0..4], .little);
            if (pos + 8 + sz > src.len) return error.InputTooSmall;
            pos += 8 + sz;
            continue;
        }
        const fh = frame.readFrameHeader(src[pos..]) catch |e| switch (e) {
            error.InputTooSmall => return error.InputTooSmall,
            else => return error.CorruptData,
        };
        if (fh.hdr.dict_id != 0) {
            if (parsed_dict == null) return error.Unsupported;
            if (parsed_dict.?.dict_id != 0 and parsed_dict.?.dict_id != fh.hdr.dict_id) {
                return error.Unsupported;
            }
        }
        pos += fh.consumed;

        const dict_content = if (parsed_dict) |d| d.content else &.{};
        const dict_len = dict_content.len;
        if (dict_len > 0) {
            try out.appendSlice(dict_content);
        }
        const frame_start = out.items.len;

        if (fh.hdr.content_size) |cs| {
            // Pre-size from the declared size, but never trust it blindly: a
            // forged header must not trigger a huge allocation.
            const trusted: u64 = @min(cs, @as(u64, src.len) * 64 + (1 << 20));
            try out.ensureTotalCapacity(frame_start + @as(usize, @intCast(trusted)));
        }

        var st = FrameState{
            .lit_buf = std.ArrayList(u8).init(allocator),
            .dict_len = dict_len,
        };
        defer st.lit_buf.deinit();

        if (parsed_dict) |d| {
            st.rep = d.rep;
            if (d.huf_table) |ht| {
                st.huf_table = ht;
                st.have_huf = true;
            }
            if (d.ll_tab) |ll| {
                st.ll = ll;
                st.of = d.of_tab.?;
                st.ml = d.ml_tab.?;
                st.have_seq_tables = true;
            }
        }

        if (pipeline and parsed_dict == null and countBlocks(src[pos..]) >= 2) {
            pos = decodeFramePipe(allocator, src, pos, &out, frame_start) catch |e| return e;
        } else {
            pos = try decodeFrameSeq(&st, src, pos, &out, frame_start);
        }

        const produced = out.items.len - frame_start;
        if (fh.hdr.content_size) |cs| {
            if (cs != produced) return error.CorruptData;
        }
        if (fh.hdr.content_checksum) {
            if (pos + 4 > src.len) return error.InputTooSmall;
            const want = std.mem.readInt(u32, src[pos..][0..4], .little);
            const got: u32 = @truncate(checksum.xxh64(out.items[frame_start..], 0));
            if (want != got) return error.ChecksumMismatch;
            pos += 4;
        }

        if (dict_len > 0) {
            try out.replaceRange(frame_start - dict_len, dict_len, &.{});
        }
    }
    return out.toOwnedSlice();
}

fn countBlocks(data: []const u8) usize {
    var pos: usize = 0;
    var count: usize = 0;
    while (pos + 3 <= data.len) {
        const raw: u24 = @as(u24, data[pos]) | (@as(u24, data[pos + 1]) << 8) | (@as(u24, data[pos + 2]) << 16);
        const last = (raw & 1) != 0;
        const btype = (raw >> 1) & 3;
        const size: usize = raw >> 3;
        pos += 3;
        count += 1;
        switch (btype) {
            0, 2 => pos += size,
            1 => pos += 1,
            else => return 0,
        }
        if (pos > data.len) return 0;
        if (last) break;
    }
    return count;
}

// Diagnostic run: compare sequential decode with pipeline decode on the same frame.
fn decodeFrameSeq(
    st: *FrameState,
    src: []const u8,
    pos_in: usize,
    out: *std.ArrayList(u8),
    frame_start: usize,
) Error!usize {
    var pos = pos_in;
    while (true) {
        const bh = frame.readBlockHeader(src[pos..]) catch return error.InputTooSmall;
        pos += 3;
        if (bh.size > frame.BLOCK_MAX) return error.CorruptData;
        switch (bh.type) {
            .raw => {
                if (pos + bh.size > src.len) return error.InputTooSmall;
                try out.appendSlice(src[pos .. pos + bh.size]);
                pos += bh.size;
            },
            .rle => {
                if (pos >= src.len) return error.InputTooSmall;
                try out.appendNTimes(src[pos], bh.size);
                pos += 1;
            },
            .compressed => {
                if (pos + bh.size > src.len) return error.InputTooSmall;
                try decodeBlock(st, src[pos .. pos + bh.size], out, frame_start);
                pos += bh.size;
            },
            .reserved => return error.CorruptData,
        }
        if (bh.last) break;
    }
    return pos;
}

// ---------------------------------------------------------------------------
// Two-thread pipeline
// ---------------------------------------------------------------------------

const JobKind = enum { raw, rle, seq, end };

const Job = struct {
    kind: JobKind = .end,
    raw_slice: []const u8 = &.{},
    rle_byte: u8 = 0,
    rle_count: usize = 0,
    lits_buf: [frame.BLOCK_MAX + 64]u8 = undefined,
    lits_len: usize = 0,
    prep: SeqPrep = undefined,
};

const Pipe = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    ready: [2]bool = .{ false, false },
    jobs: [2]Job = undefined,
    lit_lists: [2]std.ArrayList(u8),
    err: ?Error = null,
    done: bool = false,
    end_pos: usize = 0,

    fn waitSlot(self: *Pipe, slot: usize) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.ready[slot]) {
            if (self.err) |e| return e;
            self.cond.wait(&self.mutex);
        }
        if (self.err) |e| return e;
    }

    fn push(self: *Pipe, slot: usize, job: Job) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.jobs[slot] = job;
        self.ready[slot] = true;
        self.cond.broadcast();
    }

    fn pop(self: *Pipe, slot: usize) !Job {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (!self.ready[slot]) {
            if (self.err) |e| return e;
            if (self.done) return Job{ .kind = .end };
            self.cond.wait(&self.mutex);
        }
        const j = self.jobs[slot];
        self.ready[slot] = false;
        self.cond.broadcast();
        return j;
    }

    fn setErr(self: *Pipe, e: Error) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.err = e;
        self.done = true;
        self.cond.broadcast();
    }
};

fn producerThread(pipe: *Pipe, src: []const u8, start_pos: usize) void {
    var st = FrameState{ .lit_buf = std.ArrayList(u8).init(std.heap.page_allocator) };
    defer st.lit_buf.deinit();
    var pos = start_pos;
    var slot: usize = 0;

    while (true) {
        if (pipe.waitSlot(slot)) {} else |e| {
            pipe.setErr(e);
            return;
        }
        const bh = frame.readBlockHeader(src[pos..]) catch {
            pipe.setErr(error.InputTooSmall);
            return;
        };
        pos += 3;
        if (bh.size > frame.BLOCK_MAX) {
            pipe.setErr(error.CorruptData);
            return;
        }

        var j = Job{};
        switch (bh.type) {
            .raw => {
                if (pos + bh.size > src.len) {
                    pipe.setErr(error.InputTooSmall);
                    return;
                }
                j.kind = .raw;
                j.raw_slice = src[pos .. pos + bh.size];
                pos += bh.size;
            },
            .rle => {
                if (pos >= src.len) {
                    pipe.setErr(error.InputTooSmall);
                    return;
                }
                j.kind = .rle;
                j.rle_byte = src[pos];
                j.rle_count = bh.size;
                pos += 1;
            },
            .compressed => {
                if (pos + bh.size > src.len) {
                    pipe.setErr(error.InputTooSmall);
                    return;
                }
                const block = src[pos .. pos + bh.size];
                pos += bh.size;
                var bpos: usize = 0;
                const list = &pipe.lit_lists[slot];
                const lits_slice = decodeLiterals(&st, block, &bpos, list) catch |e| {
                    pipe.setErr(e);
                    return;
                };
                @memcpy(j.lits_buf[0..lits_slice.len], lits_slice);
                j.kind = .seq;
                j.lits_len = lits_slice.len;
                j.prep = prepareSeq(&st, block[bpos..]) catch |e| {
                    pipe.setErr(e);
                    return;
                };
            },
            .reserved => {
                pipe.setErr(error.CorruptData);
                return;
            },
        }

        pipe.push(slot, j);
        slot ^= 1;
        if (bh.last) break;
    }

    pipe.mutex.lock();
    pipe.end_pos = pos;
    pipe.done = true;
    pipe.cond.broadcast();
    pipe.mutex.unlock();
}

fn decodeFramePipe(
    allocator: std.mem.Allocator,
    src: []const u8,
    start_pos: usize,
    out: *std.ArrayList(u8),
    frame_start: usize,
) Error!usize {
    var lits0 = std.ArrayList(u8).init(std.heap.page_allocator);
    defer lits0.deinit();
    lits0.ensureTotalCapacity(frame.BLOCK_MAX + 64) catch return error.OutOfMemory;

    var lits1 = std.ArrayList(u8).init(std.heap.page_allocator);
    defer lits1.deinit();
    lits1.ensureTotalCapacity(frame.BLOCK_MAX + 64) catch return error.OutOfMemory;

    var pipe = try allocator.create(Pipe);
    defer allocator.destroy(pipe);
    pipe.* = .{
        .lit_lists = .{ lits0, lits1 },
    };

    const thr = std.Thread.spawn(.{}, producerThread, .{ pipe, src, start_pos }) catch {
        // Thread spawn failed: fall back smoothly to the sequential path.
        var st = FrameState{ .lit_buf = std.ArrayList(u8).init(allocator) };
        defer st.lit_buf.deinit();
        return decodeFrameSeq(&st, src, start_pos, out, frame_start);
    };

    var rep: [3]u32 = .{ 1, 4, 8 };
    var slot: usize = 0;
    var err: ?Error = null;

    while (true) {
        const j = pipe.pop(slot) catch |e| {
            err = e;
            break;
        };
        switch (j.kind) {
            .end => break,
            .raw => {
                out.appendSlice(j.raw_slice) catch {
                    err = error.OutOfMemory;
                    break;
                };
            },
            .rle => {
                out.appendNTimes(j.rle_byte, j.rle_count) catch {
                    err = error.OutOfMemory;
                    break;
                };
            },
            .seq => {
                execSeq(&j.prep, j.lits_buf[0..j.lits_len], &rep, out, frame_start, 0) catch |e| {
                    err = e;
                    break;
                };
            },
        }
        slot ^= 1;
    }

    if (err) |e| pipe.setErr(e);
    thr.join();
    if (err) |e| return e;
    if (pipe.err) |e| return e;
    return pipe.end_pos;
}

// ---------------------------------------------------------------------------
// Block decode
// ---------------------------------------------------------------------------

fn decodeBlock(
    st: *FrameState,
    block: []const u8,
    out: *std.ArrayList(u8),
    frame_start: usize,
) Error!void {
    var pos: usize = 0;
    const lits = try decodeLiterals(st, block, &pos, &st.lit_buf);
    try decodeSequences(st, block[pos..], lits, out, frame_start);
}

fn decodeLiterals(st: *FrameState, block: []const u8, pos_out: *usize, lit_out: *std.ArrayList(u8)) Error![]const u8 {
    if (block.len < 1) return error.CorruptData;
    const b0 = block[0];
    const ltype: u2 = @truncate(b0);
    const sf: u2 = @truncate(b0 >> 2);

    switch (ltype) {
        0, 1 => {
            var hdr_len: usize = undefined;
            var size: usize = undefined;
            switch (sf) {
                0, 2 => {
                    hdr_len = 1;
                    size = b0 >> 3;
                },
                1 => {
                    if (block.len < 2) return error.CorruptData;
                    hdr_len = 2;
                    size = (@as(usize, b0) >> 4) | (@as(usize, block[1]) << 4);
                },
                3 => {
                    if (block.len < 3) return error.CorruptData;
                    hdr_len = 3;
                    size = (@as(usize, b0) >> 4) | (@as(usize, block[1]) << 4) | (@as(usize, block[2]) << 12);
                },
            }
            if (size > frame.BLOCK_MAX) return error.CorruptData;
            if (ltype == 0) {
                if (hdr_len + size > block.len) return error.CorruptData;
                pos_out.* = hdr_len + size;
                return block[hdr_len .. hdr_len + size];
            }
            if (hdr_len + 1 > block.len) return error.CorruptData;
            lit_out.clearRetainingCapacity();
            try lit_out.appendNTimes(block[hdr_len], size);
            pos_out.* = hdr_len + 1;
            return lit_out.items;
        },
        2, 3 => {
            var hdr_len: usize = undefined;
            var regen: usize = undefined;
            var comp: usize = undefined;
            var streams4 = true;
            switch (sf) {
                0, 1 => {
                    if (block.len < 3) return error.CorruptData;
                    hdr_len = 3;
                    const v = @as(u32, b0) | (@as(u32, block[1]) << 8) | (@as(u32, block[2]) << 16);
                    regen = (v >> 4) & 0x3FF;
                    comp = (v >> 14) & 0x3FF;
                    streams4 = sf == 1;
                },
                2 => {
                    if (block.len < 4) return error.CorruptData;
                    hdr_len = 4;
                    const v = std.mem.readInt(u32, block[0..4], .little);
                    regen = (v >> 4) & 0x3FFF;
                    comp = (v >> 18) & 0x3FFF;
                },
                3 => {
                    if (block.len < 5) return error.CorruptData;
                    hdr_len = 5;
                    const v = @as(u64, std.mem.readInt(u32, block[0..4], .little)) | (@as(u64, block[4]) << 32);
                    regen = @intCast((v >> 4) & 0x3FFFF);
                    comp = @intCast((v >> 22) & 0x3FFFF);
                },
            }
            if (regen > frame.BLOCK_MAX) return error.CorruptData;
            if (hdr_len + comp > block.len) return error.CorruptData;
            var body = block[hdr_len .. hdr_len + comp];
            if (ltype == 2) {
                const used = huf.readTable(&st.huf_table, body) catch return error.CorruptData;
                st.have_huf = true;
                body = body[used..];
            } else if (!st.have_huf) return error.CorruptData;

            lit_out.clearRetainingCapacity();
            try lit_out.resize(regen);
            const dst = lit_out.items;
            if (streams4) {
                huf.decode4(&st.huf_table, body, dst) catch return error.CorruptData;
            } else {
                huf.decodeStream(&st.huf_table, body, dst) catch return error.CorruptData;
            }
            pos_out.* = hdr_len + comp;
            return dst;
        },
    }
}

fn buildSeqTable(
    mode: u2,
    data: []const u8,
    pos: *usize,
    default_norm: []const i16,
    default_log: u8,
    max_sym: usize,
    max_log: u8,
) Error!?fse.DTable {
    switch (mode) {
        0 => return fse.DTable.build(default_norm, default_log) catch error.CorruptData,
        1 => {
            if (pos.* >= data.len) return error.CorruptData;
            const s = data[pos.*];
            pos.* += 1;
            if (s >= max_sym) return error.CorruptData;
            return fse.DTable.rle(s);
        },
        2 => {
            const nc = fse.readNCount(data[pos.*..], max_sym, max_log) catch return error.CorruptData;
            pos.* += nc.consumed;
            return fse.DTable.build(nc.norm[0..nc.nsym], nc.log) catch error.CorruptData;
        },
        3 => return null,
    }
}

inline fn copy16(dst: [*]u8, src: [*]const u8) void {
    dst[0..16].* = src[0..16].*;
}

const SeqPrep = struct {
    nseq: usize,
    bitstream: []const u8,
    ll: SeqTab,
    of: SeqTab,
    ml: SeqTab,
};

/// Parse the sequence header and build tables. Does not touch repeat offsets or
/// the output, so a producer thread can run this while the previous block's
/// sequences are still executing.
fn prepareSeq(st: *FrameState, data: []const u8) Error!SeqPrep {
    if (data.len == 0) return error.CorruptData;
    var pos: usize = 0;
    var nseq: usize = data[0];
    pos = 1;
    if (nseq == 0) {
        return .{ .nseq = 0, .bitstream = &.{}, .ll = undefined, .of = undefined, .ml = undefined };
    } else if (nseq >= 128) {
        if (nseq < 255) {
            if (data.len < 2) return error.CorruptData;
            nseq = ((nseq - 128) << 8) + data[1];
            pos = 2;
        } else {
            if (data.len < 3) return error.CorruptData;
            nseq = @as(usize, data[1]) + (@as(usize, data[2]) << 8) + 0x7F00;
            pos = 3;
        }
    }
    if (pos >= data.len) return error.CorruptData;
    const modes = data[pos];
    pos += 1;
    if (modes & 3 != 0) return error.CorruptData;

    if (try buildSeqTable(@truncate(modes >> 6), data, &pos, &LL_DEFAULT, LL_DEFAULT_LOG, 36, 9)) |d| {
        st.ll = try SeqTab.from(&d, .ll);
    } else if (!st.have_seq_tables) return error.CorruptData;
    if (try buildSeqTable(@truncate(modes >> 4), data, &pos, &OF_DEFAULT, OF_DEFAULT_LOG, 32, 8)) |d| {
        st.of = try SeqTab.from(&d, .of);
    } else if (!st.have_seq_tables) return error.CorruptData;
    if (try buildSeqTable(@truncate(modes >> 2), data, &pos, &ML_DEFAULT, ML_DEFAULT_LOG, 53, 9)) |d| {
        st.ml = try SeqTab.from(&d, .ml);
    } else if (!st.have_seq_tables) return error.CorruptData;
    st.have_seq_tables = true;
    if (pos >= data.len) return error.CorruptData;
    return .{ .nseq = nseq, .bitstream = data[pos..], .ll = st.ll, .of = st.of, .ml = st.ml };
}

noinline fn decodeSequences(
    st: *FrameState,
    data: []const u8,
    lits: []const u8,
    out: *std.ArrayList(u8),
    frame_start: usize,
) Error!void {
    const prep = try prepareSeq(st, data);
    try execSeq(&prep, lits, &st.rep, out, frame_start, st.dict_len);
}

noinline fn execSeq(
    prep: *const SeqPrep,
    lits: []const u8,
    rep: *[3]u32,
    out: *std.ArrayList(u8),
    frame_start: usize,
    dict_len: usize,
) Error!void {
    if (prep.nseq == 0) {
        try out.appendSlice(lits);
        return;
    }

    var r = fse.FastRev.init(prep.bitstream) catch return error.CorruptData;
    const ll_s: usize = @intCast(r.get(@intCast(prep.ll.log)));
    const of_s: usize = @intCast(r.get(@intCast(prep.of.log)));
    const ml_s: usize = @intCast(r.get(@intCast(prep.ml.log)));

    // A block regenerates at most BLOCK_MAX bytes, so reserve once and write
    // through raw pointers with 16-byte wild copies into the slack.
    const start_len = out.items.len;
    try out.ensureUnusedCapacity(frame.BLOCK_MAX + 64);
    const base: [*]u8 = out.items.ptr + start_len;
    const hist_base = (start_len - frame_start) + dict_len; // bytes of history before this block
    var ctx = SeqCtx{
        .base = base,
        .hist_base = hist_base,
        .lit_ptr = lits.ptr,
        .lit_len = lits.len,
        // Literal copies may read up to 32 bytes past their end while this holds.
        .lit_wild_end = if (lits.len >= 32) lits.len - 32 else 0,
        .ll_tab = &prep.ll.e,
        .of_tab = &prep.of.e,
        .ml_tab = &prep.ml.e,
        .r = r,
        .ll_s = ll_s,
        .of_s = of_s,
        .ml_s = ml_s,
        .rep0 = rep[0],
        .rep1 = rep[1],
        .rep2 = rep[2],
    };

    var i: usize = 0;
    const nseq = prep.nseq;
    // Fast phase: 2x unrolled loop when at least 32 bytes remain.
    while (i + 2 < nseq and ctx.r.ptr >= 32) : (i += 2) {
        try ctx.step(true, false);
        try ctx.step(true, false);
    }
    while (i + 1 < nseq and ctx.r.ptr >= 24) : (i += 1) try ctx.step(true, false);
    while (i + 1 < nseq) : (i += 1) try ctx.step(false, false);
    if (nseq > 0) try ctx.step(false, true);

    if (ctx.r.bitsLeft() != 0) return error.CorruptData;
    rep.* = .{ ctx.rep0, ctx.rep1, ctx.rep2 };

    const tail = lits.len - ctx.lit_pos;
    if (tail > frame.BLOCK_MAX - ctx.op) return error.CorruptData;
    @memcpy((base + ctx.op)[0..tail], lits.ptr[ctx.lit_pos..lits.len]);
    out.items.len = start_len + ctx.op + tail;
}

/// All state of one block's sequence loop, kept together so `step` inlines into
/// the callers' loops and the fields live in registers.
const SeqCtx = struct {
    base: [*]u8,
    hist_base: usize,
    lit_ptr: [*]const u8,
    lit_len: usize,
    lit_wild_end: usize,
    ll_tab: *const [1 << fse.MAX_LOG]SeqEntry,
    of_tab: *const [1 << fse.MAX_LOG]SeqEntry,
    ml_tab: *const [1 << fse.MAX_LOG]SeqEntry,
    r: fse.FastRev,
    ll_s: usize,
    of_s: usize,
    ml_s: usize,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    op: usize = 0,
    lit_pos: usize = 0,

    inline fn step(self: *SeqCtx, comptime fast: bool, comptime last: bool) Error!void {
        const lle = self.ll_tab[self.ll_s];
        const ofe = self.of_tab[self.of_s];
        const mle = self.ml_tab[self.ml_s];

        // <= 56 bits after a reload: offset (<=31) + match extra (<=16).
        if (fast) self.r.reloadFast() else self.r.reload();
        const of_extra: u32 = @truncate(if (fast) self.r.getFast(ofe.xbits()) else self.r.get(ofe.xbits()));
        const of_val: u32 = ofe.val() + of_extra;
        const ml_extra: usize = @intCast(if (fast) self.r.getFast(mle.xbits()) else self.r.get(mle.xbits()));
        const ml_len: usize = mle.val() + ml_extra;
        // literal extra (<=16) + the three state updates (<=26).
        if (fast) self.r.reloadFast() else self.r.reload();
        const ll_extra: usize = @intCast(if (fast) self.r.getFast(lle.xbits()) else self.r.get(lle.xbits()));
        const ll_len: usize = lle.val() + ll_extra;

        if (!last) {
            if (fast) {
                self.ll_s = lle.base() + @as(usize, @intCast(self.r.getFast(lle.nb())));
                self.ml_s = mle.base() + @as(usize, @intCast(self.r.getFast(mle.nb())));
                self.of_s = ofe.base() + @as(usize, @intCast(self.r.getFast(ofe.nb())));
            } else {
                self.ll_s = lle.base() + @as(usize, @intCast(self.r.get(lle.nb())));
                self.ml_s = mle.base() + @as(usize, @intCast(self.r.get(mle.nb())));
                self.of_s = ofe.base() + @as(usize, @intCast(self.r.get(ofe.nb())));
            }
        }

        // Resolve the offset without branching on repeat-code kind.
        const is_rep = of_val <= 3;
        const idx: u32 = (of_val -% 1) +% @intFromBool(ll_len == 0);
        const cand = [4]u32{ self.rep0, self.rep1, self.rep2, self.rep0 -% 1 };
        const sel = cand[idx & 3];
        const offset: u32 = if (is_rep) sel else of_val - 3;
        if (offset == 0) return error.CorruptData;
        const shift1 = !is_rep or idx >= 1;
        const shift2 = !is_rep or idx >= 2;
        self.rep2 = if (shift2) self.rep1 else self.rep2;
        self.rep1 = if (shift1) self.rep0 else self.rep1;
        self.rep0 = offset;

        if (ll_len + ml_len > frame.BLOCK_MAX - self.op) return error.CorruptData;
        if (ll_len > self.lit_len - self.lit_pos) return error.CorruptData;

        // Literals copy: fast copy loop within safe wildcopy boundaries.
        var dst: [*]u8 = self.base + self.op;
        if (ll_len > 0) {
            if (self.lit_pos + ll_len <= self.lit_wild_end) {
                const ls = self.lit_ptr + self.lit_pos;
                copy16(dst, ls);
                if (ll_len > 16) {
                    copy16(dst + 16, ls + 16);
                    if (ll_len > 32) {
                        var k: usize = 32;
                        while (k < ll_len) : (k += 16) copy16(dst + k, ls + k);
                    }
                }
            } else {
                @memcpy(dst[0..ll_len], self.lit_ptr[self.lit_pos .. self.lit_pos + ll_len]);
            }
            self.lit_pos += ll_len;
            self.op += ll_len;
            dst += ll_len;
        }

        // Match copy optimization: copy in 32-byte chunks when offset >= 32.
        if (offset > self.hist_base + self.op) return error.CorruptData;
        const from: [*]const u8 = dst - offset;
        if (offset >= 32) {
            dst[0..32].* = from[0..32].*;
            if (ml_len > 32) {
                var k: usize = 32;
                while (k + 32 <= ml_len) : (k += 32) {
                    dst[k..][0..32].* = from[k..][0..32].*;
                }
                while (k < ml_len) : (k += 16) copy16(dst + k, from + k);
            }
        } else if (offset >= 16) {
            copy16(dst, from);
            copy16(dst + 16, from + 16);
            if (ml_len > 32) {
                var k: usize = 32;
                while (k < ml_len) : (k += 16) copy16(dst + k, from + k);
            }
        } else if (offset >= 8) {
            var k: usize = 0;
            while (k < ml_len) : (k += 8) dst[k..][0..8].* = from[k..][0..8].*;
        } else if (offset == 1) {
            @memset(dst[0..ml_len], from[0]);
        } else {
            var k: usize = 0;
            while (k < ml_len) : (k += 1) dst[k] = from[k];
        }
        self.op += ml_len;
    }
};

test "decode raw frame from reference" {
    // zstd -c of "hello hello hello hello" is validated through the CLI in
    // integration runs; here make sure an empty raw frame round-trips.
    const a = std.testing.allocator;
    const comp = @import("compress.zig");
    const z = try comp.compress(a, "");
    defer a.free(z);
    const d = try decompress(a, z);
    defer a.free(d);
    try std.testing.expectEqual(@as(usize, 0), d.len);
}

/// Decompress with up to `nthreads` workers. Streams made of several frames
/// that each declare their size (e.g. from `compressMt`) are decoded in
/// parallel; anything else falls back to the sequential path.
pub fn decompressMt(allocator: std.mem.Allocator, src: []const u8, nthreads: usize) Error![]u8 {
    if (nthreads <= 1) return decompress(allocator, src);

    // Pre-scan frame boundaries.
    var bounds = std.ArrayList(usize).init(allocator);
    defer bounds.deinit();
    var pos: usize = 0;
    while (pos < src.len) {
        const n = (try frameSize(src[pos..])) orelse return decompress(allocator, src);
        try bounds.append(pos);
        pos += n;
    }
    try bounds.append(src.len);
    const n_frames = bounds.items.len - 1;
    if (n_frames < 2) return decompressPipelined(allocator, src);

    const parts = try allocator.alloc(?[]u8, n_frames);
    defer allocator.free(parts);
    @memset(parts, null);
    var failed = std.atomic.Value(bool).init(false);
    var next = std.atomic.Value(usize).init(0);

    const Ctx = struct {
        allocator: std.mem.Allocator,
        src: []const u8,
        bounds: []const usize,
        parts: []?[]u8,
        failed: *std.atomic.Value(bool),
        next: *std.atomic.Value(usize),

        fn run(c: @This()) void {
            while (!c.failed.load(.monotonic)) {
                const i = c.next.fetchAdd(1, .monotonic);
                if (i >= c.parts.len) return;
                c.parts[i] = decompress(c.allocator, c.src[c.bounds[i]..c.bounds[i + 1]]) catch {
                    c.failed.store(true, .monotonic);
                    return;
                };
            }
        }
    };
    const ctx = Ctx{ .allocator = allocator, .src = src, .bounds = bounds.items, .parts = parts, .failed = &failed, .next = &next };

    const extra = @min(nthreads, n_frames) - 1;
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
    if (failed.load(.monotonic)) {
        // Re-run sequentially to surface the precise error.
        return decompress(allocator, src);
    }
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

/// Byte length of the first complete frame in `src`, or null when `src` ends
/// before the frame does.
pub fn frameSize(src: []const u8) Error!?usize {
    if (src.len < 4) return null;
    if (frame.isSkippable(src)) {
        if (src.len < 8) return null;
        const sz: usize = std.mem.readInt(u32, src[4..8], .little);
        if (8 + sz > src.len) return null;
        return 8 + sz;
    }
    const fh = frame.readFrameHeader(src) catch |e| switch (e) {
        error.InputTooSmall => return null,
        else => return error.CorruptData,
    };
    var pos = fh.consumed;
    while (true) {
        if (pos + 3 > src.len) return null;
        const bh = frame.readBlockHeader(src[pos..]) catch return null;
        pos += 3;
        switch (bh.type) {
            .raw, .compressed => pos += bh.size,
            .rle => pos += 1,
            .reserved => return error.CorruptData,
        }
        if (pos > src.len) return null;
        if (bh.last) break;
    }
    if (fh.hdr.content_checksum) {
        pos += 4;
        if (pos > src.len) return null;
    }
    return pos;
}
