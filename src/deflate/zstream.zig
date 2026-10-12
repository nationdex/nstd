//! Streaming Deflater / Inflater behind the zlib `z_stream` API.
//!
//! Both work with an internal buffer on each side, so callers may supply input
//! and output space in arbitrary slices. Containers: raw deflate, zlib (RFC 1950)
//! and gzip (RFC 1952); preset dictionaries are supported for raw and zlib.

const std = @import("std");
const d = @import("deflate.zig");
const checksum = @import("../core/checksum.zig");

pub const Wrap = enum { raw, zlib, gzip, auto };

pub const Flush = enum(u8) { none = 0, partial = 1, sync = 2, full = 3, finish = 4, block = 5 };

pub const Error = d.Error || error{ BadHeader, BadChecksum, BadDictionary };

const WSIZE = d.WSIZE;

// ===========================================================================
// Deflater
// ===========================================================================

pub const Deflater = struct {
    allocator: std.mem.Allocator,
    cfg: d.Config,
    level: i32,
    wrap: Wrap,
    wbits: u5,
    m: d.Matcher,
    head: []u32,
    prev: []u32,
    tl: []u16,
    tv: []u16,
    toks: d.Tokens,
    hist: std.ArrayList(u8),
    /// Next position to parse within `hist`.
    pos: usize = 0,
    /// `hist` index where the pending token block starts (for stored blocks).
    blk_start: usize = 0,
    out: std.ArrayList(u8),
    out_pos: usize = 0,
    ob: d.OutBuf,
    header_done: bool = false,
    finished: bool = false,
    adler: u32 = 1,
    crc: u32 = 0,
    total_in: u64 = 0,
    dict_id: u32 = 0,
    has_dict: bool = false,
    last_flush: Flush = .none,

    /// `wbits` is the zlib window size exponent (8..15; 8 is treated as 9).
    pub fn create(allocator: std.mem.Allocator, level_in: i32, wrap: Wrap, wbits_in: u5) Error!*Deflater {
        const self = try allocator.create(Deflater);
        errdefer allocator.destroy(self);
        const level = if (level_in < 0) 6 else @min(level_in, 9);
        const wbits: u5 = if (wbits_in < 9) 9 else if (wbits_in > 15) 15 else wbits_in;
        const head = try allocator.alloc(u32, 1 << d.HASH_BITS);
        errdefer allocator.free(head);
        @memset(head, 0);
        const prev = try allocator.alloc(u32, WSIZE);
        errdefer allocator.free(prev);
        @memset(prev, 0);
        const tl = try allocator.alloc(u16, d.TOKENS_PER_BLOCK);
        errdefer allocator.free(tl);
        const tv = try allocator.alloc(u16, d.TOKENS_PER_BLOCK);
        errdefer allocator.free(tv);
        self.* = .{
            .allocator = allocator,
            .cfg = d.configFor(level),
            .level = level,
            .wrap = wrap,
            .wbits = wbits,
            .m = .{ .head = head, .prev = prev, .wsize = (@as(usize, 1) << wbits) - 262 },
            .head = head,
            .prev = prev,
            .tl = tl,
            .tv = tv,
            .toks = .{ .len = tl, .val = tv },
            .hist = std.ArrayList(u8).init(allocator),
            .out = std.ArrayList(u8).init(allocator),
            .ob = undefined,
        };
        self.ob = .{ .list = &self.out };
        return self;
    }

    pub fn destroy(self: *Deflater) void {
        const a = self.allocator;
        a.free(self.head);
        a.free(self.prev);
        a.free(self.tl);
        a.free(self.tv);
        self.hist.deinit();
        self.out.deinit();
        a.destroy(self);
    }

    /// Start a fresh stream with the same parameters.
    pub fn reset(self: *Deflater) void {
        @memset(self.head, 0);
        @memset(self.prev, 0);
        self.hist.clearRetainingCapacity();
        self.out.clearRetainingCapacity();
        self.out_pos = 0;
        self.ob = .{ .list = &self.out };
        self.toks.n = 0;
        self.toks.span = 0;
        self.pos = 0;
        self.blk_start = 0;
        self.m.min_c = 0;
        self.header_done = false;
        self.finished = false;
        self.adler = 1;
        self.crc = 0;
        self.total_in = 0;
        self.dict_id = 0;
        self.has_dict = false;
        self.last_flush = .none;
    }

    pub fn setLevel(self: *Deflater, level_in: i32) void {
        const level = if (level_in < 0) 6 else @min(level_in, 9);
        self.level = level;
        self.cfg = d.configFor(level);
    }

    /// Preload the match window (before any data); the bytes are not emitted.
    pub fn setDictionary(self: *Deflater, dict: []const u8) Error!void {
        if (self.header_done or self.total_in != 0) return error.BadDictionary;
        const keep = dict[dict.len -| self.m.wsize..];
        try self.hist.appendSlice(keep);
        var i: usize = 0;
        while (i < keep.len) : (i += 1) self.m.insert(self.hist.items, i);
        self.pos = keep.len;
        self.blk_start = keep.len;
        self.has_dict = true;
        self.dict_id = checksum.adler32(dict, 1);
    }

    fn writeHeader(self: *Deflater) Error!void {
        self.header_done = true;
        switch (self.wrap) {
            .raw, .auto => {},
            .zlib => {
                const cmf: u32 = 0x08 | (@as(u32, self.wbits - 8) << 4);
                const flevel: u32 = if (self.level < 2) 0 else if (self.level < 6) 1 else if (self.level == 6) 2 else 3;
                var flg: u32 = flevel << 6;
                if (self.has_dict) flg |= 0x20;
                flg += 31 - ((cmf << 8) + flg) % 31;
                try self.out.append(@intCast(cmf));
                try self.out.append(@intCast(flg));
                if (self.has_dict) try self.out.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, self.dict_id)));
            },
            .gzip => {
                const xfl: u8 = if (self.level == 9) 2 else if (self.level == 1) 4 else 0;
                try self.out.appendSlice(&[_]u8{ 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, xfl, 3 });
            },
        }
    }

    /// Queue input. Data is hashed into the window lazily by `run`.
    pub fn write(self: *Deflater, data: []const u8) Error!void {
        if (data.len == 0) return;
        try self.hist.appendSlice(data);
        self.total_in += data.len;
        switch (self.wrap) {
            .zlib => self.adler = checksum.adler32(data, self.adler),
            .gzip => self.crc = checksum.crc32(data, self.crc),
            else => {},
        }
    }

    fn emitBlock(self: *Deflater, last: bool) Error!void {
        try self.out.ensureUnusedCapacity(self.toks.n * 7 + self.toks.span + 1024);
        d.writeBlock(&self.ob, &self.toks, self.hist.items, self.blk_start, last);
        self.blk_start = self.pos;
        self.toks.n = 0;
        self.toks.span = 0;
    }

    fn trim(self: *Deflater) void {
        if (self.hist.items.len < 4 * WSIZE) return;
        // Keep a full match window, plus the pending block when a stored block
        // could still be chosen for it. Shifts are multiples of WSIZE so the
        // `prev` ring slots keep mapping to the same positions.
        var keep_from = self.pos -| self.m.wsize;
        if (self.toks.span <= 65535) keep_from = @min(keep_from, self.blk_start);
        const shift = (keep_from / WSIZE) * WSIZE;
        if (shift == 0) return;
        self.hist.replaceRange(0, shift, &.{}) catch return;
        self.pos -= shift;
        self.blk_start = self.blk_start -| shift;
        self.m.min_c = self.m.min_c -| shift;
        for (self.head) |*h| h.* = if (h.* > shift) h.* - @as(u32, @intCast(shift)) else 0;
        for (self.prev) |*h| h.* = if (h.* > shift) h.* - @as(u32, @intCast(shift)) else 0;
    }

    /// Parse and emit what the flush mode allows. Output accumulates in `out`.
    pub fn run(self: *Deflater, flush: Flush) Error!void {
        if (!self.header_done) try self.writeHeader();
        if (self.finished) return;
        const lookahead: usize = 262;
        const input = &self.hist;
        while (true) {
            const avail = input.items.len - self.pos;
            if (avail == 0) break;
            if (flush == .none and avail < lookahead) break;
            if (self.toks.n >= d.TOKENS_PER_BLOCK - 1) {
                try self.emitBlock(false);
                continue;
            }
            self.pos = d.parseStep(&self.m, self.cfg, &self.toks, input.items, self.pos);
            if (self.toks.n >= d.TOKENS_PER_BLOCK - 1) try self.emitBlock(false);
        }
        self.trim();

        switch (flush) {
            .none => {},
            .partial, .sync, .full, .block => {
                if (self.toks.n > 0) try self.emitBlock(false);
                if (flush != .block) {
                    // Empty stored block: byte-aligns the stream so the decoder can
                    // emit everything produced so far.
                    try self.out.ensureUnusedCapacity(32);
                    self.ob.put(0, 1);
                    self.ob.put(0, 2);
                    self.ob.flushBytes();
                    self.out.appendSliceAssumeCapacity(&[_]u8{ 0, 0, 0xFF, 0xFF });
                }
                if (flush == .full) {
                    @memset(self.head, 0);
                    self.m.min_c = self.pos;
                }
            },
            .finish => {
                try self.out.ensureUnusedCapacity(self.toks.n * 7 + self.toks.span + 1024);
                if (self.toks.n > 0) {
                    try self.emitBlock(true);
                } else {
                    self.ob.put(1, 1);
                    self.ob.put(1, 2);
                    self.ob.put(d.rev(d.fixed_codes[256], 7), 7);
                }
                self.ob.flushBytes();
                switch (self.wrap) {
                    .zlib => try self.out.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, self.adler))),
                    .gzip => {
                        try self.out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(u32, self.crc)));
                        try self.out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(u32, @as(u32, @truncate(self.total_in)))));
                    },
                    else => {},
                }
                self.finished = true;
            },
        }
        self.last_flush = flush;
    }

    pub fn pending(self: *const Deflater) []const u8 {
        return self.out.items[self.out_pos..];
    }

    pub fn consume(self: *Deflater, n: usize) void {
        self.out_pos += n;
        if (self.out_pos == self.out.items.len) {
            self.out.clearRetainingCapacity();
            self.out_pos = 0;
        }
    }

    /// Upper bound on the compressed size of `n` input bytes (zlib's deflateBound shape).
    pub fn bound(self: *const Deflater, n: usize) usize {
        const wrap_extra: usize = switch (self.wrap) {
            .raw, .auto => 0,
            .zlib => 6 + (if (self.has_dict) @as(usize, 4) else 0),
            .gzip => 18,
        };
        return n + (n >> 12) + (n >> 14) + (n >> 25) + 13 + wrap_extra + 5 * (n / 16384 + 1);
    }
};

// ===========================================================================
// Inflater
// ===========================================================================

pub const InfStatus = enum { need_input, more_output, end, need_dict };

const Phase = enum { header, need_dict, block, stored, codes, trailer, done };

const PENDING_LIMIT: usize = 1 << 20;

pub const Inflater = struct {
    allocator: std.mem.Allocator,
    wrap: Wrap,
    detected: Wrap,
    inbuf: std.ArrayList(u8),
    /// Bit position of the next unread bit in `inbuf`.
    ibit: usize = 0,
    win: std.ArrayList(u8),
    drained: usize = 0,
    sum_done: usize = 0,
    phase: Phase = .header,
    final: bool = false,
    stored_left: usize = 0,
    lit: *d.Table,
    dist: *d.Table,
    adler: u32 = 1,
    crc: u32 = 0,
    total_out: u64 = 0,
    dict_id: u32 = 0,
    err_msg: ?[:0]const u8 = null,

    pub fn create(allocator: std.mem.Allocator, wrap: Wrap) Error!*Inflater {
        const self = try allocator.create(Inflater);
        errdefer allocator.destroy(self);
        const lit = try allocator.create(d.Table);
        errdefer allocator.destroy(lit);
        const dist = try allocator.create(d.Table);
        errdefer allocator.destroy(dist);
        self.* = .{
            .allocator = allocator,
            .wrap = wrap,
            .detected = wrap,
            .inbuf = std.ArrayList(u8).init(allocator),
            .win = std.ArrayList(u8).init(allocator),
            .lit = lit,
            .dist = dist,
        };
        return self;
    }

    pub fn destroy(self: *Inflater) void {
        const a = self.allocator;
        a.destroy(self.lit);
        a.destroy(self.dist);
        self.inbuf.deinit();
        self.win.deinit();
        a.destroy(self);
    }

    pub fn reset(self: *Inflater) void {
        self.inbuf.clearRetainingCapacity();
        self.ibit = 0;
        self.win.clearRetainingCapacity();
        self.drained = 0;
        self.sum_done = 0;
        self.phase = .header;
        self.final = false;
        self.stored_left = 0;
        self.adler = 1;
        self.crc = 0;
        self.total_out = 0;
        self.dict_id = 0;
        self.err_msg = null;
        self.detected = self.wrap;
    }

    pub fn feed(self: *Inflater, data: []const u8) Error!void {
        // Drop fully consumed bytes before growing the buffer.
        const used = self.ibit / 8;
        if (used > 0 and used >= self.inbuf.items.len / 2) {
            self.inbuf.replaceRange(0, used, &.{}) catch {};
            self.ibit -= used * 8;
        }
        try self.inbuf.appendSlice(data);
    }

    /// Input bytes held but not yet consumed (whole bytes after the stream end).
    pub fn unusedInput(self: *const Inflater) usize {
        return self.inbuf.items.len - (self.ibit + 7) / 8;
    }

    /// Hand back up to `n` of the unused trailing input bytes.
    pub fn giveBack(self: *Inflater, n: usize) void {
        self.inbuf.shrinkRetainingCapacity(self.inbuf.items.len - n);
    }

    pub fn setDictionary(self: *Inflater, dict: []const u8) Error!void {
        if (self.phase == .need_dict) {
            if (checksum.adler32(dict, 1) != self.dict_id) return error.BadDictionary;
            self.phase = .block;
        } else if (!(self.detected == .raw and self.win.items.len == 0)) {
            return error.BadDictionary;
        }
        const keep = dict[dict.len -| WSIZE..];
        try self.win.appendSlice(keep);
        self.drained = self.win.items.len;
        self.sum_done = self.win.items.len;
    }

    pub fn pending(self: *const Inflater) []const u8 {
        return self.win.items[self.drained..];
    }

    pub fn consume(self: *Inflater, n: usize) void {
        self.drained += n;
        // Keep one window of history; discard older bytes.
        if (self.drained > WSIZE * 2 and self.sum_done == self.win.items.len) {
            const cut = self.drained - WSIZE;
            self.win.replaceRange(0, cut, &.{}) catch return;
            self.drained -= cut;
            self.sum_done -= cut;
        }
    }

    fn updateSum(self: *Inflater) void {
        const fresh = self.win.items[self.sum_done..];
        if (fresh.len == 0) return;
        switch (self.detected) {
            .zlib => self.adler = checksum.adler32(fresh, self.adler),
            .gzip => self.crc = checksum.crc32(fresh, self.crc),
            else => {},
        }
        self.total_out += fresh.len;
        self.sum_done = self.win.items.len;
    }

    fn fail(self: *Inflater, msg: [:0]const u8) Error {
        self.err_msg = msg;
        return error.CorruptData;
    }

    inline fn avail(self: *const Inflater) []const u8 {
        return self.inbuf.items[self.ibit / 8 ..];
    }

    fn headerStep(self: *Inflater) Error!bool {
        const b = self.avail();
        if (self.detected == .auto) {
            if (b.len < 2) return false;
            self.detected = if (b[0] == 0x1f and b[1] == 0x8b) .gzip else .zlib;
        }
        switch (self.detected) {
            .raw => {
                self.phase = .block;
                return true;
            },
            .zlib => {
                if (b.len < 2) return false;
                const cmf = b[0];
                const flg = b[1];
                if ((cmf & 0x0F) != 8 or (cmf >> 4) > 7 or ((@as(u32, cmf) << 8) | flg) % 31 != 0) return self.fail("incorrect header check");
                if (flg & 0x20 != 0) {
                    if (b.len < 6) return false;
                    self.dict_id = std.mem.readInt(u32, b[2..6], .big);
                    self.ibit += 48;
                    self.phase = .need_dict;
                    return true;
                }
                self.ibit += 16;
                self.phase = .block;
                return true;
            },
            .gzip => {
                if (b.len < 10) return false;
                if (b[0] != 0x1f or b[1] != 0x8b or b[2] != 8) return self.fail("incorrect header check");
                const flg = b[3];
                var p: usize = 10;
                if (flg & 0x04 != 0) {
                    if (b.len < p + 2) return false;
                    p += 2 + std.mem.readInt(u16, b[p..][0..2], .little);
                }
                if (flg & 0x08 != 0) {
                    while (true) : (p += 1) {
                        if (p >= b.len) return false;
                        if (b[p] == 0) break;
                    }
                    p += 1;
                }
                if (flg & 0x10 != 0) {
                    while (true) : (p += 1) {
                        if (p >= b.len) return false;
                        if (b[p] == 0) break;
                    }
                    p += 1;
                }
                if (flg & 0x02 != 0) p += 2;
                if (b.len < p) return false;
                self.ibit += p * 8;
                self.phase = .block;
                return true;
            },
            .auto => unreachable,
        }
    }

    fn bitIn(self: *Inflater) d.BitIn {
        var br = d.BitIn{ .data = self.inbuf.items, .pos = self.ibit / 8 };
        const skip: u32 = @intCast(self.ibit % 8);
        if (skip > 0) {
            br.refill();
            _ = br.take(@intCast(skip));
        }
        return br;
    }

    fn bitPos(br: *const d.BitIn) usize {
        return br.pos * 8 - (br.nb - @min(br.nb, br.pad));
    }

    /// One literal / length-distance symbol, or end of block, with rollback when
    /// the buffered input ends mid-symbol.
    fn symbolStep(self: *Inflater, br: *d.BitIn) Error!enum { ok, eob, need } {
        const snap = br.*;
        const len0 = self.win.items.len;
        br.refill();
        var e = self.lit.fast[br.bb & ((1 << d.FAST_BITS) - 1)];
        if (e == 0) {
            const r = self.lit.slow(@truncate(br.bb)) orelse return self.fail("invalid literal/length code");
            e = d.entryFor(.lit, r.sym, r.len);
            if (e == 0) return self.fail("invalid literal/length code");
        }
        br.bb >>= @intCast(e & 15);
        br.nb -= e & 15;
        if (e & d.F_LIT != 0) {
            try self.win.append(@truncate(e >> 8));
        } else if (e & d.F_EOB != 0) {
            if (br.overrun()) {
                br.* = snap;
                return .need;
            }
            return .eob;
        } else {
            const length: usize = ((e >> 8) & 0x1FF) + br.take(@intCast((e >> 24) & 15));
            var de = self.dist.fast[br.bb & ((1 << d.FAST_BITS) - 1)];
            if (de == 0) {
                const r = self.dist.slow(@truncate(br.bb)) orelse return self.fail("invalid distance code");
                de = d.entryFor(.dist, r.sym, r.len);
                if (de == 0) return self.fail("invalid distance code");
            }
            br.bb >>= @intCast(de & 15);
            br.nb -= de & 15;
            const dd: usize = ((de >> 8) & 0x7FFF) + br.take(@intCast((de >> 24) & 15));
            if (br.overrun()) {
                br.* = snap;
                self.win.shrinkRetainingCapacity(len0);
                return .need;
            }
            if (dd > self.win.items.len) return self.fail("invalid distance too far back");
            var k: usize = 0;
            try self.win.ensureUnusedCapacity(length);
            while (k < length) : (k += 1) self.win.appendAssumeCapacity(self.win.items[self.win.items.len - dd]);
        }
        if (br.overrun()) {
            br.* = snap;
            self.win.shrinkRetainingCapacity(len0);
            return .need;
        }
        return .ok;
    }

    /// Decode as far as the buffered input and the pending-output cap allow.
    pub fn run(self: *Inflater) Error!InfStatus {
        defer self.updateSum();
        while (true) {
            if (self.win.items.len - self.drained >= PENDING_LIMIT) return .more_output;
            switch (self.phase) {
                .header => if (!try self.headerStep()) return .need_input,
                .need_dict => return .need_dict,
                .block => {
                    var br = self.bitIn();
                    br.refill();
                    const final = br.take(1);
                    const btype = br.take(2);
                    if (br.overrun()) return .need_input;
                    switch (btype) {
                        0 => {
                            br.bb >>= @intCast(br.nb % 8);
                            br.nb -= br.nb % 8;
                            const p = br.bytePos();
                            const b = self.inbuf.items;
                            if (br.overrun() or p + 4 > b.len) return .need_input;
                            const len = std.mem.readInt(u16, b[p..][0..2], .little);
                            const nlen = std.mem.readInt(u16, b[p + 2 ..][0..2], .little);
                            if (len != ~nlen) return self.fail("invalid stored block lengths");
                            self.ibit = (p + 4) * 8;
                            self.stored_left = len;
                            self.final = final == 1;
                            self.phase = .stored;
                        },
                        1 => {
                            try self.lit.build(.lit, &d.fixed_lit_lens);
                            try self.dist.build(.dist, &([_]u8{5} ** 32));
                            self.ibit = bitPos(&br);
                            self.final = final == 1;
                            self.phase = .codes;
                        },
                        2 => {
                            d.readDynamic(&br, self.lit, self.dist) catch |e| switch (e) {
                                error.InputTooSmall => return .need_input,
                                // Garbage read past the end of the buffered input is
                                // truncation, not corruption.
                                else => return if (br.overrun()) .need_input else self.fail("invalid dynamic block"),
                            };
                            if (br.overrun()) return .need_input;
                            self.ibit = bitPos(&br);
                            self.final = final == 1;
                            self.phase = .codes;
                        },
                        3 => return self.fail("invalid block type"),
                        else => unreachable,
                    }
                },
                .stored => {
                    const b = self.avail();
                    const n = @min(self.stored_left, b.len);
                    if (n > 0) {
                        try self.win.appendSlice(b[0..n]);
                        self.ibit += n * 8;
                        self.stored_left -= n;
                    }
                    if (self.stored_left > 0) return .need_input;
                    self.phase = if (self.final) .trailer else .block;
                },
                .codes => {
                    var br = self.bitIn();
                    // Bulk-decode while at least 16 buffered bytes remain, then one
                    // symbol at a time with rollback.
                    const stop = self.inbuf.items.len -| 16;
                    const limit = self.drained + PENDING_LIMIT;
                    const r = d.inflateBlock(&br, &self.win, self.lit, self.dist, stop, limit) catch |e| switch (e) {
                        error.InvalidWindow => return self.fail("invalid distance too far back"),
                        error.InputTooSmall => return self.fail("truncated block"),
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return self.fail("invalid block data"),
                    };
                    self.ibit = bitPos(&br);
                    if (r == .eob) {
                        self.phase = if (self.final) .trailer else .block;
                        continue;
                    }
                    if (self.win.items.len >= limit) continue;
                    // Careful tail.
                    var br2 = self.bitIn();
                    var steps: usize = 0;
                    while (steps < 64) : (steps += 1) {
                        switch (try self.symbolStep(&br2)) {
                            .ok => {},
                            .eob => {
                                self.ibit = bitPos(&br2);
                                self.phase = if (self.final) .trailer else .block;
                                break;
                            },
                            .need => {
                                self.ibit = bitPos(&br2);
                                return .need_input;
                            },
                        }
                        self.ibit = bitPos(&br2);
                    } else continue;
                },
                .trailer => {
                    self.updateSum();
                    const aligned = (self.ibit + 7) / 8;
                    const b = self.inbuf.items[aligned..];
                    switch (self.detected) {
                        .zlib => {
                            if (b.len < 4) return .need_input;
                            if (std.mem.readInt(u32, b[0..4], .big) != self.adler) return self.fail("incorrect data check");
                            self.ibit = (aligned + 4) * 8;
                        },
                        .gzip => {
                            if (b.len < 8) return .need_input;
                            if (std.mem.readInt(u32, b[0..4], .little) != self.crc) return self.fail("incorrect data check");
                            if (std.mem.readInt(u32, b[4..8], .little) != @as(u32, @truncate(self.total_out))) return self.fail("incorrect length check");
                            self.ibit = (aligned + 8) * 8;
                        },
                        else => self.ibit = aligned * 8,
                    }
                    self.phase = .done;
                },
                .done => return .end,
            }
        }
    }
};

test "deflater and inflater round trip with flushes in odd slices" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x2577);
    const rng = prng.random();
    const data = try a.alloc(u8, 300000);
    defer a.free(data);
    for (data, 0..) |*b, i| b.* = if (i % 4000 < 2500) "streaming deflate test data "[i % 27] else rng.int(u8);

    for ([_]Wrap{ .raw, .zlib, .gzip }) |wrap| {
        for ([_]i32{ 1, 6, 9 }) |level| {
            const df = try Deflater.create(a, level, wrap, 15);
            defer df.destroy();
            var comp = std.ArrayList(u8).init(a);
            defer comp.deinit();
            var off: usize = 0;
            var n: usize = 0;
            while (off < data.len) : (n += 1) {
                const take = @min(data.len - off, 1 + rng.uintLessThan(usize, 9000));
                try df.write(data[off .. off + take]);
                off += take;
                const fl: Flush = switch (n % 11) {
                    3 => .sync,
                    7 => .full,
                    else => .none,
                };
                try df.run(fl);
                try comp.appendSlice(df.pending());
                df.consume(df.pending().len);
            }
            try df.run(.finish);
            try comp.appendSlice(df.pending());

            const inf = try Inflater.create(a, wrap);
            defer inf.destroy();
            var got = std.ArrayList(u8).init(a);
            defer got.deinit();
            var ip: usize = 0;
            var status: InfStatus = .need_input;
            while (status != .end) {
                if (status == .need_input) {
                    try std.testing.expect(ip < comp.items.len);
                    const take = @min(comp.items.len - ip, 1 + rng.uintLessThan(usize, 700));
                    try inf.feed(comp.items[ip .. ip + take]);
                    ip += take;
                }
                status = try inf.run();
                try got.appendSlice(inf.pending());
                inf.consume(inf.pending().len);
            }
            try std.testing.expectEqualSlices(u8, data, got.items);
        }
    }
}
