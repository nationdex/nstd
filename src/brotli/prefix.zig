//! Brotli prefix codes (RFC 7932 §3): canonical code construction, the fast
//! decode table, and the bit reader shared by the decoder.

const std = @import("std");

pub const Error = error{ CorruptData, InputTooSmall, OutOfMemory };

pub const MAX_LEN = 15;
pub const FAST_BITS = 10;
const MISS: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// Bit reader (LSB-first)
// ---------------------------------------------------------------------------

pub const BitReader = struct {
    data: []const u8,
    pos: usize = 0,
    buf: u64 = 0,
    n: u7 = 0,
    /// Zero bits appended after the end of the input so reads never stall;
    /// consuming any of them is an overrun (see `eof`).
    pad: u32 = 0,
    /// Set when an invalid prefix code was met.
    bad: bool = false,

    pub fn init(data: []const u8) BitReader {
        return .{ .data = data };
    }

    /// True once more bits were consumed than the input held, or the stream
    /// was found invalid.
    pub inline fn eof(self: *const BitReader) bool {
        return self.bad or self.pad > self.n;
    }

    pub inline fn fill(self: *BitReader) void {
        if (self.n <= 56 and self.pos + 8 <= self.data.len) {
            // One unaligned load tops the buffer up to >= 56 bits.
            self.buf |= std.mem.readInt(u64, self.data[self.pos..][0..8], .little) << @intCast(self.n);
            const adv: u7 = (63 - self.n) >> 3;
            self.pos += adv;
            self.n += adv * 8;
            return;
        }
        while (self.n <= 56) {
            if (self.pos < self.data.len) {
                self.buf |= @as(u64, self.data[self.pos]) << @intCast(self.n);
                self.pos += 1;
            } else {
                self.pad += 8;
            }
            self.n += 8;
        }
    }

    /// Peek up to 32 bits; bits past the end of input read as zero.
    pub inline fn peek(self: *BitReader, k: u6) u32 {
        if (self.n < 32) self.fill();
        return @truncate(self.buf & ((@as(u64, 1) << k) - 1));
    }

    pub inline fn consume(self: *BitReader, k: u6) void {
        self.buf >>= k;
        self.n -= k;
    }

    pub inline fn read(self: *BitReader, k: u6) u32 {
        if (k == 0) return 0;
        const v = self.peek(k);
        self.consume(k);
        return v;
    }

    /// Drop bits to the next byte boundary; returns true if they were all zero.
    pub fn alignToByte(self: *BitReader) bool {
        const drop: u6 = @intCast(self.n % 8);
        const v = self.read(drop);
        return v == 0;
    }

    /// Index of the next unread byte (after `alignToByte`).
    pub fn bytePos(self: *const BitReader) usize {
        return self.pos - (self.n - @min(self.n, self.pad)) / 8;
    }

    pub fn seekByte(self: *BitReader, p: usize) void {
        self.pos = p;
        self.buf = 0;
        self.n = 0;
        self.pad = 0;
    }

    /// Total bits consumed from the start of the input (valid when not `eof`).
    pub fn bitsConsumed(self: *const BitReader) usize {
        return self.pos * 8 - (self.n - @min(self.n, self.pad));
    }
};

// ---------------------------------------------------------------------------
// Decode tree
// ---------------------------------------------------------------------------

pub const Tree = struct {
    /// fast[peeked low FAST_BITS bits] = (symbol << 4) | len, or MISS when the
    /// code is longer than FAST_BITS. A one-symbol code fills the table with len 0.
    fast: [1 << FAST_BITS]u16,
    counts: [MAX_LEN + 1]u16,
    /// Symbols ordered by (length, symbol) for the canonical slow path.
    syms: []u16,
    /// Set for a one-symbol code: decoding consumes no bits.
    single: bool,
    single_sym: u16,

    pub fn build(allocator: std.mem.Allocator, lengths: []const u8) Error!*Tree {
        var nz: usize = 0;
        for (lengths) |l| nz += @intFromBool(l != 0);
        const t = try allocator.create(Tree);
        errdefer allocator.destroy(t);
        const buf = try allocator.alloc(u16, nz);
        errdefer allocator.free(buf);
        try t.init(buf, lengths);
        if (t.single) allocator.free(buf);
        return t;
    }

    /// Initialise `self` from code lengths using caller-provided symbol storage
    /// (`syms_buf.len` must be at least the number of nonzero lengths).
    pub fn init(t: *Tree, syms_buf: []u16, lengths: []const u8) Error!void {
        t.* = .{ .fast = .{MISS} ** (1 << FAST_BITS), .counts = .{0} ** (MAX_LEN + 1), .syms = &.{}, .single = false, .single_sym = 0 };
        var nz: usize = 0;
        var last: u16 = 0;
        for (lengths, 0..) |l, s| {
            if (l > MAX_LEN) return error.CorruptData;
            if (l != 0) {
                t.counts[l] += 1;
                nz += 1;
                last = @intCast(s);
            }
        }
        if (nz == 0) return error.CorruptData;
        if (nz == 1) {
            t.single = true;
            t.single_sym = last;
            @memset(&t.fast, @as(u16, last) << 4);
            return;
        }
        // Kraft equality: the code must be complete.
        var kraft: u32 = 0;
        for (1..MAX_LEN + 1) |l| kraft += @as(u32, t.counts[l]) << @intCast(MAX_LEN - l);
        if (kraft != (1 << MAX_LEN)) return error.CorruptData;

        if (syms_buf.len < nz) return error.CorruptData;
        t.syms = syms_buf[0..nz];
        var offs: [MAX_LEN + 2]u16 = .{0} ** (MAX_LEN + 2);
        for (1..MAX_LEN + 1) |l| offs[l + 1] = offs[l] + t.counts[l];
        var next_code: [MAX_LEN + 2]u32 = .{0} ** (MAX_LEN + 2);
        var code: u32 = 0;
        for (1..MAX_LEN + 1) |l| {
            code = (code + t.counts[l - 1]) << 1;
            next_code[l] = code;
        }
        // counts[0] must not contribute
        // (counts[0] is always zero since only nonzero lengths are counted)
        for (lengths, 0..) |l, s| {
            if (l == 0) continue;
            t.syms[offs[l]] = @intCast(s);
            offs[l] += 1;
            const c = next_code[l];
            next_code[l] += 1;
            if (l <= FAST_BITS) {
                // Stream order is MSB-first, so index with the reversed code.
                const rev = reverse(c, @intCast(l));
                const step: usize = @as(usize, 1) << @intCast(l);
                var i: usize = rev;
                const entry: u16 = (@as(u16, @intCast(s)) << 4) | l;
                while (i < (1 << FAST_BITS)) : (i += step) t.fast[i] = entry;
            }
        }
    }

    pub inline fn decode(self: *const Tree, br: *BitReader) u16 {
        const bits = br.peek(MAX_LEN);
        const e = self.fast[bits & ((1 << FAST_BITS) - 1)];
        if (e != MISS) {
            br.consume(@intCast(e & 15));
            return e >> 4;
        }
        // Rare long code: pure lookup, so `br` never escapes into a call.
        const r = self.slowLookup(bits);
        if (r.len == 0) {
            br.bad = true;
            return 0;
        }
        br.consume(r.len);
        return r.sym;
    }

    fn slowLookup(self: *const Tree, bits: u32) struct { sym: u16, len: u6 } {
        var code: u32 = 0;
        var first: u32 = 0;
        var index: u32 = 0;
        var b = bits;
        for (1..MAX_LEN + 1) |l| {
            code |= b & 1;
            b >>= 1;
            const count: u32 = self.counts[l];
            if (code < first + count) return .{ .sym = self.syms[index + (code - first)], .len = @intCast(l) };
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        return .{ .sym = 0, .len = 0 };
    }
};

pub inline fn reverse(v: u32, n: u5) u32 {
    if (n == 0) return 0;
    return @bitReverse(v) >> @intCast(32 - @as(u6, n));
}

// ---------------------------------------------------------------------------
// Reading a prefix code from the stream
// ---------------------------------------------------------------------------

const CL_ORDER = [18]u8{ 1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
const CL_PREFIX_LEN = [16]u8{ 2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4 };
const CL_PREFIX_VAL = [16]u8{ 0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5 };

fn alphabetBits(size: usize) u6 {
    var bits: u6 = 0;
    var v: usize = size - 1;
    while (v > 0) : (v >>= 1) bits += 1;
    return bits;
}

/// Read one prefix code over an alphabet of `size` symbols.
pub fn readTree(allocator: std.mem.Allocator, br: *BitReader, size: usize, scratch: []u8) Error!*Tree {
    const lengths = scratch[0..size];
    @memset(lengths, 0);
    const hskip = br.read(2);
    if (hskip == 1) {
        // Simple prefix code.
        const nsym = br.read(2) + 1;
        const abits = alphabetBits(size);
        var syms: [4]u16 = undefined;
        for (0..nsym) |i| {
            const s = br.read(abits);
            if (s >= size) return error.CorruptData;
            for (0..i) |j| if (syms[j] == s) return error.CorruptData;
            syms[i] = @intCast(s);
        }
        switch (nsym) {
            1 => lengths[syms[0]] = 1,
            2 => {
                lengths[syms[0]] = 1;
                lengths[syms[1]] = 1;
            },
            3 => {
                lengths[syms[0]] = 1;
                lengths[syms[1]] = 2;
                lengths[syms[2]] = 2;
            },
            4 => {
                if (br.read(1) == 0) {
                    for (syms[0..4]) |s| lengths[s] = 2;
                } else {
                    lengths[syms[0]] = 1;
                    lengths[syms[1]] = 2;
                    lengths[syms[2]] = 3;
                    lengths[syms[3]] = 3;
                }
            },
            else => unreachable,
        }
        if (br.eof()) return error.InputTooSmall;
        if (nsym == 1) {
            // A one-symbol code costs no bits.
            const t = try allocator.create(Tree);
            t.* = .{ .fast = .{@as(u16, syms[0]) << 4} ** (1 << FAST_BITS), .counts = .{0} ** (MAX_LEN + 1), .syms = &.{}, .single = true, .single_sym = syms[0] };
            return t;
        }
        return Tree.build(allocator, lengths);
    }

    // Complex prefix code: first the code-length code.
    var cl_len: [18]u8 = .{0} ** 18;
    var space: i32 = 32;
    var num_codes: u32 = 0;
    var i: usize = hskip;
    while (i < 18 and space > 0) : (i += 1) {
        const idx = br.peek(4);
        const l = CL_PREFIX_LEN[idx];
        const v = CL_PREFIX_VAL[idx];
        br.consume(@intCast(l));
        cl_len[CL_ORDER[i]] = v;
        if (v != 0) {
            space -= @as(i32, 32) >> @intCast(v);
            num_codes += 1;
        }
    }
    if (br.eof()) return error.InputTooSmall;
    if (!(num_codes == 1 or space == 0)) return error.CorruptData;
    if (num_codes == 0) return error.CorruptData;

    var cl_tree: Tree = undefined;
    var cl_syms: [18]u16 = undefined;
    try cl_tree.init(&cl_syms, &cl_len);

    var symbol: usize = 0;
    var prev_len: u8 = 8;
    var repeat: u32 = 0;
    var repeat_len: u8 = 0;
    var sp: i32 = 32768;
    while (symbol < size and sp > 0) {
        const cs = cl_tree.decode(br);
        if (br.eof()) return error.InputTooSmall;
        if (cs < 16) {
            repeat = 0;
            lengths[symbol] = @intCast(cs);
            symbol += 1;
            if (cs != 0) {
                prev_len = @intCast(cs);
                sp -= @as(i32, 32768) >> @intCast(cs);
            }
        } else {
            const extra: u6 = if (cs == 16) 2 else 3;
            const new_len: u8 = if (cs == 16) prev_len else 0;
            if (repeat_len != new_len) {
                repeat = 0;
                repeat_len = new_len;
            }
            const old = repeat;
            if (repeat > 0) {
                repeat -= 2;
                repeat <<= @intCast(extra);
            }
            repeat += br.read(extra) + 3;
            const delta = repeat - old;
            if (symbol + delta > size) return error.CorruptData;
            @memset(lengths[symbol .. symbol + delta], repeat_len);
            symbol += delta;
            if (repeat_len != 0) sp -= @as(i32, @intCast(delta)) * (@as(i32, 32768) >> @intCast(repeat_len));
        }
    }
    if (br.eof()) return error.InputTooSmall;
    if (sp != 0) return error.CorruptData;
    return Tree.build(allocator, lengths);
}

pub fn freeTree(allocator: std.mem.Allocator, t: *Tree) void {
    if (t.syms.len != 0) allocator.free(t.syms);
    allocator.destroy(t);
}
