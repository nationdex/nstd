//! Finite State Entropy (tANS) primitives for Zstandard (RFC 8878 §4.1).
//!
//! Contains the backward bit reader/writer used by every Zstd entropy stream,
//! normalized-count header parsing/serialization, decode-table construction,
//! encode-table construction and count normalization.

const std = @import("std");

pub const Error = error{ CorruptData, NoSpaceLeft };

// ---------------------------------------------------------------------------
// Backward bit reader
// ---------------------------------------------------------------------------

/// Reads bits from the end of a buffer toward its start. The final byte carries
/// a sentinel `1` bit marking where the stream begins.
pub const RevReader = struct {
    data: []const u8,
    /// Number of unread bits. May go negative when a caller reads past the
    /// start; such bits read as zero.
    pos: i64,

    pub fn init(data: []const u8) Error!RevReader {
        if (data.len == 0) return error.CorruptData;
        const last = data[data.len - 1];
        if (last == 0) return error.CorruptData;
        const hb: i64 = 7 - @as(i64, @clz(last));
        return .{ .data = data, .pos = @as(i64, @intCast(data.len - 1)) * 8 + hb };
    }

    inline fn load(self: *const RevReader, bitpos: usize) u64 {
        const byte = bitpos >> 3;
        const shift: u6 = @intCast(bitpos & 7);
        var v: u64 = 0;
        if (byte + 8 <= self.data.len) {
            v = std.mem.readInt(u64, self.data[byte..][0..8], .little);
        } else if (byte < self.data.len) {
            var tmp: [8]u8 = .{0} ** 8;
            @memcpy(tmp[0 .. self.data.len - byte], self.data[byte..]);
            v = std.mem.readInt(u64, &tmp, .little);
        }
        return v >> shift;
    }

    /// Look at the next `n` bits (n <= 56) without consuming them.
    pub inline fn peek(self: *const RevReader, n: u6) u64 {
        if (n == 0) return 0;
        const mask = (@as(u64, 1) << n) - 1;
        const p = self.pos - @as(i64, n);
        if (p >= 0) return self.load(@intCast(p)) & mask;
        const have = @as(i64, n) + p; // bits still present
        if (have <= 0) return 0;
        const hv: u6 = @intCast(have);
        const low = self.load(0) & ((@as(u64, 1) << hv) - 1);
        return low << @intCast(-p);
    }

    pub inline fn consume(self: *RevReader, n: u6) void {
        self.pos -= n;
    }

    pub inline fn read(self: *RevReader, n: u6) u64 {
        const v = self.peek(n);
        self.pos -= n;
        return v;
    }

    pub inline fn overflowed(self: *const RevReader) bool {
        return self.pos < 0;
    }
};

/// Throughput-oriented backward reader. An 8-byte window of the stream lives in
/// `v` (next bit = MSB); `used` bits have been consumed from its top. `reload`
/// slides the window down so at least 56 bits are available while bytes remain;
/// near the stream start missing bits read as zero and `bitsLeft` goes negative
/// on overrun.
pub const FastRev = struct {
    data: []const u8,
    /// Index of the window's lowest byte.
    ptr: usize,
    v: u64,
    used: u32,
    /// Zero bits below the stream start when it is shorter than the window.
    pad: u32 = 0,

    pub fn init(data: []const u8) Error!FastRev {
        if (data.len == 0) return error.CorruptData;
        const last = data[data.len - 1];
        if (last == 0) return error.CorruptData;
        var r: FastRev = undefined;
        r.data = data;
        r.pad = 0;
        r.used = @as(u32, @clz(last)) + 1;
        if (data.len >= 8) {
            r.ptr = data.len - 8;
            r.v = std.mem.readInt(u64, data[r.ptr..][0..8], .little);
        } else {
            var buf: [8]u8 = .{0} ** 8;
            @memcpy(buf[8 - data.len ..], data);
            r.ptr = 0;
            r.pad = @intCast(8 * (8 - data.len));
            r.v = std.mem.readInt(u64, &buf, .little);
        }
        return r;
    }

    /// Slide the window toward the stream start by the whole bytes consumed.
    pub inline fn reload(self: *FastRev) void {
        const back = @min(self.used >> 3, self.ptr);
        if (back == 0) return;
        self.ptr -= back;
        self.used -= @intCast(back * 8);
        self.v = std.mem.readInt(u64, self.data[self.ptr..][0..8], .little);
    }

    /// `reload` for callers that know at least 8 whole bytes remain below the window.
    pub inline fn reloadFast(self: *FastRev) void {
        const back = self.used >> 3;
        self.ptr -= back;
        self.used &= 7;
        self.v = std.mem.readInt(u64, self.data[self.ptr..][0..8], .little);
    }

    /// `get` without the end-of-stream guard: valid while `used < 64` (i.e. after
    /// `reloadFast` and at most 56 further bits).
    pub inline fn getFast(self: *FastRev, n: u6) u64 {
        if (n == 0) return 0;
        const r = ((self.v << @intCast(self.used)) >> 1) >> @intCast(63 - @as(u7, n));
        self.used += n;
        return r;
    }

    /// Next `n` bits (0 <= n <= 56 after a reload), consumed.
    pub inline fn get(self: *FastRev, n: u6) u64 {
        const r = self.peekAny(n);
        self.used += n;
        return r;
    }

    /// Like `peek` but valid for n == 0 (two-step shift avoids a shift by 64).
    pub inline fn peekAny(self: *const FastRev, n: u6) u64 {
        if (self.used >= 64) return 0;
        return ((self.v << @intCast(self.used)) >> 1) >> @intCast(63 - @as(u7, n));
    }

    /// `peek` for n >= 1 without the end-of-stream test. A corrupt stream may
    /// push `used` past 63; the masked shift then yields wrong (but in-range)
    /// bits and the final `bitsLeft` check rejects the stream.
    pub inline fn peekFast(self: *const FastRev, n: u6) u64 {
        return (self.v << @intCast(self.used & 63)) >> @intCast(64 - @as(u7, n));
    }

    pub inline fn peek(self: *const FastRev, n: u6) u64 {
        if (self.used >= 64) return 0;
        return (self.v << @intCast(self.used)) >> @intCast(64 - @as(u7, n));
    }

    pub inline fn skip(self: *FastRev, n: u6) void {
        self.used += n;
    }

    /// Unread bits (negative when more were consumed than the stream held).
    pub inline fn bitsLeft(self: *const FastRev) i64 {
        return @as(i64, @intCast(self.ptr)) * 8 + 64 - @as(i64, self.used) - @as(i64, self.pad);
    }
};

// ---------------------------------------------------------------------------
// Bit writer for backward streams
// ---------------------------------------------------------------------------

/// Accumulates bits LSB-first into a fixed buffer. The decoder reads the same
/// bytes backward, so symbols must be fed in reverse decode order.
pub const BitW = struct {
    buf: []u8,
    len: usize = 0,
    acc: u64 = 0,
    n: u6 = 0,
    overflow: bool = false,

    pub fn init(buf: []u8) BitW {
        return .{ .buf = buf };
    }

    /// Append the low `nb` bits of `v` (nb <= 56). Whole bytes are flushed with
    /// one unaligned 8-byte store; the buffer needs 8 bytes of slack.
    pub inline fn put(self: *BitW, v: u64, nb: u6) void {
        self.acc |= (v & ((@as(u64, 1) << nb) -% 1)) << self.n;
        self.n += nb;
        if (self.len + 8 > self.buf.len) {
            self.overflow = true;
            self.acc = 0;
            self.n = 0;
            return;
        }
        std.mem.writeInt(u64, self.buf[self.len..][0..8], self.acc, .little);
        const bytes: u6 = self.n >> 3;
        self.len += bytes;
        self.acc >>= bytes * 8;
        self.n &= 7;
    }

    /// Append the sentinel bit, flush, and return the byte count.
    pub fn close(self: *BitW) Error!usize {
        self.put(1, 1);
        if (self.n > 0) {
            if (self.len >= self.buf.len) return error.NoSpaceLeft;
            self.buf[self.len] = @truncate(self.acc);
            self.len += 1;
            self.acc = 0;
            self.n = 0;
        }
        if (self.overflow) return error.NoSpaceLeft;
        return self.len;
    }
};

// ---------------------------------------------------------------------------
// Normalized counts
// ---------------------------------------------------------------------------

pub const NCount = struct {
    norm: [256]i16 = .{0} ** 256,
    nsym: usize = 0,
    log: u8 = 0,
    consumed: usize = 0,
};

fn peekFwd(src: []const u8, bitpos: usize, n: u6) u32 {
    const byte = bitpos >> 3;
    var tmp: [8]u8 = .{0} ** 8;
    if (byte < src.len) {
        const take = @min(8, src.len - byte);
        @memcpy(tmp[0..take], src[byte..][0..take]);
    }
    const v = std.mem.readInt(u64, &tmp, .little) >> @intCast(bitpos & 7);
    return @truncate(v & ((@as(u64, 1) << n) - 1));
}

/// Parse an FSE table description (RFC 8878 §4.1.1).
pub fn readNCount(src: []const u8, max_sym: usize, max_log: u8) Error!NCount {
    var r = NCount{};
    if (src.len == 0) return error.CorruptData;
    var bitpos: usize = 0;
    const al: u8 = @as(u8, @intCast(peekFwd(src, 0, 4))) + 5;
    bitpos += 4;
    if (al > max_log) return error.CorruptData;
    r.log = al;
    var remaining: i32 = (@as(i32, 1) << @intCast(al)) + 1;
    var threshold: i32 = @as(i32, 1) << @intCast(al);
    var nb: u6 = @intCast(al + 1);
    var sym: usize = 0;

    while (remaining > 1 and sym < max_sym) {
        const max: i32 = 2 * threshold - 1 - remaining;
        const bits: i32 = @intCast(peekFwd(src, bitpos, nb));
        var count: i32 = undefined;
        if ((bits & (threshold - 1)) < max) {
            count = bits & (threshold - 1);
            bitpos += nb - 1;
        } else {
            count = bits & (2 * threshold - 1);
            if (count >= threshold) count -= max;
            bitpos += nb;
        }
        count -= 1;
        remaining -= if (count < 0) -count else count;
        r.norm[sym] = @intCast(count);
        sym += 1;
        if (count == 0) {
            while (true) {
                const rep = peekFwd(src, bitpos, 2);
                bitpos += 2;
                sym += rep;
                if (sym > max_sym) return error.CorruptData;
                if (rep != 3) break;
            }
        }
        while (remaining < threshold) {
            nb -= 1;
            threshold >>= 1;
        }
    }
    if (remaining != 1) return error.CorruptData;
    r.nsym = sym;
    r.consumed = (bitpos + 7) / 8;
    if (r.consumed > src.len) return error.CorruptData;
    return r;
}

/// Serialize an FSE table description. `norm` must be indexed 0..nsym where
/// `nsym - 1` is the last symbol with a nonzero count.
pub fn writeNCount(out: []u8, norm: []const i16, nsym: usize, log: u8) Error!usize {
    var w = BitW.init(out);
    const size: i32 = @as(i32, 1) << @intCast(log);
    w.put(log - 5, 4);
    var remaining: i32 = size + 1;
    var threshold: i32 = size;
    var nb: u6 = @intCast(log + 1);
    var sym: usize = 0;
    var prev0 = false;

    while (sym < nsym and remaining > 1) {
        if (prev0) {
            var start = sym;
            while (sym < nsym and norm[sym] == 0) sym += 1;
            if (sym >= nsym) break;
            while (sym >= start + 24) {
                start += 24;
                w.put(0xFFFF, 16);
            }
            while (sym >= start + 3) {
                start += 3;
                w.put(3, 2);
            }
            w.put(sym - start, 2);
        }
        const c: i32 = norm[sym];
        sym += 1;
        const max: i32 = 2 * threshold - 1 - remaining;
        remaining -= if (c < 0) -c else c;
        var v: i32 = c + 1;
        if (v >= threshold) v += max;
        if (v < max) w.put(@intCast(v), nb - 1) else w.put(@intCast(v), nb);
        prev0 = (c == 0);
        while (remaining < threshold) {
            nb -= 1;
            threshold >>= 1;
        }
    }
    // Flush partial byte without a sentinel.
    if (w.n > 0) {
        if (w.len >= w.buf.len) return error.NoSpaceLeft;
        w.buf[w.len] = @truncate(w.acc);
        w.len += 1;
    }
    if (w.overflow) return error.NoSpaceLeft;
    return w.len;
}

/// Scale `counts` to a power-of-two total of `1 << log`, keeping every present
/// symbol at probability >= 1. Returns the number of symbols (last nonzero + 1).
pub fn normalize(counts: []const u32, total: u64, log: u8, norm: []i16) usize {
    const size: i64 = @as(i64, 1) << @intCast(log);
    var sum: i64 = 0;
    var largest: usize = 0;
    var nsym: usize = 0;
    for (counts, 0..) |c, s| {
        if (c == 0) {
            norm[s] = 0;
            continue;
        }
        var n: i64 = @intCast((@as(u64, c) * @as(u64, @intCast(size)) * 2 + total) / (total * 2));
        if (n < 1) n = 1;
        norm[s] = @intCast(n);
        sum += n;
        nsym = s + 1;
        if (c > counts[largest]) largest = s;
    }
    var diff = size - sum;
    if (diff >= 0) {
        norm[largest] += @intCast(diff);
    } else {
        while (diff < 0) {
            // shave from the symbol with the largest probability above 1
            var best: usize = largest;
            var bn: i16 = 0;
            for (norm[0..nsym], 0..) |n, s| {
                if (n > bn) {
                    bn = n;
                    best = s;
                }
            }
            const take: i64 = @min(@as(i64, bn) - 1, -diff);
            if (take <= 0) break;
            norm[best] -= @intCast(take);
            diff += take;
        }
    }
    return nsym;
}

/// Estimated payload bits to code `counts` with distribution `norm`, or null
/// if some present symbol has zero probability.
pub fn costBits(counts: []const u32, norm: []const i16, log: u8) ?f64 {
    var bits: f64 = 0;
    for (counts, 0..) |c, s| {
        if (c == 0) continue;
        if (s >= norm.len or norm[s] == 0) return null;
        const p: f64 = if (norm[s] < 0) 1 else @floatFromInt(norm[s]);
        bits += @as(f64, @floatFromInt(c)) * (@as(f64, @floatFromInt(log)) - std.math.log2(p));
    }
    return bits;
}

// ---------------------------------------------------------------------------
// Decode table
// ---------------------------------------------------------------------------

pub const DEntry = struct { sym: u8 = 0, nb: u8 = 0, base: u16 = 0 };
pub const MAX_LOG = 9;

pub const DTable = struct {
    log: u8 = 0,
    e: [1 << MAX_LOG]DEntry = undefined,

    pub fn rle(sym: u8) DTable {
        var t = DTable{};
        t.e[0] = .{ .sym = sym, .nb = 0, .base = 0 };
        return t;
    }

    pub fn build(norm: []const i16, log: u8) Error!DTable {
        if (log > MAX_LOG) return error.CorruptData;
        var t = DTable{ .log = log };
        const size: usize = @as(usize, 1) << @intCast(log);
        const mask = size - 1;
        var high: isize = @intCast(size - 1);
        var next: [256]u16 = undefined;
        var total: usize = 0;
        for (norm, 0..) |n, s| {
            if (n == -1) {
                t.e[@intCast(high)].sym = @intCast(s);
                high -= 1;
                next[s] = 1;
                total += 1;
            } else if (n >= 0) {
                next[s] = @intCast(n);
                total += @intCast(n);
            } else return error.CorruptData;
        }
        if (total != size) return error.CorruptData;
        const step = (size >> 1) + (size >> 3) + 3;
        var pos: usize = 0;
        for (norm, 0..) |n, s| {
            if (n <= 0) continue;
            var i: i16 = 0;
            while (i < n) : (i += 1) {
                t.e[pos].sym = @intCast(s);
                pos = (pos + step) & mask;
                while (@as(isize, @intCast(pos)) > high) pos = (pos + step) & mask;
            }
        }
        if (pos != 0) return error.CorruptData;
        for (0..size) |u| {
            const s = t.e[u].sym;
            const ns: u32 = next[s];
            next[s] += 1;
            const nb: u8 = log - @as(u8, @intCast(31 - @clz(ns)));
            t.e[u].nb = nb;
            t.e[u].base = @intCast((ns << @intCast(nb)) - size);
        }
        return t;
    }
};

// ---------------------------------------------------------------------------
// Encode table
// ---------------------------------------------------------------------------

pub const SymTT = struct { delta_nb: u32 = 0, delta_find: i32 = 0 };

pub const CTable = struct {
    log: u8 = 0,
    is_rle: bool = false,
    state_table: [1 << 9]u16 = undefined,
    tt: [64]SymTT = .{SymTT{}} ** 64,

    pub fn build(norm: []const i16, log: u8) CTable {
        var t = CTable{ .log = log };
        const size: usize = @as(usize, 1) << @intCast(log);
        const mask = size - 1;
        var sym_tab: [1 << 9]u8 = undefined;
        var cumul: [65]u32 = undefined;
        var high: isize = @intCast(size - 1);
        cumul[0] = 0;
        for (norm, 0..) |n, s| {
            if (n == -1) {
                cumul[s + 1] = cumul[s] + 1;
                sym_tab[@intCast(high)] = @intCast(s);
                high -= 1;
            } else {
                cumul[s + 1] = cumul[s] + @as(u32, @intCast(n));
            }
        }
        const step = (size >> 1) + (size >> 3) + 3;
        var pos: usize = 0;
        for (norm, 0..) |n, s| {
            if (n <= 0) continue;
            var i: i16 = 0;
            while (i < n) : (i += 1) {
                sym_tab[pos] = @intCast(s);
                pos = (pos + step) & mask;
                while (@as(isize, @intCast(pos)) > high) pos = (pos + step) & mask;
            }
        }
        for (0..size) |u| {
            const s = sym_tab[u];
            t.state_table[cumul[s]] = @intCast(size + u);
            cumul[s] += 1;
        }
        var total: i32 = 0;
        for (norm, 0..) |n, s| {
            switch (n) {
                0 => t.tt[s].delta_nb = ((@as(u32, log) + 1) << 16) - (@as(u32, 1) << @intCast(log)),
                -1, 1 => {
                    t.tt[s].delta_nb = (@as(u32, log) << 16) - (@as(u32, 1) << @intCast(log));
                    t.tt[s].delta_find = total - 1;
                    total += 1;
                },
                else => {
                    const nn: u32 = @intCast(n);
                    const max_bits_out: u32 = log - @as(u32, @intCast(31 - @clz(nn - 1)));
                    const min_state_plus: u32 = nn << @intCast(max_bits_out);
                    t.tt[s].delta_nb = (max_bits_out << 16) -% min_state_plus;
                    t.tt[s].delta_find = total - @as(i32, @intCast(nn));
                    total += @intCast(nn);
                },
            }
        }
        return t;
    }

    pub fn rleTable() CTable {
        return .{ .is_rle = true };
    }

    /// Initial state for the first symbol coded (the last one decoded).
    pub inline fn initState(self: *const CTable, sym: u8) u32 {
        if (self.is_rle) return 0;
        const tt = self.tt[sym];
        const nb = (tt.delta_nb +% (1 << 15)) >> 16;
        const value = (nb << 16) -% tt.delta_nb;
        const idx: i32 = @as(i32, @intCast(value >> @intCast(nb))) + tt.delta_find;
        return self.state_table[@intCast(idx)];
    }

    pub inline fn encode(self: *const CTable, w: *BitW, state: *u32, sym: u8) void {
        if (self.is_rle) return;
        const tt = self.tt[sym];
        const nb: u32 = (state.* +% tt.delta_nb) >> 16;
        w.put(state.*, @intCast(nb));
        const idx: i32 = @as(i32, @intCast(state.* >> @intCast(nb))) + tt.delta_find;
        state.* = self.state_table[@intCast(idx)];
    }

    pub inline fn flush(self: *const CTable, w: *BitW, state: u32) void {
        if (self.is_rle) return;
        w.put(state, @intCast(self.log));
    }
};

test "ncount roundtrip" {
    var norm: [64]i16 = .{0} ** 64;
    const counts = [_]u32{ 100, 50, 0, 0, 0, 20, 7, 1, 300 };
    const n = normalize(&counts, 478, 6, &norm);
    try std.testing.expectEqual(@as(usize, 9), n);
    var buf: [64]u8 = undefined;
    const len = try writeNCount(&buf, &norm, n, 6);
    const r = try readNCount(buf[0..len], 64, 9);
    try std.testing.expectEqual(len, r.consumed);
    try std.testing.expectEqual(@as(u8, 6), r.log);
    for (0..n) |i| try std.testing.expectEqual(norm[i], r.norm[i]);
}
