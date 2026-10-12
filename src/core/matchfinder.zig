//! LZ77 match finder: dual-stride rolling hash.
//!
//! Two independent hash tables:
//!   - a small 4-byte table for fast short-match discovery (Level 1)
//!   - a larger 8-byte (two 4-byte step) table for long matches
//! Positions are stored as u32 offsets; history window bounded by caller.

const std = @import("std");

pub const Match = struct {
    /// Offset backwards from current position (>= 1).
    dist: u32,
    /// Match length in bytes.
    len: u32,
};

pub const Config = struct {
    /// Log2 of hash table entries (per table).
    hash_log: u6 = 15,
    /// Maximum match distance to search back.
    max_dist: u32 = 1 << 22,
    /// Minimum match length to record.
    min_match: u3 = 4,
};

pub const MatchFinder = struct {
    cfg: Config,
    table4: []u32,
    table8: []u32,
    base: usize = 0,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) !MatchFinder {
        const n: usize = @as(usize, 1) << cfg.hash_log;
        const t4 = try allocator.alloc(u32, n);
        errdefer allocator.free(t4);
        const t8 = try allocator.alloc(u32, n);
        errdefer allocator.free(t8);
        @memset(t4, 0);
        @memset(t8, 0);
        return .{ .cfg = cfg, .table4 = t4, .table8 = t8 };
    }

    pub fn deinit(self: *MatchFinder, allocator: std.mem.Allocator) void {
        allocator.free(self.table4);
        allocator.free(self.table8);
    }

    inline fn hash4(v: u32, log: u6) u32 {
        return (v *% 0x9E3779B1) >> @intCast(32 - log);
    }

    inline fn hash8(a: u32, b: u32, log: u6) u32 {
        return ((a *% 0x9E3779B1) ^ (b *% 0x85EBCA77)) >> @intCast(32 - log);
    }

    /// Find the best match for the bytes at `pos` within `data`.
    /// Returns null when no viable match is found.
    pub fn find(self: *MatchFinder, data: []const u8, pos: usize) ?Match {
        if (pos + self.cfg.min_match > data.len) return null;
        const hlog = self.cfg.hash_log;
        const v4 = std.mem.readInt(u32, data[pos..][0..4], .little);
        const h4 = hash4(v4, hlog);
        const cand4 = self.table4[h4];
        self.table4[h4] = @intCast(pos + 1);

        var best: ?Match = null;

        // 4-byte candidate.
        if (cand4 != 0) {
            const p = self.base + cand4 - 1;
            if (p < pos and pos - p <= self.cfg.max_dist and
                p + self.cfg.min_match <= data.len and
                std.mem.readInt(u32, data[p..][0..4], .little) == v4)
            {
                const len = commonLength(data, p, pos);
                best = .{ .dist = @intCast(pos - p), .len = @intCast(len) };
            }
        }

        // 8-byte (two-step) candidate for longer matches; the table is always
        // updated but only read when the short candidate is weak.
        if (pos + 8 <= data.len) {
            const w0 = std.mem.readInt(u32, data[pos..][0..4], .little);
            const w1 = std.mem.readInt(u32, data[pos + 4 ..][0..4], .little);
            const h8 = hash8(w0, w1, hlog);
            const weak = best == null or best.?.len < 12;
            const cand8 = if (weak) self.table8[h8] else 0;
            self.table8[h8] = @intCast(pos + 1);
            if (cand8 != 0) {
                const p = self.base + cand8 - 1;
                if (p < pos and pos - p <= self.cfg.max_dist and
                    p + self.cfg.min_match <= data.len and
                    std.mem.readInt(u32, data[p..][0..4], .little) == w0 and
                    (best == null or best.?.dist != pos - p))
                {
                    const len = commonLength(data, p, pos);
                    if (len >= self.cfg.min_match and (best == null or len > best.?.len)) {
                        best = .{ .dist = @intCast(pos - p), .len = @intCast(len) };
                    }
                }
            }
        }

        return best;
    }

    /// Hint the CPU to load the table slots `pos` will touch.
    pub inline fn prefetch(self: *MatchFinder, data: []const u8, pos: usize) void {
        if (pos + 8 > data.len) return;
        const hlog = self.cfg.hash_log;
        const w0 = std.mem.readInt(u32, data[pos..][0..4], .little);
        const w1 = std.mem.readInt(u32, data[pos + 4 ..][0..4], .little);
        @prefetch(&self.table4[hash4(w0, hlog)], .{ .rw = .write, .locality = 1, .cache = .data });
        @prefetch(&self.table8[hash8(w0, w1, hlog)], .{ .rw = .write, .locality = 1, .cache = .data });
    }

    /// Record `pos` in the hash tables without searching.
    pub fn insert(self: *MatchFinder, data: []const u8, pos: usize) void {
        if (pos + 4 > data.len) return;
        const hlog = self.cfg.hash_log;
        const w0 = std.mem.readInt(u32, data[pos..][0..4], .little);
        self.table4[hash4(w0, hlog)] = @intCast(pos + 1);
        if (pos + 8 <= data.len) {
            const w1 = std.mem.readInt(u32, data[pos + 4 ..][0..4], .little);
            self.table8[hash8(w0, w1, hlog)] = @intCast(pos + 1);
        }
    }

    /// Reset history (e.g. between independent frames) while keeping tables.
    pub fn reset(self: *MatchFinder) void {
        @memset(self.table4, 0);
        @memset(self.table8, 0);
        self.base = 0;
    }
};

/// Length of the common prefix of `data[p..]` and `data[pos..]`, capped so we
/// never scan past `data.len`.
inline fn commonLength(data: []const u8, p: usize, pos: usize) usize {
    var i: usize = 0;
    const limit = data.len - pos;
    while (i + 8 <= limit) : (i += 8) {
        const a = @as(*align(1) const u64, @ptrCast(data.ptr + p + i)).*;
        const b = @as(*align(1) const u64, @ptrCast(data.ptr + pos + i)).*;
        if (a != b) {
            const x = a ^ b;
            return i + (@ctz(x) / 8);
        }
    }
    while (i < limit and data[p + i] == data[pos + i]) : (i += 1) {}
    return i;
}

test "finds repeated block" {
    const allocator = std.testing.allocator;
    var mf = try MatchFinder.init(allocator, .{});
    defer mf.deinit(allocator);

    const text = "abcdefghij" ** 5;
    // Walk to the second occurrence start (offset 10).
    _ = mf.find(text, 0);
    _ = mf.find(text, 1);
    const m = mf.find(text, 10);
    try std.testing.expect(m != null);
    try std.testing.expect(m.?.dist == 10);
    try std.testing.expect(m.?.len >= 10);
}
