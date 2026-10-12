//! Gzip (RFC 1952) container around the Deflate engine.

const std = @import("std");
const deflate_mod = @import("deflate.zig");
const checksum = @import("../core/checksum.zig");

pub const Error = deflate_mod.Error || error{BadHeader};

/// Compress `input` into a gzip member (uses the default deflate level).
pub fn compress(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    return compressLevel(allocator, input, 6);
}

/// Compress `input` into a gzip member at the given deflate level (1-9).
pub fn compressLevel(allocator: std.mem.Allocator, input: []const u8, level: i32) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    // Header: magic, CM=8, FLG=0, MTIME=0, XFL=0, OS=255.
    try out.appendSlice(&[_]u8{ 0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 255 });

    const body = try deflate_mod.deflateLevel(allocator, input, level);
    defer allocator.free(body);
    try out.appendSlice(body);

    const c = checksum.crc32(input, 0);
    var trailer: [8]u8 = undefined;
    std.mem.writeInt(u32, trailer[0..4], c, .little);
    std.mem.writeInt(u32, trailer[4..8], @intCast(input.len), .little);
    try out.appendSlice(&trailer);
    return out.toOwnedSlice();
}

/// Decompress gzip data (one or more concatenated members), verifying CRC32 and
/// ISIZE of every member.
pub fn decompress(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    var pos: usize = 0;
    var members: usize = 0;
    while (pos + 10 <= input.len and input[pos] == 0x1f and input[pos + 1] == 0x8b) {
        if (input[pos + 2] != 8) return error.BadHeader;
        const flg = input[pos + 3];
        pos += 10;
        if (flg & 0x04 != 0) { // FEXTRA
            if (pos + 2 > input.len) return error.BadHeader;
            const xlen = std.mem.readInt(u16, input[pos..][0..2], .little);
            pos += 2 + xlen;
        }
        if (flg & 0x08 != 0) { // FNAME
            while (pos < input.len and input[pos] != 0) : (pos += 1) {}
            pos += 1;
        }
        if (flg & 0x10 != 0) { // FCOMMENT
            while (pos < input.len and input[pos] != 0) : (pos += 1) {}
            pos += 1;
        }
        if (flg & 0x02 != 0) pos += 2; // FHCRC
        if (pos > input.len) return error.BadHeader;

        // The trailer's ISIZE (valid for the last member) pre-sizes the output.
        // Deflate cannot expand beyond ~1032x, so a larger claim is a forged or
        // truncated trailer and must not drive allocation.
        const hint: usize = if (input.len >= 4 and members == 0)
            @min(std.mem.readInt(u32, input[input.len - 4 ..][0..4], .little), input.len * 1032)
        else
            0;
        const r = try deflate_mod.inflateEx(allocator, input[pos..], hint);
        defer allocator.free(r.data);
        pos += r.consumed;
        if (pos + 8 > input.len) return error.InputTooSmall;
        const want_crc = std.mem.readInt(u32, input[pos..][0..4], .little);
        const want_len = std.mem.readInt(u32, input[pos + 4 ..][0..4], .little);
        if (want_crc != checksum.crc32(r.data, 0) or want_len != @as(u32, @truncate(r.data.len))) return error.CorruptData;
        pos += 8;
        try out.appendSlice(r.data);
        members += 1;
    }
    if (members == 0) return error.BadHeader;
    return out.toOwnedSlice();
}

test "gzip stored blocks and multi-member" {
    const a = std.testing.allocator;
    const data = "stored block payload, not compressed at all";
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();
    for (0..2) |_| {
        try buf.appendSlice(&[_]u8{ 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255 });
        try buf.append(0x01); // BFINAL, stored
        try buf.appendSlice(&std.mem.toBytes(@as(u16, data.len)));
        try buf.appendSlice(&std.mem.toBytes(~@as(u16, data.len)));
        try buf.appendSlice(data);
        try buf.appendSlice(&std.mem.toBytes(checksum.crc32(data, 0)));
        try buf.appendSlice(&std.mem.toBytes(@as(u32, data.len)));
    }
    const d = try decompress(a, buf.items);
    defer a.free(d);
    try std.testing.expectEqualStrings(data ++ data, d);
}

test "gzip round trip with far matches" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(7);
    const rng = prng.random();
    const buf = try a.alloc(u8, 200000);
    defer a.free(buf);
    for (buf, 0..) |*b, i| b.* = if (i % 50000 < 100) "0123456789"[i % 10] else rng.int(u8);
    const z = try compress(a, buf);
    defer a.free(z);
    const d = try decompress(a, z);
    defer a.free(d);
    try std.testing.expectEqualSlices(u8, buf, d);
}

test "truncated gzip fails fast instead of spinning" {
    const a = std.testing.allocator;
    const text = "the quick brown fox jumps over the lazy dog. " ** 2000;
    const z = try compress(a, text);
    defer a.free(z);
    var cut: usize = 0;
    while (cut < z.len - 1) : (cut += @max(1, z.len / 40)) {
        if (decompress(a, z[0..cut])) |d| a.free(d) else |_| {}
    }
}
