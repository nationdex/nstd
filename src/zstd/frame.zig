//! Zstandard frame + block layer (RFC 8878).

const std = @import("std");

pub const ZSTD_MAGIC: u32 = 0xFD2FB528;
pub const ZSTD_MAGIC_SKIPPABLE_MIN: u32 = 0x184D2A50;
pub const ZSTD_MAGIC_SKIPPABLE_MAX: u32 = 0x184D2A5F;
pub const BLOCK_MAX: usize = 128 * 1024;

pub const BlockType = enum(u2) {
    raw = 0,
    rle = 1,
    compressed = 2,
    reserved = 3,
};

pub const FrameHeader = struct {
    single_segment: bool = false,
    content_checksum: bool = false,
    dict_id: u32 = 0,
    /// Frame content size, or null when unknown (streaming).
    content_size: ?u64 = null,
    window_log: u6 = 20,
};

pub const BlockHeader = struct {
    last: bool,
    type: BlockType,
    size: u32,
};

/// Serialize the frame header for `hdr` into `out`. Returns bytes written.
pub fn writeFrameHeader(out: *std.ArrayList(u8), hdr_in: FrameHeader) !void {
    var hdr = hdr_in;
    // A sub-256 content size can only be expressed in single-segment mode.
    if (hdr.content_size) |sz| {
        if (sz < 256) hdr.single_segment = true;
    }
    const magic = ZSTD_MAGIC;
    try out.appendSlice(&std.mem.toBytes(magic));

    var fhd: u8 = 0;
    if (hdr.single_segment) fhd |= 0x20;
    if (hdr.content_checksum) fhd |= 0x04;

    const fcs: ?u64 = hdr.content_size;
    var fcs_code: u2 = 0;
    var fcs_bytes: u8 = 0;
    if (fcs) |sz| {
        if (sz < 256) {
            fcs_code = 0;
            fcs_bytes = 1;
        } else if (sz < 65536 + 256) {
            fcs_code = 1;
            fcs_bytes = 2;
        } else if (sz < (1 << 32)) {
            fcs_code = 2;
            fcs_bytes = 4;
        } else {
            fcs_code = 3;
            fcs_bytes = 8;
        }
    }

    var dict_id_flag: u2 = 0;
    var dict_id_bytes: usize = 0;
    if (hdr.dict_id != 0) {
        if (hdr.dict_id <= 0xFF) {
            dict_id_flag = 1;
            dict_id_bytes = 1;
        } else if (hdr.dict_id <= 0xFFFF) {
            dict_id_flag = 2;
            dict_id_bytes = 2;
        } else {
            dict_id_flag = 3;
            dict_id_bytes = 4;
        }
    }

    fhd |= dict_id_flag;
    fhd |= @as(u8, fcs_code) << 6;
    try out.append(fhd);

    if (!hdr.single_segment) {
        // Window_Descriptor: exponent = window_log - 10, mantissa 0.
        const exp: u8 = @intCast(hdr.window_log - 10);
        try out.append(exp << 3);
    }

    if (dict_id_bytes > 0) {
        var dbuf: [4]u8 = undefined;
        std.mem.writeInt(u32, &dbuf, hdr.dict_id, .little);
        try out.appendSlice(dbuf[0..dict_id_bytes]);
    }

    if (fcs_bytes > 0) {
        const bias: u64 = if (fcs_bytes == 2) 256 else 0;
        const sz: u64 = fcs.? - bias;
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, sz, .little);
        try out.appendSlice(buf[0..fcs_bytes]);
    }
}

/// Parse a frame header from `src`. Returns header and bytes consumed.
pub fn readFrameHeader(src: []const u8) !struct { hdr: FrameHeader, consumed: usize } {
    if (src.len < 5) return error.InputTooSmall;
    const magic = std.mem.readInt(u32, src[0..4], .little);
    if (magic != ZSTD_MAGIC) return error.CorruptData;

    const fhd = src[4];
    var hdr: FrameHeader = .{};
    hdr.single_segment = (fhd & 0x20) != 0;
    hdr.content_checksum = (fhd & 0x04) != 0;

    const dict_id_size: usize = switch (@as(u2, @truncate(fhd & 0x03))) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
    };
    const fcs_code: u2 = @intCast((fhd >> 6) & 0x03);

    var pos: usize = 5;
    if (!hdr.single_segment) {
        if (pos >= src.len) return error.InputTooSmall;
        const wd = src[pos];
        const exp: u6 = @intCast((wd >> 3) & 0x1F);
        hdr.window_log = exp + 10;
        pos += 1;
    }
    if (dict_id_size > 0) {
        if (pos + dict_id_size > src.len) return error.InputTooSmall;
        var d: u32 = 0;
        for (0..dict_id_size) |i| d |= @as(u32, src[pos + i]) << @intCast(8 * i);
        hdr.dict_id = d;
        pos += dict_id_size;
    }

    const fcs_bytes: usize = switch (fcs_code) {
        0 => if (hdr.single_segment) 1 else 0,
        1 => 2,
        2 => 4,
        3 => 8,
    };
    if (fcs_bytes > 0) {
        if (pos + fcs_bytes > src.len) return error.InputTooSmall;
        var v: u64 = 0;
        for (0..fcs_bytes) |i| v |= @as(u64, src[pos + i]) << @intCast(8 * i);
        v += if (fcs_code == 1) 256 else 0;
        hdr.content_size = v;
        pos += fcs_bytes;
    }
    return .{ .hdr = hdr, .consumed = pos };
}

/// Encode a 3-byte block header.
pub fn writeBlockHeader(out: *std.ArrayList(u8), bh: BlockHeader) !void {
    const raw: u24 = @as(u24, @intFromBool(bh.last)) |
        (@as(u24, @intFromEnum(bh.type)) << 1) |
        (@as(u24, @intCast(bh.size)) << 3);
    try out.append(@truncate(raw));
    try out.append(@truncate(raw >> 8));
    try out.append(@truncate(raw >> 16));
}

/// Decode a 3-byte block header.
pub fn readBlockHeader(src: []const u8) !BlockHeader {
    if (src.len < 3) return error.InputTooSmall;
    const raw: u24 = @as(u24, src[0]) | (@as(u24, src[1]) << 8) | (@as(u24, src[2]) << 16);
    const last = (raw & 1) != 0;
    const btype: u2 = @intCast((raw >> 1) & 0x03);
    const size: u32 = raw >> 3;
    return .{ .last = last, .type = @enumFromInt(btype), .size = size };
}

/// True when `src` begins with a skippable-frame magic number.
pub fn isSkippable(src: []const u8) bool {
    if (src.len < 4) return false;
    const m = std.mem.readInt(u32, src[0..4], .little);
    return m >= ZSTD_MAGIC_SKIPPABLE_MIN and m <= ZSTD_MAGIC_SKIPPABLE_MAX;
}

test "frame header dict_id round-trip" {
    const a = std.testing.allocator;
    for ([_]u32{ 0, 42, 1000, 0x12345678 }) |did| {
        var out = std.ArrayList(u8).init(a);
        defer out.deinit();
        try writeFrameHeader(&out, .{
            .single_segment = true,
            .content_checksum = true,
            .dict_id = did,
            .content_size = 500,
        });
        const parsed = try readFrameHeader(out.items);
        try std.testing.expectEqual(did, parsed.hdr.dict_id);
        try std.testing.expectEqual(@as(?u64, 500), parsed.hdr.content_size);
        try std.testing.expect(parsed.hdr.single_segment);
        try std.testing.expect(parsed.hdr.content_checksum);
    }
}
