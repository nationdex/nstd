//! Unified C ABI for Nstandard (nstd).
//!
//! Exposes a native API plus drop-in symbol aliases so existing C callers of
//! libzstd / zlib can link against nstd without source changes. Error values
//! follow libzstd's convention: an error is `(size_t)-code`.

const std = @import("std");
const root = @import("root.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const alloc = gpa.allocator();

// ---------------------------------------------------------------------------
// Native nstd API
// ---------------------------------------------------------------------------

/// Compress with the requested codec: 0 = zstd, 1 = gzip, 2 = brotli.
export fn nstd_compress(codec: u32, src: [*]const u8, src_len: usize, dst: [*]u8, dst_len: usize) isize {
    const input = src[0..src_len];
    const out = switch (codec) {
        0 => root.zstd.compress.compress(alloc, input) catch return -1,
        1 => root.deflate.gzip.compress(alloc, input) catch return -1,
        2 => root.brotli.compress.compress(alloc, input) catch return -1,
        else => return -1,
    };
    defer alloc.free(out);
    if (out.len > dst_len) return -1;
    @memcpy(dst[0..out.len], out);
    return @intCast(out.len);
}

/// Decompress with the requested codec.
export fn nstd_decompress(codec: u32, src: [*]const u8, src_len: usize, dst: [*]u8, dst_len: usize) isize {
    const input = src[0..src_len];
    const out = switch (codec) {
        0 => root.zstd.decompress.decompress(alloc, input) catch return -1,
        1 => root.deflate.gzip.decompress(alloc, input) catch return -1,
        2 => root.brotli.decompress.decompress(alloc, input) catch return -1,
        else => return -1,
    };
    defer alloc.free(out);
    if (out.len > dst_len) return -1;
    @memcpy(dst[0..out.len], out);
    return @intCast(out.len);
}

export fn nstd_version() [*:0]const u8 {
    return "nstd 0.2.0";
}

// ---------------------------------------------------------------------------
// libzstd: errors
// ---------------------------------------------------------------------------

const ZE = struct {
    const generic = 1;
    const prefix_unknown = 10;
    const frame_param_unsupported = 14;
    const corruption = 20;
    const checksum_wrong = 22;
    const dictionary_wrong = 32;
    const stage_wrong = 60;
    const memory_allocation = 64;
    const dst_too_small = 70;
    const src_size_wrong = 72;
    const dst_null = 74;
};

inline fn zerr(code: usize) usize {
    return 0 -% code;
}

fn mapDecErr(e: anyerror) usize {
    return switch (e) {
        error.OutOfMemory => zerr(ZE.memory_allocation),
        error.InputTooSmall => zerr(ZE.src_size_wrong),
        error.ChecksumMismatch => zerr(ZE.checksum_wrong),
        error.Unsupported => zerr(ZE.dictionary_wrong),
        else => zerr(ZE.corruption),
    };
}

export fn ZSTD_isError(code: usize) c_uint {
    return if (code > zerr(120)) 1 else 0;
}

export fn ZSTD_getErrorCode(code: usize) c_int {
    return if (code > zerr(120)) @intCast(0 -% code) else 0;
}

export fn ZSTD_getErrorName(code: usize) [*:0]const u8 {
    if (code <= zerr(120)) return "No error detected";
    return switch (0 -% code) {
        ZE.generic => "Error (generic)",
        ZE.prefix_unknown => "Unknown frame descriptor",
        ZE.frame_param_unsupported => "Unsupported frame parameter",
        ZE.corruption => "Data corruption detected",
        ZE.checksum_wrong => "Restored data doesn't match checksum",
        ZE.dictionary_wrong => "Dictionary mismatch",
        ZE.stage_wrong => "Operation not authorized at current processing stage",
        ZE.memory_allocation => "Allocation error : not enough memory",
        ZE.dst_too_small => "Destination buffer is too small",
        ZE.src_size_wrong => "Src size is incorrect",
        ZE.dst_null => "Operation on NULL destination buffer",
        else => "Unspecified error code",
    };
}

// ---------------------------------------------------------------------------
// libzstd: one-shot
// ---------------------------------------------------------------------------

export fn ZSTD_versionNumber() c_uint {
    return 10507;
}

export fn ZSTD_versionString() [*:0]const u8 {
    return "1.5.7";
}

export fn ZSTD_minCLevel() c_int {
    return -131072;
}

export fn ZSTD_maxCLevel() c_int {
    return 22;
}

export fn ZSTD_defaultCLevel() c_int {
    return 3;
}

export fn ZSTD_compressBound(src_size: usize) usize {
    const extra: usize = if (src_size < (128 << 10)) ((128 << 10) - src_size) >> 11 else 0;
    return src_size + (src_size >> 8) + extra + 64;
}

fn compressInto(dst: ?[*]u8, dst_cap: usize, src: ?[*]const u8, src_size: usize, level: c_int, dict: ?[]const u8) usize {
    const input: []const u8 = if (src) |s| s[0..src_size] else &.{};
    const out = root.zstd.compress.compressDictLevel(alloc, input, dict, level) catch return zerr(ZE.memory_allocation);
    defer alloc.free(out);
    if (out.len > dst_cap) return zerr(ZE.dst_too_small);
    const d = dst orelse return zerr(ZE.dst_null);
    @memcpy(d[0..out.len], out);
    return out.len;
}

fn decompressInto(dst: ?[*]u8, dst_cap: usize, src: ?[*]const u8, src_size: usize, dict: ?[]const u8) usize {
    const s = src orelse return zerr(ZE.src_size_wrong);
    const out = root.zstd.decompress.decompressDict(alloc, s[0..src_size], dict) catch |e| return mapDecErr(e);
    defer alloc.free(out);
    if (out.len > dst_cap) return zerr(ZE.dst_too_small);
    if (out.len == 0) return 0;
    const d = dst orelse return zerr(ZE.dst_null);
    @memcpy(d[0..out.len], out);
    return out.len;
}

export fn ZSTD_compress(dst: ?[*]u8, dst_cap: usize, src: ?[*]const u8, src_size: usize, level: c_int) usize {
    return compressInto(dst, dst_cap, src, src_size, level, null);
}

export fn ZSTD_decompress(dst: ?[*]u8, dst_cap: usize, src: ?[*]const u8, compressed_size: usize) usize {
    return decompressInto(dst, dst_cap, src, compressed_size, null);
}

const CONTENTSIZE_UNKNOWN: u64 = std.math.maxInt(u64);
const CONTENTSIZE_ERROR: u64 = std.math.maxInt(u64) - 1;

export fn ZSTD_getFrameContentSize(src: ?[*]const u8, src_size: usize) u64 {
    const s = src orelse return CONTENTSIZE_ERROR;
    const fh = root.zstd.frame.readFrameHeader(s[0..src_size]) catch return CONTENTSIZE_ERROR;
    return fh.hdr.content_size orelse CONTENTSIZE_UNKNOWN;
}

export fn ZSTD_getDecompressedSize(src: ?[*]const u8, src_size: usize) u64 {
    const v = ZSTD_getFrameContentSize(src, src_size);
    return if (v >= CONTENTSIZE_ERROR) 0 else v;
}

export fn ZSTD_findFrameCompressedSize(src: ?[*]const u8, src_size: usize) usize {
    const s = src orelse return zerr(ZE.src_size_wrong);
    const r = root.zstd.decompress.frameSize(s[0..src_size]) catch |e| return mapDecErr(e);
    return r orelse zerr(ZE.src_size_wrong);
}

// ---------------------------------------------------------------------------
// libzstd: contexts and streaming
// ---------------------------------------------------------------------------

pub const InBuffer = extern struct { src: ?[*]const u8, size: usize, pos: usize };
pub const OutBuffer = extern struct { dst: ?[*]u8, size: usize, pos: usize };

const CCtx = struct {
    level: c_int = 3,
    /// Dictionary copy used by every frame this context produces.
    dict: ?[]u8 = null,
    /// Set for a prefix (single use): the dictionary is dropped after one frame.
    dict_once: bool = false,
    in: std.ArrayList(u8),
    out: std.ArrayList(u8),
    out_pos: usize = 0,
    emitted_any: bool = false,
};

const DCtx = struct {
    dict: ?[]u8 = null,
    dict_once: bool = false,
    in: std.ArrayList(u8),
    out: std.ArrayList(u8),
    out_pos: usize = 0,
};

export fn ZSTD_createCCtx() ?*CCtx {
    const c = alloc.create(CCtx) catch return null;
    c.* = .{ .in = std.ArrayList(u8).init(alloc), .out = std.ArrayList(u8).init(alloc) };
    return c;
}

export fn ZSTD_freeCCtx(c: ?*CCtx) usize {
    const x = c orelse return 0;
    if (x.dict) |d| alloc.free(d);
    x.in.deinit();
    x.out.deinit();
    alloc.destroy(x);
    return 0;
}

export fn ZSTD_createDCtx() ?*DCtx {
    const c = alloc.create(DCtx) catch return null;
    c.* = .{ .in = std.ArrayList(u8).init(alloc), .out = std.ArrayList(u8).init(alloc) };
    return c;
}

export fn ZSTD_freeDCtx(c: ?*DCtx) usize {
    const x = c orelse return 0;
    if (x.dict) |d| alloc.free(d);
    x.in.deinit();
    x.out.deinit();
    alloc.destroy(x);
    return 0;
}

export fn ZSTD_compressCCtx(c: ?*CCtx, dst: ?[*]u8, cap: usize, src: ?[*]const u8, n: usize, level: c_int) usize {
    _ = c;
    return compressInto(dst, cap, src, n, level, null);
}

/// Compress with the context's parameters (level, dictionary).
export fn ZSTD_compress2(c: ?*CCtx, dst: ?[*]u8, cap: usize, src: ?[*]const u8, n: usize) usize {
    const x = c orelse return zerr(ZE.stage_wrong);
    const r = compressInto(dst, cap, src, n, x.level, x.dict);
    cctxDropPrefix(x);
    return r;
}

export fn ZSTD_decompressDCtx(c: ?*DCtx, dst: ?[*]u8, cap: usize, src: ?[*]const u8, n: usize) usize {
    const x = c orelse return zerr(ZE.stage_wrong);
    const r = decompressInto(dst, cap, src, n, x.dict);
    dctxDropPrefix(x);
    return r;
}

fn cctxDropPrefix(x: *CCtx) void {
    if (x.dict_once) {
        if (x.dict) |d| alloc.free(d);
        x.dict = null;
        x.dict_once = false;
    }
}

fn dctxDropPrefix(x: *DCtx) void {
    if (x.dict_once) {
        if (x.dict) |d| alloc.free(d);
        x.dict = null;
        x.dict_once = false;
    }
}

// Parameter ids (ZSTD_cParameter).
const P_COMPRESSION_LEVEL = 100;

export fn ZSTD_CCtx_setParameter(c: ?*CCtx, param: c_int, value: c_int) usize {
    const x = c orelse return zerr(ZE.stage_wrong);
    if (param == P_COMPRESSION_LEVEL) x.level = value;
    return 0;
}

export fn ZSTD_CCtx_setPledgedSrcSize(c: ?*CCtx, size: u64) usize {
    _ = c;
    _ = size;
    return 0;
}

export fn ZSTD_CCtx_reset(c: ?*CCtx, directive: c_int) usize {
    _ = directive;
    const x = c orelse return 0;
    x.in.clearRetainingCapacity();
    x.out.clearRetainingCapacity();
    x.out_pos = 0;
    x.emitted_any = false;
    return 0;
}

export fn ZSTD_DCtx_reset(c: ?*DCtx, directive: c_int) usize {
    _ = directive;
    const x = c orelse return 0;
    x.in.clearRetainingCapacity();
    x.out.clearRetainingCapacity();
    x.out_pos = 0;
    return 0;
}

// ---------------------------------------------------------------------------
// libzstd: dictionaries
// ---------------------------------------------------------------------------

const DICT_MAGIC: u32 = 0xEC30A437;

fn dictIdOf(d: []const u8) u32 {
    if (d.len < 8 or std.mem.readInt(u32, d[0..4], .little) != DICT_MAGIC) return 0;
    return std.mem.readInt(u32, d[4..8], .little);
}

fn copyDict(d: ?[*]const u8, n: usize) ?[]u8 {
    if (d == null or n == 0) return null;
    return alloc.dupe(u8, d.?[0..n]) catch null;
}

export fn ZSTD_getDictID_fromDict(dict: ?[*]const u8, size: usize) c_uint {
    const d = dict orelse return 0;
    return dictIdOf(d[0..size]);
}

export fn ZSTD_getDictID_fromFrame(src: ?[*]const u8, size: usize) c_uint {
    const s = src orelse return 0;
    const fh = root.zstd.frame.readFrameHeader(s[0..size]) catch return 0;
    return fh.hdr.dict_id;
}

export fn ZSTD_compress_usingDict(c: ?*CCtx, dst: ?[*]u8, cap: usize, src: ?[*]const u8, n: usize, dict: ?[*]const u8, dict_size: usize, level: c_int) usize {
    _ = c;
    const d: ?[]const u8 = if (dict != null and dict_size > 0) dict.?[0..dict_size] else null;
    return compressInto(dst, cap, src, n, level, d);
}

export fn ZSTD_decompress_usingDict(c: ?*DCtx, dst: ?[*]u8, cap: usize, src: ?[*]const u8, n: usize, dict: ?[*]const u8, dict_size: usize) usize {
    _ = c;
    const d: ?[]const u8 = if (dict != null and dict_size > 0) dict.?[0..dict_size] else null;
    return decompressInto(dst, cap, src, n, d);
}

export fn ZSTD_CCtx_loadDictionary(c: ?*CCtx, dict: ?[*]const u8, size: usize) usize {
    const x = c orelse return zerr(ZE.stage_wrong);
    if (x.dict) |old| alloc.free(old);
    x.dict = copyDict(dict, size);
    x.dict_once = false;
    return 0;
}

export fn ZSTD_CCtx_loadDictionary_byReference(c: ?*CCtx, dict: ?[*]const u8, size: usize) usize {
    return ZSTD_CCtx_loadDictionary(c, dict, size);
}

export fn ZSTD_CCtx_refPrefix(c: ?*CCtx, prefix: ?[*]const u8, size: usize) usize {
    const r = ZSTD_CCtx_loadDictionary(c, prefix, size);
    if (c) |x| x.dict_once = true;
    return r;
}

export fn ZSTD_DCtx_loadDictionary(c: ?*DCtx, dict: ?[*]const u8, size: usize) usize {
    const x = c orelse return zerr(ZE.stage_wrong);
    if (x.dict) |old| alloc.free(old);
    x.dict = copyDict(dict, size);
    x.dict_once = false;
    return 0;
}

export fn ZSTD_DCtx_loadDictionary_byReference(c: ?*DCtx, dict: ?[*]const u8, size: usize) usize {
    return ZSTD_DCtx_loadDictionary(c, dict, size);
}

export fn ZSTD_DCtx_refPrefix(c: ?*DCtx, prefix: ?[*]const u8, size: usize) usize {
    const r = ZSTD_DCtx_loadDictionary(c, prefix, size);
    if (c) |x| x.dict_once = true;
    return r;
}

export fn ZSTD_initCStream_usingDict(c: ?*CCtx, dict: ?[*]const u8, size: usize, level: c_int) usize {
    _ = ZSTD_initCStream(c, level);
    return ZSTD_CCtx_loadDictionary(c, dict, size);
}

export fn ZSTD_initDStream_usingDict(c: ?*DCtx, dict: ?[*]const u8, size: usize) usize {
    _ = ZSTD_initDStream(c);
    return ZSTD_DCtx_loadDictionary(c, dict, size);
}

/// Digested dictionaries are plain copies here: the parse happens per frame.
const ZDict = struct { data: []u8, level: c_int };

export fn ZSTD_createCDict(dict: ?[*]const u8, size: usize, level: c_int) ?*ZDict {
    const z = alloc.create(ZDict) catch return null;
    z.* = .{ .data = copyDict(dict, size) orelse (alloc.alloc(u8, 0) catch {
        alloc.destroy(z);
        return null;
    }), .level = level };
    return z;
}

export fn ZSTD_createCDict_byReference(dict: ?[*]const u8, size: usize, level: c_int) ?*ZDict {
    return ZSTD_createCDict(dict, size, level);
}

export fn ZSTD_freeCDict(z: ?*ZDict) usize {
    const x = z orelse return 0;
    alloc.free(x.data);
    alloc.destroy(x);
    return 0;
}

export fn ZSTD_sizeof_CDict(z: ?*const ZDict) usize {
    const x = z orelse return 0;
    return x.data.len + @sizeOf(ZDict);
}

export fn ZSTD_getDictID_fromCDict(z: ?*const ZDict) c_uint {
    const x = z orelse return 0;
    return dictIdOf(x.data);
}

export fn ZSTD_compress_usingCDict(c: ?*CCtx, dst: ?[*]u8, cap: usize, src: ?[*]const u8, n: usize, z: ?*const ZDict) usize {
    _ = c;
    const x = z orelse return zerr(ZE.stage_wrong);
    return compressInto(dst, cap, src, n, x.level, if (x.data.len > 0) x.data else null);
}

export fn ZSTD_CCtx_refCDict(c: ?*CCtx, z: ?*const ZDict) usize {
    const x = c orelse return zerr(ZE.stage_wrong);
    if (x.dict) |old| alloc.free(old);
    x.dict = null;
    x.dict_once = false;
    if (z) |zd| {
        x.dict = alloc.dupe(u8, zd.data) catch return zerr(ZE.memory_allocation);
        x.level = zd.level;
    }
    return 0;
}

export fn ZSTD_createDDict(dict: ?[*]const u8, size: usize) ?*ZDict {
    return ZSTD_createCDict(dict, size, 0);
}

export fn ZSTD_createDDict_byReference(dict: ?[*]const u8, size: usize) ?*ZDict {
    return ZSTD_createCDict(dict, size, 0);
}

export fn ZSTD_freeDDict(z: ?*ZDict) usize {
    return ZSTD_freeCDict(z);
}

export fn ZSTD_sizeof_DDict(z: ?*const ZDict) usize {
    return ZSTD_sizeof_CDict(z);
}

export fn ZSTD_getDictID_fromDDict(z: ?*const ZDict) c_uint {
    return ZSTD_getDictID_fromCDict(z);
}

export fn ZSTD_decompress_usingDDict(c: ?*DCtx, dst: ?[*]u8, cap: usize, src: ?[*]const u8, n: usize, z: ?*const ZDict) usize {
    _ = c;
    const x = z orelse return zerr(ZE.stage_wrong);
    return decompressInto(dst, cap, src, n, if (x.data.len > 0) x.data else null);
}

export fn ZSTD_DCtx_refDDict(c: ?*DCtx, z: ?*const ZDict) usize {
    const x = c orelse return zerr(ZE.stage_wrong);
    if (x.dict) |old| alloc.free(old);
    x.dict = null;
    x.dict_once = false;
    if (z) |zd| x.dict = alloc.dupe(u8, zd.data) catch return zerr(ZE.memory_allocation);
    return 0;
}

fn drain(list: *std.ArrayList(u8), pos: *usize, out: *OutBuffer) usize {
    const avail = list.items.len - pos.*;
    const room = out.size - out.pos;
    const n = @min(avail, room);
    if (n > 0) {
        const d = out.dst.?;
        @memcpy(d[out.pos .. out.pos + n], list.items[pos.* .. pos.* + n]);
        out.pos += n;
        pos.* += n;
    }
    if (pos.* == list.items.len) {
        list.clearRetainingCapacity();
        pos.* = 0;
    }
    return avail - n;
}

const E_CONTINUE = 0;
const E_FLUSH = 1;
const E_END = 2;

/// Turn the buffered input into a complete frame appended to the output queue.
fn cctxCutFrame(x: *CCtx, force: bool) bool {
    if (x.in.items.len == 0 and !(force and !x.emitted_any)) return true;
    const z = root.zstd.compress.compressDictLevel(alloc, x.in.items, x.dict, x.level) catch return false;
    defer alloc.free(z);
    cctxDropPrefix(x);
    x.out.appendSlice(z) catch return false;
    x.in.clearRetainingCapacity();
    x.emitted_any = true;
    return true;
}

export fn ZSTD_compressStream2(c: ?*CCtx, output: ?*OutBuffer, input: ?*InBuffer, end_op: c_int) usize {
    const x = c orelse return zerr(ZE.stage_wrong);
    const o = output orelse return zerr(ZE.dst_null);
    if (input) |i| {
        if (i.size > i.pos) {
            const s = i.src orelse return zerr(ZE.src_size_wrong);
            x.in.appendSlice(s[i.pos..i.size]) catch return zerr(ZE.memory_allocation);
            i.pos = i.size;
        }
    }
    switch (end_op) {
        E_CONTINUE => {},
        E_FLUSH => if (!cctxCutFrame(x, false)) return zerr(ZE.memory_allocation),
        E_END => if (!cctxCutFrame(x, true)) return zerr(ZE.memory_allocation),
        else => return zerr(ZE.generic),
    }
    if (o.size > o.pos and o.dst == null) return zerr(ZE.dst_null);
    return drain(&x.out, &x.out_pos, o);
}

export fn ZSTD_initCStream(c: ?*CCtx, level: c_int) usize {
    _ = ZSTD_CCtx_reset(c, 0);
    if (c) |x| x.level = level;
    return 0;
}

export fn ZSTD_compressStream(c: ?*CCtx, output: ?*OutBuffer, input: ?*InBuffer) usize {
    const r = ZSTD_compressStream2(c, output, input, E_CONTINUE);
    return if (ZSTD_isError(r) != 0) r else 0;
}

export fn ZSTD_flushStream(c: ?*CCtx, output: ?*OutBuffer) usize {
    return ZSTD_compressStream2(c, output, null, E_FLUSH);
}

export fn ZSTD_endStream(c: ?*CCtx, output: ?*OutBuffer) usize {
    return ZSTD_compressStream2(c, output, null, E_END);
}

export fn ZSTD_createCStream() ?*CCtx {
    return ZSTD_createCCtx();
}

export fn ZSTD_freeCStream(c: ?*CCtx) usize {
    return ZSTD_freeCCtx(c);
}

export fn ZSTD_CStreamInSize() usize {
    return 128 * 1024;
}

export fn ZSTD_CStreamOutSize() usize {
    return ZSTD_compressBound(128 * 1024) + 5;
}

export fn ZSTD_createDStream() ?*DCtx {
    return ZSTD_createDCtx();
}

export fn ZSTD_freeDStream(c: ?*DCtx) usize {
    return ZSTD_freeDCtx(c);
}

export fn ZSTD_initDStream(c: ?*DCtx) usize {
    _ = ZSTD_DCtx_reset(c, 0);
    return 128 * 1024;
}

export fn ZSTD_DStreamInSize() usize {
    return 128 * 1024 + 3;
}

export fn ZSTD_DStreamOutSize() usize {
    return 128 * 1024;
}

export fn ZSTD_decompressStream(c: ?*DCtx, output: ?*OutBuffer, input: ?*InBuffer) usize {
    const x = c orelse return zerr(ZE.stage_wrong);
    const o = output orelse return zerr(ZE.dst_null);
    if (input) |i| {
        if (i.size > i.pos) {
            const s = i.src orelse return zerr(ZE.src_size_wrong);
            x.in.appendSlice(s[i.pos..i.size]) catch return zerr(ZE.memory_allocation);
            i.pos = i.size;
        }
    }
    // Decode every complete frame currently buffered.
    while (x.in.items.len > 0) {
        const fsz = root.zstd.decompress.frameSize(x.in.items) catch |e| return mapDecErr(e);
        const n = fsz orelse break;
        const dec = root.zstd.decompress.decompressDict(alloc, x.in.items[0..n], x.dict) catch |e| return mapDecErr(e);
        defer alloc.free(dec);
        dctxDropPrefix(x);
        x.out.appendSlice(dec) catch return zerr(ZE.memory_allocation);
        x.in.replaceRange(0, n, &.{}) catch return zerr(ZE.memory_allocation);
    }
    if (o.size > o.pos and o.dst == null) return zerr(ZE.dst_null);
    const left = drain(&x.out, &x.out_pos, o);
    if (left > 0) return left;
    // 0 only when a frame boundary was reached with nothing pending.
    return if (x.in.items.len == 0) 0 else 1;
}

// ---------------------------------------------------------------------------
// zlib drop-in surface (zlib container: RFC 1950)
// ---------------------------------------------------------------------------

const Z_OK = 0;
const Z_DATA_ERROR = -3;
const Z_MEM_ERROR = -4;
const Z_BUF_ERROR = -5;

export fn zlibVersion() [*:0]const u8 {
    return "1.3.1";
}

export fn crc32(crc: c_ulong, buf: ?[*]const u8, len: c_uint) c_ulong {
    const b = buf orelse return 0;
    return root.core.checksum.crc32(b[0..len], @truncate(crc));
}

export fn adler32(adler: c_ulong, buf: ?[*]const u8, len: c_uint) c_ulong {
    const b = buf orelse return 1;
    return root.core.checksum.adler32(b[0..len], @truncate(adler));
}

export fn compressBound(source_len: c_ulong) c_ulong {
    return source_len + (source_len >> 12) + (source_len >> 14) + (source_len >> 25) + 13;
}

export fn compress2(dest: ?[*]u8, dest_len: *c_ulong, source: ?[*]const u8, source_len: c_ulong, level: c_int) c_int {
    const input: []const u8 = if (source) |s| s[0..source_len] else &.{};
    const body = root.deflate.deflate.deflateLevel(alloc, input, if (level < 0) 6 else level) catch return Z_MEM_ERROR;
    defer alloc.free(body);
    const total = 2 + body.len + 4;
    if (total > dest_len.*) return Z_BUF_ERROR;
    const d = dest orelse return Z_BUF_ERROR;
    d[0] = 0x78;
    d[1] = 0x9C;
    @memcpy(d[2 .. 2 + body.len], body);
    const ad = root.core.checksum.adler32(input, 1);
    std.mem.writeInt(u32, d[2 + body.len ..][0..4], ad, .big);
    dest_len.* = total;
    return Z_OK;
}

export fn compress(dest: ?[*]u8, dest_len: *c_ulong, source: ?[*]const u8, source_len: c_ulong) c_int {
    return compress2(dest, dest_len, source, source_len, -1);
}

export fn uncompress(dest: ?[*]u8, dest_len: *c_ulong, source: ?[*]const u8, source_len: c_ulong) c_int {
    const s = source orelse return Z_DATA_ERROR;
    if (source_len < 6) return Z_DATA_ERROR;
    const in = s[0..source_len];
    if ((in[0] & 0x0F) != 8 or ((@as(u32, in[0]) << 8) | in[1]) % 31 != 0 or (in[1] & 0x20) != 0) return Z_DATA_ERROR;
    const r = root.deflate.deflate.inflateEx(alloc, in[2 .. in.len - 4], 0) catch return Z_DATA_ERROR;
    defer alloc.free(r.data);
    const out = r.data;
    const want = std.mem.readInt(u32, in[in.len - 4 ..][0..4], .big);
    if (want != root.core.checksum.adler32(out, 1)) return Z_DATA_ERROR;
    if (out.len > dest_len.*) return Z_BUF_ERROR;
    if (out.len > 0) {
        const d = dest orelse return Z_BUF_ERROR;
        @memcpy(d[0..out.len], out);
    }
    dest_len.* = out.len;
    return Z_OK;
}

// ---------------------------------------------------------------------------
// libbrotli drop-in surface
// ---------------------------------------------------------------------------

const br_enc = root.brotli.compress;
const br_dec = root.brotli.decompress;

const BR_TRUE: c_int = 1;
const BR_FALSE: c_int = 0;
const BR_RESULT_ERROR: c_int = 0;
const BR_RESULT_SUCCESS: c_int = 1;
const BR_RESULT_NEEDS_MORE_INPUT: c_int = 2;
const BR_RESULT_NEEDS_MORE_OUTPUT: c_int = 3;

export fn BrotliEncoderVersion() u32 {
    return 0x1002000;
}

export fn BrotliDecoderVersion() u32 {
    return 0x1002000;
}

export fn BrotliEncoderMaxCompressedSize(input_size: usize) usize {
    if (input_size == 0) return 2;
    const num_large_blocks = input_size >> 14;
    const overhead = 2 + (4 * num_large_blocks) + 3 + 1;
    const result = input_size +% overhead;
    if (result < input_size) return 0;
    return result;
}

export fn BrotliEncoderCompress(
    quality: c_int,
    lgwin: c_int,
    mode: c_int,
    input_size: usize,
    input: ?[*]const u8,
    encoded_size: *usize,
    encoded: ?[*]u8,
) c_int {
    _ = lgwin;
    _ = mode;
    const in: []const u8 = if (input) |p| p[0..input_size] else &.{};
    // libbrotli's default quality is 11; nstd maps everything >= 5 to its full pipeline.
    const out = br_enc.compressQuality(alloc, in, quality) catch return BR_FALSE;
    defer alloc.free(out);
    if (out.len > encoded_size.*) return BR_FALSE;
    const d = encoded orelse return BR_FALSE;
    @memcpy(d[0..out.len], out);
    encoded_size.* = out.len;
    return BR_TRUE;
}

export fn BrotliDecoderDecompress(
    encoded_size: usize,
    encoded: ?[*]const u8,
    decoded_size: *usize,
    decoded: ?[*]u8,
) c_int {
    const in: []const u8 = if (encoded) |p| p[0..encoded_size] else &.{};
    const out = br_dec.decompress(alloc, in) catch return BR_RESULT_ERROR;
    defer alloc.free(out);
    if (out.len > decoded_size.*) return BR_RESULT_ERROR;
    if (out.len > 0) {
        const d = decoded orelse return BR_RESULT_ERROR;
        @memcpy(d[0..out.len], out);
    }
    decoded_size.* = out.len;
    return BR_RESULT_SUCCESS;
}

// ---- streaming encoder ----

const BrEnc = struct {
    enc: br_enc.Encoder,
    hist: std.ArrayList(u8),
    /// Bytes of `hist` already encoded.
    done: usize = 0,
    finished: bool = false,
    /// Output bytes handed out by TakeOutput, dropped on the next call.
    taken: usize = 0,
};

const OP_PROCESS = 0;
const OP_FLUSH = 1;
const OP_FINISH = 2;
const WINDOW_KEEP: usize = (1 << 22) - 16;
const BLOCK_MAX: usize = 1 << 20;

export fn BrotliEncoderCreateInstance(alloc_fn: ?*const anyopaque, free_fn: ?*const anyopaque, opaque_: ?*anyopaque) ?*BrEnc {
    _ = alloc_fn;
    _ = free_fn;
    _ = opaque_;
    const st = alloc.create(BrEnc) catch return null;
    const enc = br_enc.Encoder.init(alloc) catch {
        alloc.destroy(st);
        return null;
    };
    st.* = .{ .enc = enc, .hist = std.ArrayList(u8).init(alloc) };
    return st;
}

export fn BrotliEncoderDestroyInstance(st: ?*BrEnc) void {
    const s = st orelse return;
    s.enc.deinit();
    s.hist.deinit();
    alloc.destroy(s);
}

export fn BrotliEncoderSetParameter(st: ?*BrEnc, param: c_int, value: u32) c_int {
    _ = value;
    if (st == null) return BR_FALSE;
    return if (param >= 0 and param <= 9) BR_TRUE else BR_FALSE;
}

fn brEncDropTaken(s: *BrEnc) void {
    if (s.taken > 0) {
        s.enc.consume(s.taken);
        s.taken = 0;
    }
}

fn brEncSlide(s: *BrEnc) void {
    if (s.hist.items.len > 3 * WINDOW_KEEP and s.done == s.hist.items.len) {
        const drop = s.hist.items.len - WINDOW_KEEP;
        s.hist.replaceRange(0, drop, &.{}) catch return;
        s.done -= drop;
        s.enc.resetHistory();
    }
}

export fn BrotliEncoderCompressStream(
    st: ?*BrEnc,
    op: c_int,
    avail_in: *usize,
    next_in: *?[*]const u8,
    avail_out: *usize,
    next_out: *?[*]u8,
    total_out: ?*usize,
) c_int {
    const s = st orelse return BR_FALSE;
    brEncDropTaken(s);
    if (s.finished and avail_in.* > 0) return BR_FALSE;
    if (avail_in.* > 0) {
        const p = next_in.* orelse return BR_FALSE;
        s.hist.appendSlice(p[0..avail_in.*]) catch return BR_FALSE;
        next_in.* = p + avail_in.*;
        avail_in.* = 0;
    }
    switch (op) {
        OP_PROCESS => {
            while (s.hist.items.len - s.done >= BLOCK_MAX) {
                s.enc.encode(s.hist.items, s.done, s.done + BLOCK_MAX) catch return BR_FALSE;
                s.done += BLOCK_MAX;
            }
        },
        OP_FLUSH, OP_FINISH => {
            if (!s.finished) {
                if (s.hist.items.len > s.done) {
                    s.enc.encode(s.hist.items, s.done, s.hist.items.len) catch return BR_FALSE;
                    s.done = s.hist.items.len;
                }
                if (op == OP_FLUSH) {
                    s.enc.flush() catch return BR_FALSE;
                } else {
                    s.enc.finish() catch return BR_FALSE;
                    s.finished = true;
                }
            }
        },
        else => return BR_FALSE,
    }
    brEncSlide(s);

    // Drain into the caller's buffer.
    const out = s.enc.output();
    const n = @min(out.len, avail_out.*);
    if (n > 0) {
        const d = next_out.* orelse return BR_FALSE;
        @memcpy(d[0..n], out[0..n]);
        next_out.* = d + n;
        avail_out.* -= n;
        s.enc.consume(n);
        if (total_out) |t| t.* += n;
    }
    return BR_TRUE;
}

export fn BrotliEncoderIsFinished(st: ?*BrEnc) c_int {
    const s = st orelse return BR_FALSE;
    brEncDropTaken(s);
    return if (s.finished and s.enc.output().len == 0) BR_TRUE else BR_FALSE;
}

export fn BrotliEncoderHasMoreOutput(st: ?*BrEnc) c_int {
    const s = st orelse return BR_FALSE;
    brEncDropTaken(s);
    return if (s.enc.output().len > 0) BR_TRUE else BR_FALSE;
}

export fn BrotliEncoderTakeOutput(st: ?*BrEnc, size: *usize) ?[*]const u8 {
    const s = st orelse return null;
    brEncDropTaken(s);
    const out = s.enc.output();
    const n = if (size.* == 0) out.len else @min(size.*, out.len);
    size.* = n;
    s.taken = n;
    return out.ptr;
}

// ---- streaming decoder ----

const BrDec = struct {
    dec: br_dec.Decoder,
    err: c_int = 0,
    used: bool = false,
};

fn brErrCode(e: anyerror) c_int {
    return switch (e) {
        error.OutOfMemory => -26,
        error.Unsupported => -13,
        else => -2,
    };
}

export fn BrotliDecoderCreateInstance(alloc_fn: ?*const anyopaque, free_fn: ?*const anyopaque, opaque_: ?*anyopaque) ?*BrDec {
    _ = alloc_fn;
    _ = free_fn;
    _ = opaque_;
    const st = alloc.create(BrDec) catch return null;
    st.* = .{ .dec = br_dec.Decoder.init(alloc) };
    return st;
}

export fn BrotliDecoderDestroyInstance(st: ?*BrDec) void {
    const s = st orelse return;
    s.dec.deinit();
    alloc.destroy(s);
}

export fn BrotliDecoderSetParameter(st: ?*BrDec, param: c_int, value: u32) c_int {
    _ = st;
    _ = param;
    _ = value;
    return BR_FALSE; // no large-window support
}

export fn BrotliDecoderDecompressStream(
    st: ?*BrDec,
    avail_in: *usize,
    next_in: *?[*]const u8,
    avail_out: *usize,
    next_out: *?[*]u8,
    total_out: ?*usize,
) c_int {
    const s = st orelse return BR_RESULT_ERROR;
    if (s.err < 0) return BR_RESULT_ERROR;
    const fed = avail_in.*;
    if (fed > 0 and !s.dec.finished) {
        const p = next_in.* orelse return BR_RESULT_ERROR;
        s.dec.feed(p[0..fed]) catch {
            s.err = -26;
            return BR_RESULT_ERROR;
        };
        s.used = true;
        next_in.* = p + fed;
        avail_in.* = 0;
    }
    s.dec.process() catch |e| {
        s.err = brErrCode(e);
        return BR_RESULT_ERROR;
    };
    if (s.dec.finished and fed > 0) {
        // Give back input that lies past the end of the stream.
        const used_bytes = (s.dec.bitpos + 7) / 8;
        const extra = s.dec.input.items.len -| used_bytes;
        const give = @min(extra, fed);
        if (give > 0) {
            s.dec.input.shrinkRetainingCapacity(s.dec.input.items.len - give);
            next_in.* = next_in.*.? - give;
            avail_in.* = give;
        }
    }
    const pend = s.dec.pending();
    const n = @min(pend.len, avail_out.*);
    if (n > 0) {
        const d = next_out.* orelse return BR_RESULT_ERROR;
        @memcpy(d[0..n], pend[0..n]);
        next_out.* = d + n;
        avail_out.* -= n;
        s.dec.take(n);
        if (total_out) |t| t.* += n;
    }
    if (s.dec.pending().len > 0) return BR_RESULT_NEEDS_MORE_OUTPUT;
    if (s.dec.finished) return BR_RESULT_SUCCESS;
    return BR_RESULT_NEEDS_MORE_INPUT;
}

export fn BrotliDecoderHasMoreOutput(st: ?*const BrDec) c_int {
    const s = st orelse return BR_FALSE;
    return if (s.dec.pending().len > 0) BR_TRUE else BR_FALSE;
}

export fn BrotliDecoderTakeOutput(st: ?*BrDec, size: *usize) ?[*]const u8 {
    const s = st orelse return null;
    const pend = s.dec.pending();
    const n = if (size.* == 0) pend.len else @min(size.*, pend.len);
    size.* = n;
    const ptr = pend.ptr;
    s.dec.take(n);
    return ptr;
}

export fn BrotliDecoderIsUsed(st: ?*const BrDec) c_int {
    const s = st orelse return BR_FALSE;
    return if (s.used) BR_TRUE else BR_FALSE;
}

export fn BrotliDecoderIsFinished(st: ?*const BrDec) c_int {
    const s = st orelse return BR_FALSE;
    return if (s.dec.finished and s.dec.pending().len == 0) BR_TRUE else BR_FALSE;
}

export fn BrotliDecoderGetErrorCode(st: ?*const BrDec) c_int {
    const s = st orelse return -20;
    return s.err;
}

export fn BrotliDecoderErrorString(code: c_int) [*:0]const u8 {
    return switch (code) {
        0 => "NO_ERROR",
        1 => "SUCCESS",
        2 => "NEEDS_MORE_INPUT",
        3 => "NEEDS_MORE_OUTPUT",
        -2 => "FORMAT_RESERVED",
        -13 => "FORMAT_WINDOW_BITS",
        -20 => "INVALID_ARGUMENTS",
        -26 => "ALLOC_RING_BUFFER_1",
        else => "UNKNOWN",
    };
}

// ---------------------------------------------------------------------------
// zlib streaming API (z_stream)
// ---------------------------------------------------------------------------

const Z_STREAM_END = 1;
const Z_NEED_DICT = 2;
const Z_STREAM_ERROR = -2;
const Z_VERSION_ERROR = -6;
const Z_FINISH = 4;
const Z_BLOCK = 5;

const ZStream = extern struct {
    next_in: ?[*]const u8,
    avail_in: c_uint,
    total_in: c_ulong,
    next_out: ?[*]u8,
    avail_out: c_uint,
    total_out: c_ulong,
    msg: ?[*:0]const u8,
    state: ?*anyopaque,
    zalloc: ?*anyopaque,
    zfree: ?*anyopaque,
    @"opaque": ?*anyopaque,
    data_type: c_int,
    adler: c_ulong,
    reserved: c_ulong,
};

const zs = root.deflate.zstream;

const ZState = struct {
    def: ?*zs.Deflater = null,
    inf: ?*zs.Inflater = null,
    /// Set once Z_STREAM_END has been returned.
    done: bool = false,
    /// Input bytes (ending at `next_in`) that may be handed back at the end of
    /// the stream: the last chunk supplied, which later calls continue from.
    contig: usize = 0,
};

fn zstateOf(strm: ?*ZStream) ?*ZState {
    const s = strm orelse return null;
    return @ptrCast(@alignCast(s.state orelse return null));
}

fn zVersionOk(version: ?[*:0]const u8, size: c_int) bool {
    const v = version orelse return false;
    return v[0] == '1' and size == @sizeOf(ZStream);
}

fn zInit(strm: ?*ZStream) ?*ZState {
    const s = strm orelse return null;
    const st = alloc.create(ZState) catch return null;
    st.* = .{};
    s.state = st;
    s.total_in = 0;
    s.total_out = 0;
    s.msg = null;
    s.data_type = 2;
    s.adler = 0;
    return st;
}

export fn deflateInit_(strm: ?*ZStream, level: c_int, version: ?[*:0]const u8, size: c_int) c_int {
    return deflateInit2_(strm, level, 8, 15, 8, 0, version, size);
}

export fn deflateInit2_(strm: ?*ZStream, level: c_int, method: c_int, window_bits: c_int, mem_level: c_int, strategy: c_int, version: ?[*:0]const u8, size: c_int) c_int {
    _ = strategy;
    if (!zVersionOk(version, size)) return Z_VERSION_ERROR;
    if (strm == null or method != 8 or mem_level < 1 or mem_level > 9 or level < -1 or level > 9) return Z_STREAM_ERROR;
    var wrap: zs.Wrap = .zlib;
    var wb = window_bits;
    if (wb < 0) {
        wrap = .raw;
        wb = -wb;
    } else if (wb > 15) {
        wrap = .gzip;
        wb -= 16;
    }
    if (wb < 8 or wb > 15 or (wb == 8 and wrap != .raw)) return Z_STREAM_ERROR;
    const st = zInit(strm) orelse return Z_MEM_ERROR;
    st.def = zs.Deflater.create(alloc, level, wrap, @intCast(wb)) catch {
        alloc.destroy(st);
        strm.?.state = null;
        return Z_MEM_ERROR;
    };
    strm.?.adler = if (wrap == .gzip) 0 else 1;
    return Z_OK;
}

export fn deflateEnd(strm: ?*ZStream) c_int {
    const st = zstateOf(strm) orelse return Z_STREAM_ERROR;
    const premature = if (st.def) |d| !d.finished else false;
    if (st.def) |d| d.destroy();
    alloc.destroy(st);
    strm.?.state = null;
    return if (premature) Z_DATA_ERROR else Z_OK;
}

export fn deflateReset(strm: ?*ZStream) c_int {
    const st = zstateOf(strm) orelse return Z_STREAM_ERROR;
    const d = st.def orelse return Z_STREAM_ERROR;
    d.reset();
    st.done = false;
    const s = strm.?;
    s.total_in = 0;
    s.total_out = 0;
    s.msg = null;
    s.adler = if (d.wrap == .gzip) 0 else 1;
    return Z_OK;
}

export fn deflateParams(strm: ?*ZStream, level: c_int, strategy: c_int) c_int {
    _ = strategy;
    const st = zstateOf(strm) orelse return Z_STREAM_ERROR;
    const d = st.def orelse return Z_STREAM_ERROR;
    if (level < -1 or level > 9) return Z_STREAM_ERROR;
    d.setLevel(level);
    return Z_OK;
}

export fn deflateTune(strm: ?*ZStream, good: c_int, lazy: c_int, nice: c_int, chain: c_int) c_int {
    _ = good;
    _ = lazy;
    _ = nice;
    _ = chain;
    return if (zstateOf(strm) != null) Z_OK else Z_STREAM_ERROR;
}

export fn deflateBound(strm: ?*ZStream, source_len: c_ulong) c_ulong {
    const st = zstateOf(strm) orelse return compressBound(source_len);
    const d = st.def orelse return compressBound(source_len);
    return d.bound(source_len);
}

export fn deflatePending(strm: ?*ZStream, pending: ?*c_uint, bits: ?*c_int) c_int {
    const st = zstateOf(strm) orelse return Z_STREAM_ERROR;
    const d = st.def orelse return Z_STREAM_ERROR;
    if (pending) |p| p.* = @intCast(d.pending().len);
    if (bits) |b| b.* = d.ob.n;
    return Z_OK;
}

export fn deflateSetDictionary(strm: ?*ZStream, dict: ?[*]const u8, len: c_uint) c_int {
    const st = zstateOf(strm) orelse return Z_STREAM_ERROR;
    const d = st.def orelse return Z_STREAM_ERROR;
    if (dict == null or d.wrap == .gzip) return Z_STREAM_ERROR;
    d.setDictionary(dict.?[0..len]) catch |e| return if (e == error.OutOfMemory) Z_MEM_ERROR else Z_STREAM_ERROR;
    if (d.wrap == .zlib) strm.?.adler = d.dict_id;
    return Z_OK;
}

export fn deflateCopy(dest: ?*ZStream, source: ?*ZStream) c_int {
    _ = dest;
    _ = source;
    return Z_STREAM_ERROR; // not supported
}

export fn deflatePrime(strm: ?*ZStream, bits: c_int, value: c_int) c_int {
    _ = strm;
    _ = bits;
    _ = value;
    return Z_STREAM_ERROR; // not supported
}

fn zFlushMode(flush: c_int) ?zs.Flush {
    return switch (flush) {
        0 => .none,
        1 => .partial,
        2 => .sync,
        3 => .full,
        4 => .finish,
        5 => .block,
        else => null,
    };
}

export fn deflate(strm: ?*ZStream, flush: c_int) c_int {
    const s = strm orelse return Z_STREAM_ERROR;
    const st = zstateOf(strm) orelse return Z_STREAM_ERROR;
    const df = st.def orelse return Z_STREAM_ERROR;
    const mode = zFlushMode(flush) orelse return Z_STREAM_ERROR;
    if (s.next_out == null and s.avail_out > 0) return Z_STREAM_ERROR;
    if (s.next_in == null and s.avail_in > 0) return Z_STREAM_ERROR;
    if (df.finished and mode != .finish) return Z_STREAM_ERROR;
    if (s.avail_out == 0) return Z_BUF_ERROR;

    var progress = false;
    const had_pending = df.pending().len > 0;
    const fed = s.avail_in;
    if (!df.finished and fed > 0) {
        df.write(s.next_in.?[0..fed]) catch return Z_MEM_ERROR;
        s.next_in = s.next_in.? + fed;
        s.avail_in = 0;
        s.total_in += fed;
        progress = true;
    }
    // Repeating the same flush with nothing new to say is not progress (zlib returns Z_BUF_ERROR).
    const repeat = mode == df.last_flush and fed == 0 and mode != .none and mode != .finish and !had_pending;
    if (!repeat and !df.finished) {
        df.run(mode) catch return Z_MEM_ERROR;
    }
    const pend = df.pending();
    const n = @min(pend.len, s.avail_out);
    if (n > 0) {
        @memcpy(s.next_out.?[0..n], pend[0..n]);
        s.next_out = s.next_out.? + n;
        s.avail_out -= @intCast(n);
        s.total_out += n;
        df.consume(n);
        progress = true;
    }
    s.adler = if (df.wrap == .gzip) df.crc else df.adler;
    if (df.finished and df.pending().len == 0) {
        st.done = true;
        return Z_STREAM_END;
    }
    if (!progress and !(mode == .finish)) return Z_BUF_ERROR;
    return Z_OK;
}

fn zWindowBits(window_bits: c_int) ?struct { wrap: zs.Wrap } {
    var wb = window_bits;
    if (wb == 0) return .{ .wrap = .zlib }; // size taken from the header
    if (wb < 0) {
        wb = -wb;
        if (wb < 8 or wb > 15) return null;
        return .{ .wrap = .raw };
    }
    if (wb >= 32) {
        wb -= 32;
        if (wb != 0 and (wb < 8 or wb > 15)) return null;
        return .{ .wrap = .auto };
    }
    if (wb >= 16) {
        wb -= 16;
        if (wb != 0 and (wb < 8 or wb > 15)) return null;
        return .{ .wrap = .gzip };
    }
    if (wb < 8 or wb > 15) return null;
    return .{ .wrap = .zlib };
}

export fn inflateInit_(strm: ?*ZStream, version: ?[*:0]const u8, size: c_int) c_int {
    return inflateInit2_(strm, 15, version, size);
}

export fn inflateInit2_(strm: ?*ZStream, window_bits: c_int, version: ?[*:0]const u8, size: c_int) c_int {
    if (!zVersionOk(version, size)) return Z_VERSION_ERROR;
    if (strm == null) return Z_STREAM_ERROR;
    const w = zWindowBits(window_bits) orelse return Z_STREAM_ERROR;
    const st = zInit(strm) orelse return Z_MEM_ERROR;
    st.inf = zs.Inflater.create(alloc, w.wrap) catch {
        alloc.destroy(st);
        strm.?.state = null;
        return Z_MEM_ERROR;
    };
    strm.?.adler = 1;
    return Z_OK;
}

export fn inflateEnd(strm: ?*ZStream) c_int {
    const st = zstateOf(strm) orelse return Z_STREAM_ERROR;
    if (st.inf) |i| i.destroy();
    alloc.destroy(st);
    strm.?.state = null;
    return Z_OK;
}

export fn inflateReset(strm: ?*ZStream) c_int {
    const st = zstateOf(strm) orelse return Z_STREAM_ERROR;
    const i = st.inf orelse return Z_STREAM_ERROR;
    i.reset();
    st.done = false;
    const s = strm.?;
    s.total_in = 0;
    s.total_out = 0;
    s.msg = null;
    s.adler = 1;
    return Z_OK;
}

export fn inflateReset2(strm: ?*ZStream, window_bits: c_int) c_int {
    const st = zstateOf(strm) orelse return Z_STREAM_ERROR;
    const i = st.inf orelse return Z_STREAM_ERROR;
    const w = zWindowBits(window_bits) orelse return Z_STREAM_ERROR;
    i.wrap = w.wrap;
    return inflateReset(strm);
}

export fn inflateSetDictionary(strm: ?*ZStream, dict: ?[*]const u8, len: c_uint) c_int {
    const st = zstateOf(strm) orelse return Z_STREAM_ERROR;
    const i = st.inf orelse return Z_STREAM_ERROR;
    if (dict == null) return Z_STREAM_ERROR;
    i.setDictionary(dict.?[0..len]) catch |e| return switch (e) {
        error.BadDictionary => Z_DATA_ERROR,
        error.OutOfMemory => Z_MEM_ERROR,
        else => Z_STREAM_ERROR,
    };
    return Z_OK;
}

export fn inflateSync(strm: ?*ZStream) c_int {
    _ = strm;
    return Z_DATA_ERROR; // not supported
}

export fn inflateCopy(dest: ?*ZStream, source: ?*ZStream) c_int {
    _ = dest;
    _ = source;
    return Z_STREAM_ERROR; // not supported
}

export fn inflatePrime(strm: ?*ZStream, bits: c_int, value: c_int) c_int {
    _ = strm;
    _ = bits;
    _ = value;
    return Z_STREAM_ERROR; // not supported
}

export fn inflate(strm: ?*ZStream, flush: c_int) c_int {
    const s = strm orelse return Z_STREAM_ERROR;
    const st = zstateOf(strm) orelse return Z_STREAM_ERROR;
    const inf = st.inf orelse return Z_STREAM_ERROR;
    if (zFlushMode(flush) == null) return Z_STREAM_ERROR;
    if (s.next_out == null and s.avail_out > 0) return Z_STREAM_ERROR;
    if (s.next_in == null and s.avail_in > 0) return Z_STREAM_ERROR;
    if (st.done) return Z_STREAM_END;

    const fed = s.avail_in;
    if (fed > 0) {
        st.contig = fed;
        inf.feed(s.next_in.?[0..fed]) catch return Z_MEM_ERROR;
        s.next_in = s.next_in.? + fed;
        s.avail_in = 0;
        s.total_in += fed;
    }
    var produced = false;
    var status: zs.InfStatus = .need_input;
    var ret: c_int = Z_OK;
    while (true) {
        // Hand out whatever is ready first.
        const pend = inf.pending();
        const n = @min(pend.len, s.avail_out);
        if (n > 0) {
            @memcpy(s.next_out.?[0..n], pend[0..n]);
            s.next_out = s.next_out.? + n;
            s.avail_out -= @intCast(n);
            s.total_out += n;
            inf.consume(n);
            produced = true;
        }
        if (inf.pending().len > 0) break; // output space exhausted
        status = inf.run() catch |e| {
            s.msg = if (inf.err_msg) |m| m.ptr else null;
            ret = switch (e) {
                error.OutOfMemory => Z_MEM_ERROR,
                else => Z_DATA_ERROR,
            };
            break;
        };
        if (status == .more_output) continue;
        if (inf.pending().len == 0) break;
    }
    s.adler = if (inf.detected == .gzip) inf.crc else inf.adler;
    if (ret != Z_OK) return ret;
    if (inf.pending().len == 0 and status == .end) {
        // Return input bytes that lie beyond the end of the stream.
        const give = @min(inf.unusedInput(), st.contig);
        if (give > 0) {
            inf.giveBack(give);
            s.next_in = s.next_in.? - give;
            s.avail_in = @intCast(give);
            s.total_in -= give;
        }
        st.done = true;
        return Z_STREAM_END;
    }
    if (status == .need_dict and inf.pending().len == 0) {
        s.adler = inf.dict_id;
        return Z_NEED_DICT;
    }
    if (!produced and fed == 0) return Z_BUF_ERROR;
    if (!produced and status == .need_input and mode_is_finish(flush)) return Z_BUF_ERROR;
    return Z_OK;
}

fn mode_is_finish(flush: c_int) bool {
    return flush == Z_FINISH;
}

export fn zError(err: c_int) [*:0]const u8 {
    return switch (err) {
        2 => "need dictionary",
        1 => "stream end",
        0 => "",
        -1 => "file error",
        -2 => "stream error",
        -3 => "data error",
        -4 => "insufficient memory",
        -5 => "buffer error",
        -6 => "incompatible version",
        else => "",
    };
}

export fn zlibCompileFlags() c_ulong {
    // sizeof(uInt)=4, uLong=8, voidpf=8, z_off_t=8 in the two-bit-pair encoding.
    return 0xA9;
}

export fn adler32_combine(adler1: c_ulong, adler2: c_ulong, len2: c_long) c_ulong {
    const base: u64 = 65521;
    if (len2 < 0) return 0xffffffff;
    const rem: u64 = @as(u64, @intCast(len2)) % base;
    var sum1: u64 = adler1 & 0xffff;
    var sum2: u64 = (rem * sum1) % base;
    sum1 += (adler2 & 0xffff) + base - 1;
    sum2 += ((adler1 >> 16) & 0xffff) + ((adler2 >> 16) & 0xffff) + base - rem;
    if (sum1 >= base) sum1 -= base;
    if (sum1 >= base) sum1 -= base;
    if (sum2 >= (base << 1)) sum2 -= (base << 1);
    if (sum2 >= base) sum2 -= base;
    return sum1 | (sum2 << 16);
}

fn gf2Times(mat: *const [32]u32, vec_in: u32) u32 {
    var vec = vec_in;
    var sum: u32 = 0;
    var i: usize = 0;
    while (vec != 0) : ({
        vec >>= 1;
        i += 1;
    }) {
        if (vec & 1 != 0) sum ^= mat[i];
    }
    return sum;
}

fn gf2Square(square: *[32]u32, mat: *const [32]u32) void {
    for (0..32) |n| square[n] = gf2Times(mat, mat[n]);
}

export fn crc32_combine(crc1_in: c_ulong, crc2: c_ulong, len2_in: c_long) c_ulong {
    var crc1: u32 = @truncate(crc1_in);
    var len2: i64 = len2_in;
    if (len2 <= 0) return crc1;
    var even: [32]u32 = undefined;
    var odd: [32]u32 = undefined;
    odd[0] = 0xedb88320;
    var row: u32 = 1;
    for (1..32) |n| {
        odd[n] = row;
        row <<= 1;
    }
    gf2Square(&even, &odd);
    gf2Square(&odd, &even);
    while (true) {
        gf2Square(&even, &odd);
        if (len2 & 1 != 0) crc1 = gf2Times(&even, crc1);
        len2 >>= 1;
        if (len2 == 0) break;
        gf2Square(&odd, &even);
        if (len2 & 1 != 0) crc1 = gf2Times(&odd, crc1);
        len2 >>= 1;
        if (len2 == 0) break;
    }
    return crc1 ^ @as(u32, @truncate(crc2));
}

test "c abi smoke" {
    const v = nstd_version();
    try std.testing.expect(std.mem.startsWith(u8, std.mem.span(v), "nstd"));
    try std.testing.expect(ZSTD_compressBound(100) >= 100);
    try std.testing.expect(ZSTD_isError(zerr(ZE.corruption)) == 1);
    try std.testing.expect(ZSTD_isError(1234) == 0);
}

// ---------------------------------------------------------------------------
// ZDICT: dictionary training
// ---------------------------------------------------------------------------

const ZDICT_params_t = extern struct { compressionLevel: c_int, notificationLevel: c_uint, dictID: c_uint };
const ZDICT_cover_params_t = extern struct {
    k: c_uint,
    d: c_uint,
    steps: c_uint,
    nbThreads: c_uint,
    splitPoint: f64,
    shrinkDict: c_uint,
    shrinkDictMaxRegression: c_uint,
    zParams: ZDICT_params_t,
};

fn trainInto(dst: ?*anyopaque, cap: usize, samples: ?*const anyopaque, sizes: ?[*]const usize, n: c_uint, k: u32, d: u32, id: u32, level: c_int) usize {
    const out: [*]u8 = @ptrCast(dst orelse return zerr(ZE.dst_null));
    const base: [*]const u8 = @ptrCast(samples orelse return zerr(ZE.generic));
    const sz = sizes orelse return zerr(ZE.generic);
    const views = alloc.alloc([]const u8, n) catch return zerr(ZE.memory_allocation);
    defer alloc.free(views);
    var off: usize = 0;
    for (0..n) |i| {
        views[i] = base[off .. off + sz[i]];
        off += sz[i];
    }
    const dict = root.zstd.train.train(alloc, views, cap, .{ .k = k, .d = d, .dict_id = id, .level = if (level > 0) level else 3 }, null) catch |e| return switch (e) {
        error.OutOfMemory => zerr(ZE.memory_allocation),
        error.DictTooSmall => zerr(ZE.dst_too_small),
        else => zerr(ZE.generic),
    };
    defer alloc.free(dict);
    @memcpy(out[0..dict.len], dict);
    return dict.len;
}

export fn ZDICT_trainFromBuffer(dst: ?*anyopaque, cap: usize, samples: ?*const anyopaque, sizes: ?[*]const usize, n: c_uint) usize {
    return trainInto(dst, cap, samples, sizes, n, 0, 0, 0, 0);
}

export fn ZDICT_trainFromBuffer_cover(dst: ?*anyopaque, cap: usize, samples: ?*const anyopaque, sizes: ?[*]const usize, n: c_uint, p: ZDICT_cover_params_t) usize {
    return trainInto(dst, cap, samples, sizes, n, p.k, p.d, p.zParams.dictID, p.zParams.compressionLevel);
}

export fn ZDICT_optimizeTrainFromBuffer_cover(dst: ?*anyopaque, cap: usize, samples: ?*const anyopaque, sizes: ?[*]const usize, n: c_uint, p: *ZDICT_cover_params_t) usize {
    return trainInto(dst, cap, samples, sizes, n, p.k, p.d, p.zParams.dictID, p.zParams.compressionLevel);
}

export fn ZDICT_getDictID(dict: ?[*]const u8, size: usize) c_uint {
    return ZSTD_getDictID_fromDict(dict, size);
}

export fn ZDICT_isError(code: usize) c_uint {
    return ZSTD_isError(code);
}

export fn ZDICT_getErrorName(code: usize) [*:0]const u8 {
    return ZSTD_getErrorName(code);
}

const ZDICT_fastCover_params_t = extern struct {
    k: c_uint,
    d: c_uint,
    f: c_uint,
    steps: c_uint,
    nbThreads: c_uint,
    splitPoint: f64,
    accel: c_uint,
    shrinkDict: c_uint,
    shrinkDictMaxRegression: c_uint,
    zParams: ZDICT_params_t,
};
const ZDICT_legacy_params_t = extern struct { selectivityLevel: c_uint, zParams: ZDICT_params_t };

// The fastCover entry points share the one trainer; threads are never spawned
// here because this library has no libc of its own.
export fn ZDICT_trainFromBuffer_fastCover(dst: ?*anyopaque, cap: usize, samples: ?*const anyopaque, sizes: ?[*]const usize, n: c_uint, p: ZDICT_fastCover_params_t) usize {
    return trainInto(dst, cap, samples, sizes, n, p.k, p.d, p.zParams.dictID, p.zParams.compressionLevel);
}

export fn ZDICT_optimizeTrainFromBuffer_fastCover(dst: ?*anyopaque, cap: usize, samples: ?*const anyopaque, sizes: ?[*]const usize, n: c_uint, p: *ZDICT_fastCover_params_t) usize {
    return trainInto(dst, cap, samples, sizes, n, p.k, p.d, p.zParams.dictID, p.zParams.compressionLevel);
}

export fn ZDICT_trainFromBuffer_legacy(dst: ?*anyopaque, cap: usize, samples: ?*const anyopaque, sizes: ?[*]const usize, n: c_uint, p: ZDICT_legacy_params_t) usize {
    return trainInto(dst, cap, samples, sizes, n, 0, 0, p.zParams.dictID, p.zParams.compressionLevel);
}

export fn ZDICT_finalizeDictionary(dst: ?*anyopaque, max: usize, content: ?*const anyopaque, csize: usize, samples: ?*const anyopaque, sizes: ?[*]const usize, n: c_uint, p: ZDICT_params_t) usize {
    const out: [*]u8 = @ptrCast(dst orelse return zerr(ZE.dst_null));
    const cbuf: [*]const u8 = @ptrCast(content orelse return zerr(ZE.generic));
    const base: [*]const u8 = @ptrCast(samples orelse return zerr(ZE.generic));
    const sz = sizes orelse return zerr(ZE.generic);
    const views = alloc.alloc([]const u8, n) catch return zerr(ZE.memory_allocation);
    defer alloc.free(views);
    var off: usize = 0;
    for (0..n) |i| {
        views[i] = base[off .. off + sz[i]];
        off += sz[i];
    }
    const dict = root.zstd.train.finalize(alloc, cbuf[0..csize], views, max, p.dictID, p.compressionLevel) catch |e| return switch (e) {
        error.OutOfMemory => zerr(ZE.memory_allocation),
        error.DictTooSmall => zerr(ZE.dst_too_small),
        else => zerr(ZE.generic),
    };
    defer alloc.free(dict);
    @memcpy(out[0..dict.len], dict);
    return dict.len;
}

export fn ZDICT_getDictHeaderSize(dict: ?[*]const u8, size: usize) usize {
    const d = dict orelse return zerr(ZE.generic);
    const dd = root.zstd.dict.Dict.init(d[0..size]) catch return zerr(ZE.dictionary_wrong);
    return size - dd.content.len;
}
