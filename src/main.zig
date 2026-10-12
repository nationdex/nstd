//! nstd — lightweight compression CLI.
//!
//! Unified tool for Zstandard, Gzip and Brotli with auto-format detection,
//! compression, decompression, integrity test and microbenchmark modes.

const std = @import("std");
const nstd = @import("nstd");

const Codec = enum { zstd, gzip, brotli };

const Options = struct {
    codec: Codec = .zstd,
    decompress: bool = false,
    test_only: bool = false,
    to_stdout: bool = false,
    bench: bool = false,
    dbench: bool = false,
    train: bool = false,
    maxdict: usize = 112640,
    train_k: u32 = 0,
    train_d: u32 = 0,
    reps: u32 = 5,
    threads: usize = 1,
    /// Path of a zstd dictionary (-D).
    dict_path: ?[]const u8 = null,
    /// null = each codec's own default (zstd 3, gzip 6).
    level: ?i32 = null,
    input: ?[]const u8 = null,
    output: ?[]const u8 = null,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var opts = Options{};
    var train_files = std.ArrayList([]const u8).init(allocator);
    defer train_files.deinit();
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-z") or std.mem.eql(u8, a, "--zstd")) {
            opts.codec = .zstd;
        } else if (std.mem.eql(u8, a, "-g") or std.mem.eql(u8, a, "--gzip")) {
            opts.codec = .gzip;
        } else if (std.mem.eql(u8, a, "-b") or std.mem.eql(u8, a, "--brotli")) {
            opts.codec = .brotli;
        } else if (std.mem.eql(u8, a, "-d") or std.mem.eql(u8, a, "--decompress")) {
            opts.decompress = true;
        } else if (std.mem.eql(u8, a, "-t") or std.mem.eql(u8, a, "--test")) {
            opts.test_only = true;
        } else if (std.mem.eql(u8, a, "-c") or std.mem.eql(u8, a, "--stdout")) {
            opts.to_stdout = true;
        } else if (std.mem.eql(u8, a, "--bench")) {
            opts.bench = true;
        } else if (std.mem.eql(u8, a, "-D")) {
            i += 1;
            if (i < args.len) opts.dict_path = args[i];
        } else if (std.mem.eql(u8, a, "-T")) {
            i += 1;
            const n = if (i < args.len) std.fmt.parseInt(usize, args[i], 10) catch 1 else 1;
            opts.threads = if (n == 0) (std.Thread.getCpuCount() catch 1) else n;
        } else if (std.mem.eql(u8, a, "--train")) {
            opts.train = true;
        } else if (std.mem.eql(u8, a, "--maxdict")) {
            i += 1;
            if (i < args.len) opts.maxdict = std.fmt.parseInt(usize, args[i], 10) catch opts.maxdict;
        } else if (std.mem.eql(u8, a, "--train-k")) {
            i += 1;
            if (i < args.len) opts.train_k = std.fmt.parseInt(u32, args[i], 10) catch 0;
        } else if (std.mem.eql(u8, a, "--train-d")) {
            i += 1;
            if (i < args.len) opts.train_d = std.fmt.parseInt(u32, args[i], 10) catch 0;
        } else if (std.mem.eql(u8, a, "--dbench")) {
            opts.dbench = true;
        } else if (std.mem.eql(u8, a, "--reps")) {
            i += 1;
            if (i < args.len) opts.reps = std.fmt.parseInt(u32, args[i], 10) catch 5;
        } else if (std.mem.eql(u8, a, "-o")) {
            i += 1;
            if (i < args.len) opts.output = args[i];
        } else if (std.mem.eql(u8, a, "-V") or std.mem.eql(u8, a, "--version")) {
            try std.io.getStdOut().writer().print("{s}\n", .{c_abi_version()});
            return;
        } else if (a.len >= 2 and a[0] == '-' and a[1] >= '0' and a[1] <= '9') {
            opts.level = std.fmt.parseInt(i32, a[1..], 10) catch null;
        } else if (a.len > 0 and a[0] != '-') {
            if (opts.train) {
                try train_files.append(a);
            } else if (opts.input == null) opts.input = a else opts.output = a;
        }
    }

    if (opts.train) return trainDictionary(allocator, &opts, train_files.items);

    const input_path = opts.input orelse {
        try usage();
        return error.MissingInput;
    };

    const data = try std.fs.cwd().readFileAlloc(allocator, input_path, 1 << 30);
    defer allocator.free(data);
    if (opts.dict_path) |dp| {
        g_dict = try std.fs.cwd().readFileAlloc(allocator, dp, 1 << 28);
    }
    defer if (g_dict) |d| allocator.free(d);

    if (opts.dbench) {
        // Decode-only throughput on an existing compressed file.
        var best: i128 = std.math.maxInt(i128);
        var n: usize = 0;
        var rep: u32 = 0;
        while (rep < opts.reps) : (rep += 1) {
            const t0 = std.time.nanoTimestamp();
            const d = try dispatch_decompress(allocator, detect(data) orelse opts.codec, data, opts.threads);
            best = @min(best, std.time.nanoTimestamp() - t0);
            n = d.len;
            allocator.free(d);
        }
        try std.io.getStdOut().writer().print("{d:.1} MB/s\n", .{@as(f64, @floatFromInt(n)) / (@as(f64, @floatFromInt(best)) / 1e9) / 1e6});
        return;
    }
    if (opts.bench) {
        try bench(allocator, opts.codec, data, opts.level, opts.reps, opts.threads);
        return;
    }

    var result: []u8 = undefined;
    if (opts.decompress) {
        // If file extension is .br, default to brotli; otherwise magic number or opts.codec
        var detected = detect(data);
        if (detected == null and std.mem.endsWith(u8, input_path, ".br")) {
            detected = .brotli;
        }
        const codec = detected orelse opts.codec;
        result = try dispatch_decompress(allocator, codec, data, opts.threads);
    } else {
        result = try dispatch_compress(allocator, opts.codec, data, opts.level, opts.threads);
    }
    defer allocator.free(result);

    if (opts.test_only) {
        try std.io.getStdOut().writer().print("OK\n", .{});
        return;
    }

    if (opts.to_stdout) {
        var bw = std.io.bufferedWriter(std.io.getStdOut().writer());
        try bw.writer().writeAll(result);
        try bw.flush();
    } else {
        const out_path = opts.output orelse try defaultName(allocator, input_path, opts);
        defer if (opts.output == null) allocator.free(out_path);
        try std.fs.cwd().writeFile(.{ .sub_path = out_path, .data = result });
    }
}

/// `nstd --train [--maxdict N] [-o dict] FILE...`: build a zstd dictionary.
fn trainDictionary(allocator: std.mem.Allocator, opts: *const Options, files: []const []const u8) !void {
    const stderr = std.io.getStdErr().writer();
    if (files.len == 0) {
        try stderr.writeAll("nstd --train: no sample files given\n");
        return error.MissingInput;
    }
    const bufs = try allocator.alloc([]u8, files.len);
    defer allocator.free(bufs);
    var loaded: usize = 0;
    defer for (bufs[0..loaded]) |b| allocator.free(b);
    for (files) |f| {
        bufs[loaded] = std.fs.cwd().readFileAlloc(allocator, f, 1 << 28) catch |e| {
            try stderr.print("nstd --train: cannot read {s}: {s}\n", .{ f, @errorName(e) });
            return e;
        };
        loaded += 1;
    }
    const views = try allocator.alloc([]const u8, files.len);
    defer allocator.free(views);
    for (bufs, 0..) |b, k| views[k] = b;

    var chosen: nstd.zstd.train.Chosen = undefined;
    const dict = nstd.zstd.train.train(allocator, views, opts.maxdict, .{ .k = opts.train_k, .d = opts.train_d, .threads = opts.threads, .level = opts.level orelse 3 }, &chosen) catch |e| {
        try stderr.print("nstd --train: {s}\n", .{@errorName(e)});
        return e;
    };
    defer allocator.free(dict);
    const out_path = opts.output orelse "dictionary";
    try std.fs.cwd().writeFile(.{ .sub_path = out_path, .data = dict });
    try stderr.print("Trained a {d}-byte dictionary from {d} files (k={d}, d={d}, id={d}) -> {s}\n", .{ dict.len, files.len, chosen.k, chosen.d, nstd.zstd.dict.Dict.getDictID(dict), out_path });
}

fn c_abi_version() []const u8 {
    return "nstd 0.1.0";
}

fn usage() !void {
    const w = std.io.getStdOut().writer();
    try w.writeAll(
        \\usage: nstd [options] <input> [-o output]
        \\  -z, --zstd       Zstandard format (default)
        \\  -g, --gzip       Gzip format
        \\  -b, --brotli     Brotli format
        \\  -d, --decompress Decompress
        \\  -t, --test       Integrity check only
        \\  -c, --stdout     Write to stdout
        \\  -N               Compression level (e.g. -1 .. -9)
        \\  -T N             Worker threads for zstd (0 = all cores)
        \\  -D FILE          Zstd dictionary (formatted or raw content)
        \\  --train FILES    Train a zstd dictionary (-o OUT, --maxdict N, --train-k K, --train-d D)
        \\  --bench          Run microbenchmark (best of --reps N, default 5)
        \\  -V, --version    Print version
        \\
    );
}

fn detect(data: []const u8) ?Codec {
    if (data.len >= 4) {
        const magic = std.mem.readInt(u32, data[0..4], .little);
        if (magic == 0xFD2FB528) return .zstd;
    }
    if (data.len >= 2 and data[0] == 0x1f and data[1] == 0x8b) return .gzip;
    return null;
}

/// Zstd dictionary loaded with -D (null when absent).
var g_dict: ?[]u8 = null;

fn dispatch_compress(allocator: std.mem.Allocator, codec: Codec, data: []const u8, level: ?i32, threads: usize) ![]u8 {
    return switch (codec) {
        .zstd => if (g_dict) |d|
            nstd.zstd.compress.compressDictLevel(allocator, data, d, level orelse 3)
        else
            nstd.zstd.compress.compressMt(allocator, data, level orelse 3, threads, nstd.zstd.compress.MT_CHUNK),
        .gzip => nstd.deflate.gzip.compressLevel(allocator, data, level orelse 6),
        .brotli => nstd.brotli.compress.compressQuality(allocator, data, level orelse nstd.brotli.compress.DEFAULT_QUALITY),
    };
}

fn dispatch_decompress(allocator: std.mem.Allocator, codec: Codec, data: []const u8, threads: usize) ![]u8 {
    return switch (codec) {
        .zstd => if (g_dict) |d|
            nstd.zstd.decompress.decompressDict(allocator, data, d)
        else
            nstd.zstd.decompress.decompressMt(allocator, data, threads),
        .gzip => nstd.deflate.gzip.decompress(allocator, data),
        .brotli => nstd.brotli.decompress.decompress(allocator, data),
    };
}

fn defaultName(allocator: std.mem.Allocator, input: []const u8, opts: Options) ![]u8 {
    if (opts.decompress) {
        return try std.fmt.allocPrint(allocator, "{s}.out", .{input});
    }
    const ext: []const u8 = switch (opts.codec) {
        .zstd => ".zst",
        .gzip => ".gz",
        .brotli => ".br",
    };
    return try std.fmt.allocPrint(allocator, "{s}{s}", .{ input, ext });
}

fn bench(allocator: std.mem.Allocator, codec: Codec, data: []const u8, level: ?i32, reps: u32, threads: usize) !void {
    var best_c: i128 = std.math.maxInt(i128);
    var best_d: i128 = std.math.maxInt(i128);
    var csize: usize = 0;
    var rep: u32 = 0;
    while (rep < reps) : (rep += 1) {
        const t0 = std.time.nanoTimestamp();
        const c = try dispatch_compress(allocator, codec, data, level, threads);
        const t1 = std.time.nanoTimestamp();
        const d = try dispatch_decompress(allocator, codec, c, threads);
        const t2 = std.time.nanoTimestamp();
        if (!std.mem.eql(u8, d, data)) return error.RoundTripMismatch;
        csize = c.len;
        best_c = @min(best_c, t1 - t0);
        best_d = @min(best_d, t2 - t1);
        allocator.free(c);
        allocator.free(d);
    }

    const bytes = data.len;
    const comp_secs = @as(f64, @floatFromInt(best_c)) / 1e9;
    const dec_secs = @as(f64, @floatFromInt(best_d)) / 1e9;
    const ratio = @as(f64, @floatFromInt(bytes)) / @as(f64, @floatFromInt(@max(csize, 1)));

    const w = std.io.getStdOut().writer();
    try w.print(
        \\codec      : {s}
        \\input      : {d} bytes
        \\compressed : {d} bytes (ratio {d:.2}x)
        \\compress   : {d:.2} MB/s
        \\decompress : {d:.2} MB/s
        \\
    , .{
        @tagName(codec),
        bytes,
        csize,
        ratio,
        @as(f64, @floatFromInt(bytes)) / comp_secs / 1e6,
        @as(f64, @floatFromInt(bytes)) / dec_secs / 1e6,
    });
}
