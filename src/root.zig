//! Nstandard (nstd) — high-performance compression engine in Zig.
//! Unifies Zstandard (RFC 8878), Brotli (RFC 7932) and Deflate/Gzip (RFC 1951/1952)
//! behind a single zero-dependency core with a C ABI drop-in surface.

const std = @import("std");

pub const core = struct {
    pub const bits = @import("core/bits.zig");
    pub const checksum = @import("core/checksum.zig");
    pub const simd = @import("core/simd.zig");
    pub const matchfinder = @import("core/matchfinder.zig");
    pub const prefixlen = @import("core/prefixlen.zig");
};

pub const deflate = struct {
    pub const gzip = @import("deflate/gzip.zig");
    pub const deflate = @import("deflate/deflate.zig");
    pub const zstream = @import("deflate/zstream.zig");
};

pub const zstd = struct {
    pub const frame = @import("zstd/frame.zig");
    pub const decompress = @import("zstd/decompress.zig");
    pub const compress = @import("zstd/compress.zig");
    pub const fse = @import("zstd/fse.zig");
    pub const huf = @import("zstd/huf.zig");
    pub const dict = @import("zstd/dict.zig");
    pub const train = @import("zstd/train.zig");
};

pub const brotli = struct {
    pub const decompress = @import("brotli/decompress.zig");
    pub const compress = @import("brotli/compress.zig");
    pub const prefix = @import("brotli/prefix.zig");
    pub const dict_match = @import("brotli/dict_match.zig");
    pub const tables = @import("brotli/tables.zig");
};

// Pull the C ABI exports into every build that roots at this module.
comptime {
    _ = @import("c_abi.zig");
    _ = @import("deflate/zstream.zig");
    _ = @import("zstd/dict_tests.zig");
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("c_abi.zig");
    _ = @import("deflate/zstream.zig");
    std.testing.refAllDeclsRecursive(zstd);
    std.testing.refAllDeclsRecursive(core);
}
