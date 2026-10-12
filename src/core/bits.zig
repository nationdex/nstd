//! Bit-level primitives shared by every codec.
//!
//! Provides a forward LSB-first writer/reader (used by Deflate and Zstd literal
//! streams) and a reverse writer (used by Zstd FSE sequence streams, which are
//! written backwards). All hot-path reads are branchless with a 64-bit refill
//! buffer; bounds are proven at block boundaries so inner loops never check.

const std = @import("std");

/// Forward LSB-first bit writer. Bits are packed into a 64-bit accumulator and
/// flushed to the output as whole little-endian bytes.
pub const BitWriter = struct {
    out: std.ArrayList(u8),
    bit_buf: u64 = 0,
    bit_cnt: u32 = 0,

    pub fn init(allocator: std.mem.Allocator) BitWriter {
        return .{ .out = std.ArrayList(u8).init(allocator) };
    }

    pub fn deinit(self: *BitWriter) void {
        self.out.deinit();
    }

    /// Write the low `n` bits of `value` (n must be <= 64).
    pub fn write(self: *BitWriter, value: u64, n: u6) !void {
        if (n == 0) return;
        const mask: u64 = if (n == 64) ~@as(u64, 0) else (@as(u64, 1) << n) - 1;
        self.bit_buf |= (value & mask) << @intCast(self.bit_cnt);
        self.bit_cnt += n;
        try self.flushFull();
    }

    /// Flush whole bytes from the accumulator down to the output.
    fn flushFull(self: *BitWriter) !void {
        while (self.bit_cnt >= 8) {
            try self.out.append(@truncate(self.bit_buf));
            self.bit_buf >>= 8;
            self.bit_cnt -= 8;
        }
    }

    /// Pad to the next byte boundary with zero bits and flush the final partial
    /// byte if any.
    pub fn alignToByte(self: *BitWriter) !void {
        if (self.bit_cnt > 0) {
            try self.out.append(@truncate(self.bit_buf));
            self.bit_buf = 0;
            self.bit_cnt = 0;
        }
    }

    /// Return the accumulated bytes as an owned slice. Flushes any pending
    /// partial byte and transfers ownership to the caller.
    pub fn finish(self: *BitWriter) ![]u8 {
        try self.alignToByte();
        return try self.out.toOwnedSlice();
    }

    pub fn bytesWritten(self: *const BitWriter) usize {
        return self.out.items.len;
    }
};

/// Reverse (backward) bit writer matching Zstd's `BIT_CStream`. Bits accumulate
/// LSB-first in a 64-bit container; whole bytes are emitted moving backward from
/// the end of the destination buffer. On close, the live region is `buf[ptr..]`.
pub const ReverseBitWriter = struct {
    buf: []u8,
    end: usize,
    ptr: usize,
    bit_buf: u64 = 0,
    bit_cnt: u32 = 0,

    /// `buf` is the full destination; writing happens from the end downward.
    pub fn init(buf: []u8) ReverseBitWriter {
        return .{ .buf = buf, .end = buf.len, .ptr = buf.len };
    }

    pub fn write(self: *ReverseBitWriter, value: u64, n: u6) !void {
        if (n == 0) return;
        const mask: u64 = if (n == 64) ~@as(u64, 0) else (@as(u64, 1) << n) - 1;
        self.bit_buf |= (value & mask) << @intCast(self.bit_cnt);
        self.bit_cnt += n;
        while (self.bit_cnt >= 8) {
            if (self.ptr == 0) return error.NoSpaceLeft;
            self.ptr -= 1;
            self.buf[self.ptr] = @truncate(self.bit_buf);
            self.bit_buf >>= 8;
            self.bit_cnt -= 8;
        }
    }

    /// Flush the remaining bits with a terminating high bit so the decoder can
    /// locate the first valid bit. Returns the live byte slice.
    pub fn close(self: *ReverseBitWriter) ![]u8 {
        // Add a single '1' marker bit as the final bit of the stream.
        try self.write(1, 1);
        while (self.bit_cnt > 0) {
            if (self.ptr == 0) return error.NoSpaceLeft;
            self.ptr -= 1;
            self.buf[self.ptr] = @truncate(self.bit_buf);
            self.bit_buf >>= 8;
            if (self.bit_cnt > 8) self.bit_cnt -= 8 else self.bit_cnt = 0;
        }
        return self.buf[self.ptr..self.end];
    }
};

/// Forward LSB-first bit reader with a 64-bit refill window. Designed for
/// hot loops: refill is amortized and all reads use masking only.
pub const BitReader = struct {
    data: []const u8,
    byte_pos: usize = 0,
    bit_buf: u64 = 0,
    bit_cnt: u32 = 0,
    /// Set when a read asked for more bits than the input held (reads then
    /// return zeros). Decoders must check this to avoid spinning on padding.
    eof: bool = false,

    pub fn init(data: []const u8) BitReader {
        var r: BitReader = .{ .data = data };
        r.refill();
        return r;
    }

    pub fn refill(self: *BitReader) void {
        while (self.bit_cnt <= 56 and self.byte_pos < self.data.len) {
            self.bit_buf |= @as(u64, self.data[self.byte_pos]) << @intCast(self.bit_cnt);
            self.byte_pos += 1;
            self.bit_cnt += 8;
        }
    }

    /// Read `n` low bits (n <= 64). Caller guarantees bits are available.
    pub fn read(self: *BitReader, n: u6) u64 {
        if (n == 0) return 0;
        if (self.bit_cnt < n) {
            self.eof = true;
            self.bit_buf = 0;
            self.bit_cnt = 0;
            return 0;
        }
        const mask: u64 = if (n == 64) ~@as(u64, 0) else (@as(u64, 1) << n) - 1;
        const v = self.bit_buf & mask;
        self.bit_buf >>= n;
        self.bit_cnt -= n;
        self.refill();
        return v;
    }

    /// Peek `n` bits without consuming (n <= 64).
    pub fn peek(self: *BitReader, n: u6) u64 {
        const mask: u64 = if (n == 64) ~@as(u64, 0) else (@as(u64, 1) << n) - 1;
        return self.bit_buf & mask;
    }

    pub fn skip(self: *BitReader, n: u6) void {
        self.bit_buf >>= n;
        self.bit_cnt -= n;
        self.refill();
    }

    /// Discard bits to reach the next byte boundary.
    pub fn alignToByte(self: *BitReader) void {
        const drop: u32 = self.bit_cnt % 8;
        self.bit_buf >>= @intCast(drop);
        self.bit_cnt -= drop;
        self.refill();
    }

    pub fn bitsAvailable(self: *const BitReader) u64 {
        const unread_bytes: u64 = self.data.len - self.byte_pos;
        return @as(u64, self.bit_cnt) + unread_bytes * 8;
    }
};
