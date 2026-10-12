//! Zstandard dictionary handling (RFC 8878 §5).
//!
//! Parses both formatted dictionaries (magic 0xEC30A437, containing Huffman
//! and FSE entropy tables, repeat offsets and dictionary content) and raw
//! content dictionaries (arbitrary bytes acting as prefix history).

const std = @import("std");
const fse = @import("fse.zig");
const huf = @import("huf.zig");
const dec = @import("decompress.zig");

pub const ZSTD_MAGIC_DICTIONARY: u32 = 0xEC30A437;

pub const Error = error{
    CorruptData,
    DictionaryCorrupted,
    OutOfMemory,
};

pub const Dict = struct {
    dict_id: u32 = 0,
    is_formatted: bool = false,
    content: []const u8 = &.{},
    huf_table: ?huf.DTable = null,
    of_tab: ?dec.SeqTab = null,
    ml_tab: ?dec.SeqTab = null,
    ll_tab: ?dec.SeqTab = null,
    rep: [3]u32 = .{ 1, 4, 8 },

    /// Parse a dictionary buffer. If the buffer is smaller than 8 bytes or does
    /// not begin with ZSTD_MAGIC_DICTIONARY, it is treated as a raw content
    /// dictionary.
    pub fn init(dict_bytes: []const u8) Error!Dict {
        if (dict_bytes.len < 8) {
            return .{
                .dict_id = 0,
                .is_formatted = false,
                .content = dict_bytes,
            };
        }
        const magic = std.mem.readInt(u32, dict_bytes[0..4], .little);
        if (magic != ZSTD_MAGIC_DICTIONARY) {
            return .{
                .dict_id = 0,
                .is_formatted = false,
                .content = dict_bytes,
            };
        }

        const dict_id = std.mem.readInt(u32, dict_bytes[4..8], .little);
        var pos: usize = 8;

        // 1. Huffman table for literals
        var huf_tab = huf.DTable{};
        const huf_consumed = huf.readTable(&huf_tab, dict_bytes[pos..]) catch return error.DictionaryCorrupted;
        pos += huf_consumed;

        // 2. Offsets FSE table (max sym 31, max log 8)
        const nc_of = fse.readNCount(dict_bytes[pos..], 32, 8) catch return error.DictionaryCorrupted;
        pos += nc_of.consumed;
        const dt_of = fse.DTable.build(nc_of.norm[0..nc_of.nsym], nc_of.log) catch return error.DictionaryCorrupted;
        const of_tab = dec.SeqTab.from(&dt_of, .of) catch return error.DictionaryCorrupted;

        // 3. Match lengths FSE table (max sym 53, max log 9)
        const nc_ml = fse.readNCount(dict_bytes[pos..], 53, 9) catch return error.DictionaryCorrupted;
        pos += nc_ml.consumed;
        const dt_ml = fse.DTable.build(nc_ml.norm[0..nc_ml.nsym], nc_ml.log) catch return error.DictionaryCorrupted;
        const ml_tab = dec.SeqTab.from(&dt_ml, .ml) catch return error.DictionaryCorrupted;

        // 4. Literal lengths FSE table (max sym 36, max log 9)
        const nc_ll = fse.readNCount(dict_bytes[pos..], 36, 9) catch return error.DictionaryCorrupted;
        pos += nc_ll.consumed;
        const dt_ll = fse.DTable.build(nc_ll.norm[0..nc_ll.nsym], nc_ll.log) catch return error.DictionaryCorrupted;
        const ll_tab = dec.SeqTab.from(&dt_ll, .ll) catch return error.DictionaryCorrupted;

        // 5. Repeat offsets: 3 x 4-byte LE integers
        if (pos + 12 > dict_bytes.len) return error.DictionaryCorrupted;
        const rep0 = std.mem.readInt(u32, dict_bytes[pos..][0..4], .little);
        const rep1 = std.mem.readInt(u32, dict_bytes[pos + 4 ..][0..4], .little);
        const rep2 = std.mem.readInt(u32, dict_bytes[pos + 8 ..][0..4], .little);
        pos += 12;

        const content = dict_bytes[pos..];

        return .{
            .dict_id = dict_id,
            .is_formatted = true,
            .content = content,
            .huf_table = huf_tab,
            .of_tab = of_tab,
            .ml_tab = ml_tab,
            .ll_tab = ll_tab,
            .rep = .{ rep0, rep1, rep2 },
        };
    }

    /// Extract dictID from a dictionary buffer if formatted, else returns 0.
    pub fn getDictID(dict_bytes: []const u8) u32 {
        if (dict_bytes.len < 8) return 0;
        const magic = std.mem.readInt(u32, dict_bytes[0..4], .little);
        if (magic != ZSTD_MAGIC_DICTIONARY) return 0;
        return std.mem.readInt(u32, dict_bytes[4..8], .little);
    }
};

test "parse raw dictionary" {
    const raw = "sample raw dictionary content string";
    const d = try Dict.init(raw);
    try std.testing.expectEqual(@as(u32, 0), d.dict_id);
    try std.testing.expect(!d.is_formatted);
    try std.testing.expectEqualStrings(raw, d.content);
    try std.testing.expectEqual(@as(u32, 0), Dict.getDictID(raw));
}
