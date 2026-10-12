# nstd — Nstandard

One zero-dependency Zig core for **Zstandard** (RFC 8878), **Brotli** (RFC 7932) and
**Deflate/Gzip** (RFC 1951/1952), with a CLI and a C ABI that is link-compatible with
the common `libzstd`, `zlib` and `libbrotli` entry points.

## Build and verify

```sh
zig build -Doptimize=ReleaseFast        # nstd CLI, libnstd.a, libnstd.so
zig build test                          # unit, round-trip fuzz, corrupt-input fuzz
zig build test-c -Doptimize=ReleaseFast # C caller built from the REAL zstd/zlib/brotli headers
BROTLI_PYPATH=<dir with brotli.py> tests/interop.sh   # vs system zstd/gzip + reference brotli
```

## Speed (single thread, 4-core i5-8265U, best of 12; ratio / compress MB/s / decompress MB/s)

| Codec | text | binary | source tar | reference on same box |
|---|---|---|---|---|
| zstd `-1` | 4.91x / 202 / 584 | 3.28x / 158 / 461 | 4.40x / 207 / 560 | libzstd -1: 4.94x / 321 / 931 (text), 3.13x, 4.36x |
| zstd `-3` | 5.52x / 182 / ~700 | 3.44x / 134 / ~455 | 4.81x / 183 / ~620 | libzstd -3: 5.59x / 226 / 850 (text); decode of libzstd-made files runs at 70-80% of libzstd |
| gzip `-6` | 4.65x / 39 / ~380 | 3.42x / 36 / ~240 | 4.21x / 42 / ~375 | gzip -6 ratio parity (text 691.8 KB vs 692.5 KB); inflate ~1.1x system zlib |
| brotli `-1` | 4.87x / 140 / 321 | 3.11x / 113 / 229 | 4.11x / 148 / 271 | reference q1: 4.75x / 240 / 310 |
| brotli `-5` | 6.26x / 44 / 283 | 3.68x / 20 / 193 | 5.4x / 50 / 288 | reference q5: 6.62x / 47 / 456 |
| brotli `-6` / `-9` | 6.47x / 26 / 336, 6.86x / 7 / 296 | 3.70x / 15, 3.74x / 5 | | reference q6 6.80x / 41, q9 7.12x / 16 |

`-T N` (zstd) cuts the input into independent 8 MB frames: ~1.5x faster compress and decode on this
machine at ~1.2% ratio cost; the result is an ordinary multi-frame Zstandard stream.

## Status

| Area | State |
|---|---|
| Zstd decode | Dictionaries (formatted and raw content; `-D FILE`; train with `nstd --train [--maxdict N] -o OUT FILES…`). Complete: raw/RLE/compressed blocks, Huffman literals (1 and 4 stream, treeless), FSE sequences (predefined/RLE/FSE/repeat), repeat offsets, checksum. Bit-exact with `zstd -1 … --ultra -22`. |
| Zstd encode | FSE + Huffman back end, repeat-offset coding, per-stream table choice (predefined/RLE/custom). `-1` fast single-hash parse with repeat-offset probing and custom FSE tables (ratio parity with libzstd -1), `-2` wider table, `-3` double-hash parse with repeat-offset probing (libzstd-class ratio), `-4`+ lazy hash-chain parse. Multi-threaded via `-T`. Output decodes with stock `zstd`. |
| Brotli decode | Complete: prefix codes, block switching, context maps, distance params, 122 KB static dictionary + all 121 transforms. Incremental (meta-block resumable). Verified vs reference encoder q0–q11. |
| Brotli encode | Quality 0–2: fast parse, one literal tree. 3–4: lazy LZ + 64-context literal modeling (UTF8/LSB6, clustered trees) + distance contexts. 5: bucketed 4-byte hash with bit-cost scoring (a match is scored by bits saved minus distance and command cost, lazily compared), 6+: hash chains of growing depth (16/32/64/128), static-dictionary matches near the stream start for 5-8 and everywhere for 9+. Stored fallback, incremental flush/finish. Verified by the reference decoder. |
| Deflate/Gzip | Table-driven inflate; hash-chain compressor (levels 1–9, greedy ≤3, lazy ≥4) emitting dynamic/fixed/stored blocks. Output accepted by `gzip`; CRC/ISIZE verified on decode. |
| C ABI | `ZSTD_*` one-shot, CCtx/DCtx, CStream/DStream, `compressStream2`, dictionaries (`*_usingDict`, `CDict/DDict`, `loadDictionary`, `refPrefix`, `getDictID_*`); zlib `compress/uncompress/crc32/adler32` plus the full `z_stream` API (`deflateInit2/deflate/deflateSetDictionary/deflateParams/deflateBound`, `inflateInit2/inflate/inflateSetDictionary/inflateReset`; raw, zlib, gzip and auto-detect containers; `Z_SYNC/FULL_FLUSH`, `Z_FINISH`); `BrotliEncoder*/BrotliDecoder*` including streaming. `ZDICT_trainFromBuffer` (+ `_cover`/`optimize_cover`, which map to the same trainer). Not provided: `gz*` file functions, `deflateCopy/inflateCopy/inflatePrime/inflateSync`, `fastCover`/`legacy` trainers, `ZDICT_finalizeDictionary`. |

Layout: `src/zstd/{fse,huf,frame,compress,decompress}.zig`, `src/brotli/{prefix,tables,dict_match,compress,decompress}.zig`,
`src/deflate`, `src/core/{bits,checksum,matchfinder,prefixlen,simd}.zig`, `src/c_abi.zig`.
`src/brotli/tables.zig` is generated from RFC 7932 (transform list and context LUTs; CRC-checked).
