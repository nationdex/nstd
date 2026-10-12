#!/usr/bin/env bash
# Cross-implementation conformance: nstd vs system zstd/gzip and the reference
# Brotli encoder/decoder (python `brotli` module; set BROTLI_PYPATH to its dir).
# Usage: tests/interop.sh [path/to/nstd]
set -u
NSTD=${1:-zig-out/bin/nstd}
# Every nstd call runs under a memory cap and timeout so a decoder bug cannot take the machine down.
N() { ( ulimit -v 2000000; exec timeout 60 "$NSTD" "$@" ); }
T=$(mktemp -d "${TMPDIR:-$PWD/.tmp}/interop.XXXXXX" 2>/dev/null || mktemp -d)
trap 'rm -rf "$T"' EXIT
fail=0
bad() { echo "FAIL: $*"; fail=1; }

# Corpus: text, binary, random, runs, empty, tiny, tar.
cat zstd/lib/zstd.h zstd/doc/zstd_manual.html > "$T/text"
cp "$NSTD" "$T/bin"
head -c 300000 /dev/urandom > "$T/rand"
head -c 100000 /dev/zero | tr '\0' 'a' > "$T/rle"
: > "$T/empty"; printf hi > "$T/tiny"
tar cf "$T/tar" zstd/lib zstd/programs 2>/dev/null

for f in text bin rand rle empty tiny tar; do
  in="$T/$f"
  for l in 1 2 3 9; do
    N -$l -c "$in" > "$T/c.zst" || bad "nstd -$l compress $f"
    zstd -q -t "$T/c.zst" 2>/dev/null || bad "system zstd rejects nstd -$l $f"
    zstd -q -d -c "$T/c.zst" | cmp -s - "$in" || bad "system zstd decode of nstd -$l $f"
  done
  for l in 1 3 9 19; do
    zstd -q -$l -c "$in" > "$T/s.zst"
    N -d -c "$T/s.zst" | cmp -s - "$in" || bad "nstd decode of zstd -$l $f"
  done
  for gl in 1 3 4 6 9; do
    N -g -$gl -c "$in" > "$T/c.gz" && gzip -t "$T/c.gz" 2>/dev/null || bad "gzip rejects nstd gzip -$gl $f"
    gzip -dc "$T/c.gz" 2>/dev/null | cmp -s - "$in" || bad "gzip decode of nstd gzip -$gl $f"
  done
  gzip -c "$in" > "$T/s.gz"; N -d -c "$T/s.gz" | cmp -s - "$in" || bad "nstd decode of gzip $f"
done

# Dictionaries: a trained (formatted) one and a raw-content one, both directions.
mkdir -p "$T/samples"
i=0; for f in zstd/lib/common/*.c zstd/lib/compress/*.c zstd/lib/decompress/*.c zstd/lib/*.h zstd/programs/*.c; do i=$((i+1)); cp "$f" "$T/samples/s$i"; done
zstd -q --train "$T"/samples/* -o "$T/dict.zst" --maxdict=16384 2>/dev/null
head -c 20000 zstd/lib/common/zstd_internal.h > "$T/raw.dict"
N --train --maxdict 16384 -o "$T/own.dict" "$T"/samples/* 2>/dev/null || bad "nstd --train"
for d in dict.zst raw.dict own.dict; do
  for f in zstd/lib/zstd.h zstd/programs/zstdcli.c zstd/doc/zstd_compression_format.md; do
    for l in 1 3 9; do
      zstd -q -$l -D "$T/$d" -c "$f" > "$T/dz.zst"
      N -d -D "$T/$d" -c "$T/dz.zst" | cmp -s - "$f" || bad "nstd decode of zstd -$l -D $d $f"
      N -$l -D "$T/$d" -c "$f" > "$T/dz.zst" || bad "nstd -$l -D $d compress $f"
      zstd -q -D "$T/$d" -d -c "$T/dz.zst" | cmp -s - "$f" || bad "zstd decode of nstd -$l -D $d $f"
    done
  done
done

if [ -n "${BROTLI_PYPATH:-}" ]; then
  for f in text bin rand rle empty tiny tar; do
    in="$T/$f"
    for bq in 1 3 5 11; do
      N -b -$bq -c "$in" > "$T/c.br" || bad "nstd brotli -$bq compress $f"
      python3 - "$BROTLI_PYPATH" "$T/c.br" "$in" <<'PY' || bad "reference brotli decode of nstd -$bq $f"
import sys; sys.path.insert(0, sys.argv[1]); import brotli
assert brotli.decompress(open(sys.argv[2],'rb').read()) == open(sys.argv[3],'rb').read()
PY
    done
    for q in 0 4 9 11; do
      python3 - "$BROTLI_PYPATH" "$in" $q > "$T/s.br" <<'PY'
import sys; sys.path.insert(0, sys.argv[1]); import brotli
sys.stdout.buffer.write(brotli.compress(open(sys.argv[2],'rb').read(), quality=int(sys.argv[3])))
PY
      N -b -d -c "$T/s.br" | cmp -s - "$in" || bad "nstd decode of brotli q$q $f"
    done
  done
fi
if command -v python3 >/dev/null && [ -x "$(dirname "$NSTD")/zstream_tool" ]; then
  ZSTREAM_TOOL="$(dirname "$NSTD")/zstream_tool" ZSTREAM_BIN="$NSTD" TMPDIR="$T" python3 tests/zstream_interop.py | grep -q "all pass" || bad "zstream interop vs system zlib"
fi
[ $fail = 0 ] && echo "interop: all pass"
exit $fail
