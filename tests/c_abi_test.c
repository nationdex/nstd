/* Links against libnstd using the *real* libzstd header, proving ABI parity. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#define ZDICT_STATIC_LINKING_ONLY
#include <zdict.h>
#include <zlib.h>
#include <brotli/encode.h>
#include <brotli/decode.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); return 1; } } while (0)

static char *mkdata(size_t n) {
    char *p = malloc(n);
    for (size_t i = 0; i < n; i++) p[i] = "lorem ipsum dolor sit amet, "[(i * 7 + (i >> 9)) % 28];
    return p;
}

int main(void) {
    size_t n = 700000;
    char *src = mkdata(n);

    /* one-shot */
    size_t cap = ZSTD_compressBound(n);
    char *z = malloc(cap), *back = malloc(n);
    size_t zn = ZSTD_compress(z, cap, src, n, 3);
    CHECK(!ZSTD_isError(zn));
    CHECK(ZSTD_getFrameContentSize(z, zn) == n);
    CHECK(ZSTD_findFrameCompressedSize(z, zn) == zn);
    CHECK(ZSTD_decompress(back, n, z, zn) == n && !memcmp(src, back, n));
    CHECK(ZSTD_isError(ZSTD_decompress(back, n / 2, z, zn)));
    z[zn / 2] ^= 0x55;
    CHECK(ZSTD_isError(ZSTD_decompress(back, n, z, zn)));
    printf("one-shot ok: %zu -> %zu\n", n, zn);

    /* CCtx */
    ZSTD_CCtx *cc = ZSTD_createCCtx();
    zn = ZSTD_compressCCtx(cc, z, cap, src, n, 5);
    CHECK(!ZSTD_isError(zn));
    ZSTD_DCtx *dc = ZSTD_createDCtx();
    CHECK(ZSTD_decompressDCtx(dc, back, n, z, zn) == n && !memcmp(src, back, n));
    ZSTD_freeCCtx(cc); ZSTD_freeDCtx(dc);

    /* streaming compress in 64K slices, tiny output buffer */
    ZSTD_CStream *cs = ZSTD_createCStream();
    ZSTD_initCStream(cs, 3);
    size_t zcap = n + 4096, zlen = 0;
    char *zs = malloc(zcap);
    char obuf[1000];
    size_t pos = 0;
    while (pos < n) {
        size_t chunk = n - pos < 65536 ? n - pos : 65536;
        ZSTD_inBuffer in = { src + pos, chunk, 0 };
        while (in.pos < in.size) {
            ZSTD_outBuffer out = { obuf, sizeof obuf, 0 };
            size_t r = ZSTD_compressStream(cs, &out, &in);
            CHECK(!ZSTD_isError(r));
            memcpy(zs + zlen, obuf, out.pos); zlen += out.pos;
        }
        pos += chunk;
    }
    size_t rem;
    do {
        ZSTD_outBuffer out = { obuf, sizeof obuf, 0 };
        rem = ZSTD_endStream(cs, &out);
        CHECK(!ZSTD_isError(rem));
        memcpy(zs + zlen, obuf, out.pos); zlen += out.pos;
    } while (rem);
    ZSTD_freeCStream(cs);
    CHECK(ZSTD_decompress(back, n, zs, zlen) == n && !memcmp(src, back, n));

    /* streaming decompress, odd input slices */
    ZSTD_DStream *ds = ZSTD_createDStream();
    ZSTD_initDStream(ds);
    char *dec = malloc(n); size_t dlen = 0, ip = 0, last = 1;
    while (ip < zlen) {
        size_t chunk = zlen - ip < 777 ? zlen - ip : 777;
        ZSTD_inBuffer in = { zs + ip, chunk, 0 };
        do {
            ZSTD_outBuffer out = { obuf, sizeof obuf, 0 };
            last = ZSTD_decompressStream(ds, &out, &in);
            CHECK(!ZSTD_isError(last));
            memcpy(dec + dlen, obuf, out.pos); dlen += out.pos;
        } while (in.pos < in.size || (last > 0 && 0));
        ip += chunk;
    }
    for (;;) {  /* drain */
        ZSTD_inBuffer in = { "", 0, 0 };
        ZSTD_outBuffer out = { obuf, sizeof obuf, 0 };
        last = ZSTD_decompressStream(ds, &out, &in);
        CHECK(!ZSTD_isError(last));
        memcpy(dec + dlen, obuf, out.pos); dlen += out.pos;
        if (!out.pos) break;
    }
    CHECK(last == 0 && dlen == n && !memcmp(src, dec, n));
    ZSTD_freeDStream(ds);
    printf("streaming ok: %zu bytes\n", zlen);

    /* dictionaries: a raw-content dictionary shared by both sides */
    {
        size_t dn = 20000, sn = 5000;
        char *dict = mkdata(dn), *sample = mkdata(sn);
        for (size_t i = 0; i < sn; i += 97) sample[i] ^= 0x15; /* similar, not identical */
        size_t dcap = ZSTD_compressBound(sn);
        char *dz = malloc(dcap), *db = malloc(sn);
        ZSTD_CCtx *dcc = ZSTD_createCCtx(); ZSTD_DCtx *ddc = ZSTD_createDCtx();
        size_t plain = ZSTD_compress(dz, dcap, sample, sn, 3);
        size_t dzn = ZSTD_compress_usingDict(dcc, dz, dcap, sample, sn, dict, dn, 3);
        CHECK(!ZSTD_isError(dzn) && dzn < plain);
        CHECK(ZSTD_decompress_usingDict(ddc, db, sn, dz, dzn, dict, dn) == sn && !memcmp(sample, db, sn));
        /* digested dictionaries */
        ZSTD_CDict *cd = ZSTD_createCDict(dict, dn, 3); ZSTD_DDict *dd = ZSTD_createDDict(dict, dn);
        size_t czn = ZSTD_compress_usingCDict(dcc, dz, dcap, sample, sn, cd);
        CHECK(!ZSTD_isError(czn) && czn == dzn);
        memset(db, 0, sn);
        CHECK(ZSTD_decompress_usingDDict(ddc, db, sn, dz, czn, dd) == sn && !memcmp(sample, db, sn));
        /* advanced API: context carries the dictionary */
        CHECK(!ZSTD_isError(ZSTD_CCtx_loadDictionary(dcc, dict, dn)));
        size_t c2 = ZSTD_compress2(dcc, dz, dcap, sample, sn);
        CHECK(!ZSTD_isError(c2));
        CHECK(!ZSTD_isError(ZSTD_DCtx_loadDictionary(ddc, dict, dn)));
        memset(db, 0, sn);
        CHECK(ZSTD_decompressDCtx(ddc, db, sn, dz, c2) == sn && !memcmp(sample, db, sn));
        /* streaming with a dictionary */
        ZSTD_CStream *cs2 = ZSTD_createCStream();
        CHECK(!ZSTD_isError(ZSTD_initCStream_usingDict(cs2, dict, dn, 3)));
        ZSTD_inBuffer in2 = { sample, sn, 0 }; ZSTD_outBuffer out2 = { dz, dcap, 0 };
        CHECK(!ZSTD_isError(ZSTD_compressStream(cs2, &out2, &in2)));
        while (ZSTD_endStream(cs2, &out2) > 0) {}
        ZSTD_DStream *ds2 = ZSTD_createDStream();
        CHECK(!ZSTD_isError(ZSTD_initDStream_usingDict(ds2, dict, dn)));
        ZSTD_inBuffer in3 = { dz, out2.pos, 0 }; ZSTD_outBuffer out3 = { db, sn, 0 };
        memset(db, 0, sn);
        while (in3.pos < in3.size) CHECK(!ZSTD_isError(ZSTD_decompressStream(ds2, &out3, &in3)));
        CHECK(out3.pos == sn && !memcmp(sample, db, sn));
        printf("dictionary ok: %zu -> %zu (plain %zu)\n", sn, dzn, plain);
        ZSTD_freeCDict(cd); ZSTD_freeDDict(dd); ZSTD_freeCCtx(dcc); ZSTD_freeDCtx(ddc);
        ZSTD_freeCStream(cs2); ZSTD_freeDStream(ds2);
        free(dict); free(sample); free(dz); free(db);
    }

    /* zlib */
    uLongf zl = compressBound(n);
    Bytef *zb = malloc(zl);
    CHECK(compress(zb, &zl, (Bytef *)src, n) == Z_OK);
    uLongf bl = n;
    CHECK(uncompress((Bytef *)back, &bl, zb, zl) == Z_OK && bl == n && !memcmp(src, back, n));
    CHECK(crc32(0, (Bytef *)"123456789", 9) == 0xCBF43926UL);
    CHECK(adler32(1, (Bytef *)"Wikipedia", 9) == 0x11E60398UL);
    printf("zlib ok: %zu -> %lu\n", n, (unsigned long)zl);

    /* zlib streaming: tiny buffers, sync flush, trailing bytes handed back */
    {
        z_stream zs; memset(&zs, 0, sizeof zs);
        CHECK(deflateInit(&zs, 6) == Z_OK);
        uLong zb = deflateBound(&zs, n);
        unsigned char *cz = malloc(zb + 16), *tail = cz;
        zs.next_in = (Bytef *)src; zs.avail_in = n / 2;
        zs.next_out = cz; zs.avail_out = 64;
        size_t produced = 0;
        int r;
        do { zs.avail_out = 64; zs.next_out = cz + produced; r = deflate(&zs, Z_SYNC_FLUSH); produced = zs.total_out; }
        while (zs.avail_in > 0 || zs.avail_out == 0);
        CHECK(r == Z_OK);
        size_t mid = produced;
        /* the first half must be decodable from just the bytes produced so far */
        z_stream is; memset(&is, 0, sizeof is);
        CHECK(inflateInit(&is) == Z_OK);
        unsigned char *half = malloc(n);
        is.next_in = cz; is.avail_in = mid; is.next_out = half; is.avail_out = n;
        r = inflate(&is, Z_NO_FLUSH);
        CHECK(r == Z_OK && is.total_out == n / 2 && !memcmp(half, src, n / 2));
        CHECK(inflateEnd(&is) == Z_OK);
        zs.next_in = (Bytef *)src + n / 2; zs.avail_in = n - n / 2;
        do { zs.avail_out = zb + 16 - produced; zs.next_out = tail + produced; r = deflate(&zs, Z_FINISH); produced = zs.total_out; }
        while (r == Z_OK);
        CHECK(r == Z_STREAM_END);
        CHECK(deflateEnd(&zs) == Z_OK);
        /* append junk after the stream; inflate must stop at the end and return it */
        memcpy(cz + produced, "JUNK", 4);
        memset(&is, 0, sizeof is);
        CHECK(inflateInit(&is) == Z_OK);
        is.next_in = cz; is.avail_in = produced + 4;
        unsigned char ob[4096]; size_t got = 0;
        do { is.next_out = ob; is.avail_out = sizeof ob; r = inflate(&is, Z_NO_FLUSH); CHECK(r == Z_OK || r == Z_STREAM_END); memcpy(back + got, ob, sizeof ob - is.avail_out); got += sizeof ob - is.avail_out; } while (r == Z_OK);
        CHECK(r == Z_STREAM_END && got == n && !memcmp(back, src, n));
        CHECK(is.avail_in == 4 && !memcmp(is.next_in, "JUNK", 4));
        CHECK(inflateEnd(&is) == Z_OK);
        /* a truncated stream with Z_FINISH is a buffer error, not success */
        memset(&is, 0, sizeof is);
        CHECK(inflateInit(&is) == Z_OK);
        is.next_in = cz; is.avail_in = produced / 2; is.next_out = (Bytef *)back; is.avail_out = n;
        r = inflate(&is, Z_NO_FLUSH);
        CHECK(r == Z_OK || r == Z_BUF_ERROR);
        is.avail_in = 0; is.avail_out = 16;
        CHECK(inflate(&is, Z_FINISH) == Z_BUF_ERROR);
        inflateEnd(&is);
        free(cz); free(half);
        printf("zlib streaming ok: %zu -> %zu\n", n, produced);
    }

    /* brotli one-shot */
    size_t bcap = BrotliEncoderMaxCompressedSize(n), bn = bcap;
    uint8_t *bz = malloc(bcap);
    CHECK(BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC, n, (uint8_t *)src, &bn, bz));
    size_t bd = n;
    CHECK(BrotliDecoderDecompress(bn, bz, &bd, (uint8_t *)back) == BROTLI_DECODER_RESULT_SUCCESS && bd == n && !memcmp(src, back, n));
    bd = n / 2;
    CHECK(BrotliDecoderDecompress(bn, bz, &bd, (uint8_t *)back) == BROTLI_DECODER_RESULT_ERROR);
    printf("brotli one-shot ok: %zu -> %zu\n", n, bn);

    /* brotli streaming encode with a flush in the middle, tiny output buffer */
    BrotliEncoderState *be = BrotliEncoderCreateInstance(0, 0, 0);
    uint8_t *bs = malloc(bcap + 64); size_t blen = 0;
    size_t half = n / 2;
    for (int phase = 0; phase < 2; phase++) {
        const uint8_t *ip = (uint8_t *)src + (phase ? half : 0);
        size_t ain = phase ? n - half : half;
        BrotliEncoderOperation op = phase ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_FLUSH;
        for (;;) {
            uint8_t o[333]; uint8_t *op_ = o; size_t aout = sizeof o;
            CHECK(BrotliEncoderCompressStream(be, op, &ain, &ip, &aout, &op_, 0));
            memcpy(bs + blen, o, sizeof o - aout); blen += sizeof o - aout;
            if (ain == 0 && !BrotliEncoderHasMoreOutput(be)) break;
        }
        if (phase == 0) {
            /* after FLUSH the first half must already be decodable */
            BrotliDecoderState *probe = BrotliDecoderCreateInstance(0, 0, 0);
            size_t pin = blen; const uint8_t *pip = bs;
            uint8_t *pb = malloc(n); size_t pout = n; uint8_t *pop = pb;
            BrotliDecoderResult r = BrotliDecoderDecompressStream(probe, &pin, &pip, &pout, &pop, 0);
            CHECK(r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT);
            CHECK((size_t)(pop - pb) == half && !memcmp(pb, src, half));
            free(pb); BrotliDecoderDestroyInstance(probe);
        }
    }
    CHECK(BrotliEncoderIsFinished(be));
    BrotliEncoderDestroyInstance(be);
    bd = n;
    CHECK(BrotliDecoderDecompress(blen, bs, &bd, (uint8_t *)back) == BROTLI_DECODER_RESULT_SUCCESS && bd == n && !memcmp(src, back, n));

    /* brotli streaming decode in odd slices */
    BrotliDecoderState *bds = BrotliDecoderCreateInstance(0, 0, 0);
    size_t bpos = 0, dl = 0; BrotliDecoderResult br = BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
    while (br != BROTLI_DECODER_RESULT_SUCCESS) {
        size_t chunk = blen - bpos < 509 ? blen - bpos : 509;
        const uint8_t *ip = bs + bpos; size_t ain = chunk;
        do {
            uint8_t o[701]; uint8_t *op_ = o; size_t aout = sizeof o;
            br = BrotliDecoderDecompressStream(bds, &ain, &ip, &aout, &op_, 0);
            CHECK(br != BROTLI_DECODER_RESULT_ERROR);
            memcpy(dec + dl, o, sizeof o - aout); dl += sizeof o - aout;
        } while (br == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);
        bpos += chunk - ain;
        CHECK(bpos <= blen);
        if (br == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) CHECK(chunk > 0);
    }
    CHECK(dl == n && !memcmp(src, dec, n));
    CHECK(BrotliDecoderIsFinished(bds));
    BrotliDecoderDestroyInstance(bds);
    printf("brotli streaming ok: %zu bytes\n", blen);

    /* dictionary training */
    {
        enum { NS = 60 };
        static char pool[NS * 160];
        size_t sizes[NS];
        unsigned seed = 12345;
        for (int i = 0; i < NS; i++) {
            seed = seed * 1103515245u + 12345u;
            sizes[i] = (size_t)snprintf(pool + i * 160, 160,
                "{\"id\":%u,\"kind\":\"event\",\"source\":\"sensor-%u\",\"ok\":true,\"tags\":[\"alpha\",\"beta\",\"gamma\"]}",
                seed >> 16, (seed >> 8) & 15);
        }
        /* samples must be contiguous */
        static char flat[NS * 160];
        size_t fo = 0;
        for (int i = 0; i < NS; i++) { memcpy(flat + fo, pool + i * 160, sizes[i]); fo += sizes[i]; }
        char tdict[2048];
        size_t tn = ZDICT_trainFromBuffer(tdict, sizeof tdict, flat, sizes, NS);
        CHECK(!ZDICT_isError(tn) && tn > 0 && tn <= sizeof tdict);
        CHECK(ZDICT_getDictID(tdict, tn) != 0);
        {   /* finalize around raw content, and the legacy/fastCover entry points */
            char fd[2048];
            ZDICT_params_t zp; memset(&zp, 0, sizeof zp); zp.dictID = 77777;
            size_t fn_ = ZDICT_finalizeDictionary(fd, sizeof fd, flat, 1500, flat, sizes, NS, zp);
            CHECK(!ZDICT_isError(fn_) && ZDICT_getDictID(fd, fn_) == 77777);
            CHECK(ZDICT_getDictHeaderSize(fd, fn_) < fn_);
            char z[512], b[512];
            size_t zn = ZSTD_compress_usingDict(ZSTD_createCCtx(), z, sizeof z, flat, sizes[3], fd, fn_, 3);
            CHECK(!ZSTD_isError(zn) && ZSTD_decompress_usingDict(ZSTD_createDCtx(), b, sizeof b, z, zn, fd, fn_) == sizes[3] && !memcmp(b, flat, sizes[3]));
            ZDICT_fastCover_params_t fp; memset(&fp, 0, sizeof fp);
            CHECK(!ZDICT_isError(ZDICT_optimizeTrainFromBuffer_fastCover(fd, sizeof fd, flat, sizes, NS, &fp)));
            ZDICT_legacy_params_t lp; memset(&lp, 0, sizeof lp);
            CHECK(!ZDICT_isError(ZDICT_trainFromBuffer_legacy(fd, sizeof fd, flat, sizes, NS, lp)));
        }
        char z1[512], z0[512], back[512];
        size_t a = ZSTD_compress_usingDict(ZSTD_createCCtx(), z1, sizeof z1, flat, sizes[0], tdict, tn, 3);
        size_t b = ZSTD_compress(z0, sizeof z0, flat, sizes[0], 3);
        CHECK(!ZSTD_isError(a) && !ZSTD_isError(b) && a < b);
        CHECK(ZSTD_decompress_usingDict(ZSTD_createDCtx(), back, sizeof back, z1, a, tdict, tn) == sizes[0] && !memcmp(back, flat, sizes[0]));
    }
    printf("ALL OK (%s)\n", ZSTD_versionString());
    return 0;
}
