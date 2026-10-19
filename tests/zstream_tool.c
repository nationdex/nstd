/* Streaming driver for the z_stream API, used by tests/interop.sh against the
 * system zlib (via python).  Built from the real zlib.h.
 *   zstream_tool def LEVEL WBITS CHUNK FLUSH_EVERY IN OUT [DICT]
 *   zstream_tool inf WBITS INCHUNK OUTCHUNK IN OUT [DICT]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <zlib.h>
#ifndef _WIN32
#include <unistd.h>
#endif

static FILE *open_out(const char *path) {
#ifdef _WIN32
    FILE *f = fopen(path, "wb");
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) { perror(path); exit(2); }
    FILE *f = fdopen(fd, "wb");
#endif
    if (!f) { perror(path); exit(2); }
    return f;
}

static unsigned char *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(sz ? sz : 1);
    if (fread(b, 1, sz, f) != (size_t)sz) exit(2);
    fclose(f); *n = sz; return b;
}

int main(int argc, char **argv) {
    if (argc < 7) return 2;
    int deflating = !strcmp(argv[1], "def");
    size_t in_n, dict_n = 0;
    unsigned char *dict = NULL;
    z_stream z; memset(&z, 0, sizeof z);
    FILE *out;
    if (deflating) {
        int level = atoi(argv[2]), wbits = atoi(argv[3]);
        size_t chunk = atol(argv[4]), flush_every = atol(argv[5]);
        unsigned char *in = slurp(argv[6], &in_n);
        out = open_out(argv[7]);
        if (argc > 8) dict = slurp(argv[8], &dict_n);
        if (deflateInit2(&z, level, Z_DEFLATED, wbits, 8, Z_DEFAULT_STRATEGY) != Z_OK) return 3;
        if (dict && deflateSetDictionary(&z, dict, dict_n) != Z_OK) return 4;
        unsigned char obuf[257];
        size_t off = 0, n = 0;
        for (;;) {
            size_t take = in_n - off < chunk ? in_n - off : chunk;
            z.next_in = in + off; z.avail_in = take; off += take; n++;
            int fl = off >= in_n ? Z_FINISH : ((flush_every && n % flush_every == 0) ? (n % (2 * flush_every) ? Z_SYNC_FLUSH : Z_FULL_FLUSH) : Z_NO_FLUSH);
            int r;
            do {
                z.next_out = obuf; z.avail_out = sizeof obuf;
                r = deflate(&z, fl);
                if (r != Z_OK && r != Z_STREAM_END && r != Z_BUF_ERROR) return 5;
                fwrite(obuf, 1, sizeof obuf - z.avail_out, out);
            } while (z.avail_out == 0 || (fl == Z_FINISH && r != Z_STREAM_END));
            if (z.avail_in != 0) return 6;
            if (fl == Z_FINISH) break;
        }
        if (deflateEnd(&z) != Z_OK) return 7;
    } else {
        int wbits = atoi(argv[2]);
        size_t inchunk = atol(argv[3]), outchunk = atol(argv[4]);
        unsigned char *in = slurp(argv[5], &in_n);
        out = open_out(argv[6]);
        if (argc > 7) dict = slurp(argv[7], &dict_n);
        if (inflateInit2(&z, wbits) != Z_OK) return 3;
        unsigned char *obuf = malloc(outchunk);
        size_t off = 0;
        int r = Z_OK;
        while (r != Z_STREAM_END) {
            size_t take = in_n - off < inchunk ? in_n - off : inchunk;
            z.next_in = in + off; z.avail_in = take;
            do {
                z.next_out = obuf; z.avail_out = outchunk;
                r = inflate(&z, Z_NO_FLUSH);
                if (r == Z_NEED_DICT) {
                    if (!dict || inflateSetDictionary(&z, dict, dict_n) != Z_OK) return 8;
                    continue;
                }
                if (r != Z_OK && r != Z_STREAM_END && r != Z_BUF_ERROR) { fprintf(stderr, "inflate rc=%d msg=%s\n", r, z.msg ? z.msg : "-"); return 5; }
                fwrite(obuf, 1, outchunk - z.avail_out, out);
            } while (r != Z_STREAM_END && (z.avail_out == 0 || z.avail_in > 0));
            off += take - z.avail_in;
            if (r != Z_STREAM_END && take == 0) return 9; /* truncated */
        }
        if (inflateEnd(&z) != Z_OK) return 7;
    }
    fclose(out);
    return 0;
}
