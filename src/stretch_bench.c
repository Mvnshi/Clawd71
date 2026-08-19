/*
 * Fast C port of Electrum Type-1's stretch_key -- the ONLY genuinely
 * expensive step in that scheme (100,000 rounds of SHA256, ~50ms/candidate
 * in Python). Everything after stretch_key (one EC scalar mult for the
 * master pubkey, one SHA256d + bigint add per puzzle index checked) is
 * cheap and stays in Python (src/seed_attack.py), which already has a
 * validated, tested implementation of that part.
 *
 * stretch_key, reproduced from spesmilo/electrum's Old_KeyStore.stretch_key:
 *   encoded = hex_seed.encode('ascii')   # 32 bytes for a 32-hex-char seed
 *   x = encoded
 *   for i in range(100000):
 *       x = sha256(x + encoded)
 *   return x  (as a 256-bit big-endian integer)
 *
 * For a standard 32-hex-char seed, x is always exactly 32 bytes (either the
 * seed itself on round 0, or the previous digest), so `x + encoded` is
 * always exactly 64 bytes -- one message block plus one padding-only block.
 * That fixed shape is what makes a specialised, fast loop possible.
 *
 * Correctness is not assumed: `selftest` reproduces the same seed used in
 * tests/test_seed_attack.py (itself validated against a real published
 * spesmilo/electrum test vector) and must match exactly before this is
 * trusted for anything.
 *
 * Build:  cc -O3 -march=native -msse4.1 -msha -pthread -o stretch_bench src/stretch_bench.c
 * (requires a CPU with SHA-NI; falls back are not implemented -- if your
 * CPU lacks SHA-NI, use src/seed_attack.py's Python electrum_stretch_key
 * instead, which uses whatever hashlib/OpenSSL provides on your machine)
 * Usage:  ./stretch_bench selftest
 *         ./stretch_bench batch <threads>   (reads 32-hex-char seeds on
 *                                             stdin, one per line; writes
 *                                             "<seed> <secexp_hex>" per line)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

/* Intel SHA-NI hardware-accelerated compressor -- see src/sha256_ni.c for
 * provenance/validation. This container's CPU has SHA-NI (confirmed via
 * `grep sha_ni /proc/cpuinfo`); a hand-written scalar SHA256 loop measured
 * SLOWER than Python's hashlib (OpenSSL, which does use SHA-NI here), so
 * this replaces an earlier scalar version rather than complementing it. */
#include "sha256_ni.c"

/* seed: exactly 32 raw bytes (the ASCII encoding of a 32-hex-char seed
 * string). 100,000 rounds of x = SHA256(x || seed). The 128-byte message
 * buffer (data block + padding block) is built ONCE outside the loop --
 * only its first 32 bytes (the running digest x) change per round.
 *
 * Two prior versions were measured and rejected before this one:
 *   1. A generic sha256_64() helper that rebuilt the whole 128-byte buffer
 *      (including the constant seed suffix and padding) from scratch every
 *      round -- ~10x slower than necessary from pure redundant work.
 *   2. This function's own first version, using a scalar `put_be32` loop to
 *      byte-swap the digest back into `blk` between rounds -- ~100x SLOWER
 *      than the version below, despite doing "the same" byte-swap. Isolating
 *      sha256_process_x86 alone measured ~96ns/call (so 100,000 rounds should
 *      cost ~9.6ms), but that scalar-store version measured ~1.01s/candidate.
 *      Root cause, confirmed by isolated A/B benchmark: writing the digest
 *      4 bytes at a time via scalar stores, then immediately reading it back
 *      via a 16-byte SIMD load (`_mm_loadu_si128` inside the next call) is a
 *      textbook store-to-load-forwarding stall -- the CPU can't forward a
 *      narrow store to a wider, differently-aligned load without a costly
 *      pipeline flush, once per round, 100,000 times. Replacing the scalar
 *      byte-swap loop with SIMD stores of matching width (below) closed the
 *      gap to ~9.8ms/candidate -- matches the isolated sha256_process_x86-only
 *      prediction, and still reproduces the same known-answer test vector. */
__attribute__((always_inline)) static inline void stretch_key_64(const uint8_t seed[32], uint8_t out[32]) {
    static const uint32_t IV[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    const __m128i BSWAP = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);
    uint8_t blk[128];
    memcpy(blk + 32, seed, 32);   /* fixed suffix, set once */
    memset(blk + 64, 0, 64);
    blk[64] = 0x80;
    blk[126] = 0x02; blk[127] = 0x00; /* 64*8 = 512 = 0x0200, fixed, set once */
    memcpy(blk, seed, 32);        /* round 0's first half is the seed itself */

    uint32_t st[8];
    for (int i = 0; i < 100000; i++) {
        memcpy(st, IV, sizeof IV);
        sha256_process_x86(st, blk, 128);
        __m128i lo = _mm_loadu_si128((__m128i*)&st[0]);
        __m128i hi = _mm_loadu_si128((__m128i*)&st[4]);
        lo = _mm_shuffle_epi8(lo, BSWAP);
        hi = _mm_shuffle_epi8(hi, BSWAP);
        _mm_storeu_si128((__m128i*)(blk + 0), lo);
        _mm_storeu_si128((__m128i*)(blk + 16), hi);
    }
    memcpy(out, blk, 32);
}

static void hex_encode(const uint8_t *in, int n, char *out) {
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[2*i] = h[in[i]>>4]; out[2*i+1] = h[in[i]&0xf]; }
    out[2*n] = 0;
}

static int hex_decode(const char *in, uint8_t *out, int n) {
    for (int i = 0; i < n; i++) {
        int hi, lo;
        char c1 = in[2*i], c2 = in[2*i+1];
        if (c1 >= '0' && c1 <= '9') hi = c1 - '0';
        else if (c1 >= 'a' && c1 <= 'f') hi = c1 - 'a' + 10;
        else if (c1 >= 'A' && c1 <= 'F') hi = c1 - 'A' + 10;
        else return -1;
        if (c2 >= '0' && c2 <= '9') lo = c2 - '0';
        else if (c2 >= 'a' && c2 <= 'f') lo = c2 - 'a' + 10;
        else if (c2 >= 'A' && c2 <= 'F') lo = c2 - 'A' + 10;
        else return -1;
        out[i] = (hi << 4) | lo;
    }
    return 0;
}

static void run_selftest(void) {
    /* same seed as tests/test_seed_attack.py's KNOWN_ELECTRUM_MNEMONIC-derived
     * hex seed, validated there against a real spesmilo/electrum test vector */
    const char *seed_hex = "acb740e454c3134901d7c8f16497cc1c";
    const char *expected_secexp = "21b880fda2fd30081834683a7049ac9e3941a42adbc3a4616c9a9275aa960c0d";
    uint8_t seed_ascii[32];
    memcpy(seed_ascii, seed_hex, 32); /* the ASCII bytes of the hex string itself */
    uint8_t out[32];
    stretch_key_64(seed_ascii, out);
    char got[65];
    hex_encode(out, 32, got);
    printf("seed        : %s\n", seed_hex);
    printf("got secexp  : %s\n", got);
    printf("expect secexp: %s\n", expected_secexp);
    if (strcmp(got, expected_secexp) == 0) {
        printf("SELFTEST PASS\n");
    } else {
        printf("SELFTEST FAIL -- do not trust this binary\n");
        exit(1);
    }
}

typedef struct { char **lines; int start, end; char **out; } job;

static void *worker(void *arg) {
    job *j = (job *)arg;
    for (int i = j->start; i < j->end; i++) {
        uint8_t seed_ascii[32];
        memcpy(seed_ascii, j->lines[i], 32);
        uint8_t out[32];
        stretch_key_64(seed_ascii, out);
        char *line = malloc(32 + 1 + 64 + 2);
        memcpy(line, j->lines[i], 32);
        line[32] = ' ';
        hex_encode(out, 32, line + 33);
        line[33 + 64] = '\n';
        line[33 + 64 + 1] = 0;
        j->out[i] = line;
    }
    return NULL;
}

static void run_batch(int nthreads) {
    char **lines = NULL;
    int n = 0, cap = 0;
    char buf[128];
    while (fgets(buf, sizeof buf, stdin)) {
        int len = strlen(buf);
        while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) buf[--len] = 0;
        if (len != 32) continue; /* only exactly-32-hex-char seeds supported */
        uint8_t tmp[16];
        if (hex_decode(buf, tmp, 16) != 0) continue; /* validates hex */
        if (n == cap) { cap = cap ? cap * 2 : 4096; lines = realloc(lines, cap * sizeof(char*)); }
        lines[n] = strdup(buf);
        n++;
    }
    if (n == 0) return;
    char **out = calloc(n, sizeof(char*));
    pthread_t th[64];
    job jobs[64];
    if (nthreads > 64) nthreads = 64;
    if (nthreads < 1) nthreads = 1;
    int chunk = (n + nthreads - 1) / nthreads;
    int actual = 0;
    for (int t = 0; t < nthreads; t++) {
        int s = t * chunk, e = s + chunk; if (e > n) e = n; if (s >= n) break;
        jobs[t] = (job){ lines, s, e, out };
        pthread_create(&th[t], NULL, worker, &jobs[t]);
        actual++;
    }
    for (int t = 0; t < actual; t++) pthread_join(th[t], NULL);
    for (int i = 0; i < n; i++) { fputs(out[i], stdout); }
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "selftest") == 0) { run_selftest(); return 0; }
    if (argc >= 3 && strcmp(argv[1], "batch") == 0) { run_batch(atoi(argv[2])); return 0; }
    fprintf(stderr, "usage:\n  %s selftest\n  %s batch <threads>   (seeds on stdin, 32 hex chars each)\n", argv[0], argv[0]);
    return 1;
}
