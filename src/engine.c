/*
 * Puzzle #71 search engine.
 *
 * Scope: Bitcoin Puzzle #71 (address 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU,
 * interval [2^70, 2^71-1]). Not a general wallet-attack tool.
 *
 * Puzzle #71's public key has never been exposed on chain (the address has
 * zero outgoing value), so Pollard kangaroo / BSGS are unavailable and the
 * only generic attack is a HASH160 preimage scan over the interval. This
 * engine therefore optimises the scan itself:
 *
 *   - consecutive candidates are produced by *incremental* EC addition, never
 *     by a fresh scalar multiplication;
 *   - a batch of BATCH additions shares one modular inversion (Montgomery's
 *     trick), so per-key cost is ~5 field multiplications;
 *   - SHA256 and RIPEMD160 are specialised to their single fixed-size block
 *     (33-byte pubkey and 32-byte digest both fit in one padded block);
 *   - candidates are rejected on a 4-byte HASH160 prefix before any full
 *     comparison.
 *
 * Build:  cc -O3 -march=native -pthread -o engine src/engine.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

/* --------------------------------------------------------------------- */
/* Field arithmetic mod p = 2^256 - 2^32 - 977                            */
/* --------------------------------------------------------------------- */
typedef struct { uint64_t n[4]; } fe;

static const uint64_t P0 = 0xFFFFFFFEFFFFFC2FULL;
static const uint64_t P1 = 0xFFFFFFFFFFFFFFFFULL;
static const uint64_t P2 = 0xFFFFFFFFFFFFFFFFULL;
static const uint64_t P3 = 0xFFFFFFFFFFFFFFFFULL;
#define FE_C 0x1000003D1ULL   /* 2^32 + 977 */

static inline int fe_ge_p(const fe *a) {
    if (a->n[3] != P3) return a->n[3] > P3;
    if (a->n[2] != P2) return a->n[2] > P2;
    if (a->n[1] != P1) return a->n[1] > P1;
    return a->n[0] >= P0;
}

static inline void fe_sub_p(fe *a) {
    __uint128_t b = 0;
    uint64_t r[4];
    b = (__uint128_t)a->n[0] - P0;           r[0] = (uint64_t)b; b = (b >> 64) & 1;
    b = (__uint128_t)a->n[1] - P1 - b;       r[1] = (uint64_t)b; b = (b >> 64) & 1;
    b = (__uint128_t)a->n[2] - P2 - b;       r[2] = (uint64_t)b; b = (b >> 64) & 1;
    b = (__uint128_t)a->n[3] - P3 - b;       r[3] = (uint64_t)b;
    memcpy(a->n, r, sizeof(r));
}

static inline void fe_norm(fe *a) { if (fe_ge_p(a)) fe_sub_p(a); }

static inline void fe_add(fe *r, const fe *a, const fe *b) {
    __uint128_t c = 0;
    c = (__uint128_t)a->n[0] + b->n[0];        r->n[0] = (uint64_t)c; c >>= 64;
    c += (__uint128_t)a->n[1] + b->n[1];       r->n[1] = (uint64_t)c; c >>= 64;
    c += (__uint128_t)a->n[2] + b->n[2];       r->n[2] = (uint64_t)c; c >>= 64;
    c += (__uint128_t)a->n[3] + b->n[3];       r->n[3] = (uint64_t)c; c >>= 64;
    /* fold the 2^256 overflow back in */
    if (c) {
        __uint128_t d = (__uint128_t)r->n[0] + FE_C;
        r->n[0] = (uint64_t)d; d >>= 64;
        d += r->n[1]; r->n[1] = (uint64_t)d; d >>= 64;
        d += r->n[2]; r->n[2] = (uint64_t)d; d >>= 64;
        d += r->n[3]; r->n[3] = (uint64_t)d;
    }
    fe_norm(r);
}

static inline void fe_sub(fe *r, const fe *a, const fe *b) {
    /* r = a - b mod p, for a,b < p.
     * Computing a - b + p directly would reach up to 2p, which does not fit in
     * 256 bits; instead subtract and add p back only on borrow. */
    uint64_t t[4];
    __uint128_t d;
    uint64_t borrow;
    d = (__uint128_t)a->n[0] - b->n[0];            t[0] = (uint64_t)d; borrow = (uint64_t)((d >> 64) & 1);
    d = (__uint128_t)a->n[1] - b->n[1] - borrow;   t[1] = (uint64_t)d; borrow = (uint64_t)((d >> 64) & 1);
    d = (__uint128_t)a->n[2] - b->n[2] - borrow;   t[2] = (uint64_t)d; borrow = (uint64_t)((d >> 64) & 1);
    d = (__uint128_t)a->n[3] - b->n[3] - borrow;   t[3] = (uint64_t)d; borrow = (uint64_t)((d >> 64) & 1);
    if (borrow) {
        __uint128_t c;
        c = (__uint128_t)t[0] + P0;         t[0] = (uint64_t)c; c >>= 64;
        c += (__uint128_t)t[1] + P1;        t[1] = (uint64_t)c; c >>= 64;
        c += (__uint128_t)t[2] + P2;        t[2] = (uint64_t)c; c >>= 64;
        c += (__uint128_t)t[3] + P3;        t[3] = (uint64_t)c;
    }
    r->n[0] = t[0]; r->n[1] = t[1]; r->n[2] = t[2]; r->n[3] = t[3];
}

/* full 256x256 -> 512 then reduce */
static void fe_mul(fe *r, const fe *a, const fe *b) {
    __uint128_t acc;
    uint64_t w[8] = {0};
    uint64_t carry;

    for (int i = 0; i < 4; i++) {
        carry = 0;
        for (int j = 0; j < 4; j++) {
            acc = (__uint128_t)a->n[i] * b->n[j] + w[i + j] + carry;
            w[i + j] = (uint64_t)acc;
            carry = (uint64_t)(acc >> 64);
        }
        w[i + 4] = carry;
    }

    /* fold high 256 bits: value = lo + hi * C */
    uint64_t t[5];
    acc = 0; carry = 0;
    for (int i = 0; i < 4; i++) {
        acc = (__uint128_t)w[i + 4] * FE_C + w[i] + carry;
        t[i] = (uint64_t)acc;
        carry = (uint64_t)(acc >> 64);
    }
    t[4] = carry;

    /* fold the remaining limb */
    acc = (__uint128_t)t[4] * FE_C + t[0];
    r->n[0] = (uint64_t)acc; carry = (uint64_t)(acc >> 64);
    acc = (__uint128_t)t[1] + carry; r->n[1] = (uint64_t)acc; carry = (uint64_t)(acc >> 64);
    acc = (__uint128_t)t[2] + carry; r->n[2] = (uint64_t)acc; carry = (uint64_t)(acc >> 64);
    acc = (__uint128_t)t[3] + carry; r->n[3] = (uint64_t)acc; carry = (uint64_t)(acc >> 64);
    if (carry) {
        acc = (__uint128_t)r->n[0] + FE_C; r->n[0] = (uint64_t)acc; carry = (uint64_t)(acc >> 64);
        acc = (__uint128_t)r->n[1] + carry; r->n[1] = (uint64_t)acc; carry = (uint64_t)(acc >> 64);
        acc = (__uint128_t)r->n[2] + carry; r->n[2] = (uint64_t)acc; carry = (uint64_t)(acc >> 64);
        r->n[3] += carry;
    }
    fe_norm(r);
}

static inline void fe_sqr(fe *r, const fe *a) { fe_mul(r, a, a); }

static void fe_set_u64(fe *r, uint64_t v) { r->n[0] = v; r->n[1] = r->n[2] = r->n[3] = 0; }
static int fe_is_zero(const fe *a) { return !(a->n[0] | a->n[1] | a->n[2] | a->n[3]); }
static int fe_eq(const fe *a, const fe *b) {
    return a->n[0] == b->n[0] && a->n[1] == b->n[1] && a->n[2] == b->n[2] && a->n[3] == b->n[3];
}

/* inverse via Fermat: a^(p-2). p-2 = 2^256 - 2^32 - 979 */
static void fe_inv(fe *r, const fe *a) {
    /* addition chain used by libsecp256k1 (x2,x3,x6,x9,x11,x22,x44,x88,x176,x220,x223) */
    fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t;
    int j;
    fe_sqr(&x2, a);      fe_mul(&x2, &x2, a);
    fe_sqr(&x3, &x2);    fe_mul(&x3, &x3, a);
    t = x3; for (j = 0; j < 3; j++) fe_sqr(&t, &t); fe_mul(&x6, &t, &x3);
    t = x6; for (j = 0; j < 3; j++) fe_sqr(&t, &t); fe_mul(&x9, &t, &x3);
    t = x9; for (j = 0; j < 2; j++) fe_sqr(&t, &t); fe_mul(&x11, &t, &x2);
    t = x11; for (j = 0; j < 11; j++) fe_sqr(&t, &t); fe_mul(&x22, &t, &x11);
    t = x22; for (j = 0; j < 22; j++) fe_sqr(&t, &t); fe_mul(&x44, &t, &x22);
    t = x44; for (j = 0; j < 44; j++) fe_sqr(&t, &t); fe_mul(&x88, &t, &x44);
    t = x88; for (j = 0; j < 88; j++) fe_sqr(&t, &t); fe_mul(&x176, &t, &x88);
    t = x176; for (j = 0; j < 44; j++) fe_sqr(&t, &t); fe_mul(&x220, &t, &x44);
    t = x220; for (j = 0; j < 3; j++) fe_sqr(&t, &t); fe_mul(&x223, &t, &x3);
    t = x223; for (j = 0; j < 23; j++) fe_sqr(&t, &t); fe_mul(&t, &t, &x22);
    for (j = 0; j < 5; j++) fe_sqr(&t, &t); fe_mul(&t, &t, a);
    for (j = 0; j < 3; j++) fe_sqr(&t, &t); fe_mul(&t, &t, &x2);
    for (j = 0; j < 2; j++) fe_sqr(&t, &t); fe_mul(r, &t, a);
}

/* --------------------------------------------------------------------- */
/* EC points (affine)                                                     */
/* --------------------------------------------------------------------- */
typedef struct { fe x, y; } pt;

static const pt GEN = {
    {{0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL}},
    {{0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL}}
};

static void pt_add(pt *r, const pt *a, const pt *b) {
    fe dx, dy, inv, lam, t1, t2;
    fe_sub(&dx, &b->x, &a->x);
    fe_sub(&dy, &b->y, &a->y);
    fe_inv(&inv, &dx);
    fe_mul(&lam, &dy, &inv);
    fe_sqr(&t1, &lam);
    fe_sub(&t1, &t1, &a->x);
    fe_sub(&t1, &t1, &b->x);
    fe_sub(&t2, &a->x, &t1);
    fe_mul(&t2, &t2, &lam);
    fe_sub(&t2, &t2, &a->y);
    r->x = t1; r->y = t2;
}

static void pt_dbl(pt *r, const pt *a) {
    fe num, den, inv, lam, t1, t2;
    fe_sqr(&num, &a->x);
    fe_set_u64(&t1, 3);
    fe_mul(&num, &num, &t1);
    fe_add(&den, &a->y, &a->y);
    fe_inv(&inv, &den);
    fe_mul(&lam, &num, &inv);
    fe_sqr(&t1, &lam);
    fe_sub(&t1, &t1, &a->x);
    fe_sub(&t1, &t1, &a->x);
    fe_sub(&t2, &a->x, &t1);
    fe_mul(&t2, &t2, &lam);
    fe_sub(&t2, &t2, &a->y);
    r->x = t1; r->y = t2;
}

/* scalar mult from a 256-bit little-endian limb array (setup only, not hot) */
static void pt_mul(pt *r, const uint64_t k[4]) {
    pt acc, addend = GEN;
    int started = 0;
    for (int i = 0; i < 256; i++) {
        if ((k[i >> 6] >> (i & 63)) & 1) {
            if (!started) { acc = addend; started = 1; }
            else pt_add(&acc, &acc, &addend);
        }
        pt_dbl(&addend, &addend);
    }
    *r = acc;
}

/* --------------------------------------------------------------------- */
/* SHA-256, specialised to a single padded block                          */
/* --------------------------------------------------------------------- */
static const uint32_t K256[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define S0(x) (ROR32(x,2) ^ ROR32(x,13) ^ ROR32(x,22))
#define S1(x) (ROR32(x,6) ^ ROR32(x,11) ^ ROR32(x,25))
#define s0(x) (ROR32(x,7) ^ ROR32(x,18) ^ ((x) >> 3))
#define s1(x) (ROR32(x,17) ^ ROR32(x,19) ^ ((x) >> 10))

static void sha256_block(uint32_t st[8], const uint32_t in[16]) {
    uint32_t w[64], a,b,c,d,e,f,g,h,t1,t2;
    for (int i = 0; i < 16; i++) w[i] = in[i];
    for (int i = 16; i < 64; i++) w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];
    a=st[0];b=st[1];c=st[2];d=st[3];e=st[4];f=st[5];g=st[6];h=st[7];
    for (int i = 0; i < 64; i++) {
        t1 = h + S1(e) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        t2 = S0(a) + ((a & b) ^ (a & c) ^ (b & c));
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

/* 33-byte input -> one 64-byte block */
static void sha256_33(const uint8_t in[33], uint8_t out[32]) {
    uint32_t st[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t blk[64] = {0};
    memcpy(blk, in, 33);
    blk[33] = 0x80;
    blk[62] = 0x01;   /* 33*8 = 264 = 0x0108 */
    blk[63] = 0x08;
    uint32_t w[16];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[4*i]<<24)|((uint32_t)blk[4*i+1]<<16)|
               ((uint32_t)blk[4*i+2]<<8)|blk[4*i+3];
    sha256_block(st, w);
    for (int i = 0; i < 8; i++) {
        out[4*i]   = st[i] >> 24; out[4*i+1] = st[i] >> 16;
        out[4*i+2] = st[i] >> 8;  out[4*i+3] = st[i];
    }
}

/* --------------------------------------------------------------------- */
/* RIPEMD-160, specialised to a single padded block (32-byte input)       */
/* --------------------------------------------------------------------- */
#define ROL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))
#define F1(x,y,z) ((x)^(y)^(z))
#define F2(x,y,z) (((x)&(y))|(~(x)&(z)))
#define F3(x,y,z) (((x)|~(y))^(z))
#define F4(x,y,z) (((x)&(z))|((y)&~(z)))
#define F5(x,y,z) ((x)^((y)|~(z)))

static const uint8_t RL[80] = {
0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
static const uint8_t RR[80] = {
5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
static const uint8_t SL[80] = {
11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
static const uint8_t SR[80] = {
8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};
static const uint32_t KL[5] = {0x00000000,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e};
static const uint32_t KR[5] = {0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0x00000000};

static void ripemd160_32(const uint8_t in[32], uint8_t out[20]) {
    uint32_t x[16] = {0};
    for (int i = 0; i < 8; i++)
        x[i] = (uint32_t)in[4*i] | ((uint32_t)in[4*i+1]<<8) |
               ((uint32_t)in[4*i+2]<<16) | ((uint32_t)in[4*i+3]<<24);
    x[8] = 0x80;
    x[14] = 256;    /* 32 * 8 bits */

    uint32_t al=0x67452301, bl=0xefcdab89, cl=0x98badcfe, dl=0x10325476, el=0xc3d2e1f0;
    uint32_t ar=al, br=bl, cr=cl, dr=dl, er=el, t;
    for (int j = 0; j < 80; j++) {
        int r = j / 16;
        uint32_t fl, fr;
        switch (r) {
            case 0: fl=F1(bl,cl,dl); fr=F5(br,cr,dr); break;
            case 1: fl=F2(bl,cl,dl); fr=F4(br,cr,dr); break;
            case 2: fl=F3(bl,cl,dl); fr=F3(br,cr,dr); break;
            case 3: fl=F4(bl,cl,dl); fr=F2(br,cr,dr); break;
            default: fl=F5(bl,cl,dl); fr=F1(br,cr,dr); break;
        }
        t = ROL32(al + fl + x[RL[j]] + KL[r], SL[j]) + el;
        al=el; el=dl; dl=ROL32(cl,10); cl=bl; bl=t;
        t = ROL32(ar + fr + x[RR[j]] + KR[r], SR[j]) + er;
        ar=er; er=dr; dr=ROL32(cr,10); cr=br; br=t;
    }
    uint32_t h0=0x67452301, h1=0xefcdab89, h2=0x98badcfe, h3=0x10325476, h4=0xc3d2e1f0;
    t  = h1 + cl + dr;
    h1 = h2 + dl + er;
    h2 = h3 + el + ar;
    h3 = h4 + al + br;
    h4 = h0 + bl + cr;
    h0 = t;
    uint32_t hh[5] = {h0,h1,h2,h3,h4};
    for (int i = 0; i < 5; i++) {
        out[4*i]   = hh[i];        out[4*i+1] = hh[i] >> 8;
        out[4*i+2] = hh[i] >> 16;  out[4*i+3] = hh[i] >> 24;
    }
}

static void hash160_pub(const uint8_t pub[33], uint8_t out[20]) {
    uint8_t sh[32];
    sha256_33(pub, sh);
    ripemd160_32(sh, out);
}

/* --------------------------------------------------------------------- */
/* Search                                                                 */
/* --------------------------------------------------------------------- */
#define BATCH 1024

typedef struct {
    uint64_t start[4];      /* first key of this worker's range */
    uint64_t count;         /* keys to scan */
    int      tid;
    uint8_t  target[20];
    volatile int *stop;
    uint64_t done;          /* progress */
    int      found;
    uint64_t found_key[4];
} job;

static pt TBL[BATCH];       /* TBL[j] = (j+1) * G, shared read-only */
static pt TBL_STEP;         /* BATCH * G */

static void build_table(void) {
    /* TBL[i] = (i+1)*G. TBL[1] must be a doubling: pt_add(G,G) would divide by
     * (x_G - x_G) = 0. Every later step adds G to a point with a different x. */
    TBL[0] = GEN;
    pt_dbl(&TBL[1], &GEN);
    for (int i = 2; i < BATCH; i++) pt_add(&TBL[i], &TBL[i-1], &GEN);
    TBL_STEP = TBL[BATCH-1];
}

static void fe_to_be32(const fe *a, uint8_t out[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t v = a->n[3 - i];
        for (int j = 0; j < 8; j++) out[i*8 + j] = (uint8_t)(v >> (56 - 8*j));
    }
}

static void *worker(void *arg) {
    job *J = (job *)arg;
    pt base;
    uint64_t k[4];
    memcpy(k, J->start, sizeof(k));
    pt_mul(&base, k);       /* base = start * G  (one scalar mult, then increments) */

    fe dx[BATCH], prefix[BATCH], inv, acc, tmp;
    uint8_t pub[33], h160[20];
    uint32_t tprefix;
    memcpy(&tprefix, J->target, 4);

    uint64_t scanned = 0;
    /* candidate 0 is `start` itself */
    {
        fe_to_be32(&base.x, pub + 1);
        pub[0] = 0x02 | (base.y.n[0] & 1);
        hash160_pub(pub, h160);
        if (memcmp(h160, J->target, 20) == 0) {
            J->found = 1; memcpy(J->found_key, k, sizeof(k));
            *J->stop = 1; return NULL;
        }
    }

    while (scanned < J->count && !*J->stop) {
        /* dx[j] = TBL[j].x - base.x ; batch-invert them all */
        for (int j = 0; j < BATCH; j++) fe_sub(&dx[j], &TBL[j].x, &base.x);
        acc = dx[0];
        prefix[0] = acc;
        for (int j = 1; j < BATCH; j++) { fe_mul(&acc, &acc, &dx[j]); prefix[j] = acc; }
        fe_inv(&inv, &acc);
        for (int j = BATCH - 1; j > 0; j--) {
            fe_mul(&tmp, &inv, &prefix[j-1]);   /* = 1/dx[j] */
            fe_mul(&inv, &inv, &dx[j]);         /* running inverse for j-1 */
            /* lambda = (TBL[j].y - base.y) / dx[j] */
            fe lam, t1, t2, dy;
            fe_sub(&dy, &TBL[j].y, &base.y);
            fe_mul(&lam, &dy, &tmp);
            fe_sqr(&t1, &lam);
            fe_sub(&t1, &t1, &base.x);
            fe_sub(&t1, &t1, &TBL[j].x);
            fe_sub(&t2, &base.x, &t1);
            fe_mul(&t2, &t2, &lam);
            fe_sub(&t2, &t2, &base.y);
            fe_to_be32(&t1, pub + 1);
            pub[0] = 0x02 | (t2.n[0] & 1);
            hash160_pub(pub, h160);
            if (memcmp(h160, &tprefix, 4) == 0 && memcmp(h160, J->target, 20) == 0) {
                uint64_t kk[4]; memcpy(kk, k, sizeof(kk));
                __uint128_t c = (__uint128_t)kk[0] + (uint64_t)(j + 1);
                kk[0] = (uint64_t)c; c >>= 64;
                for (int q = 1; q < 4 && c; q++) { c += kk[q]; kk[q] = (uint64_t)c; c >>= 64; }
                J->found = 1; memcpy(J->found_key, kk, sizeof(kk));
                *J->stop = 1; return NULL;
            }
        }
        {   /* j == 0 */
            fe lam, t1, t2, dy;
            fe_sub(&dy, &TBL[0].y, &base.y);
            fe_mul(&lam, &dy, &inv);
            fe_sqr(&t1, &lam);
            fe_sub(&t1, &t1, &base.x);
            fe_sub(&t1, &t1, &TBL[0].x);
            fe_sub(&t2, &base.x, &t1);
            fe_mul(&t2, &t2, &lam);
            fe_sub(&t2, &t2, &base.y);
            fe_to_be32(&t1, pub + 1);
            pub[0] = 0x02 | (t2.n[0] & 1);
            hash160_pub(pub, h160);
            if (memcmp(h160, &tprefix, 4) == 0 && memcmp(h160, J->target, 20) == 0) {
                uint64_t kk[4]; memcpy(kk, k, sizeof(kk));
                __uint128_t c = (__uint128_t)kk[0] + 1;
                kk[0] = (uint64_t)c; c >>= 64;
                for (int q = 1; q < 4 && c; q++) { c += kk[q]; kk[q] = (uint64_t)c; c >>= 64; }
                J->found = 1; memcpy(J->found_key, kk, sizeof(kk));
                *J->stop = 1; return NULL;
            }
        }

        /* advance base by BATCH*G and the scalar by BATCH */
        pt_add(&base, &base, &TBL_STEP);
        __uint128_t c = (__uint128_t)k[0] + BATCH;
        k[0] = (uint64_t)c; c >>= 64;
        for (int q = 1; q < 4 && c; q++) { c += k[q]; k[q] = (uint64_t)c; c >>= 64; }

        scanned += BATCH;
        J->done = scanned;
    }
    return NULL;
}

/* --------------------------------------------------------------------- */
static void parse_hex_key(const char *s, uint64_t k[4]) {
    memset(k, 0, 32);
    size_t L = strlen(s);
    for (size_t i = 0; i < L; i++) {
        int d;
        char ch = s[i];
        if (ch >= '0' && ch <= '9') d = ch - '0';
        else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
        else continue;
        for (int q = 3; q > 0; q--) k[q] = (k[q] << 4) | (k[q-1] >> 60);
        k[0] = (k[0] << 4) | (uint64_t)d;
    }
}

static void parse_hex_bytes(const char *s, uint8_t *out, int n) {
    for (int i = 0; i < n; i++) {
        unsigned v; sscanf(s + 2*i, "%2x", &v); out[i] = (uint8_t)v;
    }
}

static double now_sec(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(int argc, char **argv) {
    build_table();

    /* selftest: derive hash160 for a given key and print it */
    if (argc >= 3 && strcmp(argv[1], "selftest") == 0) {
        uint64_t k[4]; parse_hex_key(argv[2], k);
        pt P; pt_mul(&P, k);
        uint8_t pub[33], h[20];
        fe_to_be32(&P.x, pub + 1);
        pub[0] = 0x02 | (P.y.n[0] & 1);
        hash160_pub(pub, h);
        for (int i = 0; i < 33; i++) printf("%02x", pub[i]);
        printf(" ");
        for (int i = 0; i < 20; i++) printf("%02x", h[i]);
        printf("\n");
        return 0;
    }

    /* search  <start_hex> <count> <target_hash160_hex> <threads> */
    if (argc < 5) {
        fprintf(stderr,
          "usage:\n"
          "  %s selftest <privkey_hex>\n"
          "  %s search <start_hex> <count> <hash160_hex> <threads>\n", argv[0], argv[0]);
        return 1;
    }
    uint64_t start[4]; parse_hex_key(argv[2], start);
    uint64_t count = strtoull(argv[3], NULL, 10);
    uint8_t target[20]; parse_hex_bytes(argv[4], target, 20);
    int nthreads = atoi(argv[5]);
    if (nthreads < 1) nthreads = 1;

    volatile int stop = 0;
    pthread_t th[64];
    job jobs[64];
    uint64_t per = count / nthreads;
    per = (per / BATCH) * BATCH;
    if (per == 0) per = BATCH;

    double t0 = now_sec();
    for (int i = 0; i < nthreads; i++) {
        memset(&jobs[i], 0, sizeof(job));
        memcpy(jobs[i].start, start, sizeof(start));
        /* deterministic, non-overlapping range allocation */
        __uint128_t c = (__uint128_t)jobs[i].start[0] + (__uint128_t)per * i;
        jobs[i].start[0] = (uint64_t)c; c >>= 64;
        for (int q = 1; q < 4 && c; q++) { c += jobs[i].start[q]; jobs[i].start[q] = (uint64_t)c; c >>= 64; }
        /* The last worker absorbs the remainder so the union of worker ranges
         * covers [start, start+count) exactly -- no silent gap at the tail. */
        jobs[i].count = (i == nthreads - 1) ? (count - per * (uint64_t)i) : per;
        jobs[i].tid = i;
        jobs[i].stop = &stop;
        memcpy(jobs[i].target, target, 20);
        pthread_create(&th[i], NULL, worker, &jobs[i]);
    }
    /* Progress reporting: lets the coordinator checkpoint a long-running unit
     * so a crash costs seconds of work rather than the whole range. */
    int progress_secs = (argc >= 7) ? atoi(argv[6]) : 0;
    if (progress_secs > 0) {
        int alive = 1;
        while (alive && !stop) {
            struct timespec ts = {progress_secs, 0};
            nanosleep(&ts, NULL);
            uint64_t d = 0;
            for (int i = 0; i < nthreads; i++) d += jobs[i].done;
            double el = now_sec() - t0;
            printf("PROGRESS %llu %.0f %.3f\n", (unsigned long long)d, el,
                   d / el / 1e6);
            fflush(stdout);
            alive = 0;
            for (int i = 0; i < nthreads; i++)
                if (jobs[i].done < jobs[i].count) alive = 1;
        }
    }

    uint64_t total = 0;
    int found = -1;
    for (int i = 0; i < nthreads; i++) {
        pthread_join(th[i], NULL);
        total += jobs[i].done;
        if (jobs[i].found) found = i;
    }
    double dt = now_sec() - t0;

    printf("scanned   : %llu keys\n", (unsigned long long)total);
    printf("elapsed   : %.3f s\n", dt);
    printf("rate      : %.3f Mkeys/s (%d threads)\n", total / dt / 1e6, nthreads);
    if (found >= 0) {
        /* Deliberately terse: a hit on an UNSOLVED puzzle must not be splashed
         * across logs. The key is written to a restricted file by the caller. */
        printf("FOUND     : yes (thread %d)\n", found);
        printf("KEY       : %016llx%016llx%016llx%016llx\n",
               (unsigned long long)jobs[found].found_key[3],
               (unsigned long long)jobs[found].found_key[2],
               (unsigned long long)jobs[found].found_key[1],
               (unsigned long long)jobs[found].found_key[0]);
        return 2;
    }
    printf("FOUND     : no\n");
    return 0;
}
