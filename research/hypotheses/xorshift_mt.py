"""
Hypothesis: keys are outputs of a non-cryptographic PRNG with known internal
structure -- xorshift family (xorshift32/64/128), or MT19937 (Python's
random module, and by extension C rand()-style / Mersenne-Twister-seeded
generators) -- used directly (masked output) or seeded with something
guessable (small integer 0..100000, or a Unix timestamp in 2015, the
puzzle series' creation year).

Working data: lower_bits_hex(n) for n=1..70, read directly from
data/solved_puzzles.json (verified, 70/70 keys). L(n) = int(lower_bits_hex,16)
is an (n-1)-bit integer (0 for n=1). key(n) = 2^(n-1) + L(n).

Two independent, DIRECT falsification strategies (per task spec):

  A. xorshift GF(2) linear-recurrence test (no seed search needed).
     Real xorshift32/64 outputs satisfy x_{i+1} = A(x_i) for a FIXED linear
     map A over GF(2)^w built from a shift-xor triple (a,b,c):
         pattern 1: t = x ^ (x<<a); t ^= (t>>b); t ^= (t<<c)
         pattern 2: t = x ^ (x>>a); t ^= (t<<b); t ^= (t>>c)
     If consecutive puzzle keys' low-w bits were consecutive xorshift-w
     states, SOME (pattern,a,b,c) must map low-w(L(n)) -> low-w(L(n+1))
     for EVERY consecutive pair simultaneously. We brute-force search all
     (pattern,a,b,c) with a,b,c in 1..31 (59,582 candidate maps) for w=32
     (pairs with n>=33, i.e. n-1>=32 known bits) and w=64 (pairs with
     n>=65). For each map we count how many of the available pairs it gets
     right; the single-best matching triple's hit-count is compared to a
     Monte Carlo null: the identical best-of-59,582 search re-run on
     independently-redrawn random low-w pairs, many times.

  B. Direct PRNG-replay brute force (falsification by exhaustive replay).
     For each candidate generator/seed we build the FULL sequence of 70
     "would-be" outputs the way the puzzle creator's own description
     implies ("consecutive keys ... masked to set difficulty"): one
     continuous stream, consumed sequentially, puzzle n taking the next
     (n-1) bits (mode A / getrandbits(n-1) for MT19937; one xorshift step's
     w-bit output truncated to its low (n-1) bits for xorshift). We record,
     for every seed tried, the longest run of consecutive puzzles whose
     predicted lower bits EXACTLY equal the real lower bits, and the total
     bits covered by that run. The best (across the whole seed space)
     result is reported, together with a Monte Carlo null: the identical
     full-scale search re-run against independently-redrawn random target
     data of the same bit-widths.

  Seed spaces actually searched (bounded, cheap, explicit):
    - xorshift32 / xorshift64 / xorshift128: seeds 1 .. 500,000
    - Python random (MT19937): small int seeds 0 .. 100,000
    - Python random (MT19937): Unix timestamps for every second of 2015
      (1420070400 .. 1451606399 inclusive, 31,536,000 seeds -- all of
      Jan 1 2015 00:00:00 UTC through Dec 31 2015 23:59:59 UTC)

Anti-bullshit rule: a match only counts if it beats the null. We never
report "found a run of length 2" as meaningful without the accompanying
Monte Carlo context, because short runs at small n are simply expected
by chance (n=1..~9 have so few bits that hitting them exactly is not
improbable).

Run: python3 xorshift_mt.py
Deterministic given random.seed(20260819) / np.random.seed(20260819) for the
Monte Carlo control portions. Full run (including the 31.5M-second MT
timestamp brute force and its null replications) takes on the order of
20-30 minutes on this machine; progress is printed as each stage completes.
"""

import json
import random as pyrandom
import time
import numpy as np
from multiprocessing import Pool
import os

RNG_SEED = 20260819
DATA_PATH = "/home/user/Clawd71/data/solved_puzzles.json"
N_WORKERS = max(1, os.cpu_count() or 1)

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
MASK128 = (1 << 128) - 1


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_data():
    with open(DATA_PATH) as f:
        d = json.load(f)
    d = sorted(d, key=lambda e: e["n"])
    assert [e["n"] for e in d] == list(range(1, 71)), "expected puzzles #1..#70"
    L = [int(e["lower_bits_hex"], 16) for e in d]  # L[i] for puzzle n=i+1
    return L


# ---------------------------------------------------------------------------
# Part A: xorshift GF(2) direct linear-relation test (no seed search)
# ---------------------------------------------------------------------------

def xorshift_transform_vec(x, a, b, c, pattern, mask):
    x = x.astype(np.uint64)
    if pattern == 1:
        t = x ^ ((x << a) & mask)
        t = t ^ (t >> b)
        t = t ^ ((t << c) & mask)
    else:
        t = x ^ (x >> a)
        t = t ^ ((t << b) & mask)
        t = t ^ (t >> c)
    return t & mask


def best_xorshift_triple(xs, ys, mask, a_range=range(1, 32)):
    """Brute-force search (pattern,a,b,c) maximizing exact matches xs->ys."""
    xs = np.array(xs, dtype=np.uint64)
    ys = np.array(ys, dtype=np.uint64)
    n_pairs = len(xs)
    best = (-1, None, None, None, None)
    for pattern in (1, 2):
        for a in a_range:
            for b in a_range:
                for c in a_range:
                    pred = xorshift_transform_vec(xs, a, b, c, pattern, mask)
                    hits = int(np.sum(pred == ys))
                    if hits > best[0]:
                        best = (hits, pattern, a, b, c)
    return best  # (hit_count, pattern, a, b, c), out of n_pairs


def part_a_gf2_test(L, n_null_reps=100):
    print("=== Part A: xorshift GF(2) linear-relation direct test ===", flush=True)
    results = {}
    rng = np.random.default_rng(RNG_SEED)

    for w, mask, min_n in ((32, MASK32, 33), (64, MASK64, 65)):
        xs, ys = [], []
        for n in range(min_n, 70):
            i = n - 1  # index of puzzle n in L (0-indexed)
            xs.append(L[i] & mask)
            ys.append(L[i + 1] & mask)
        n_pairs = len(xs)
        t0 = time.time()
        real_best = best_xorshift_triple(xs, ys, mask)
        t1 = time.time()
        print(f"  w={w}: {n_pairs} consecutive pairs (n={min_n}..70). "
              f"Best triple: hits={real_best[0]}/{n_pairs} "
              f"pattern={real_best[1]} (a,b,c)=({real_best[2]},{real_best[3]},{real_best[4]}) "
              f"[search took {t1 - t0:.1f}s]", flush=True)

        # Monte Carlo null: same search on independently redrawn random pairs
        null_best_hits = []
        t0 = time.time()
        for rep in range(n_null_reps):
            rxs = rng.integers(0, mask, size=n_pairs, dtype=np.uint64)
            rys = rng.integers(0, mask, size=n_pairs, dtype=np.uint64)
            nb = best_xorshift_triple(list(rxs), list(rys), mask)
            null_best_hits.append(nb[0])
        t1 = time.time()
        null_best_hits = np.array(null_best_hits)
        p_value = (np.sum(null_best_hits >= real_best[0]) + 1) / (n_null_reps + 1)
        print(f"  w={w}: null (n={n_null_reps} reps) best-hit-count mean={null_best_hits.mean():.3f} "
              f"max={null_best_hits.max()} min={null_best_hits.min()} "
              f"[{t1 - t0:.1f}s]  Monte Carlo p-value(real >= null) = {p_value:.4f}", flush=True)

        results[f"w{w}"] = {
            "n_pairs": n_pairs,
            "real_best_hits": real_best[0],
            "real_best_triple": real_best[1:],
            "null_reps": n_null_reps,
            "null_best_hits_mean": float(null_best_hits.mean()),
            "null_best_hits_max": int(null_best_hits.max()),
            "null_best_hits_all": [int(v) for v in null_best_hits],
            "p_value": float(p_value),
        }
    return results


# ---------------------------------------------------------------------------
# Part B: PRNG replay brute force
# ---------------------------------------------------------------------------

def longest_run(matches, bitwidths):
    """Longest run of consecutive True in `matches`; also longest run with
    start index >= 9 (n>=10) to separate 'trivial small-n' matches (expected
    by chance) from anything covering a meaningful number of bits."""
    def scan(min_start_idx):
        best_len = best_bits = 0
        best_start = -1
        cur_len = cur_bits = 0
        cur_start = -1
        for i, m in enumerate(matches):
            if i < min_start_idx and cur_len == 0:
                continue
            if m:
                if cur_len == 0:
                    cur_start = i
                cur_len += 1
                cur_bits += bitwidths[i]
            else:
                if cur_len > best_len or (cur_len == best_len and cur_bits > best_bits):
                    best_len, best_bits, best_start = cur_len, cur_bits, cur_start
                cur_len = cur_bits = 0
        if cur_len > best_len or (cur_len == best_len and cur_bits > best_bits):
            best_len, best_bits, best_start = cur_len, cur_bits, cur_start
        return best_len, best_bits, best_start

    overall = scan(0)
    filtered = scan(9)  # n >= 10
    return overall, filtered


def xorshift32_stream(seed):
    x = seed & MASK32
    if x == 0:
        x = 0x9E3779B9
    out = []
    for _ in range(70):
        x ^= (x << 13) & MASK32
        x ^= (x >> 17)
        x ^= (x << 5) & MASK32
        x &= MASK32
        out.append(x)
    return out


def xorshift64_stream(seed):
    x = seed & MASK64
    if x == 0:
        x = 0x9E3779B97F4A7C15
    out = []
    for _ in range(70):
        x ^= (x << 13) & MASK64
        x ^= (x >> 7)
        x ^= (x << 17) & MASK64
        x &= MASK64
        out.append(x)
    return out


def xorshift128_stream(seed):
    # Marsaglia xorshift128, classic 4x32-bit state
    x = (seed * 2654435761 + 1) & MASK32 or 1
    y = (seed * 2246822519 + 2) & MASK32 or 2
    z = (seed * 3266489917 + 3) & MASK32 or 3
    w = (seed * 668265263 + 4) & MASK32 or 4
    out = []
    for _ in range(70):
        t = x ^ ((x << 11) & MASK32)
        t &= MASK32
        x, y, z = y, z, w
        w = (w ^ (w >> 19)) ^ (t ^ (t >> 8))
        w &= MASK32
        out.append(w)
    return out


def replay_search_xorshift(L, stream_fn, width, seed_lo, seed_hi):
    bitwidths = [i for i in range(70)]  # bits used for puzzle n=i+1 is n-1=i
    best_overall = (0, 0, -1, None)   # (len, bits, start_idx, seed)
    best_filtered = (0, 0, -1, None)
    for seed in range(seed_lo, seed_hi + 1):
        stream = stream_fn(seed)
        # Build candidate value per puzzle: low (n-1) bits of stream output,
        # but only meaningful (potentially exact) when n-1 <= width.
        matches = []
        for i in range(70):
            bits_needed = i  # n-1
            if bits_needed > width:
                matches.append(False)
                continue
            cand = stream[i] & ((1 << bits_needed) - 1) if bits_needed > 0 else 0
            matches.append(cand == L[i])
        overall, filtered = longest_run(matches, bitwidths)
        if overall[0] > best_overall[0] or (overall[0] == best_overall[0] and overall[1] > best_overall[1]):
            best_overall = (overall[0], overall[1], overall[2], seed)
        if filtered[0] > best_filtered[0] or (filtered[0] == best_filtered[0] and filtered[1] > best_filtered[1]):
            best_filtered = (filtered[0], filtered[1], filtered[2], seed)
    return best_overall, best_filtered


def replay_search_mt(L, seed_iter, mode="getrandbits_seq"):
    """mode='getrandbits_seq': single Random() instance per seed, sequential
    calls r.getrandbits(n-1) for n=1..70 (the natural reading of 'consecutive
    keys ... masked to set difficulty' as one continuous stream)."""
    bitwidths = [i for i in range(70)]
    best_overall = (0, 0, -1, None)
    best_filtered = (0, 0, -1, None)
    for seed in seed_iter:
        r = pyrandom.Random(seed)
        matches = []
        for i in range(70):
            bits_needed = i
            cand = r.getrandbits(bits_needed) if bits_needed > 0 else 0
            matches.append(cand == L[i])
        overall, filtered = longest_run(matches, bitwidths)
        if overall[0] > best_overall[0] or (overall[0] == best_overall[0] and overall[1] > best_overall[1]):
            best_overall = (overall[0], overall[1], overall[2], seed)
        if filtered[0] > best_filtered[0] or (filtered[0] == best_filtered[0] and filtered[1] > best_filtered[1]):
            best_filtered = (filtered[0], filtered[1], filtered[2], seed)
    return best_overall, best_filtered


_XORSHIFT_STREAMS = {
    "xorshift32": (xorshift32_stream, 32),
    "xorshift64": (xorshift64_stream, 64),
    "xorshift128": (xorshift128_stream, 32),
}


def _worker_xorshift(args):
    L, gen_name, seed_lo, seed_hi = args
    fn, width = _XORSHIFT_STREAMS[gen_name]
    return replay_search_xorshift(L, fn, width, seed_lo, seed_hi)


def _worker_mt(args):
    L, seed_lo, seed_hi = args
    return replay_search_mt(L, range(seed_lo, seed_hi + 1))


def _merge_best(results):
    """results: list of (best_overall, best_filtered) tuples -> single merged pair."""
    bo = max((r[0] for r in results), key=lambda t: (t[0], t[1]))
    bf = max((r[1] for r in results), key=lambda t: (t[0], t[1]))
    return bo, bf


def _chunk_range(lo, hi, n_chunks):
    """Split inclusive [lo, hi] into n_chunks contiguous sub-ranges."""
    total = hi - lo + 1
    n_chunks = max(1, min(n_chunks, total))
    chunk = -(-total // n_chunks)  # ceil div
    ranges = []
    cur = lo
    while cur <= hi:
        end = min(hi, cur + chunk - 1)
        ranges.append((cur, end))
        cur = end + 1
    return ranges


def parallel_replay_search_xorshift(L, gen_name, seed_lo, seed_hi, pool):
    ranges = _chunk_range(seed_lo, seed_hi, N_WORKERS)
    args = [(L, gen_name, lo, hi) for lo, hi in ranges]
    results = pool.map(_worker_xorshift, args)
    return _merge_best(results)


def parallel_replay_search_mt(L, seed_lo, seed_hi, pool):
    ranges = _chunk_range(seed_lo, seed_hi, N_WORKERS)
    args = [(L, lo, hi) for lo, hi in ranges]
    results = pool.map(_worker_mt, args)
    return _merge_best(results)


def make_random_L(rng, real_L):
    """Independently redraw a control target dataset with the SAME
    bit-widths as the real data (L[i] uniform in [0, 2^i)).

    Uses a plain Python random.Random (arbitrary-precision getrandbits) --
    NOT numpy -- because bit-widths run up to 69 bits (puzzle #70), and
    numpy's Generator.integers() with the default int64 dtype overflows
    for any high bound >= 2**63. `rng` here is deliberately a control-only
    random.Random instance, seeded far outside every seed space actually
    searched (max 2,000,000 for xorshift, ~1.45e9 for MT timestamps), so
    there is no possibility of the control-generation seed accidentally
    colliding with a seed tried by the search itself.
    """
    return [rng.getrandbits(i) if i > 0 else 0 for i in range(70)]


def part_b_xorshift(L, pool, seed_lo=1, seed_hi=2_000_000, n_null_reps=15):
    print(f"=== Part B1: xorshift replay brute force, seeds {seed_lo}..{seed_hi} "
          f"(parallel, {N_WORKERS} workers) ===", flush=True)
    results = {}
    ctrl_rng = pyrandom.Random((1 << 100) + RNG_SEED + 1)  # control-only, far outside any searched seed space
    for name in ("xorshift32", "xorshift64", "xorshift128"):
        t0 = time.time()
        best_overall, best_filtered = parallel_replay_search_xorshift(L, name, seed_lo, seed_hi, pool)
        t1 = time.time()
        print(f"  {name}: best_overall(run_len,bits,start_idx,seed)={best_overall}  "
              f"best_filtered(n>=10)={best_filtered}  [{t1 - t0:.1f}s]", flush=True)

        null_overall_lens = []
        null_filtered_lens = []
        t0 = time.time()
        for rep in range(n_null_reps):
            rand_L = make_random_L(ctrl_rng, L)
            ro, rf = parallel_replay_search_xorshift(rand_L, name, seed_lo, seed_hi, pool)
            null_overall_lens.append(ro[0])
            null_filtered_lens.append(rf[0])
        t1 = time.time()
        null_overall_lens = np.array(null_overall_lens)
        null_filtered_lens = np.array(null_filtered_lens)
        p_overall = (np.sum(null_overall_lens >= best_overall[0]) + 1) / (n_null_reps + 1)
        p_filtered = (np.sum(null_filtered_lens >= best_filtered[0]) + 1) / (n_null_reps + 1)
        print(f"  {name}: null (n={n_null_reps}) overall best run len mean={null_overall_lens.mean():.2f} "
              f"max={null_overall_lens.max()}  p_overall={p_overall:.3f}  "
              f"filtered(n>=10) mean={null_filtered_lens.mean():.2f} max={null_filtered_lens.max()} "
              f"p_filtered={p_filtered:.3f}  [{t1 - t0:.1f}s]", flush=True)

        results[name] = {
            "seed_range": [seed_lo, seed_hi],
            "best_overall": best_overall,
            "best_filtered_n_ge_10": best_filtered,
            "null_reps": n_null_reps,
            "null_overall_lens": [int(v) for v in null_overall_lens],
            "null_filtered_lens": [int(v) for v in null_filtered_lens],
            "p_overall": float(p_overall),
            "p_filtered": float(p_filtered),
        }
    return results


def part_b_mt(L, pool):
    print(f"=== Part B2: MT19937 (Python random) replay brute force (parallel, {N_WORKERS} workers) ===",
          flush=True)
    results = {}
    ctrl_rng = pyrandom.Random((1 << 100) + RNG_SEED + 2)  # control-only, far outside any searched seed space

    # --- small int seeds 0..100000 ---
    print("  -- small int seeds 0..100000 --", flush=True)
    t0 = time.time()
    best_overall, best_filtered = parallel_replay_search_mt(L, 0, 100_000, pool)
    t1 = time.time()
    print(f"  small-int: best_overall={best_overall}  best_filtered(n>=10)={best_filtered}  [{t1 - t0:.1f}s]",
          flush=True)

    n_null_reps_small = 50
    null_overall_lens, null_filtered_lens = [], []
    t0 = time.time()
    for rep in range(n_null_reps_small):
        rand_L = make_random_L(ctrl_rng, L)
        ro, rf = parallel_replay_search_mt(rand_L, 0, 100_000, pool)
        null_overall_lens.append(ro[0])
        null_filtered_lens.append(rf[0])
    t1 = time.time()
    null_overall_lens = np.array(null_overall_lens)
    null_filtered_lens = np.array(null_filtered_lens)
    p_overall = (np.sum(null_overall_lens >= best_overall[0]) + 1) / (n_null_reps_small + 1)
    p_filtered = (np.sum(null_filtered_lens >= best_filtered[0]) + 1) / (n_null_reps_small + 1)
    print(f"  small-int: null (n={n_null_reps_small}) overall max={null_overall_lens.max()} "
          f"p_overall={p_overall:.3f}  filtered max={null_filtered_lens.max()} p_filtered={p_filtered:.3f}  "
          f"[{t1 - t0:.1f}s]", flush=True)

    results["small_int"] = {
        "seed_range": [0, 100_000],
        "best_overall": best_overall,
        "best_filtered_n_ge_10": best_filtered,
        "null_reps": n_null_reps_small,
        "p_overall": float(p_overall),
        "p_filtered": float(p_filtered),
        "null_overall_lens": [int(v) for v in null_overall_lens],
        "null_filtered_lens": [int(v) for v in null_filtered_lens],
    }

    # --- Unix timestamps, every second of 2015 ---
    ts_lo, ts_hi = 1420070400, 1451606399  # Jan 1 2015 00:00:00 UTC .. Dec 31 2015 23:59:59 UTC
    n_seconds = ts_hi - ts_lo + 1
    print(f"  -- Unix timestamp seeds, every second of 2015: {ts_lo}..{ts_hi} ({n_seconds} seeds) --", flush=True)
    t0 = time.time()
    best_overall, best_filtered = parallel_replay_search_mt(L, ts_lo, ts_hi, pool)
    t1 = time.time()
    print(f"  timestamp: best_overall={best_overall}  best_filtered(n>=10)={best_filtered}  [{t1 - t0:.1f}s]",
          flush=True)

    n_null_reps_ts = 5
    null_overall_lens, null_filtered_lens = [], []
    t0 = time.time()
    for rep in range(n_null_reps_ts):
        rand_L = make_random_L(ctrl_rng, L)
        ro, rf = parallel_replay_search_mt(rand_L, ts_lo, ts_hi, pool)
        null_overall_lens.append(ro[0])
        null_filtered_lens.append(rf[0])
        print(f"    null rep {rep + 1}/{n_null_reps_ts} done: overall_len={ro[0]} filtered_len={rf[0]}  "
              f"[{time.time() - t0:.1f}s elapsed]", flush=True)
    null_overall_lens = np.array(null_overall_lens)
    null_filtered_lens = np.array(null_filtered_lens)
    p_overall = (np.sum(null_overall_lens >= best_overall[0]) + 1) / (n_null_reps_ts + 1)
    p_filtered = (np.sum(null_filtered_lens >= best_filtered[0]) + 1) / (n_null_reps_ts + 1)
    print(f"  timestamp: null (n={n_null_reps_ts}) overall max={null_overall_lens.max()} p_overall={p_overall:.3f}  "
          f"filtered max={null_filtered_lens.max()} p_filtered={p_filtered:.3f}", flush=True)

    results["timestamp_2015"] = {
        "seed_range": [ts_lo, ts_hi],
        "n_seeds": n_seconds,
        "best_overall": best_overall,
        "best_filtered_n_ge_10": best_filtered,
        "null_reps": n_null_reps_ts,
        "p_overall": float(p_overall),
        "p_filtered": float(p_filtered),
        "null_overall_lens": [int(v) for v in null_overall_lens],
        "null_filtered_lens": [int(v) for v in null_filtered_lens],
    }
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    pyrandom.seed(RNG_SEED)
    np.random.seed(RNG_SEED)

    L = load_data()
    print(f"Loaded {len(L)} puzzle lower-bits values.", flush=True)

    t_start = time.time()
    out = {}
    out["part_a_gf2"] = part_a_gf2_test(L, n_null_reps=100)
    print(f"Using {N_WORKERS} worker processes for Part B.", flush=True)
    with Pool(N_WORKERS) as pool:
        out["part_b_xorshift"] = part_b_xorshift(L, pool, seed_lo=1, seed_hi=2_000_000, n_null_reps=15)
        out["part_b_mt"] = part_b_mt(L, pool)
    t_end = time.time()
    print(f"\nTOTAL RUNTIME: {t_end - t_start:.1f}s", flush=True)

    with open("/home/user/Clawd71/research/hypotheses/xorshift_mt_results.json", "w") as f:
        json.dump(out, f, indent=2)
    print("Wrote results JSON.", flush=True)


if __name__ == "__main__":
    main()
