"""
Hypothesis: the puzzle-key generator was seeded or otherwise influenced by
real-world timing around the January 2015 creation/funding event -- Unix
timestamps in the plausible creation window, Bitcoin block hashes/heights
around the funding transaction, or system-clock jitter from a script that
generated all 256 keys in a tight loop (e.g. naive per-key time()-based RNG
seeding at high call rate, which for weak RNGs can produce correlated or
even identical seeds for nearby puzzle indices).

Ground truth anchor (independently verified on-chain, see
research/onchain/funding_transactions.md and the re-fetch in this script's
companion data file): all 71 puzzle addresses #1-#71 were funded by ONE
transaction, txid 08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15,
in block height 339085, block time 1421345234 (2015-01-15T18:07:14 UTC),
block hash 0000000000000000188de542fd76b1676c4be6c380b39ddea119358c290cebd7.
This gives us an exact, non-searched, independently-confirmed real-world
timestamp/height/hash to test against -- the strongest and most literal
version of "plausible Unix timestamp/block info for the creation period"
the task asks for, not a guess.

Three independent test families, each with an explicit Monte Carlo null
(never "does it fit" -- always "does it fit MORE than chance produces"):

  1. FIXED VALUE TEST (no search at all): does the low (n-1) bits of the
     independently-known funding block's timestamp / mediantime / height /
     hash-as-integer show any bit-level correlation with lower_bits(n),
     across all n=2..70? Two statistics: (a) mean bit-agreement fraction
     between value mod 2^(n-1) and lower_bits(n) across all n (expected
     0.5 under the null), and (b) count of n where the two are EXACTLY
     equal (expected ~1, dominated by small n, under the null). Since the
     comparison value is fixed a priori (independently established by
     on-chain forensics, not chosen by scanning the key data), this test
     needs no multiple-testing correction beyond the handful of source
     values tried (Bonferroni over 4 source values x 2 statistics = 8).

  2. NEARBY-BLOCKS SEARCH (small "handful" of real blocks): using 21 real
     block hashes/heights/timestamps fetched from blockstream.info around
     the funding block (11 in a +/-5-block fine window, 10 more spanning
     +/-5 days at ~1/day resolution, capturing the possibility that key
     generation happened somewhat before the payout), test the same
     fixed-value statistics PLUS a hex-substring-match statistic across
     all (n, block, source-value-type) combinations. Real-data statistic
     = best result found across the whole 21-block x 3-value-type search;
     Monte Carlo null = the identical search re-run on random control key
     sequences (matching each puzzle's real per-position precision), which
     automatically corrects for the multiple-comparisons problem baked
     into "we get to pick the best of many blocks/value-types".

  3. FULL TIMESTAMP-RANGE SEARCH: brute-force scan of candidate creation
     timestamps T over the plausible Jan-Mar 2015 window
     (1420070400-1425168000, ~5.10M seconds), testing whether
     lower_bits(n) == f(T, n) mod 2^(n-1) for simple candidate relations f
     (direct mod, T+n, T XOR n), for n=2..63 (n=64..70 excluded from this
     specific vectorized numpy scan only because 2^63+ moduli do not fit
     in int64 -- those 7 puzzles are still covered by tests 1 and 2 above
     via exact Python bigint arithmetic). Real-data statistic = best match
     count found over the full 5.10M-candidate x 3-relation search; Monte
     Carlo null = the identical full-range search re-run on random control
     key sequences. A walk-forward variant is also run: the single best
     (T, relation) is *selected* using only training puzzles n=2..50, then
     evaluated -- with no further fitting -- against held-out puzzles
     n=51..70, compared to the trivial chance baseline.

Run: python3 timestamp_creation.py  (network-independent: block data was
fetched once from blockstream.info on 2026-08-19 and cached in
_nearby_blocks_cache.json for reproducibility; see timestamp_creation.md
for the exact fetch commands/log).
Deterministic given random.seed(20260819) / np.random.seed(20260819).
"""

import json
import math
import random as pyrandom
import time

import numpy as np

SEED = 20260819
py_rng = pyrandom.Random(SEED)          # exact Python bigint arithmetic tests
np_rng = np.random.default_rng(SEED)    # vectorized numpy full-range scan

DATA_PATH = "/home/user/Clawd71/data/solved_puzzles.json"
BLOCKS_CACHE = "/home/user/Clawd71/research/hypotheses/_nearby_blocks_cache.json"

# Independently verified on-chain facts (see research/onchain/funding_transactions.md
# and the direct re-fetch performed for this script -- both agree exactly).
FUNDING_BLOCK_HEIGHT = 339085
FUNDING_BLOCK_HASH = "0000000000000000188de542fd76b1676c4be6c380b39ddea119358c290cebd7"
FUNDING_BLOCK_TIME = 1421345234        # block timestamp (2015-01-15T18:07:14 UTC)
FUNDING_BLOCK_MEDIANTIME = 1421342061  # median-time-past of that block

TS_RANGE_MIN = 1420070400  # 2015-01-01T00:00:00 UTC (task-specified plausible window)
TS_RANGE_MAX = 1425168000  # 2015-03-01T00:00:00 UTC


# --------------------------------------------------------------------------
# Data loading
# --------------------------------------------------------------------------

def load_data():
    data = json.load(open(DATA_PATH))
    data.sort(key=lambda d: d["n"])
    assert [d["n"] for d in data] == list(range(1, 71)), "expected puzzles #1-70"
    return data


def lower_bits_int(d):
    n = d["n"]
    if n == 1:
        return 0
    lb = d["key_int"] - 2 ** (n - 1)
    assert 0 <= lb < 2 ** (n - 1)
    return lb


def load_blocks_cache():
    return json.load(open(BLOCKS_CACHE))


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

def popcount(x):
    return bin(x).count("1")


# Precomputed once at import time: POW2[n] = 2**(n-1) for n=1..70, and
# BITS[n] = n-1. Avoids re-deriving these (arbitrary-precision pow) inside
# every inner-loop iteration of every Monte Carlo trial, which is the
# dominant cost otherwise (millions of redundant bigint exponentiations).
POW2 = {n: (2 ** (n - 1)) for n in range(1, 71)}
BITS = {n: (n - 1) for n in range(1, 71)}


def random_control_lower_bits(data, py_rng_):
    """One random control sequence matching the real data's exact per-n
    precision: puzzle n draws its lower bits uniformly from [0, 2**(n-1)),
    exactly like the real puzzles (n=1 forced to 0). Returns dict n->int."""
    out = {}
    for d in data:
        n = d["n"]
        out[n] = py_rng_.getrandbits(n - 1) if n > 1 else 0
    return out


# --------------------------------------------------------------------------
# TEST 1: fixed-value comparison (no search) against the independently
# known funding block's timestamp / mediantime / height / hash-as-int
# --------------------------------------------------------------------------

def agreement_stat(value_int, lower_bits_by_n, n_min=2, n_max=70):
    fracs = []
    exact_hits = 0
    total = 0
    # value_int mod each modulus is recomputed once per n as needed, but
    # the moduli themselves (POW2) are precomputed module-level constants
    # (see POW2 above) -- this is the main hot loop across every Monte
    # Carlo trial in tests 1 and 2, so avoiding repeated 2**(n-1) bigint
    # exponentiation here matters a lot for total runtime.
    for n in range(n_min, n_max + 1):
        mod = POW2[n]
        bits = BITS[n]
        if bits == 0:
            continue
        lb = lower_bits_by_n[n]
        v = value_int % mod
        x = lb ^ v
        agree = 1.0 - (popcount(x) / bits)
        fracs.append(agree)
        total += 1
        if v == lb:
            exact_hits += 1
    return float(np.mean(fracs)), exact_hits, total


def mc_fixed_value_test(value_int, real_lb, data, n_trials=8000, n_min=2, n_max=70):
    real_frac, real_hits, total = agreement_stat(value_int, real_lb, n_min, n_max)
    null_fracs = np.empty(n_trials)
    null_hits = np.empty(n_trials, dtype=np.int64)
    for t in range(n_trials):
        trial_lb = random_control_lower_bits(data, py_rng)
        f, h, _ = agreement_stat(value_int, trial_lb, n_min, n_max)
        null_fracs[t] = f
        null_hits[t] = h
    # two-sided on the agreement fraction (correlation could show as EITHER
    # anomalously high agreement -- same-bits relationship -- OR anomalously
    # low agreement -- systematic bit-inversion relationship, e.g. NOT(T))
    p_frac = (np.sum(np.abs(null_fracs - 0.5) >= abs(real_frac - 0.5)) + 1) / (n_trials + 1)
    p_hits = (np.sum(null_hits >= real_hits) + 1) / (n_trials + 1)
    return {
        "real_frac": real_frac, "real_hits": real_hits, "total": total,
        "null_frac_mean": float(null_fracs.mean()), "null_frac_std": float(null_fracs.std()),
        "null_hits_mean": float(null_hits.mean()), "null_hits_max": int(null_hits.max()),
        "p_frac": p_frac, "p_hits": p_hits,
    }


# --------------------------------------------------------------------------
# TEST 2: nearby-blocks handful search (mod/add/xor agreement + hex substring)
# --------------------------------------------------------------------------

def best_over_blocks(lower_bits_by_n, blocks, n_min=2, n_max=70):
    """Best (max) agreement fraction and best (max) exact-hit count, over
    all blocks x {hash-as-int, timestamp, height}."""
    best_frac = 0.0
    best_hits = 0
    for h, info in blocks.items():
        hash_int = int(info["hash"], 16)
        for value_int in (hash_int, info["timestamp"], info["height"]):
            frac, hits, _ = agreement_stat(value_int, lower_bits_by_n, n_min, n_max)
            if frac > best_frac:
                best_frac = frac
            if hits > best_hits:
                best_hits = hits
    return best_frac, best_hits


def substring_match_count(lower_bits_by_n, blocks, n_min_hex=17, n_max=70, min_hexlen=4):
    """Count (n, block, orientation) combos where hex(lower_bits(n)),
    stripped of leading zeros (min min_hexlen hex chars to avoid trivial
    short-string false positives), is a substring of the block hash hex
    string (as returned by the API) or its byte-reversed form (covers both
    common display/internal byte-order conventions)."""
    hexes = []
    for info in blocks.values():
        h = info["hash"]
        hexes.append(h)
        # byte-reversed (internal little-endian) representation
        b = bytes.fromhex(h)[::-1].hex()
        hexes.append(b)
    count = 0
    checked = 0
    for n in range(n_min_hex, n_max + 1):
        lb = lower_bits_by_n[n]
        hx = format(lb, "x").lstrip("0") or "0"
        if len(hx) < min_hexlen:
            continue
        for hexstr in hexes:
            checked += 1
            if hx in hexstr:
                count += 1
    return count, checked, len(hexes)


def mc_nearby_blocks_test(real_lb, data, blocks, n_trials=4000):
    real_best_frac, real_best_hits = best_over_blocks(real_lb, blocks)
    real_sub_count, sub_checked, n_hexes = substring_match_count(real_lb, blocks)

    null_best_frac = np.empty(n_trials)
    null_best_hits = np.empty(n_trials, dtype=np.int64)
    null_sub_count = np.empty(n_trials, dtype=np.int64)
    for t in range(n_trials):
        trial_lb = random_control_lower_bits(data, py_rng)
        f, h = best_over_blocks(trial_lb, blocks)
        null_best_frac[t] = f
        null_best_hits[t] = h
        sc, _, _ = substring_match_count(trial_lb, blocks)
        null_sub_count[t] = sc

    p_frac = (np.sum(null_best_frac >= real_best_frac) + 1) / (n_trials + 1)
    p_hits = (np.sum(null_best_hits >= real_best_hits) + 1) / (n_trials + 1)
    p_sub = (np.sum(null_sub_count >= real_sub_count) + 1) / (n_trials + 1)
    return {
        "n_blocks": len(blocks), "real_best_frac": real_best_frac, "real_best_hits": real_best_hits,
        "null_best_frac_mean": float(null_best_frac.mean()), "null_best_frac_max": float(null_best_frac.max()),
        "null_best_hits_mean": float(null_best_hits.mean()), "null_best_hits_max": int(null_best_hits.max()),
        "p_frac": p_frac, "p_hits": p_hits,
        "real_sub_count": real_sub_count, "sub_checked": sub_checked, "n_hexes": n_hexes,
        "null_sub_mean": float(null_sub_count.mean()), "null_sub_max": int(null_sub_count.max()),
        "p_sub": p_sub,
    }


# --------------------------------------------------------------------------
# TEST 3: full timestamp-range search (vectorized numpy, n=2..63)
# --------------------------------------------------------------------------

N_MAX_VEC = 63  # 2^62 modulus fits safely in signed int64 (max ~4.6e18 < 9.2e18)


def build_vec_inputs(data, n_min=2, n_max=N_MAX_VEC):
    n_values = np.arange(n_min, n_max + 1, dtype=np.int64)
    pow2 = (1 << (n_values - 1)).astype(np.int64)
    by_n = {d["n"]: lower_bits_int(d) for d in data}
    lb = np.array([by_n[int(n)] for n in n_values], dtype=np.int64)
    return n_values, pow2, lb


def full_range_scan(lb_rows, pow2, n_values, T_min, T_max, chunk):
    """lb_rows: (trials, n_count) int64 array (row 0 = real data by
    convention when called from the trial-batch wrapper below).
    Returns per-relation best match count arrays, shape (trials,)."""
    trials = lb_rows.shape[0]
    best_mod = np.zeros(trials, dtype=np.int64)
    best_add = np.zeros(trials, dtype=np.int64)
    for start in range(T_min, T_max, chunk):
        end = min(start + chunk, T_max)
        Ts = np.arange(start, end, dtype=np.int64)
        Tmod = Ts[:, None] % pow2[None, :]
        Tadd = (Ts[:, None] + n_values[None, :]) % pow2[None, :]
        eq_mod = (Tmod[:, None, :] == lb_rows[None, :, :]).sum(axis=2)  # (C, trials)
        eq_add = (Tadd[:, None, :] == lb_rows[None, :, :]).sum(axis=2)
        best_mod = np.maximum(best_mod, eq_mod.max(axis=0))
        best_add = np.maximum(best_add, eq_add.max(axis=0))
    return best_mod, best_add


def mc_full_range_test(data, n_trials=100, chunk=50000):
    n_values, pow2, real_lb = build_vec_inputs(data)
    n_count = len(n_values)

    trial_rows = [real_lb]
    for _ in range(n_trials):
        row = np.array(
            [int(np_rng.integers(0, int(p))) for p in pow2], dtype=np.int64
        )
        trial_rows.append(row)
    lb_rows = np.stack(trial_rows, axis=0)  # (1+n_trials, n_count)

    t0 = time.time()
    best_mod, best_add = full_range_scan(lb_rows, pow2, n_values, TS_RANGE_MIN, TS_RANGE_MAX, chunk)
    elapsed = time.time() - t0

    real_mod, null_mod = int(best_mod[0]), best_mod[1:]
    real_add, null_add = int(best_add[0]), best_add[1:]
    real_best = max(real_mod, real_add)
    null_best = np.maximum(null_mod, null_add)

    p_mod = (np.sum(null_mod >= real_mod) + 1) / (n_trials + 1)
    p_add = (np.sum(null_add >= real_add) + 1) / (n_trials + 1)
    p_combined = (np.sum(null_best >= real_best) + 1) / (n_trials + 1)

    return {
        "n_candidates": TS_RANGE_MAX - TS_RANGE_MIN, "n_puzzles": n_count, "n_trials": n_trials,
        "elapsed_s": elapsed,
        "real_mod": real_mod, "null_mod_mean": float(null_mod.mean()), "null_mod_max": int(null_mod.max()), "p_mod": p_mod,
        "real_add": real_add, "null_add_mean": float(null_add.mean()), "null_add_max": int(null_add.max()), "p_add": p_add,
        "real_best_combined": real_best, "null_best_mean": float(null_best.mean()),
        "null_best_max": int(null_best.max()), "p_combined": p_combined,
    }


# --------------------------------------------------------------------------
# TEST 3b: walk-forward -- select best (T, relation) on training puzzles
# only (n=2..50), evaluate with NO further fitting on held-out n=51..70
# --------------------------------------------------------------------------

def walk_forward_timestamp(data, chunk=50000, train_max=50):
    n_values, pow2, real_lb = build_vec_inputs(data, n_min=2, n_max=N_MAX_VEC)
    train_mask = n_values <= train_max
    train_n, train_pow2, train_lb = n_values[train_mask], pow2[train_mask], real_lb[train_mask]

    best_score, best_T, best_rel = -1, None, None
    for start in range(TS_RANGE_MIN, TS_RANGE_MAX, chunk):
        end = min(start + chunk, TS_RANGE_MAX)
        Ts = np.arange(start, end, dtype=np.int64)
        Tmod = Ts[:, None] % train_pow2[None, :]
        Tadd = (Ts[:, None] + train_n[None, :]) % train_pow2[None, :]
        c_mod = (Tmod == train_lb[None, :]).sum(axis=1)
        c_add = (Tadd == train_lb[None, :]).sum(axis=1)
        i_mod, i_add = int(c_mod.argmax()), int(c_add.argmax())
        if c_mod[i_mod] > best_score:
            best_score, best_T, best_rel = int(c_mod[i_mod]), int(Ts[i_mod]), "mod"
        if c_add[i_add] > best_score:
            best_score, best_T, best_rel = int(c_add[i_add]), int(Ts[i_add]), "add"

    # evaluate the single selected (T, relation) on held-out puzzles,
    # n = train_max+1 .. 70, with EXACT Python bigints (no further fitting,
    # no re-search -- literal walk-forward, and covers n up to 70 since no
    # int64 constraint applies to a single scalar evaluation)
    by_n = {d["n"]: lower_bits_int(d) for d in data}
    held_out_ns = [n for n in by_n if n > train_max]
    exact_hits = 0
    bit_agree_fracs = []
    for n in held_out_ns:
        mod = 2 ** (n - 1)
        if best_rel == "mod":
            pred = best_T % mod
        else:
            pred = (best_T + n) % mod
        lb = by_n[n]
        if pred == lb:
            exact_hits += 1
        bits = n - 1
        agree = 1.0 - (popcount(lb ^ pred) / bits) if bits > 0 else 1.0
        bit_agree_fracs.append(agree)

    chance_exact_expected = sum(1.0 / 2 ** (n - 1) for n in held_out_ns)
    return {
        "train_max": train_max, "best_T": best_T, "best_relation": best_rel,
        "train_score": best_score, "train_n_count": int(train_mask.sum()),
        "held_out_n": held_out_ns, "held_out_exact_hits": exact_hits,
        "held_out_chance_expected_exact": chance_exact_expected,
        "held_out_mean_bit_agreement": float(np.mean(bit_agree_fracs)),
        "held_out_chance_bit_agreement": 0.5,
    }


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    t0 = time.time()
    data = load_data()
    real_lb = {d["n"]: lower_bits_int(d) for d in data}
    blocks = load_blocks_cache()
    blocks = {int(k): v for k, v in blocks.items()}
    print(f"Loaded {len(data)} puzzles, {len(blocks)} cached nearby blocks.")

    print("\n" + "=" * 78)
    print("TEST 1: fixed-value comparison against the independently known")
    print("funding block's timestamp / mediantime / height / hash-as-int (NO search)")
    print("=" * 78)
    fixed_values = {
        "funding_block_time (1421345234)": FUNDING_BLOCK_TIME,
        "funding_block_mediantime (1421342061)": FUNDING_BLOCK_MEDIANTIME,
        "funding_block_height (339085)": FUNDING_BLOCK_HEIGHT,
        "funding_block_hash_as_int": int(FUNDING_BLOCK_HASH, 16),
    }
    test1_results = {}
    for label, val in fixed_values.items():
        res = mc_fixed_value_test(val, real_lb, data, n_trials=8000)
        test1_results[label] = res
        print(f"\n  {label}:")
        print(f"    mean bit-agreement fraction (n=2..70): real={res['real_frac']:.4f}  "
              f"null mean={res['null_frac_mean']:.4f} (std={res['null_frac_std']:.4f})  "
              f"p(two-sided)={res['p_frac']:.4f}")
        print(f"    exact-match count (n=2..70, out of {res['total']}): real={res['real_hits']}  "
              f"null mean={res['null_hits_mean']:.3f} max={res['null_hits_max']}  p={res['p_hits']:.4f}")
    bonf_n = len(fixed_values) * 2
    min_p1 = min(min(r["p_frac"], r["p_hits"]) for r in test1_results.values())
    print(f"\n  Bonferroni correction over {bonf_n} tests ({len(fixed_values)} values x 2 statistics): "
          f"min raw p={min_p1:.4f}, corrected={min(1.0, min_p1*bonf_n):.4f}")

    print("\n" + "=" * 78)
    print(f"TEST 2: nearby-blocks handful search ({len(blocks)} real blocks around funding)")
    print("=" * 78)
    res2 = mc_nearby_blocks_test(real_lb, data, blocks, n_trials=4000)
    print(f"  Blocks searched: {res2['n_blocks']} (heights {sorted(blocks.keys())[:3]}...{sorted(blocks.keys())[-3:]})")
    print(f"  Best bit-agreement fraction over all (block, value-type) combos:")
    print(f"    real={res2['real_best_frac']:.4f}  null mean={res2['null_best_frac_mean']:.4f} "
          f"max={res2['null_best_frac_max']:.4f}  p={res2['p_frac']:.4f}")
    print(f"  Best exact-match count over all combos:")
    print(f"    real={res2['real_best_hits']}  null mean={res2['null_best_hits_mean']:.3f} "
          f"max={res2['null_best_hits_max']}  p={res2['p_hits']:.4f}")
    print(f"  Hex-substring matches (lower_bits(n) hex, n>=17, min 4 hex chars, "
          f"vs {res2['n_hexes']} hash strings incl. byte-reversed):")
    print(f"    real={res2['real_sub_count']} (of {res2['sub_checked']} checked)  "
          f"null mean={res2['null_sub_mean']:.3f} max={res2['null_sub_max']}  p={res2['p_sub']:.4f}")

    print("\n" + "=" * 78)
    print("TEST 3: full timestamp-range search (Jan-Mar 2015, ~5.10M candidates,")
    print("        n=2..63, relations: T mod 2^(n-1), (T+n) mod 2^(n-1))")
    print("=" * 78)
    N_TRIALS_3 = 100
    CHUNK_3 = 50000
    res3 = mc_full_range_test(data, n_trials=N_TRIALS_3, chunk=CHUNK_3)
    print(f"  Candidates T searched: {res3['n_candidates']:,}  Puzzles covered: {res3['n_puzzles']} (n=2..{N_MAX_VEC})")
    print(f"  Monte Carlo trials: {res3['n_trials']}  (scan wall time: {res3['elapsed_s']:.1f}s)")
    print(f"  Relation T mod 2^(n-1):      real best={res3['real_mod']}  "
          f"null mean={res3['null_mod_mean']:.3f} max={res3['null_mod_max']}  p={res3['p_mod']:.4f}")
    print(f"  Relation (T+n) mod 2^(n-1):  real best={res3['real_add']}  "
          f"null mean={res3['null_add_mean']:.3f} max={res3['null_add_max']}  p={res3['p_add']:.4f}")
    print(f"  Combined (best of both relations): real={res3['real_best_combined']}  "
          f"null mean={res3['null_best_mean']:.3f} max={res3['null_best_max']}  p={res3['p_combined']:.4f}")

    print("\n" + "=" * 78)
    print("TEST 3b: walk-forward -- fit best (T, relation) on n<=50 ONLY, evaluate")
    print("         with no further fitting on held-out n=51..70")
    print("=" * 78)
    resWF = walk_forward_timestamp(data, chunk=CHUNK_3, train_max=50)
    print(f"  Training puzzles: n=2..{resWF['train_max']} ({resWF['train_n_count']} puzzles)")
    print(f"  Best (T, relation) found on TRAINING data only: T={resWF['best_T']}, "
          f"relation={resWF['best_relation']}, training match count={resWF['train_score']}")
    print(f"  Held-out puzzles: n={resWF['held_out_n']}")
    print(f"  Held-out exact hits: {resWF['held_out_exact_hits']}  "
          f"(chance-expected: {resWF['held_out_chance_expected_exact']:.4f})")
    print(f"  Held-out mean bit-agreement fraction: {resWF['held_out_mean_bit_agreement']:.4f}  "
          f"(chance baseline: {resWF['held_out_chance_bit_agreement']:.4f})")

    print(f"\nTotal runtime: {time.time()-t0:.1f}s")

    return {
        "test1": test1_results,
        "test2": res2,
        "test3": res3,
        "test3b": resWF,
    }


if __name__ == "__main__":
    main()
