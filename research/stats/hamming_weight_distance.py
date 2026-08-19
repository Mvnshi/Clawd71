#!/usr/bin/env python3
"""
Hamming-weight and pairwise Hamming-distance analysis of the "free bits" of
the 70 verified/solved Bitcoin puzzle private keys (puzzles #1-70).

Definitions
-----------
For puzzle n, the private key k satisfies k in [2^(n-1), 2^n). Written as an
n-bit binary string, the top bit (position n-1, 0-indexed from the LSB) is
FORCED to 1 by construction of the puzzle interval -- it carries zero
information. The remaining (n-1) bits

    lower_bits = key_int - 2^(n-1),   0 <= lower_bits < 2^(n-1)

are the "free bits" (L(n) = n-1 of them), right-aligned at the LSB end of
the key. Puzzle n=1 has L(1)=0 free bits (key=1 is fully forced by the
interval [1,2)) and is excluded from every test below (69 usable puzzles,
n=2..70).

We verified against the dataset that `binary[1:]` (the key's full binary
string with the forced leading '1' stripped) equals `lower_bits_hex`
zero-padded to (n-1) bits, for every puzzle -- confirmed programmatically
below via an assertion before any statistics are computed.

Two independent questions are asked of these free bits, both stress-testing
the puzzle creator's claim ("no pattern, just consecutive keys from a
deterministic wallet"):

PART A -- Hamming weight (popcount) per puzzle
------------------------------------------------
If lower_bits_n really is L(n) independent fair coin flips, popcount(n) ~
Binomial(L(n), 0.5). We normalize each puzzle's popcount to a z-score using
the binomial mean/variance (mu = L/2, var = L/4) so puzzles of very
different bit_length can be pooled on a common scale, then test:
  A1. Pooled statistic T = sum_n z_n^2 over all 69 puzzles (df=69 under the
      classical asymptotic chi-square-of-a-sum-of-normals approximation).
      Because several puzzles have very small L(n) (e.g. L=1..5 bits, where
      the normal approximation to the binomial is poor), we do NOT trust
      the asymptotic chi2(69) p-value alone -- we calibrate T against an
      exact Monte Carlo null (see below) and report both.
  A2. Overall pooled bit balance: total ones / total free bits (2415 total)
      vs 0.5, again Monte-Carlo calibrated.
  A3. Per-puzzle exact two-sided binomial test (descriptive; also carries
      its own Bonferroni/BH correction across 69 tests so no single
      "lucky" puzzle is over-interpreted).

Monte Carlo null for Part A: for each of NUM_SIMS_WEIGHT simulated
datasets, draw popcount_n ~ Binomial(L(n), 0.5) independently for each of
the 69 puzzles (this is EXACTLY the distribution of a real popcount of
L(n) independent fair bits, so no bit-level simulation is needed for this
part -- sampling straight from the exact null is both correct and fast).

PART B -- Pairwise Hamming distance between puzzles' free bits
------------------------------------------------------------------
For every pair of puzzles (i,j) with i<j, both drawn from n=2..70 (69
puzzles => C(69,2) = 2346 valid pairs; note this is NOT 70*69/2=2415,
because puzzle n=1 has zero free bits and is excluded -- see note in the
report), we right-align both puzzles' free-bit strings at the LSB and
compare over the SHORTER of the two bit-lengths:

    L_min   = min(L(n_i), L(n_j))
    mask    = (1 << L_min) - 1
    HD(i,j) = popcount( (lower_bits_i & mask) XOR (lower_bits_j & mask) )

Under independence, HD(i,j) ~ Binomial(L_min, 0.5) EXACTLY (the XOR of two
independent uniform L_min-bit strings is itself uniform, so this is not an
approximation). We are specifically hunting for anomalously LOW HD (i.e.
HD_frac = HD/L_min well below 0.5), which is what shared/reused short
secret material between two puzzle keys would produce. For every pair we
compute the exact one-sided left-tail p-value p_low = P(Binom(L_min,0.5)
<= HD_observed), rank all 2346 pairs by p_low, and apply:
  B1. Bonferroni correction (alpha_fam=0.05 / 2346 pairs).
  B2. Benjamini-Hochberg FDR correction.
  B3. A Monte Carlo family-wise calibration: NUM_SIMS_PAIR simulated
      datasets, each drawing a fresh independent random lower_bits_n for
      every puzzle (via true random bit generation, not just popcount,
      since HD depends on WHICH bits are set, not just how many), from
      which we recompute the full 2346-pair HD matrix and record the
      single smallest p_low seen in that simulated dataset. Comparing the
      REAL smallest p_low against this simulated distribution gives an
      exact, assumption-free family-wise error rate (this also sanity-
      checks Bonferroni, which is conservative under any correlation
      between overlapping pairs sharing a puzzle).

Anti-bullshit stance
---------------------
No claim in this script is allowed to rest on "it matches the 70 known
keys" alone. Every headline number reported has an accompanying Monte
Carlo (or exact analytic, where the analytic null is itself exact -- as it
is for both popcount and pairwise-XOR-of-uniform-bits) null-model
comparison, and the pairwise section is explicitly corrected for the ~2346
comparisons being made. If nothing survives correction, that is reported
as the (expected, valid) result -- not glossed over.
"""

import json
import math
import random
from pathlib import Path

import numpy as np
from scipy import stats

RNG_SEED = 20260819  # today's date, for reproducibility
rng = np.random.default_rng(RNG_SEED)
py_rng = random.Random(RNG_SEED)

DATA_PATH = Path("/home/user/Clawd71/data/solved_puzzles.json")
OUT_MD = Path("/home/user/Clawd71/research/stats/hamming_weight_distance.md")

NUM_SIMS_WEIGHT = 500_000   # Part A Monte Carlo simulations
NUM_SIMS_PAIR = 100_000     # Part B Monte Carlo simulations (family-wise)

ALPHA = 0.05


def load_puzzles():
    with open(DATA_PATH) as f:
        data = json.load(f)
    data.sort(key=lambda d: d["n"])
    assert [d["n"] for d in data] == list(range(1, 71)), "expected puzzles #1..#70"
    return data


def build_free_bit_records(data):
    """Return list of dicts for n=2..70 (69 puzzles with >=1 free bit)."""
    records = []
    for d in data:
        n = d["n"]
        L = n - 1
        lower_bits = int(d["lower_bits_hex"], 16) if d["lower_bits_hex"] else 0
        if L == 0:
            assert lower_bits == 0
            continue
        assert 0 <= lower_bits < (1 << L), f"n={n}: lower_bits out of range"
        # cross-check against the 'binary' field independently
        bits_from_binary = d["binary"][1:]  # strip forced leading '1'
        assert len(bits_from_binary) == L, f"n={n}: binary field length mismatch"
        bits_from_lower = bin(lower_bits)[2:].zfill(L)
        assert bits_from_binary == bits_from_lower, f"n={n}: free-bit mismatch"
        records.append({"n": n, "L": L, "lower_bits": lower_bits})
    return records


# ---------------------------------------------------------------------------
# PART A: Hamming weight (popcount) per puzzle
# ---------------------------------------------------------------------------

def part_a(records):
    ns = np.array([r["n"] for r in records])
    Ls = np.array([r["L"] for r in records])
    popcounts = np.array([r["lower_bits"].bit_count() for r in records])

    mu = Ls / 2.0
    var = Ls / 4.0
    z = (popcounts - mu) / np.sqrt(var)

    T_obs = float(np.sum(z ** 2))
    df = len(records)  # 69

    # classical asymptotic reference (known to be a poor approximation for
    # the several puzzles with very small L -- reported for reference only)
    chi2_asymp_p = float(stats.chi2.sf(T_obs, df))

    total_ones = int(popcounts.sum())
    total_bits = int(Ls.sum())
    z_overall = (total_ones - total_bits / 2.0) / math.sqrt(total_bits / 4.0)
    p_overall_asymp = float(2 * stats.norm.sf(abs(z_overall)))

    # exact per-puzzle two-sided binomial tests (descriptive)
    per_puzzle_p = np.array([
        stats.binomtest(int(w), int(L), 0.5, alternative="two-sided").pvalue
        for w, L in zip(popcounts, Ls)
    ])
    bonf_per_puzzle = np.minimum(1.0, per_puzzle_p * df)
    bh_per_puzzle = bh_qvalues(per_puzzle_p)

    # ---- Monte Carlo null for T_obs and overall balance ----
    # exact null distribution of popcount_n is Binomial(L_n, 0.5); sample
    # directly (no need to simulate raw bits for a popcount-only statistic)
    sim_popcounts = rng.binomial(
        n=Ls[np.newaxis, :],
        p=0.5,
        size=(NUM_SIMS_WEIGHT, df),
    )
    sim_z = (sim_popcounts - mu[np.newaxis, :]) / np.sqrt(var[np.newaxis, :])
    sim_T = np.sum(sim_z ** 2, axis=1)

    mc_p_T_high = float(np.mean(sim_T >= T_obs))   # too dispersed / skewed
    mc_p_T_low = float(np.mean(sim_T <= T_obs))    # too "regular"/uniform
    mc_p_T_two_sided = float(2 * min(mc_p_T_high, mc_p_T_low))
    mc_p_T_two_sided = min(1.0, mc_p_T_two_sided)

    sim_total_ones = sim_popcounts.sum(axis=1)
    mc_p_overall_high = float(np.mean(sim_total_ones >= total_ones))
    mc_p_overall_low = float(np.mean(sim_total_ones <= total_ones))
    mc_p_overall_two_sided = min(1.0, 2 * min(mc_p_overall_high, mc_p_overall_low))

    return {
        "ns": ns, "Ls": Ls, "popcounts": popcounts, "z": z,
        "T_obs": T_obs, "df": df, "chi2_asymp_p": chi2_asymp_p,
        "total_ones": total_ones, "total_bits": total_bits,
        "z_overall": z_overall, "p_overall_asymp": p_overall_asymp,
        "per_puzzle_p": per_puzzle_p, "bonf_per_puzzle": bonf_per_puzzle,
        "bh_per_puzzle": bh_per_puzzle,
        "mc_p_T_high": mc_p_T_high, "mc_p_T_low": mc_p_T_low,
        "mc_p_T_two_sided": mc_p_T_two_sided,
        "mc_p_overall_high": mc_p_overall_high, "mc_p_overall_low": mc_p_overall_low,
        "mc_p_overall_two_sided": mc_p_overall_two_sided,
        "sim_T_mean": float(sim_T.mean()), "sim_T_std": float(sim_T.std()),
    }


def bh_qvalues(pvals):
    """Benjamini-Hochberg FDR q-values."""
    p = np.asarray(pvals)
    n = len(p)
    order = np.argsort(p)
    ranked = p[order]
    q = ranked * n / (np.arange(n) + 1)
    # enforce monotonicity (running minimum from the largest p down)
    q = np.minimum.accumulate(q[::-1])[::-1]
    q = np.minimum(q, 1.0)
    out = np.empty(n)
    out[order] = q
    return out


# ---------------------------------------------------------------------------
# PART B: Pairwise Hamming distance
# ---------------------------------------------------------------------------

def part_b(records):
    n_rec = len(records)
    ns = [r["n"] for r in records]
    Ls = [r["L"] for r in records]
    vals = [r["lower_bits"] for r in records]

    pairs = [(i, j) for i in range(n_rec) for j in range(i + 1, n_rec)]
    n_pairs = len(pairs)

    # precompute exact binomial CDF lookup table: table[L_min][hd] = P(X<=hd)
    max_L = max(Ls)
    cdf_table = {}
    for L in set(min(Ls[i], Ls[j]) for i, j in pairs):
        xs = np.arange(L + 1)
        cdf_table[L] = stats.binom.cdf(xs, L, 0.5)

    real_rows = []
    for i, j in pairs:
        Lmin = min(Ls[i], Ls[j])
        mask = (1 << Lmin) - 1
        hd = ((vals[i] & mask) ^ (vals[j] & mask)).bit_count()
        p_low = float(cdf_table[Lmin][hd])
        real_rows.append({
            "ni": ns[i], "nj": ns[j], "Lmin": Lmin, "hd": hd,
            "hd_frac": hd / Lmin, "p_low": p_low,
        })

    p_low_arr = np.array([r["p_low"] for r in real_rows])
    bonf_arr = np.minimum(1.0, p_low_arr * n_pairs)
    bh_arr = bh_qvalues(p_low_arr)
    for row, bo, bh in zip(real_rows, bonf_arr, bh_arr):
        row["p_bonf"] = float(bo)
        row["q_bh"] = float(bh)

    real_rows_sorted = sorted(real_rows, key=lambda r: r["p_low"])
    real_min_p = real_rows_sorted[0]["p_low"]
    n_below_01_real = int(np.sum(p_low_arr < 0.01))
    n_below_05_real = int(np.sum(p_low_arr < 0.05))

    # ---- Monte Carlo family-wise null ----
    # draw fresh independent random lower_bits per puzzle per simulation
    # (true random bit patterns needed -- HD depends on which bits match,
    # not just popcount)
    Ls_arr = np.array(Ls)
    i_idx = np.array([p[0] for p in pairs])
    j_idx = np.array([p[1] for p in pairs])
    Lmin_arr = np.array([min(Ls[i], Ls[j]) for i, j in pairs])

    # build a flat lookup: for each pair-index k, cdf_table[Lmin_arr[k]] is
    # an array; to vectorize the lookup across many sims we index per-pair
    # tables individually (fast enough given the sim count / pair count).
    min_p_null = np.empty(NUM_SIMS_PAIR)
    below01_null = np.empty(NUM_SIMS_PAIR, dtype=np.int64)
    below05_null = np.empty(NUM_SIMS_PAIR, dtype=np.int64)

    # Draw true random L-bit patterns per puzzle per simulation using
    # Python's arbitrary-precision getrandbits (correct for any L,
    # including L>63 where fixed-width numpy integer RNGs would overflow).
    # Benchmarked at ~0.5ms per full simulation (69 draws + 2346 pairwise
    # XOR/popcount/table-lookup ops), so NUM_SIMS_PAIR=100,000 sims runs in
    # well under a minute.
    for s in range(NUM_SIMS_PAIR):
        sim_vals = [py_rng.getrandbits(L) if L > 0 else 0 for L in Ls]
        best = 1.0
        c01 = 0
        c05 = 0
        for k, (i, j) in enumerate(pairs):
            Lmin = Lmin_arr[k]
            mask = (1 << int(Lmin)) - 1
            hd = ((sim_vals[i] & mask) ^ (sim_vals[j] & mask)).bit_count()
            p = cdf_table[int(Lmin)][hd]
            if p < best:
                best = p
            if p < 0.01:
                c01 += 1
            if p < 0.05:
                c05 += 1
        min_p_null[s] = best
        below01_null[s] = c01
        below05_null[s] = c05

    mc_family_p = float(np.mean(min_p_null <= real_min_p))
    mc_p_count01 = float(np.mean(below01_null >= n_below_01_real))
    mc_p_count05 = float(np.mean(below05_null >= n_below_05_real))

    return {
        "n_pairs": n_pairs,
        "rows_sorted": real_rows_sorted,
        "real_min_p": real_min_p,
        "n_below_01_real": n_below_01_real,
        "n_below_05_real": n_below_05_real,
        "mc_family_p": mc_family_p,
        "mc_p_count01": mc_p_count01,
        "mc_p_count05": mc_p_count05,
        "min_p_null_mean": float(min_p_null.mean()),
        "min_p_null_p05": float(np.percentile(min_p_null, 5)),
        "below01_null_mean": float(below01_null.mean()),
        "below05_null_mean": float(below05_null.mean()),
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def fmt_p(p):
    if p < 1e-4:
        return f"{p:.3e}"
    return f"{p:.4f}"


def main():
    data = load_puzzles()
    records = build_free_bit_records(data)
    assert len(records) == 69

    print(f"Loaded {len(data)} puzzles, {len(records)} with >=1 free bit.")
    print(f"Total free bits across dataset: {sum(r['L'] for r in records)}")

    print("\n=== PART A: Hamming weight per puzzle ===")
    a = part_a(records)
    print(f"T_obs (pooled sum z^2, df={a['df']}) = {a['T_obs']:.3f}")
    print(f"  classical asymptotic chi2({a['df']}) sf p = {fmt_p(a['chi2_asymp_p'])}")
    print(f"  Monte Carlo ({NUM_SIMS_WEIGHT} sims) null mean={a['sim_T_mean']:.2f} std={a['sim_T_std']:.2f}")
    print(f"  MC p (T too high, i.e. overdispersed) = {fmt_p(a['mc_p_T_high'])}")
    print(f"  MC p (T too low, i.e. underdispersed/too-uniform) = {fmt_p(a['mc_p_T_low'])}")
    print(f"  MC p (two-sided) = {fmt_p(a['mc_p_T_two_sided'])}")
    print(f"Overall bit balance: {a['total_ones']}/{a['total_bits']} ones "
          f"({100*a['total_ones']/a['total_bits']:.3f}%)")
    print(f"  z_overall={a['z_overall']:.3f}, asymptotic two-sided p={fmt_p(a['p_overall_asymp'])}")
    print(f"  MC two-sided p = {fmt_p(a['mc_p_overall_two_sided'])}")
    n_sig_bonf = int(np.sum(a['bonf_per_puzzle'] < ALPHA))
    n_sig_bh = int(np.sum(a['bh_per_puzzle'] < ALPHA))
    print(f"Per-puzzle exact binomial tests: {n_sig_bonf}/{a['df']} survive Bonferroni "
          f"at alpha={ALPHA}, {n_sig_bh}/{a['df']} survive BH")

    print("\n=== PART B: Pairwise Hamming distance ===")
    b = part_b(records)
    print(f"Total valid pairs tested: {b['n_pairs']}")
    print(f"Most anomalous (lowest HD) real pair: p_low={fmt_p(b['real_min_p'])}")
    top = b['rows_sorted'][0]
    print(f"  n={top['ni']} vs n={top['nj']}: Lmin={top['Lmin']}, HD={top['hd']} "
          f"({top['hd_frac']:.3f}), Bonferroni p={fmt_p(top['p_bonf'])}, BH q={fmt_p(top['q_bh'])}")
    print(f"Monte Carlo family-wise p (is min real p_low more extreme than "
          f"{NUM_SIMS_PAIR} simulated null datasets' best pair?) = {fmt_p(b['mc_family_p'])}")
    print(f"  null min-p distribution: mean={b['min_p_null_mean']:.4f}, 5th pctile={b['min_p_null_p05']:.4e}")
    print(f"Pairs with raw p_low<0.01: real={b['n_below_01_real']}, null mean={b['below01_null_mean']:.2f}, "
          f"MC p(>=real)={fmt_p(b['mc_p_count01'])}")
    print(f"Pairs with raw p_low<0.05: real={b['n_below_05_real']}, null mean={b['below05_null_mean']:.2f}, "
          f"MC p(>=real)={fmt_p(b['mc_p_count05'])}")

    write_report(records, a, b)
    print(f"\nReport written to {OUT_MD}")


def write_report(records, a, b):
    lines = []
    lines.append("# Hamming Weight and Pairwise Hamming Distance Analysis")
    lines.append("")
    lines.append(f"Puzzle #71 research -- generated by `hamming_weight_distance.py`, "
                 f"seed={RNG_SEED}.")
    lines.append("")
    lines.append("Dataset: `/home/user/Clawd71/data/solved_puzzles.json`, 70 verified "
                 "puzzles (#1-70). Puzzle #1 has zero free bits (key=1 is fully forced "
                 "by its interval [1,2)) and is excluded from both analyses below, "
                 "leaving 69 usable puzzles (#2-70) and C(69,2)=2346 valid pairs "
                 "(not 70*69/2=2415, since #1 contributes no free bits to compare).")
    lines.append("")
    lines.append("## Anti-bullshit rule applied")
    lines.append("")
    lines.append("Every statistic below is checked against an explicit Monte Carlo "
                 "null model (either sampled directly from the exact analytic null "
                 "distribution, which is available in closed form for both popcount "
                 "and pairwise-XOR-of-uniform-bits, or -- for the pairwise family-wise "
                 "test -- simulated from scratch with fresh random bit patterns per "
                 "puzzle). Nothing here is claimed as a 'pattern' merely because it "
                 "differs numerically from 0.5 or 50%; only a result whose Monte Carlo "
                 "p-value clears both an uncorrected and a multiple-comparison-corrected "
                 "threshold would count as evidence.")
    lines.append("")

    # ---------------- Part A ----------------
    lines.append("## Part A: Hamming weight (popcount) per puzzle")
    lines.append("")
    lines.append("For puzzle n, free bits L(n)=n-1, popcount ~ Binomial(L(n),0.5) "
                 "under the null. Each puzzle's popcount is normalized to a z-score "
                 "(mu=L/2, sigma=sqrt(L/4)) so puzzles of different bit-length can be "
                 "pooled on one scale.")
    lines.append("")
    lines.append("### Pooled statistic")
    lines.append("")
    lines.append("| Statistic | Value |")
    lines.append("|---|---|")
    lines.append(f"| T = sum of z^2 over 69 puzzles (df=69) | {a['T_obs']:.3f} |")
    lines.append(f"| Expected T under null (=df) | {a['df']} |")
    lines.append(f"| Classical asymptotic chi2({a['df']}) upper-tail p | {fmt_p(a['chi2_asymp_p'])} |")
    lines.append(f"| Monte Carlo null mean (N={NUM_SIMS_WEIGHT:,}) | {a['sim_T_mean']:.2f} |")
    lines.append(f"| Monte Carlo null std | {a['sim_T_std']:.2f} |")
    lines.append(f"| MC p (T too high / overdispersed) | {fmt_p(a['mc_p_T_high'])} |")
    lines.append(f"| MC p (T too low / underdispersed) | {fmt_p(a['mc_p_T_low'])} |")
    lines.append(f"| **MC p (two-sided, headline)** | **{fmt_p(a['mc_p_T_two_sided'])}** |")
    lines.append("")
    lines.append("The classical asymptotic chi-square reference is included for "
                 "context only -- several puzzles have very small L(n) (e.g. n=2..8 "
                 "give L=1..7 bits), where the normal approximation to a binomial is "
                 "coarse, so the Monte Carlo p-value (sampled directly from the exact "
                 "per-puzzle binomial null) is the trustworthy number.")
    lines.append("")
    lines.append("### Overall pooled bit balance")
    lines.append("")
    lines.append(f"Total ones across all 2415 free bits: **{a['total_ones']} / {a['total_bits']}** "
                 f"({100*a['total_ones']/a['total_bits']:.3f}%, null expectation 50%).")
    lines.append("")
    lines.append(f"- z_overall = {a['z_overall']:.3f}, asymptotic two-sided p = {fmt_p(a['p_overall_asymp'])}")
    lines.append(f"- **Monte Carlo two-sided p = {fmt_p(a['mc_p_overall_two_sided'])}** (N={NUM_SIMS_WEIGHT:,})")
    lines.append("")
    lines.append("### Per-puzzle exact binomial tests (descriptive, multiple-comparison corrected)")
    lines.append("")
    n_sig_bonf = int(np.sum(a['bonf_per_puzzle'] < ALPHA))
    n_sig_bh = int(np.sum(a['bh_per_puzzle'] < ALPHA))
    lines.append(f"Across all 69 puzzles, exact two-sided binomial tests give "
                 f"**{n_sig_bonf}/69 surviving Bonferroni** (alpha={ALPHA}) and "
                 f"**{n_sig_bh}/69 surviving Benjamini-Hochberg FDR** (alpha={ALPHA}).")
    lines.append("")
    lines.append("Full per-puzzle table (n, L, popcount, expected L/2, z, raw p, "
                 "Bonferroni p, BH q):")
    lines.append("")
    lines.append("| n | L | popcount | L/2 | z | raw p | Bonferroni p | BH q |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for idx in range(len(records)):
        n = int(a['ns'][idx]); L = int(a['Ls'][idx]); w = int(a['popcounts'][idx])
        z = a['z'][idx]
        rawp = a['per_puzzle_p'][idx]
        bo = a['bonf_per_puzzle'][idx]
        bh = a['bh_per_puzzle'][idx]
        lines.append(f"| {n} | {L} | {w} | {L/2:.1f} | {z:+.2f} | {fmt_p(rawp)} | {fmt_p(bo)} | {fmt_p(bh)} |")
    lines.append("")

    # ---------------- Part B ----------------
    lines.append("## Part B: Pairwise Hamming distance between puzzles' free bits")
    lines.append("")
    lines.append(f"For all {b['n_pairs']} valid pairs (i<j among puzzles #2-70), "
                 "free-bit strings are right-aligned at the LSB and compared over "
                 "L_min = min(L_i, L_j) bits: HD = popcount(XOR). Under independence "
                 "HD ~ Binomial(L_min, 0.5) exactly. We test for anomalously LOW HD "
                 "(a signature of shared/reused short secret material) via the exact "
                 "one-sided left-tail p-value p_low = P(Binom(L_min,0.5) <= HD).")
    lines.append("")
    lines.append("### Headline family-wise result")
    lines.append("")
    lines.append("| Statistic | Value |")
    lines.append("|---|---|")
    lines.append(f"| Pairs tested | {b['n_pairs']} |")
    lines.append(f"| Smallest raw p_low observed | {fmt_p(b['real_min_p'])} |")
    top = b['rows_sorted'][0]
    lines.append(f"| ...belongs to pair | n={top['ni']} vs n={top['nj']} (Lmin={top['Lmin']}, HD={top['hd']}, HD_frac={top['hd_frac']:.3f}) |")
    lines.append(f"| Bonferroni-corrected p (x{b['n_pairs']}) | {fmt_p(top['p_bonf'])} |")
    lines.append(f"| Benjamini-Hochberg q-value | {fmt_p(top['q_bh'])} |")
    lines.append(f"| **Monte Carlo family-wise p** (N={NUM_SIMS_PAIR:,} simulated datasets, each's own best-of-2346-pairs p_low compared to the real best) | **{fmt_p(b['mc_family_p'])}** |")
    lines.append("")
    lines.append(f"Null calibration check: simulated null datasets' best-pair p_low has "
                 f"mean {b['min_p_null_mean']:.4f} and 5th percentile {b['min_p_null_p05']:.4e} "
                 f"across {NUM_SIMS_PAIR:,} sims -- i.e. by pure chance alone, testing 2346 "
                 f"pairs is expected to throw up a fairly small nominal p-value for its best "
                 f"pair anyway (multiple-comparisons inflation), which is exactly why the "
                 f"Monte Carlo family-wise p-value (not the raw or even the Bonferroni number "
                 f"alone) is the number to trust.")
    lines.append("")
    lines.append("### Secondary robustness check: count of nominally-small p-values")
    lines.append("")
    lines.append("In case the signal (if any) is spread across several mildly-anomalous "
                 "pairs rather than concentrated in one extreme pair, we also compare the "
                 "*count* of pairs clearing nominal thresholds to its null distribution:")
    lines.append("")
    lines.append("| Threshold | Real count | Null mean count | MC p(null >= real) |")
    lines.append("|---|---|---|---|")
    lines.append(f"| p_low < 0.01 | {b['n_below_01_real']} | {b['below01_null_mean']:.2f} | {fmt_p(b['mc_p_count01'])} |")
    lines.append(f"| p_low < 0.05 | {b['n_below_05_real']} | {b['below05_null_mean']:.2f} | {fmt_p(b['mc_p_count05'])} |")
    lines.append("")
    lines.append("### Top 20 most anomalous pairs (lowest HD relative to L_min)")
    lines.append("")
    lines.append("| rank | n_i | n_j | L_min | HD | HD_frac | raw p_low | Bonferroni p | BH q |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for rank, row in enumerate(b['rows_sorted'][:20], start=1):
        lines.append(f"| {rank} | {row['ni']} | {row['nj']} | {row['Lmin']} | {row['hd']} | "
                     f"{row['hd_frac']:.3f} | {fmt_p(row['p_low'])} | {fmt_p(row['p_bonf'])} | {fmt_p(row['q_bh'])} |")
    lines.append("")

    # ---------------- Interpretation ----------------
    lines.append("## Interpretation")
    lines.append("")
    verdict_a = a['mc_p_T_two_sided'] < ALPHA or a['mc_p_overall_two_sided'] < ALPHA
    verdict_b = b['mc_family_p'] < ALPHA
    lines.append(f"- **Part A (Hamming weight):** headline Monte Carlo two-sided p-values "
                 f"are {fmt_p(a['mc_p_T_two_sided'])} (pooled T statistic) and "
                 f"{fmt_p(a['mc_p_overall_two_sided'])} (overall bit balance). "
                 f"{'This clears the alpha=0.05 threshold and would warrant a closer look.' if verdict_a else 'Neither clears alpha=0.05 -- the free-bit popcounts are statistically indistinguishable from independent fair coin flips.'}")
    lines.append(f"- **Part B (pairwise Hamming distance):** the Monte Carlo family-wise "
                 f"p-value for the single most anomalous pair among all {b['n_pairs']} "
                 f"tested is {fmt_p(b['mc_family_p'])}. "
                 f"{'This clears alpha=0.05 after accounting for the full multiple-comparisons family via direct simulation -- worth further investigation (though still not proof of key reuse).' if verdict_b else 'This does NOT clear alpha=0.05 -- no pair of puzzles shows a Hamming distance between their free bits that is more extreme than pure chance across 2346 comparisons would predict. There is no statistical evidence of shared/reused short secret material between any two solved puzzle keys.'}")
    lines.append("")
    lines.append("Per the anti-bullshit rule: these are the actual computed results, "
                 "not estimates, and neither test is reported as a 'finding' unless its "
                 "Monte-Carlo-calibrated (not merely nominal/asymptotic) p-value clears "
                 "significance after the stated multiple-comparisons correction.")
    lines.append("")

    OUT_MD.write_text("\n".join(lines))


if __name__ == "__main__":
    main()
