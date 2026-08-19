#!/usr/bin/env python3
"""
Hypothesis: cross-puzzle bit persistence.

Tests whether bit positions or byte patterns in the "free" (post-leading-bit)
portion of key n correlate with the corresponding portion of key n+1, n+2, ...,
and whether the puzzle index n itself predicts the normalized key position
(trend, or periodicity mod 8/16/32).

All statistics are checked against an explicit Monte Carlo null model:
>=10,000 synthetic 70-puzzle datasets, each puzzle n's key drawn independently
and uniformly at random from [2^(n-1), 2^n) (matching the true interval
structure exactly), with p-values computed as the fraction of null datasets
whose statistic is at least as extreme as the real one. A Bonferroni
correction is applied across the family of test statistics.

Deterministic given random.seed / np.random.seed(20260819).
"""

import json
import math
import random
import statistics
from collections import Counter

import numpy as np
from scipy import stats as spstats

random.seed(20260819)
np.random.seed(20260819)

DATA_PATH = "/home/user/Clawd71/data/solved_puzzles.json"
N_MC = 20000  # Monte Carlo synthetic datasets (>= the requested 10000)

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------

with open(DATA_PATH) as f:
    puzzles = json.load(f)

puzzles.sort(key=lambda p: p["n"])
assert [p["n"] for p in puzzles] == list(range(1, 71))

key_int = {p["n"]: p["key_int"] for p in puzzles}
bit_length = {p["n"]: p["bit_length"] for p in puzzles}
lower_bits = {p["n"]: p["key_int"] - 2 ** (p["n"] - 1) for p in puzzles}  # = lower_bits_hex as int
normalized = {p["n"]: p["normalized"] for p in puzzles}

for p in puzzles:
    assert lower_bits[p["n"]] == int(p["lower_bits_hex"], 16) if p["lower_bits_hex"] else lower_bits[p["n"]] == 0
    assert bit_length[p["n"]] == p["n"]  # by construction, puzzle n key in [2^(n-1), 2^n)

Ns = list(range(1, 71))
norm_seq = np.array([normalized[n] for n in Ns])


# ---------------------------------------------------------------------------
# Statistic definitions (applied identically to real data and MC nulls)
# ---------------------------------------------------------------------------

def free_bits_string(n, kint):
    """Free bits of key n: the low (n-1) bits (bit n-1, the forced leading
    bit, is excluded), as a bitstring of length n-1, MSB first."""
    if n == 1:
        return ""
    lb = kint - 2 ** (n - 1)
    return format(lb, f"0{n-1}b")


def hamming_right_justified(n1, kint1, n2, kint2):
    """Compare the low min(bitlen-1) free bits of two keys, right-justified
    (i.e. compare low k bits of lower_bits(n1) and lower_bits(n2), where
    k = min(n1-1, n2-1))."""
    k = min(n1 - 1, n2 - 1)
    if k <= 0:
        return None, 0
    lb1 = (kint1 - 2 ** (n1 - 1)) & ((1 << k) - 1)
    lb2 = (kint2 - 2 ** (n2 - 1)) & ((1 << k) - 1)
    x = lb1 ^ lb2
    return bin(x).count("1"), k


def popcount_free_bits(n, kint):
    if n == 1:
        return 0, 0
    lb = kint - 2 ** (n - 1)
    return bin(lb).count("1"), n - 1


def lag_autocorr(seq, lag):
    a = np.array(seq[:-lag]) if lag > 0 else np.array(seq)
    b = np.array(seq[lag:]) if lag > 0 else np.array(seq)
    if len(a) < 3:
        return 0.0
    if np.std(a) == 0 or np.std(b) == 0:
        return 0.0
    return float(np.corrcoef(a, b)[0, 1])


def mod_k_anova_stat(ns, norm, k):
    """One-way ANOVA F-stat of normalized value grouped by n mod k."""
    groups = {}
    for n, v in zip(ns, norm):
        groups.setdefault(n % k, []).append(v)
    groups = [g for g in groups.values() if len(g) >= 2]
    if len(groups) < 2:
        return 0.0
    try:
        f, p = spstats.f_oneway(*groups)
        if math.isnan(f):
            return 0.0
        return float(f)
    except Exception:
        return 0.0


def compute_all_stats(ns, kints, norm):
    """Compute the full statistic battery for one dataset (real or synthetic).
    ns: list of puzzle indices 1..70 (sorted)
    kints: dict n -> key_int
    norm: dict n -> normalized value (or array aligned with ns)
    Returns a dict of statistic name -> value.
    """
    out = {}

    norm_arr = np.array([norm[n] for n in ns])

    # --- A. n vs normalized correlation (trend) ---
    rho, _ = spstats.spearmanr(ns, norm_arr)
    out["spearman_n_vs_norm"] = abs(rho) if not math.isnan(rho) else 0.0

    pear, _ = spstats.pearsonr(ns, norm_arr)
    out["pearson_n_vs_norm"] = abs(pear) if not math.isnan(pear) else 0.0

    # --- B. lag-k autocorrelation of normalized sequence, lags 1..5 ---
    for lag in range(1, 6):
        out[f"autocorr_lag{lag}"] = abs(lag_autocorr(norm_arr, lag))

    # --- C. periodicity: ANOVA F-stat of normalized grouped by n mod {8,16,32} ---
    for k in (8, 16, 32):
        out[f"anova_F_mod{k}"] = mod_k_anova_stat(ns, norm_arr, k)

    # --- D. Hamming distance between consecutive keys' free bits (right-justified) ---
    hd_fracs = []
    for i in range(len(ns) - 1):
        n1, n2 = ns[i], ns[i + 1]
        hd, k = hamming_right_justified(n1, kints[n1], n2, kints[n2])
        if hd is not None and k > 0:
            hd_fracs.append(hd / k)
    hd_fracs = np.array(hd_fracs)
    mean_hd_frac = float(np.mean(hd_fracs)) if len(hd_fracs) else 0.5
    # statistic: deviation of mean Hamming fraction from 0.5 (two-sided)
    out["hamming_meanfrac_dev"] = abs(mean_hd_frac - 0.5)
    out["hamming_meanfrac"] = mean_hd_frac

    # --- E. Hamming weight (popcount) of free bits vs expected k/2 per key ---
    # aggregate z-like statistic: sum over keys of (popcount - k/2) / sqrt(k/4),
    # then take the mean absolute standardized deviation, and also a pooled
    # binomial test statistic (total ones vs total free bits).
    total_ones = 0
    total_free = 0
    per_key_z = []
    for n in ns:
        pc, k = popcount_free_bits(n, kints[n])
        if k > 0:
            total_ones += pc
            total_free += k
            z = (pc - k / 2.0) / math.sqrt(k / 4.0)
            per_key_z.append(z)
    out["popcount_pooled_frac"] = total_ones / total_free if total_free else 0.5
    out["popcount_pooled_dev"] = abs(out["popcount_pooled_frac"] - 0.5)
    out["popcount_mean_abs_z"] = float(np.mean(np.abs(per_key_z))) if per_key_z else 0.0

    # --- F. bit-position persistence: for each free-bit position (aligned by
    # LSB, i.e. bit offset from the right), correlate bit value at position j
    # across consecutive puzzles where both have >= j+1 free bits. We
    # summarize with the max |correlation| across positions 0..20 (low bits,
    # where sample size across n=1..70 is largest) as the headline statistic,
    # analogous to "does some bit position's value in key n predict the same
    # position in key n+1".
    max_bitpos_corr = 0.0
    bitpos_corrs = []
    for j in range(0, 20):  # bit offset from LSB of the free-bits field
        cur = []
        nxt = []
        for i in range(len(ns) - 1):
            n1, n2 = ns[i], ns[i + 1]
            k1 = n1 - 1
            k2 = n2 - 1
            if k1 > j and k2 > j:
                lb1 = kints[n1] - 2 ** (n1 - 1)
                lb2 = kints[n2] - 2 ** (n2 - 1)
                b1 = (lb1 >> j) & 1
                b2 = (lb2 >> j) & 1
                cur.append(b1)
                nxt.append(b2)
        if len(cur) >= 15 and np.std(cur) > 0 and np.std(nxt) > 0:
            c = np.corrcoef(cur, nxt)[0, 1]
            if not math.isnan(c):
                bitpos_corrs.append(abs(c))
    out["max_bitpos_corr"] = max(bitpos_corrs) if bitpos_corrs else 0.0
    out["mean_bitpos_corr"] = float(np.mean(bitpos_corrs)) if bitpos_corrs else 0.0

    # --- G. lag-2..5 Hamming distance fraction deviation (generalizes D) ---
    for lag in (2, 3, 4, 5):
        fracs = []
        for i in range(len(ns) - lag):
            n1, n2 = ns[i], ns[i + lag]
            hd, k = hamming_right_justified(n1, kints[n1], n2, kints[n2])
            if hd is not None and k > 0:
                fracs.append(hd / k)
        mf = float(np.mean(fracs)) if fracs else 0.5
        out[f"hamming_lag{lag}_dev"] = abs(mf - 0.5)

    return out


# ---------------------------------------------------------------------------
# Real-data statistics
# ---------------------------------------------------------------------------

real_stats = compute_all_stats(Ns, key_int, normalized)

print("=== REAL DATA STATISTICS ===")
for k, v in real_stats.items():
    print(f"{k}: {v:.6f}")

# ---------------------------------------------------------------------------
# Monte Carlo null model
# ---------------------------------------------------------------------------

print(f"\n=== RUNNING {N_MC} MONTE CARLO SIMULATIONS ===")

stat_names = list(real_stats.keys())
null_values = {k: np.empty(N_MC) for k in stat_names}

for sim in range(N_MC):
    synth_kint = {}
    for n in Ns:
        lo = 2 ** (n - 1)
        if n == 1:
            synth_kint[n] = 1
        else:
            # lower_bits uniform in [0, 2^(n-1)) via Python's arbitrary-precision
            # random.getrandbits -- numpy's randint cannot handle >64-bit ranges.
            synth_kint[n] = lo + random.getrandbits(n - 1)
    synth_norm = {n: (synth_kint[n] - 2 ** (n - 1)) / (2 ** (n - 1)) if n > 1 else 0.0 for n in Ns}
    s = compute_all_stats(Ns, synth_kint, synth_norm)
    for k in stat_names:
        null_values[k][sim] = s[k]
    if (sim + 1) % 5000 == 0:
        print(f"  ...{sim+1}/{N_MC} done")

# ---------------------------------------------------------------------------
# P-values (one-sided: fraction of null >= real, for "how extreme" stats;
# for popcount_pooled_frac and hamming_meanfrac we use two-sided deviation
# from 0.5 versions already, so all of these are "larger = more extreme")
# ---------------------------------------------------------------------------

# statistics where "larger magnitude" = more extreme (all of ours except the
# raw fraction values, which are informational only, not tested directly)
tested_stats = [k for k in stat_names if not k.endswith("_frac") and not k.endswith("_pooled_frac") and k != "hamming_meanfrac"]

pvals = {}
for k in tested_stats:
    real_v = real_stats[k]
    null_arr = null_values[k]
    pvals[k] = float(np.mean(null_arr >= real_v))

n_tests = len(tested_stats)
bonferroni_alpha = 0.05 / n_tests

print(f"\n=== MONTE CARLO P-VALUES ({n_tests} tests, Bonferroni alpha = {bonferroni_alpha:.6f}) ===")
sorted_by_p = sorted(pvals.items(), key=lambda kv: kv[1])
for k, p in sorted_by_p:
    null_mean = float(np.mean(null_values[k]))
    null_std = float(np.std(null_values[k]))
    sig = " <-- SIGNIFICANT after Bonferroni" if p < bonferroni_alpha else ""
    print(f"{k:28s} real={real_stats[k]:.5f}  null_mean={null_mean:.5f}  null_std={null_std:.5f}  p={p:.5f}{sig}")

min_stat, min_p = sorted_by_p[0]
print(f"\nMost extreme statistic: {min_stat}  p={min_p:.5f}  (Bonferroni-corrected threshold {bonferroni_alpha:.6f})")

# ---------------------------------------------------------------------------
# Family-wise Monte Carlo correction (exact, accounts for correlation between
# the 19 test statistics -- more powerful and more honest than Bonferroni,
# which assumes independence). For each of the N_MC synthetic datasets,
# compute that dataset's own per-statistic p-value against the *same* null
# distribution used for the real data, then take the min p across statistics
# for that synthetic dataset. This produces a null distribution of "best of
# 19 tests" p-values; the real data's min-p is judged against THAT
# distribution, giving an exact family-wise Monte Carlo p-value.
# ---------------------------------------------------------------------------

print("\n=== FAMILY-WISE MONTE CARLO CORRECTION (best-of-19-tests null) ===")

p_matrix = np.empty((n_tests, N_MC))
for ti, k in enumerate(tested_stats):
    v = null_values[k]
    sorted_v = np.sort(v)
    counts_ge = N_MC - np.searchsorted(sorted_v, v, side="left")
    p_matrix[ti, :] = counts_ge / N_MC

min_p_null = p_matrix.min(axis=0)  # null distribution of "best of 19 tests" p-value
global_p = float(np.mean(min_p_null <= min_p))

print(f"Real data's min p-value across {n_tests} tests: {min_p:.5f} (stat: {min_stat})")
print(f"Null distribution of min-p-across-{n_tests}-tests: mean={np.mean(min_p_null):.5f}, "
      f"median={np.median(min_p_null):.5f}, 5th pct={np.percentile(min_p_null,5):.5f}")
print(f"Family-wise Monte Carlo p-value (fraction of null sims whose OWN best-of-{n_tests} "
      f"result is at least as extreme as the real data's): p = {global_p:.5f}")

# ---------------------------------------------------------------------------
# Walk-forward test: does lag-1 autocorrelation (the natural "persistence"
# predictor) beat the naive midpoint (0.5) baseline for predicting
# normalized(n+1) from normalized(n)?
# ---------------------------------------------------------------------------

print("\n=== WALK-FORWARD TEST (lag-1 persistence predictor vs. midpoint baseline) ===")

wf_rows = []
for split in [10, 20, 30, 40, 50, 60, 65]:
    fit_ns = [n for n in Ns if n <= split]
    fit_norm = [normalized[n] for n in fit_ns]
    # Fit: linear regression of normalized(n+1) on normalized(n) using n <= split
    xs, ys = [], []
    for i in range(len(fit_ns) - 1):
        xs.append(normalized[fit_ns[i]])
        ys.append(normalized[fit_ns[i + 1]])
    if len(xs) >= 3 and np.std(xs) > 0:
        slope, intercept, r, p, se = spstats.linregress(xs, ys)
    else:
        slope, intercept = 0.0, 0.5

    # predict for all n+1 in (split, min(split+10,70)]
    model_sq_errs = []
    base_sq_errs = []
    for n in Ns:
        if n > split and n <= min(split + 10, 70) and (n - 1) in normalized:
            pred = slope * normalized[n - 1] + intercept
            true = normalized[n]
            model_sq_errs.append((pred - true) ** 2)
            base_sq_errs.append((0.5 - true) ** 2)
    if model_sq_errs:
        mse_model = float(np.mean(model_sq_errs))
        mse_base = float(np.mean(base_sq_errs))
        wf_rows.append((split, slope, intercept, mse_model, mse_base, mse_model < mse_base))
        print(f"split N={split:2d}  slope={slope:+.4f} intercept={intercept:.4f}  "
              f"MSE_model={mse_model:.5f}  MSE_baseline={mse_base:.5f}  "
              f"beats_baseline={mse_model < mse_base}")

n_wins = sum(1 for r in wf_rows if r[5])
print(f"\nWalk-forward: model beats baseline in {n_wins}/{len(wf_rows)} splits")

# ---------------------------------------------------------------------------
# Save full results JSON
# ---------------------------------------------------------------------------

results = {
    "n_mc": N_MC,
    "real_stats": real_stats,
    "null_mean": {k: float(np.mean(v)) for k, v in null_values.items()},
    "null_std": {k: float(np.std(v)) for k, v in null_values.items()},
    "pvalues": pvals,
    "n_tests": n_tests,
    "bonferroni_alpha": bonferroni_alpha,
    "most_extreme_stat": min_stat,
    "most_extreme_p": min_p,
    "family_wise_mc_p": global_p,
    "min_p_null_mean": float(np.mean(min_p_null)),
    "min_p_null_median": float(np.median(min_p_null)),
    "walk_forward": [
        {"split": r[0], "slope": r[1], "intercept": r[2], "mse_model": r[3],
         "mse_baseline": r[4], "beats_baseline": r[5]}
        for r in wf_rows
    ],
    "walk_forward_wins": n_wins,
    "walk_forward_total": len(wf_rows),
}

with open("/home/user/Clawd71/research/hypotheses/cross_puzzle_persistence_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("\nResults saved to cross_puzzle_persistence_results.json")
