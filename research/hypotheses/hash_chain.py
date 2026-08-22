#!/usr/bin/env python3
"""
Hypothesis: Bitcoin Puzzle private keys are produced by a cryptographic
hash / HMAC construction over the puzzle index n (and/or the previous
key), e.g.:

  (a) k_n = SHA256(seed || n) mod range_n                  ["salted hash"]
  (b) k_n = SHA256(k_{n-1}) mod range_n                     ["hash chain"]
  (c) BIP32 non-hardened child derivation:
        child_priv = (parent_priv + HMAC-SHA512(chaincode, parent_pub || n)[:32]) mod secp256k1_order
      restricted to whatever range puzzle n imposes.

All three constructions share one property that matters for THIS
analysis: with an unknown seed/master-key/chaincode, their outputs are
*computationally indistinguishable from independent uniform random
integers in range* under the standard PRF/random-oracle assumption for
SHA-256 / HMAC-SHA512. That is not a hope -- it is the literal security
definition those primitives are built to satisfy. So this hypothesis
class predicts, and can ONLY be tested via, statistical randomness of
the revealed key bits -- there is no seed-recovery attack available
(that would break SHA-256/HMAC-SHA512 as PRFs).

What this script actually does, honestly:
  1. Runs a battery of standard randomness tests on the *verified*
     70-puzzle dataset (bit-frequency-by-position with per-position
     chi-square + Bonferroni correction, serial autocorrelation
     [Pearson + Spearman] between consecutive normalized keys with a
     permutation-test p-value, and a NIST-style runs test on the
     concatenated free-bit sequence).
  2. Builds an explicit Monte Carlo null: many synthetic 70-puzzle
     datasets drawn as independent uniform integers in the *correct*
     puzzle-specific range [2^(n-1), 2^n), i.e. exactly what the
     puzzle-creator's stated construction ("consecutive keys from a
     deterministic wallet, masked to set difficulty") and every hash/
     HMAC-based hypothesis above predict. Compares the REAL dataset's
     test statistics against this null distribution to get Monte Carlo
     p-values -- NOT p-values against a textbook chi-square table alone
     (small-sample-size correctness at high bit positions requires the
     Monte Carlo check, not just the asymptotic chi-square).
  3. States plainly: passing these tests does NOT "confirm" the hash
     hypothesis (indistinguishable-from-random is also what a
     well-seeded LCG deep in its state space or plain uniform sampling
     would look like on 70 points) -- it only shows the data is NOT
     falsifiable as non-random by these tests, which is the expected,
     uninteresting outcome for any hash/HMAC-based generator and is
     explicitly NOT evidence that the private key is predictable.
  4. Does a walk-forward sanity check: no feature derived from puzzles
     <= N can beat the naive interval-midpoint / uniform-prior baseline
     for predicting puzzle N+1, because there is nothing in this
     hypothesis class that would produce such a feature (autocorrelation
     is null by construction of the underlying PRF).
"""

import json
import math
import random
import statistics
from collections import Counter

import numpy as np
from scipy import stats

random.seed(20260819)
np.random.seed(20260819)

DATA_PATH = "/home/user/Clawd71/data/solved_puzzles.json"
N_SIM = 20000          # Monte Carlo control datasets
N_PERM = 20000         # permutation-test resamples for autocorrelation


def load_data():
    with open(DATA_PATH) as f:
        data = json.load(f)
    data.sort(key=lambda r: r["n"])
    assert [r["n"] for r in data] == list(range(1, 71)), "expected puzzles 1..70"
    return data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def free_bits_msb_first(n, lower_bits_int):
    """Return the (n-1) free bits of puzzle n as a list of 0/1 ints,
    MSB (most significant *free* bit) first. n=1 has zero free bits."""
    width = n - 1
    if width == 0:
        return []
    bstr = format(lower_bits_int, f"0{width}b")
    return [int(c) for c in bstr]


def simulate_dataset():
    """Draw one synthetic 70-puzzle dataset under the null: for each n,
    lower_bits ~ Uniform{0, ..., 2**(n-1) - 1} independently -- exactly
    what SHA256(seed||n) mod range, a hash chain, or BIP32 derivation
    all predict when the seed/chaincode is unknown."""
    sim = []
    for n in range(1, 71):
        width = n - 1
        lb = random.getrandbits(width) if width > 0 else 0
        norm = lb / (2 ** width) if width > 0 else 0.0
        sim.append({"n": n, "lower_bits_int": lb, "normalized": norm})
    return sim


# ---------------------------------------------------------------------------
# Test 1: bit-frequency-by-position (from MSB of the free-bit field),
# chi-square goodness of fit per position vs 50/50, Bonferroni corrected.
# ---------------------------------------------------------------------------

def _chi2_1dof_sf(chi2):
    """Upper-tail p-value for a chi-square statistic with 1 degree of
    freedom, computed directly (avoids per-call scipy overhead when this
    runs inside a tight Monte Carlo loop): P(X > chi2) = erfc(sqrt(chi2/2))."""
    if chi2 <= 0:
        return 1.0
    return math.erfc(math.sqrt(chi2 / 2.0))


def bit_frequency_by_position(records, min_support=30):
    """For free-bit position k (0 = MSB of the free bits), pool the bit
    across every puzzle n with enough free bits (n-1 > k), i.e. n >= k+2.
    Only test positions with at least `min_support` samples (chi-square
    is unreliable/underpowered otherwise, and this is disclosed rather
    than silently testing 1-sample positions).

    Each record's free-bit list is computed ONCE (not once per position)
    -- this is the dominant cost when this function is called inside a
    Monte Carlo loop over thousands of synthetic datasets."""
    bits_by_record = [free_bits_msb_first(r["n"], r["lower_bits_int"]) for r in records]
    max_width = max((len(b) for b in bits_by_record), default=0)
    results = []
    for k in range(max_width):
        ones = 0
        support = 0
        for fb in bits_by_record:
            if k < len(fb):
                support += 1
                ones += fb[k]
        if support < min_support:
            continue
        zeros = support - ones
        exp = support / 2.0
        chi2 = ((zeros - exp) ** 2 + (ones - exp) ** 2) / exp
        p = _chi2_1dof_sf(chi2)
        results.append({
            "position_from_msb": k,
            "support": support,
            "ones": ones,
            "zeros": zeros,
            "frac_ones": ones / support,
            "chi2": chi2,
            "p_raw": p,
        })
    n_tests = len(results)
    alpha = 0.05
    bonf_alpha = alpha / n_tests if n_tests else alpha
    for r in results:
        r["p_bonferroni_sig"] = r["p_raw"] < bonf_alpha
    return results, n_tests, bonf_alpha


# ---------------------------------------------------------------------------
# Test 2: serial autocorrelation between consecutive normalized keys.
# ---------------------------------------------------------------------------

def serial_autocorrelation(records, n_perm=N_PERM):
    # exclude n=1 (degenerate: normalized always 0.0, zero free bits)
    norm = [r["normalized"] for r in records if r["n"] >= 2]
    x = np.array(norm[:-1])
    y = np.array(norm[1:])

    pearson_r, pearson_p_asym = stats.pearsonr(x, y)
    spearman_r, spearman_p_asym = stats.spearmanr(x, y)

    # permutation test (shuffle y, recompute |r|, two-sided empirical p)
    rng = np.random.default_rng(20260819)
    obs_abs_pearson = abs(pearson_r)
    obs_abs_spearman = abs(spearman_r)
    count_pearson = 0
    count_spearman = 0
    y_arr = y.copy()
    for _ in range(n_perm):
        rng.shuffle(y_arr)
        rp = np.corrcoef(x, y_arr)[0, 1]
        if abs(rp) >= obs_abs_pearson:
            count_pearson += 1
        rs, _ = stats.spearmanr(x, y_arr)
        if abs(rs) >= obs_abs_spearman:
            count_spearman += 1
    perm_p_pearson = (count_pearson + 1) / (n_perm + 1)
    perm_p_spearman = (count_spearman + 1) / (n_perm + 1)

    return {
        "n_pairs": len(x),
        "pearson_r": pearson_r,
        "pearson_p_asymptotic": pearson_p_asym,
        "pearson_p_permutation": perm_p_pearson,
        "spearman_r": spearman_r,
        "spearman_p_asymptotic": spearman_p_asym,
        "spearman_p_permutation": perm_p_spearman,
    }


# ---------------------------------------------------------------------------
# Test 3: NIST-style runs test on concatenated free-bit sequence.
# ---------------------------------------------------------------------------

def nist_runs_test(records):
    bits = []
    for r in records:
        bits.extend(free_bits_msb_first(r["n"], r["lower_bits_int"]))
    n = len(bits)
    ones = sum(bits)
    pi = ones / n

    # NIST SP 800-22 runs test pre-check
    tau = 2 / math.sqrt(n)
    prereq_ok = abs(pi - 0.5) < tau

    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            runs += 1

    if 0 < pi < 1:
        num = abs(runs - 2 * n * pi * (1 - pi))
        den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
        p_value = math.erfc(num / den) if den > 0 else float("nan")
    else:
        p_value = 0.0  # all-same-bit sequence is maximally non-random

    return {
        "n_bits": n,
        "ones": ones,
        "pi": pi,
        "prereq_ok": prereq_ok,
        "runs": runs,
        "p_value": p_value,
    }


# ---------------------------------------------------------------------------
# Monte Carlo null: repeat all three test statistics on synthetic
# uniform-in-range datasets to get empirical p-values for the summary
# statistics (max chi2 across tested positions, |pearson r|, runs-test
# deviation), not just per-test asymptotic p-values.
# ---------------------------------------------------------------------------

def summary_stats_for_dataset(records):
    bitpos_results, n_tests, bonf_alpha = bit_frequency_by_position(records)
    max_chi2 = max((r["chi2"] for r in bitpos_results), default=0.0)
    n_sig_bonf = sum(1 for r in bitpos_results if r["p_bonferroni_sig"])

    autocorr = serial_autocorrelation(records, n_perm=0) if False else None
    # (cheap Pearson/Spearman only, no inner permutation loop, for MC speed)
    norm = [r["normalized"] for r in records if r["n"] >= 2]
    x = np.array(norm[:-1])
    y = np.array(norm[1:])
    pearson_r = np.corrcoef(x, y)[0, 1]
    spearman_r, _ = stats.spearmanr(x, y)

    runs = nist_runs_test(records)

    return {
        "max_chi2": max_chi2,
        "n_sig_bonf": n_sig_bonf,
        "abs_pearson_r": abs(pearson_r),
        "abs_spearman_r": abs(spearman_r),
        "runs_deviation": abs(runs["runs"] - 2 * runs["n_bits"] * runs["pi"] * (1 - runs["pi"])),
    }


def monte_carlo_null(n_sim=N_SIM):
    stats_list = []
    for _ in range(n_sim):
        sim = simulate_dataset()
        for r in sim:
            r["lower_bits_int"] = r["lower_bits_int"]  # already set
        stats_list.append(summary_stats_for_dataset(sim))
    return stats_list


def mc_p_value(observed, null_values, greater_is_more_extreme=True):
    null_values = np.array(null_values)
    if greater_is_more_extreme:
        count = np.sum(null_values >= observed)
    else:
        count = np.sum(null_values <= observed)
    return (count + 1) / (len(null_values) + 1)


# ---------------------------------------------------------------------------
# Walk-forward test: does anything fit on puzzles <= N beat the naive
# midpoint baseline for predicting puzzle N+1's normalized position?
# ---------------------------------------------------------------------------

def walk_forward(records):
    """For each N from 5..69, using only puzzles 1..N:
       - naive baseline: predict normalized_{N+1} = 0.5
       - 'linear trend' predictor: predict normalized_{N+1} = mean(normalized_1..N)
       - 'last value' predictor (tests simple momentum/autocorrelation):
         predict normalized_{N+1} = normalized_N
       - 'linear regression on n' predictor: fit normalized ~ a + b*n on
         1..N, predict at N+1
       Compare squared error of each vs baseline, aggregate over all N.
    """
    norms = {r["n"]: r["normalized"] for r in records}
    ns = sorted(norms)

    se_baseline, se_mean, se_last, se_linreg = [], [], [], []
    for N in range(5, 70):
        target_n = N + 1
        if target_n not in norms:
            continue
        actual = norms[target_n]
        hist_n = [n for n in ns if n <= N and n >= 2]  # exclude degenerate n=1
        hist_v = [norms[n] for n in hist_n]
        if len(hist_v) < 3:
            continue

        pred_baseline = 0.5
        pred_mean = statistics.mean(hist_v)
        pred_last = norms[N]

        # simple OLS of normalized on n
        xs = np.array(hist_n, dtype=float)
        ys = np.array(hist_v, dtype=float)
        b, a = np.polyfit(xs, ys, 1)  # ys ~ a + b*xs
        pred_linreg = a + b * target_n
        pred_linreg = min(1.0, max(0.0, pred_linreg))

        se_baseline.append((actual - pred_baseline) ** 2)
        se_mean.append((actual - pred_mean) ** 2)
        se_last.append((actual - pred_last) ** 2)
        se_linreg.append((actual - pred_linreg) ** 2)

    return {
        "n_predictions": len(se_baseline),
        "mse_baseline_midpoint": statistics.mean(se_baseline),
        "mse_running_mean": statistics.mean(se_mean),
        "mse_last_value": statistics.mean(se_last),
        "mse_linreg_on_n": statistics.mean(se_linreg),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    data = load_data()
    records = []
    for r in data:
        lb_int = int(r["lower_bits_hex"], 16) if r["lower_bits_hex"] else 0
        records.append({
            "n": r["n"],
            "lower_bits_int": lb_int,
            "normalized": r["normalized"],
        })

    print("=" * 70)
    print("TEST 1: bit-frequency-by-position (MSB-first free bits)")
    print("=" * 70)
    bitpos_results, n_tests, bonf_alpha = bit_frequency_by_position(records)
    print(f"positions tested (support >= 30): {n_tests}")
    print(f"Bonferroni-corrected alpha: {bonf_alpha:.6f}")
    n_sig = sum(1 for r in bitpos_results if r["p_bonferroni_sig"])
    print(f"positions significant after Bonferroni correction: {n_sig} / {n_tests}")
    print(f"{'pos(MSB=0)':>10} {'support':>8} {'ones':>5} {'frac_ones':>10} {'chi2':>8} {'p_raw':>10}")
    for r in bitpos_results:
        print(f"{r['position_from_msb']:>10} {r['support']:>8} {r['ones']:>5} "
              f"{r['frac_ones']:>10.4f} {r['chi2']:>8.4f} {r['p_raw']:>10.4f}")

    print()
    print("=" * 70)
    print("TEST 2: serial autocorrelation between consecutive normalized keys")
    print("=" * 70)
    autocorr = serial_autocorrelation(records)
    for k, v in autocorr.items():
        print(f"{k}: {v}")

    print()
    print("=" * 70)
    print("TEST 3: NIST-style runs test on concatenated free-bit sequence")
    print("=" * 70)
    runs = nist_runs_test(records)
    for k, v in runs.items():
        print(f"{k}: {v}")

    print()
    print("=" * 70)
    print(f"MONTE CARLO NULL ({N_SIM} synthetic uniform-in-range datasets)")
    print("=" * 70)
    observed_summary = summary_stats_for_dataset(records)
    print("observed summary stats:", observed_summary)
    mc_stats = monte_carlo_null(N_SIM)
    mc_max_chi2 = [s["max_chi2"] for s in mc_stats]
    mc_n_sig = [s["n_sig_bonf"] for s in mc_stats]
    mc_abs_pearson = [s["abs_pearson_r"] for s in mc_stats]
    mc_abs_spearman = [s["abs_spearman_r"] for s in mc_stats]
    mc_runs_dev = [s["runs_deviation"] for s in mc_stats]

    p_max_chi2 = mc_p_value(observed_summary["max_chi2"], mc_max_chi2)
    p_n_sig = mc_p_value(observed_summary["n_sig_bonf"], mc_n_sig)
    p_pearson = mc_p_value(observed_summary["abs_pearson_r"], mc_abs_pearson)
    p_spearman = mc_p_value(observed_summary["abs_spearman_r"], mc_abs_spearman)
    p_runs = mc_p_value(observed_summary["runs_deviation"], mc_runs_dev)

    print(f"MC p-value, max chi2 across positions: {p_max_chi2:.4f} "
          f"(observed {observed_summary['max_chi2']:.4f}, "
          f"null mean {np.mean(mc_max_chi2):.4f})")
    print(f"MC p-value, # Bonferroni-significant positions: {p_n_sig:.4f} "
          f"(observed {observed_summary['n_sig_bonf']}, "
          f"null mean {np.mean(mc_n_sig):.4f})")
    print(f"MC p-value, |Pearson r| (consecutive normalized): {p_pearson:.4f} "
          f"(observed {observed_summary['abs_pearson_r']:.4f}, "
          f"null mean {np.mean(mc_abs_pearson):.4f})")
    print(f"MC p-value, |Spearman r| (consecutive normalized): {p_spearman:.4f} "
          f"(observed {observed_summary['abs_spearman_r']:.4f}, "
          f"null mean {np.mean(mc_abs_spearman):.4f})")
    print(f"MC p-value, runs-test deviation: {p_runs:.4f} "
          f"(observed {observed_summary['runs_deviation']:.4f}, "
          f"null mean {np.mean(mc_runs_dev):.4f})")

    print()
    print("=" * 70)
    print("WALK-FORWARD TEST: does anything fit on puzzles <=N beat the naive")
    print("midpoint / uniform-prior baseline for predicting puzzle N+1?")
    print("=" * 70)
    wf = walk_forward(records)
    for k, v in wf.items():
        print(f"{k}: {v}")

    results = {
        "bit_frequency_by_position": bitpos_results,
        "n_tests": n_tests,
        "bonferroni_alpha": bonf_alpha,
        "n_significant_bonferroni": n_sig,
        "autocorrelation": autocorr,
        "runs_test": runs,
        "observed_summary": observed_summary,
        "monte_carlo": {
            "n_sim": N_SIM,
            "p_max_chi2": p_max_chi2,
            "p_n_sig_bonf": p_n_sig,
            "p_abs_pearson": p_pearson,
            "p_abs_spearman": p_spearman,
            "p_runs_deviation": p_runs,
            "null_mean_max_chi2": float(np.mean(mc_max_chi2)),
            "null_mean_n_sig": float(np.mean(mc_n_sig)),
            "null_mean_abs_pearson": float(np.mean(mc_abs_pearson)),
            "null_mean_abs_spearman": float(np.mean(mc_abs_spearman)),
            "null_mean_runs_dev": float(np.mean(mc_runs_dev)),
        },
        "walk_forward": wf,
    }
    with open("/home/user/Clawd71/research/hypotheses/hash_chain_results.json", "w") as f:
        json.dump(results, f, indent=2, default=float)
    print()
    print("Full results written to research/hypotheses/hash_chain_results.json")


if __name__ == "__main__":
    main()
