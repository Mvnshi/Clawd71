#!/usr/bin/env python3
"""
Bit-frequency-by-position and runs-test analysis of the "free bits" of the
70 verified/solved Bitcoin puzzle private keys (puzzles #1-70).

Definitions
-----------
For puzzle n, the private key k satisfies k in [2^(n-1), 2^n). Written as an
n-bit binary string, bit position (n-1) (0-indexed from the LSB, i.e. the
MOST significant bit of the n-bit representation) is FORCED to 1 by
construction of the puzzle interval -- it carries zero information and is
excluded from every test below. The remaining (n-1) bits
    lower_bits = key_int - 2^(n-1),  0 <= lower_bits < 2^(n-1)
are, under the puzzle creator's stated generation process ("consecutive
keys from a deterministic wallet"), assumed free/patternless. This script
tests that null hypothesis directly against the data instead of assuming it.

We verified against the dataset that dataset field `binary`[1:] (the key's
binary string with the forced leading '1' stripped) exactly equals
`lower_bits_hex` zero-padded to (n-1) bits, for every puzzle, e.g. n=70:
  binary[1:]                                          == 69-bit zero-padded lower_bits
  '101001001101110000100101101100100001100011010011011000100111011110001'

Free-bit string per puzzle:
  L(n) = n - 1 bits, read MSB-first (i.e. position 0 = the bit immediately
  following the forced leading 1; position L(n)-1 = the key's LSB).
  Puzzle n=1 has L(1)=0 free bits (key=1 is fully forced) and contributes
  nothing.

Concatenated free-bit sequence: free-bit strings for n=1..70, in puzzle
order, concatenated. Total length = sum_{n=1}^{70} (n-1) = sum_{k=0}^{69} k
= 69*70/2 = 2415 bits.

Tests implemented (self-implemented, NIST SP 800-22 style but simplified;
noted explicitly where simplified):
  1. Per-bit-position frequency (chi-square, 1 dof, vs 50/50), for every
     position i where at least MIN_N puzzles reach that depth (L(n) > i).
     Sample size shrinks with i since only larger puzzles have deep bits.
  2. Overall frequency test on the full concatenated sequence.
  3. Runs test (NIST-style Wald-Wolfowitz runs count) on the full
     concatenated sequence, asymptotic p-value via the standard NIST
     formula (erfc based).
  4. Longest-run-of-ones and longest-run-of-zeros in the full concatenated
     sequence (simplified: raw longest run in the single sequence, NOT the
     block-partitioned NIST "Longest Run of Ones in a Block" test).
  5. Omnibus max-chi-square-over-positions statistic, to has a single
     number that already accounts for testing many positions.

Null model / Monte Carlo calibration
-------------------------------------
Because the puzzle intervals themselves force bit (n-1) to be 1 (already
excluded above) and force NOTHING else, the "correct" null model for the
free bits is: for each puzzle n, lower_bits ~ Uniform{0, ..., 2^(n-1)-1}
independently across puzzles. This is exactly what get_null_dataset()
below draws -- i.e. the Monte Carlo null respects the true per-puzzle
interval widths/bit-lengths rather than pretending all puzzles contribute
equal-length or unconstrained data. We simulate NUM_SIMS >= 10000 such
null datasets and, for every statistic above, compute an empirical
Monte Carlo p-value = fraction of simulated datasets whose statistic is
>= (or <=, for symmetric two-sided appropriately) the real, observed
statistic. We also report the classical asymptotic p-values for reference
and note where they agree/disagree with the Monte Carlo calibration.

Multiple-comparison correction
-------------------------------
The ~60 per-position chi-square tests are corrected with both Bonferroni
and Benjamini-Hochberg FDR. The omnibus max-chi-square statistic is
already a single Monte-Carlo-calibrated test that accounts for the
multiplicity of positions by construction (it asks "what's the chance the
*best* of 60 positions looks this skewed by pure luck"), so it needs no
further correction. A final combined Bonferroni correction is also applied
across the small family of headline statistics (overall frequency, runs
count, longest run of ones, longest run of zeros, omnibus max-chi-square)
to produce one family-wise verdict.
"""

import json
import math
import random
import statistics
from collections import Counter

import numpy as np
from scipy import stats as sstats

RNG_SEED = 20260819  # today's date, for reproducibility
NUM_SIMS = 20000      # >= 10000 required; use 20000 for tighter MC resolution
MIN_N_FOR_POSITION_TEST = 10  # need expected cell count >=5 per side for chi2

DATA_PATH = "/home/user/Clawd71/data/solved_puzzles.json"
OUT_MD = "/home/user/Clawd71/research/stats/bit_frequency_runs.md"


# ---------------------------------------------------------------------------
# Data loading / free-bit extraction
# ---------------------------------------------------------------------------

def load_puzzles(path=DATA_PATH):
    with open(path) as f:
        data = json.load(f)
    data.sort(key=lambda e: e["n"])
    assert [e["n"] for e in data] == list(range(1, 71)), "expected puzzles 1..70"
    return data


def free_bits_of(n, lower_bits_int):
    """Return the (n-1)-bit, MSB-first, zero-padded free-bit string."""
    L = n - 1
    if L == 0:
        return ""
    assert 0 <= lower_bits_int < (1 << L), f"lower_bits out of range for n={n}"
    return format(lower_bits_int, f"0{L}b")


def build_real_dataset(puzzles):
    """Return (list_of_per_puzzle_bitstrings, concatenated_bitstring)."""
    per_puzzle = []
    for e in puzzles:
        n = e["n"]
        lb = int(e["lower_bits_hex"], 16) if e["lower_bits_hex"] != "" else 0
        bits = free_bits_of(n, lb)
        # cross-check against the 'binary' field (defense in depth)
        expected = e["binary"][1:] if n > 1 else ""
        assert bits == expected, f"mismatch at n={n}"
        per_puzzle.append(bits)
    concat = "".join(per_puzzle)
    return per_puzzle, concat


def get_null_dataset(rng, lengths):
    """Draw one Monte Carlo null dataset respecting true per-puzzle interval
    widths: for puzzle with L free bits, draw uniformly in [0, 2^L).
    Returns (list_of_per_puzzle_bitstrings, concatenated_bitstring)."""
    per_puzzle = []
    for L in lengths:
        if L == 0:
            per_puzzle.append("")
            continue
        val = rng.getrandbits(L)
        per_puzzle.append(format(val, f"0{L}b"))
    concat = "".join(per_puzzle)
    return per_puzzle, concat


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def position_counts(per_puzzle_bits, max_len):
    """For each position i in [0, max_len), return (n_valid, n_ones)."""
    n_valid = [0] * max_len
    n_ones = [0] * max_len
    for bits in per_puzzle_bits:
        for i, ch in enumerate(bits):
            n_valid[i] += 1
            if ch == "1":
                n_ones[i] += 1
    return n_valid, n_ones


def chi2_stat_1dof(n_ones, n_total):
    """Chi-square goodness-of-fit statistic vs 50/50, 1 dof."""
    if n_total == 0:
        return 0.0
    n_zeros = n_total - n_ones
    expected = n_total / 2.0
    return ((n_ones - expected) ** 2) / expected + ((n_zeros - expected) ** 2) / expected


def runs_count(bitstring):
    if len(bitstring) == 0:
        return 0
    runs = 1
    for a, b in zip(bitstring, bitstring[1:]):
        if a != b:
            runs += 1
    return runs


def longest_run(bitstring, char):
    best = 0
    cur = 0
    for ch in bitstring:
        if ch == char:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def nist_runs_pvalue(bitstring):
    """Standard NIST SP 800-22 runs-test asymptotic p-value.
    Returns (pi, V_obs, p_value, applicable)."""
    n = len(bitstring)
    ones = bitstring.count("1")
    pi = ones / n
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return pi, None, None, False  # pre-test fails; runs test not applicable
    v_obs = runs_count(bitstring)
    denom = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    p = math.erfc(abs(v_obs - 2.0 * n * pi * (1.0 - pi)) / denom)
    return pi, v_obs, p, True


def bh_fdr(pvals):
    """Benjamini-Hochberg adjusted p-values. Returns array same order as input."""
    pvals = np.asarray(pvals)
    n = len(pvals)
    order = np.argsort(pvals)
    ranked = pvals[order]
    adj = ranked * n / (np.arange(n) + 1)
    # enforce monotonicity from the largest down
    adj = np.minimum.accumulate(adj[::-1])[::-1]
    adj = np.clip(adj, 0, 1)
    out = np.empty(n)
    out[order] = adj
    return out


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def main():
    puzzles = load_puzzles()
    lengths = [e["n"] - 1 for e in puzzles]  # free-bit length per puzzle, n=1..70
    per_puzzle_real, concat_real = build_real_dataset(puzzles)
    max_len = max(lengths)  # 69

    N = len(concat_real)
    assert N == sum(lengths) == 2415

    # ---- 1. Per-position frequency (real data) --------------------------
    n_valid, n_ones = position_counts(per_puzzle_real, max_len)
    testable_positions = [i for i in range(max_len) if n_valid[i] >= MIN_N_FOR_POSITION_TEST]

    pos_chi2 = {}
    pos_pval_asym = {}
    for i in testable_positions:
        c2 = chi2_stat_1dof(n_ones[i], n_valid[i])
        pos_chi2[i] = c2
        pos_pval_asym[i] = float(sstats.chi2.sf(c2, df=1))

    # ---- 2. Overall frequency (real) -------------------------------------
    total_ones_real = concat_real.count("1")
    overall_chi2_real = chi2_stat_1dof(total_ones_real, N)
    overall_pval_asym = float(sstats.chi2.sf(overall_chi2_real, df=1))

    # ---- 3. Runs test (real) --------------------------------------------
    pi_real, v_obs_real, runs_pval_asym, runs_applicable = nist_runs_pvalue(concat_real)
    runs_count_real = runs_count(concat_real)

    # ---- 4. Longest runs (real) ------------------------------------------
    lr_ones_real = longest_run(concat_real, "1")
    lr_zeros_real = longest_run(concat_real, "0")

    # ---- 5. Omnibus max-chi2-over-positions (real) ------------------------
    max_chi2_real = max(pos_chi2.values()) if pos_chi2 else 0.0
    argmax_pos_real = max(pos_chi2, key=pos_chi2.get) if pos_chi2 else None

    # -----------------------------------------------------------------
    # Monte Carlo null: simulate NUM_SIMS datasets under the TRUE
    # per-puzzle interval-constrained null (uniform lower_bits per puzzle,
    # correct bit-length per puzzle n), and compute the same statistics.
    # -----------------------------------------------------------------
    rng = random.Random(RNG_SEED)

    sim_overall_chi2 = np.empty(NUM_SIMS)
    sim_runs_count = np.empty(NUM_SIMS)
    sim_lr_ones = np.empty(NUM_SIMS)
    sim_lr_zeros = np.empty(NUM_SIMS)
    sim_max_chi2 = np.empty(NUM_SIMS)
    # per-position chi2 accumulator for MC-calibrated per-position p-values
    sim_pos_chi2_ge = {i: 0 for i in testable_positions}  # count of sims >= real

    for s in range(NUM_SIMS):
        per_puzzle_sim, concat_sim = get_null_dataset(rng, lengths)

        ones_sim = concat_sim.count("1")
        sim_overall_chi2[s] = chi2_stat_1dof(ones_sim, N)

        sim_runs_count[s] = runs_count(concat_sim)
        sim_lr_ones[s] = longest_run(concat_sim, "1")
        sim_lr_zeros[s] = longest_run(concat_sim, "0")

        nv_sim, no_sim = position_counts(per_puzzle_sim, max_len)
        sim_chi2_this = {}
        for i in testable_positions:
            c2 = chi2_stat_1dof(no_sim[i], nv_sim[i])
            sim_chi2_this[i] = c2
            if c2 >= pos_chi2[i]:
                sim_pos_chi2_ge[i] += 1
        sim_max_chi2[s] = max(sim_chi2_this.values()) if sim_chi2_this else 0.0

    # Monte Carlo p-values (one-sided, "as extreme or more" in the
    # direction that matters -- chi2/runs-deviation/longest-run are all
    # "larger = more anomalous")
    def mc_pval_ge(real_stat, sim_array):
        return float((np.sum(sim_array >= real_stat) + 1) / (len(sim_array) + 1))

    mc_p_overall_chi2 = mc_pval_ge(overall_chi2_real, sim_overall_chi2)
    mc_p_max_chi2 = mc_pval_ge(max_chi2_real, sim_max_chi2)

    # runs count and longest runs: deviation from the null median matters in
    # both directions (too few runs = clumping, too many runs = alternation);
    # report two-sided MC p via symmetric extremity.
    def mc_pval_two_sided(real_stat, sim_array):
        med = np.median(sim_array)
        real_dev = abs(real_stat - med)
        sim_dev = np.abs(sim_array - med)
        return float((np.sum(sim_dev >= real_dev) + 1) / (len(sim_array) + 1))

    mc_p_runs = mc_pval_two_sided(runs_count_real, sim_runs_count)
    mc_p_lr_ones = mc_pval_ge(lr_ones_real, sim_lr_ones)
    mc_p_lr_zeros = mc_pval_ge(lr_zeros_real, sim_lr_zeros)

    mc_p_positions = {i: (sim_pos_chi2_ge[i] + 1) / (NUM_SIMS + 1) for i in testable_positions}

    # ---- Multiple comparison correction on per-position asymptotic p ----
    pos_list = sorted(testable_positions)
    asym_p_array = np.array([pos_pval_asym[i] for i in pos_list])
    bonf_p_array = np.clip(asym_p_array * len(pos_list), 0, 1)
    bh_p_array = bh_fdr(asym_p_array)

    min_asym_p = float(asym_p_array.min()) if len(asym_p_array) else 1.0
    min_asym_p_pos = pos_list[int(asym_p_array.argmin())] if len(asym_p_array) else None
    min_bonf_p = float(bonf_p_array.min()) if len(bonf_p_array) else 1.0
    min_bh_p = float(bh_p_array.min()) if len(bh_p_array) else 1.0

    # ---- Family-wise Bonferroni across the 5 headline statistics ----
    headline_mc_pvals = {
        "overall_frequency_chi2": mc_p_overall_chi2,
        "omnibus_max_position_chi2": mc_p_max_chi2,
        "runs_count": mc_p_runs,
        "longest_run_ones": mc_p_lr_ones,
        "longest_run_zeros": mc_p_lr_zeros,
    }
    n_headline = len(headline_mc_pvals)
    headline_bonf = {k: min(1.0, v * n_headline) for k, v in headline_mc_pvals.items()}
    min_headline_mc_p = min(headline_mc_pvals.values())
    min_headline_key = min(headline_mc_pvals, key=headline_mc_pvals.get)

    significant_after_correction = (min_headline_mc_p * n_headline) < 0.05 or (min_bh_p < 0.05)

    # -----------------------------------------------------------------
    # Write results
    # -----------------------------------------------------------------
    lines = []
    lines.append("# Bit-Frequency-by-Position and Runs-Test Analysis")
    lines.append("")
    lines.append("Puzzle #71 research -- statistical test of the null hypothesis that the")
    lines.append("\"free bits\" (private key minus the forced leading bit 2^(n-1)) of solved")
    lines.append("puzzles #1-70 are independent, uniform (fair-coin) bits, as claimed by the")
    lines.append("puzzle creator (\"just consecutive keys from a deterministic wallet\").")
    lines.append("")
    lines.append(f"Generated by `bit_frequency_runs.py`. RNG seed = {RNG_SEED}. "
                  f"Monte Carlo simulations = {NUM_SIMS:,}.")
    lines.append("")
    lines.append("## 1. Data / method")
    lines.append("")
    lines.append(f"- 70 puzzles (n=1..70) loaded from `data/solved_puzzles.json`.")
    lines.append(f"- Free-bit string per puzzle = `lower_bits_hex` as an (n-1)-bit, "
                  f"MSB-first, zero-padded binary string (n=1 contributes 0 bits).")
    lines.append(f"- Cross-checked against the dataset's own `binary` field "
                  f"(`binary[1:]`) for all 70 puzzles: exact match.")
    lines.append(f"- Concatenated free-bit sequence length: **{N} bits** "
                  f"(= sum_{{n=1}}^{{70}} (n-1) = 69*70/2).")
    lines.append(f"- Per-position tests restricted to positions reaching "
                  f"**n_valid >= {MIN_N_FOR_POSITION_TEST}** puzzles "
                  f"(expected cell count >= 5), i.e. positions "
                  f"0..{max(testable_positions)} "
                  f"({len(testable_positions)} positions tested; "
                  f"positions {max(testable_positions)+1}..{max_len-1} skipped, "
                  f"too few puzzles reach that depth).")
    lines.append(f"- Null model for Monte Carlo: for each puzzle n, draw "
                  f"lower_bits ~ Uniform{{0..2^(n-1)-1}} independently -- i.e. "
                  f"the *true* per-puzzle interval width, not a naive "
                  f"fixed-length or unconstrained draw.")
    lines.append("")

    lines.append("## 2. Per-bit-position chi-square (vs 50/50)")
    lines.append("")
    lines.append("Only positions with >= {} puzzles reaching that depth are shown/tested "
                  "(sample size shrinks for deeper positions since early, small puzzles "
                  "have few or zero free bits)."
                  .format(MIN_N_FOR_POSITION_TEST))
    lines.append("")
    lines.append(f"- Most significant single position (raw/uncorrected asymptotic chi2 "
                  f"p-value): position **{min_asym_p_pos}** "
                  f"(chi2={pos_chi2[min_asym_p_pos]:.4f}, "
                  f"n_valid={n_valid[min_asym_p_pos]}, "
                  f"n_ones={n_ones[min_asym_p_pos]}), "
                  f"raw p = {min_asym_p:.4f}.")
    lines.append(f"- Same position, Bonferroni-corrected across "
                  f"{len(pos_list)} tested positions: p = {min_bonf_p:.4f}.")
    lines.append(f"- Same family, Benjamini-Hochberg FDR-adjusted minimum: "
                  f"q = {min_bh_p:.4f}.")
    lines.append(f"- Monte Carlo-calibrated p-value for that same position's chi2 "
                  f"statistic (fraction of {NUM_SIMS:,} true-interval-constrained "
                  f"null simulations producing an equal-or-larger chi2 at that "
                  f"position): p_MC = {mc_p_positions[min_asym_p_pos]:.4f}.")
    lines.append(f"- **Omnibus test** -- max chi2 across all {len(pos_list)} tested "
                  f"positions (this is the statistic that correctly accounts for "
                  f"\"testing many positions and taking the best one\"): "
                  f"observed max chi2 = {max_chi2_real:.4f} at position "
                  f"{argmax_pos_real}; Monte Carlo p-value "
                  f"(fraction of {NUM_SIMS:,} null simulations whose own "
                  f"max-over-positions chi2 is >= observed) = "
                  f"**p_MC = {mc_p_max_chi2:.4f}**.")
    lines.append("")
    lines.append("Full per-position table (first 20 and last 10 tested positions):")
    lines.append("")
    lines.append("| position | n_valid | n_ones | frac_ones | chi2 | asym p | bonf p | BH q | MC p |")
    lines.append("|---:|---:|---:|---:|---:|---:|---:|---:|---:|")

    def fmt_row(i, bonf, bh):
        frac = n_ones[i] / n_valid[i]
        return (f"| {i} | {n_valid[i]} | {n_ones[i]} | {frac:.3f} | "
                f"{pos_chi2[i]:.3f} | {pos_pval_asym[i]:.4f} | {bonf:.4f} | "
                f"{bh:.4f} | {mc_p_positions[i]:.4f} |")

    show_positions = pos_list[:20] + (["..."] if len(pos_list) > 30 else []) + pos_list[-10:]
    seen = set()
    for item in show_positions:
        if item == "...":
            lines.append("| ... | | | | | | | | |")
            continue
        i = item
        if i in seen:
            continue
        seen.add(i)
        idx = pos_list.index(i)
        lines.append(fmt_row(i, bonf_p_array[idx], bh_p_array[idx]))
    lines.append("")

    lines.append("## 3. Overall frequency test (all 2415 free bits pooled)")
    lines.append("")
    lines.append(f"- Total ones = {total_ones_real} / {N} "
                  f"({total_ones_real/N:.4f}); expected under H0 = {N/2:.1f} "
                  f"(0.5000).")
    lines.append(f"- chi2 (1 dof) = {overall_chi2_real:.4f}, asymptotic p = "
                  f"{overall_pval_asym:.4f}.")
    lines.append(f"- Monte Carlo p-value ({NUM_SIMS:,} true-interval-constrained "
                  f"null sims) = **{mc_p_overall_chi2:.4f}**.")
    lines.append("")

    lines.append("## 4. Runs test (NIST SP 800-22 style, on the full 2415-bit "
                  "concatenated sequence)")
    lines.append("")
    lines.append(f"- Proportion of ones (pi) = {pi_real:.4f}.")
    lines.append(f"- Pre-test |pi - 0.5| >= 2/sqrt(n) check: "
                  f"{'FAILS (test not applicable)' if not runs_applicable else 'passes (test applicable)'}.")
    if runs_applicable:
        lines.append(f"- Observed number of runs V_obs = {v_obs_real} "
                      f"(expected under H0 ~ {N/2 + 1:.1f}).")
        lines.append(f"- NIST asymptotic p-value (erfc formula) = {runs_pval_asym:.4f}.")
    lines.append(f"- Monte Carlo p-value for runs count vs the true-interval-"
                  f"constrained null ({NUM_SIMS:,} sims, two-sided extremity "
                  f"around the null median) = **{mc_p_runs:.4f}**.")
    lines.append(f"  - Null runs-count distribution: mean={sim_runs_count.mean():.2f}, "
                  f"sd={sim_runs_count.std():.2f}, "
                  f"median={np.median(sim_runs_count):.1f}, "
                  f"observed={runs_count_real}.")
    lines.append("")

    lines.append("## 5. Longest-run statistics (simplified: single longest run in "
                  "the full concatenated sequence, not the NIST block-partitioned "
                  "variant)")
    lines.append("")
    lines.append(f"- Longest run of 1s observed = {lr_ones_real} bits. "
                  f"Null distribution: mean={sim_lr_ones.mean():.2f}, "
                  f"sd={sim_lr_ones.std():.2f}, "
                  f"95th pct={np.percentile(sim_lr_ones,95):.1f}. "
                  f"Monte Carlo p (>= observed) = **{mc_p_lr_ones:.4f}**.")
    lines.append(f"- Longest run of 0s observed = {lr_zeros_real} bits. "
                  f"Null distribution: mean={sim_lr_zeros.mean():.2f}, "
                  f"sd={sim_lr_zeros.std():.2f}, "
                  f"95th pct={np.percentile(sim_lr_zeros,95):.1f}. "
                  f"Monte Carlo p (>= observed) = **{mc_p_lr_zeros:.4f}**.")
    lines.append("")

    lines.append("## 6. Family-wise verdict")
    lines.append("")
    lines.append("Headline statistics and their Monte Carlo p-values "
                  "(true-interval-constrained null, N={:,} sims each):".format(NUM_SIMS))
    lines.append("")
    lines.append("| statistic | MC p-value | Bonferroni-corrected (x{}) |".format(n_headline))
    lines.append("|---|---:|---:|")
    for k, v in headline_mc_pvals.items():
        lines.append(f"| {k} | {v:.4f} | {headline_bonf[k]:.4f} |")
    lines.append("")
    lines.append(f"Smallest headline MC p-value: **{min_headline_key}** = "
                  f"{min_headline_mc_p:.4f} "
                  f"(Bonferroni x{n_headline} = {min(1.0, min_headline_mc_p*n_headline):.4f}).")
    lines.append("")
    lines.append(f"Smallest per-position result after BH-FDR correction across "
                  f"{len(pos_list)} tested positions: q = {min_bh_p:.4f}.")
    lines.append("")
    lines.append(f"**Overall verdict: "
                  f"{'SIGNIFICANT' if significant_after_correction else 'NOT SIGNIFICANT'} "
                  f"after multiple-comparison correction (alpha=0.05).**")
    lines.append("")
    lines.append("## 7. Interpretation")
    lines.append("")
    if significant_after_correction:
        lines.append("A statistic survived correction -- see above for which one and "
                      "its corrected p-value. Per the anti-bullshit rule, this alone "
                      "is NOT sufficient to claim a usable pattern: it must still be "
                      "checked with a walk-forward test (fit on puzzles <= N, predict "
                      "N+1..M) before it can be used to narrow candidate keys for "
                      "puzzle #71, and even then it only narrows a distribution, it "
                      "does not solve the discrete-log problem.")
    else:
        lines.append("No statistic -- individual bit positions (Bonferroni- or "
                      "BH-corrected), the omnibus max-chi-square-over-positions test, "
                      "overall bit frequency, the runs test, or longest-run-of-ones/"
                      "zeros -- survives multiple-comparison correction at alpha=0.05 "
                      "against a null model that correctly respects each puzzle's "
                      "true interval width. This is consistent with the puzzle "
                      "creator's claim that the keys are unpatterned (masked "
                      "'random-looking' deterministic-wallet output) and gives no "
                      "statistical basis for narrowing the search interval for "
                      "puzzle #71 below the full [2^70, 2^71) range implied by the "
                      "puzzle index alone.")
    lines.append("")
    lines.append("Per the task's anti-bullshit rule: this result (no significant "
                  "deviation from a fair-coin, uniform-in-interval null) is reported "
                  "as-is. A null result is the expected and statistically honest "
                  "outcome here, not a failure of the analysis.")
    lines.append("")

    with open(OUT_MD, "w") as f:
        f.write("\n".join(lines) + "\n")

    # Console summary for the calling harness
    print("=== SUMMARY ===")
    print(f"N free bits = {N}")
    print(f"positions tested = {len(pos_list)} (0..{max(testable_positions)})")
    print(f"min asym p (uncorrected) = {min_asym_p:.6f} at position {min_asym_p_pos}")
    print(f"min bonferroni p (positions) = {min_bonf_p:.6f}")
    print(f"min BH q (positions) = {min_bh_p:.6f}")
    print(f"omnibus max-chi2 = {max_chi2_real:.4f} at position {argmax_pos_real}, MC p = {mc_p_max_chi2:.6f}")
    print(f"overall chi2 = {overall_chi2_real:.4f}, asym p = {overall_pval_asym:.6f}, MC p = {mc_p_overall_chi2:.6f}")
    print(f"runs: V_obs={v_obs_real}, applicable={runs_applicable}, asym p={runs_pval_asym}, MC p={mc_p_runs:.6f}")
    print(f"longest run ones = {lr_ones_real}, MC p = {mc_p_lr_ones:.6f}")
    print(f"longest run zeros = {lr_zeros_real}, MC p = {mc_p_lr_zeros:.6f}")
    print(f"headline min MC p = {min_headline_key} = {min_headline_mc_p:.6f}, bonferroni x{n_headline} = {min(1.0, min_headline_mc_p*n_headline):.6f}")
    print(f"SIGNIFICANT_AFTER_CORRECTION = {significant_after_correction}")


if __name__ == "__main__":
    main()
