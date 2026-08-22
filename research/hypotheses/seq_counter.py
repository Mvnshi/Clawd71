#!/usr/bin/env python3
"""
Hypothesis: Bitcoin Puzzle keys come from a literal sequential integer
counter -- i.e. there is a "raw" deterministic-wallet key sequence
raw(n) = base + step*n (or some simple polynomial in n) and the puzzle
setter's "masking" for puzzle n is simply: take the low (n-1) bits of
raw(n) as lower_bits_hex(n), and force bit (n-1) high to land the key in
[2^(n-1), 2^n).

If that's true, then for consecutive puzzles n, n+1 with step s:
    raw(n+1) = raw(n) + s
    L(n+1) mod 2^(n-1) == (L(n) + s) mod 2^(n-1)
i.e. the low (n-1) bits of L(n+1) should equal L(n) plus a SMALL, CONSTANT
step s (the same s for every n), modulo 2^(n-1). Because 2^(n-1) is huge
for n gtr than about 15-20, "mod 2^(n-1)" is a non-event for any
plausible small step -- so under the hypothesis, delta(n) defined below
should literally be the same integer constant s for (almost) all 69
consecutive pairs. Under the null (independent uniform random keys in
each interval, which is what the puzzle creator claims and what a real
HD-wallet child-key derivation via HMAC-SHA512 would produce), delta(n)
is just the difference of two independent (near-)uniform random
integers and will look different for every n, with no shared constant.

This script:
  1. Loads the verified 70-puzzle dataset.
  2. Computes delta(n) = (L(n+1) mod M(n)) - L(n) for every consecutive
     pair, where L(n) = lower_bits_hex(n) as int, M(n) = 2**(n-1).
  3. Also computes the diff2(n) = key_int(n+1) - 2*key_int(n) statistic
     explicitly requested in the task.
  4. Looks for ANY small constant step that repeats across many pairs
     (max-frequency-of-a-repeated-delta statistic).
  5. Tests monotonicity / rank correlation of normalized key position
     vs n (Spearman), and chi-square uniformity of low-order bits.
  6. Builds a Monte Carlo null: N_SIM synthetic 70-puzzle datasets with
     independent-uniform keys in the correct [2**(n-1), 2**n) intervals,
     runs the identical statistics, and reports where the REAL dataset
     falls in that null distribution (empirical two-sided p-values).
  7. Walk-forward test: fit the "best step" on puzzles <= N, use it to
     predict puzzle N+1's normalized position, compare squared error to
     the naive baseline of always guessing 0.5 (interval midpoint).
"""

import json
import math
import random
import statistics
from collections import Counter

random.seed(20260819)  # reproducibility of the Monte Carlo runs

DATA_PATH = "/home/user/Clawd71/data/solved_puzzles.json"
N_SIM = 20000  # Monte Carlo synthetic datasets


def load_data():
    with open(DATA_PATH) as f:
        data = json.load(f)
    data.sort(key=lambda d: d["n"])
    assert [d["n"] for d in data] == list(range(1, 71)), "expected puzzles 1..70"
    return data


def lower_bits_list(data):
    """Return L[n] for n=1..70 as a dict, from lower_bits_hex (or key_int - 2**(n-1))."""
    L = {}
    for d in data:
        n = d["n"]
        Ln = int(d["lower_bits_hex"], 16) if d["lower_bits_hex"] else 0
        # sanity cross-check against key_int
        assert Ln == d["key_int"] - 2 ** (n - 1), f"lower_bits mismatch at n={n}"
        L[n] = Ln
    return L


def key_int_list(data):
    return {d["n"]: d["key_int"] for d in data}


# ---------------------------------------------------------------------------
# Core statistics (applied identically to REAL data and every synthetic sim)
# ---------------------------------------------------------------------------

def compute_deltas(L, nmax=70):
    """delta(n) = (L(n+1) mod 2**(n-1)) - L(n), for n=1..nmax-1."""
    deltas = {}
    for n in range(1, nmax):
        M = 2 ** (n - 1)
        Ln = L[n]
        Ln1 = L[n + 1]
        deltas[n] = (Ln1 % M) - Ln if M > 0 else 0
    return deltas


def compute_diff2(K, nmax=70):
    """diff2(n) = key_int(n+1) - 2*key_int(n), for n=1..nmax-1."""
    return {n: K[n + 1] - 2 * K[n] for n in range(1, nmax)}


def max_repeated_delta_freq(deltas, nmin=10):
    """
    Search for any constant step s that recurs across the most pairs,
    restricted to n >= nmin (skip tiny early puzzles where 2**(n-1) is
    small and near-collisions are common purely by chance / by
    construction of the tiny modulus).
    Returns (best_step, max_count, total_pairs_considered).
    """
    sub = {n: d for n, d in deltas.items() if n >= nmin}
    counts = Counter(sub.values())
    if not counts:
        return None, 0, 0
    best_step, max_count = counts.most_common(1)[0]
    return best_step, max_count, len(sub)


def spearman(xs, ys):
    """Spearman rank correlation (no scipy dependency needed, but use it if present)."""
    try:
        from scipy.stats import spearmanr
        rho, p = spearmanr(xs, ys)
        return rho, p
    except ImportError:
        pass
    # manual fallback
    def rank(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        ranks = [0] * len(v)
        for r, i in enumerate(order):
            ranks[i] = r + 1
        return ranks
    rx, ry = rank(xs), rank(ys)
    n = len(xs)
    d2 = sum((a - b) ** 2 for a, b in zip(rx, ry))
    rho = 1 - (6 * d2) / (n * (n ** 2 - 1))
    return rho, None


def ascent_run_stat(normalized_by_n):
    """Count how many consecutive-n steps are 'ascending' in normalized value."""
    ns = sorted(normalized_by_n)
    vals = [normalized_by_n[n] for n in ns]
    ascents = sum(1 for a, b in zip(vals, vals[1:]) if b > a)
    return ascents, len(vals) - 1


def low_hexdigit_chisquare(K):
    """Chi-square goodness of fit of last hex digit of key_int (n>=8, 16 buckets)."""
    digits = [K[n] % 16 for n in K if n >= 8]
    obs = Counter(digits)
    k = 16
    total = len(digits)
    expected = total / k
    chi2 = sum((obs.get(d, 0) - expected) ** 2 / expected for d in range(k))
    return chi2, total


# ---------------------------------------------------------------------------
# Real-data computation
# ---------------------------------------------------------------------------

def main():
    data = load_data()
    L = lower_bits_list(data)
    K = key_int_list(data)
    normalized = {d["n"]: d["normalized"] for d in data}

    real_deltas = compute_deltas(L)
    real_diff2 = compute_diff2(K)
    real_best_step, real_max_count, real_pairs = max_repeated_delta_freq(real_deltas, nmin=10)

    ns = sorted(normalized)
    xs = [float(n) for n in ns]
    ys = [normalized[n] for n in ns]
    real_rho, real_rho_p = spearman(xs, ys)

    real_ascents, real_total_steps = ascent_run_stat(normalized)

    real_chi2, real_chi2_n = low_hexdigit_chisquare(K)

    print("=" * 78)
    print("REAL DATASET: delta(n) = (L(n+1) mod 2**(n-1)) - L(n), n=1..69")
    print("=" * 78)
    for n in range(1, 70):
        M = 2 ** (n - 1)
        print(f"  n={n:2d} M=2^{n-1:<3d} L(n)={L[n]:<25d} L(n+1) mod M={L[n+1] % M if M else 0:<25d} "
              f"delta={real_deltas[n]}")

    print()
    print(f"Unique delta values across all 69 pairs: {len(set(real_deltas.values()))} / 69")
    print(f"(If hypothesis TRUE with a small constant step, this should be close to 1.)")
    print()
    print(f"Best repeated small step among n>=10 pairs (60 pairs considered): "
          f"step={real_best_step}, appears {real_max_count}/{real_pairs} times")
    print()
    print("diff2(n) = key_int(n+1) - 2*key_int(n), first 10 and stats:")
    diff2_vals = [real_diff2[n] for n in range(1, 70)]
    for n in range(1, 11):
        print(f"  n={n:2d}: diff2={real_diff2[n]}")
    print(f"  mean={statistics.mean(diff2_vals):.3e} stdev={statistics.pstdev(diff2_vals):.3e}")
    print()
    print(f"Spearman rho(n, normalized_key_position) = {real_rho:.4f} "
          f"(p={real_rho_p})" if real_rho_p is not None else
          f"Spearman rho(n, normalized_key_position) = {real_rho:.4f}")
    print(f"Ascending steps in normalized value: {real_ascents}/{real_total_steps} "
          f"({100*real_ascents/real_total_steps:.1f}%, expect ~50% under null)")
    print(f"Chi-square (16 buckets, last hex digit of key_int, n>=8, N={real_chi2_n}): "
          f"chi2={real_chi2:.3f} (df=15, critical value at p=0.05 is 24.996)")

    # -----------------------------------------------------------------
    # Monte Carlo null model
    # -----------------------------------------------------------------
    print()
    print("=" * 78)
    print(f"MONTE CARLO NULL MODEL: {N_SIM} synthetic 70-puzzle datasets")
    print("Each synthetic key n drawn uniformly at random from [2**(n-1), 2**n)")
    print("=" * 78)

    null_unique_delta_counts = []
    null_max_repeat_counts = []
    null_rhos = []
    null_ascent_fracs = []
    null_chi2s = []
    null_diff2_stdevs = []

    # Track, for the "best_step" statistic specifically, how many sims achieve
    # a max_count >= real_max_count (this IS the Monte Carlo p-value for the
    # headline claim "some small step repeats suspiciously often").
    sims_with_repeat_ge_real = 0
    sims_with_unique_le_real = 0
    sims_with_chi2_ge_real = 0
    sims_with_absrho_ge_real = 0

    for sim in range(N_SIM):
        simL = {}
        simK = {}
        prev_norm = {}
        for n in range(1, 71):
            lo = 2 ** (n - 1)
            width = lo  # interval size 2**(n-1) for n>=1 (n=1 -> width 1 -> only key=1)
            if n == 1:
                simK[1] = 1
                simL[1] = 0
                prev_norm[1] = 0.0
                continue
            r = random.getrandbits(n - 1)  # uniform in [0, 2**(n-1))
            simL[n] = r
            simK[n] = lo + r
            prev_norm[n] = r / float(width)

        sim_deltas = compute_deltas(simL)
        sim_diff2 = compute_diff2(simK)
        _, sim_max_count, sim_pairs = max_repeated_delta_freq(sim_deltas, nmin=10)
        null_max_repeat_counts.append(sim_max_count)
        null_unique_delta_counts.append(len(set(sim_deltas.values())))

        sxs = [float(n) for n in range(1, 71)]
        sys_ = [prev_norm[n] for n in range(1, 71)]
        s_rho, _ = spearman(sxs, sys_)
        null_rhos.append(s_rho)

        s_asc, s_tot = ascent_run_stat(prev_norm)
        null_ascent_fracs.append(s_asc / s_tot)

        s_chi2, _ = low_hexdigit_chisquare(simK)
        null_chi2s.append(s_chi2)

        null_diff2_stdevs.append(statistics.pstdev(list(sim_diff2.values())))

        if sim_max_count >= real_max_count:
            sims_with_repeat_ge_real += 1
        if len(set(sim_deltas.values())) <= len(set(real_deltas.values())):
            sims_with_unique_le_real += 1
        if s_chi2 >= real_chi2:
            sims_with_chi2_ge_real += 1
        if abs(s_rho) >= abs(real_rho):
            sims_with_absrho_ge_real += 1

    p_repeat = sims_with_repeat_ge_real / N_SIM
    p_unique = sims_with_unique_le_real / N_SIM
    p_chi2 = sims_with_chi2_ge_real / N_SIM
    p_rho = sims_with_absrho_ge_real / N_SIM

    null_max_repeat_counts.sort()
    null_unique_delta_counts.sort()

    def percentile_rank(sorted_list, value):
        # fraction of null values <= observed value
        import bisect
        return bisect.bisect_right(sorted_list, value) / len(sorted_list)

    print(f"\nStatistic 1: max count of a repeated delta(n) step among n>=10 (60 pairs)")
    print(f"  REAL max_count = {real_max_count} (step={real_best_step})")
    print(f"  NULL max_count: mean={statistics.mean(null_max_repeat_counts):.3f} "
          f"stdev={statistics.pstdev(null_max_repeat_counts):.3f} "
          f"min={null_max_repeat_counts[0]} max={null_max_repeat_counts[-1]}")
    print(f"  Empirical Monte Carlo p-value P(null max_count >= real) = {p_repeat:.5f} "
          f"({sims_with_repeat_ge_real}/{N_SIM})")
    print(f"  Real value sits at the {100*percentile_rank(null_max_repeat_counts, real_max_count):.2f} "
          f"percentile of the null distribution")

    print(f"\nStatistic 2: number of UNIQUE delta(n) values across all 69 pairs")
    print(f"  REAL unique count = {len(set(real_deltas.values()))} / 69")
    print(f"  NULL unique count: mean={statistics.mean(null_unique_delta_counts):.3f} "
          f"stdev={statistics.pstdev(null_unique_delta_counts):.3f} "
          f"min={null_unique_delta_counts[0]} max={null_unique_delta_counts[-1]}")
    print(f"  Empirical Monte Carlo p-value P(null unique <= real) = {p_unique:.5f} "
          f"({sims_with_unique_le_real}/{N_SIM})")

    print(f"\nStatistic 3: |Spearman rho(n, normalized position)|")
    print(f"  REAL rho = {real_rho:.4f}, |rho| = {abs(real_rho):.4f}")
    print(f"  NULL |rho|: mean={statistics.mean([abs(r) for r in null_rhos]):.4f} "
          f"stdev={statistics.pstdev([abs(r) for r in null_rhos]):.4f}")
    print(f"  Empirical Monte Carlo p-value P(null |rho| >= real |rho|) = {p_rho:.5f} "
          f"({sims_with_absrho_ge_real}/{N_SIM})")

    print(f"\nStatistic 4: chi-square uniformity of last hex digit of key_int (n>=8)")
    print(f"  REAL chi2 = {real_chi2:.3f}")
    print(f"  NULL chi2: mean={statistics.mean(null_chi2s):.3f} stdev={statistics.pstdev(null_chi2s):.3f}")
    print(f"  Empirical Monte Carlo p-value P(null chi2 >= real chi2) = {p_chi2:.5f} "
          f"({sims_with_chi2_ge_real}/{N_SIM})")

    print(f"\nAscending-step fraction: REAL={real_ascents}/{real_total_steps} "
          f"({100*real_ascents/real_total_steps:.1f}%)  "
          f"NULL mean={100*statistics.mean(null_ascent_fracs):.1f}% "
          f"stdev={100*statistics.pstdev(null_ascent_fracs):.1f}%")

    # -----------------------------------------------------------------
    # Walk-forward test
    # -----------------------------------------------------------------
    print()
    print("=" * 78)
    print("WALK-FORWARD TEST")
    print("For each split N in {20,30,40,50,60}, fit the modal/most-frequent")
    print("delta(n) step from pairs n=10..N-1, use it to predict normalized")
    print("position of puzzle N+1 from puzzle N's lower bits, and compare")
    print("squared error in NORMALIZED SPACE to the naive baseline (always")
    print("predict normalized = 0.5, the interval midpoint / uniform-prior mean).")
    print("=" * 78)

    for split in [20, 30, 40, 50, 60]:
        fit_deltas = {n: real_deltas[n] for n in range(10, split) if n in real_deltas}
        if not fit_deltas:
            continue
        counts = Counter(fit_deltas.values())
        fit_step, fit_count = counts.most_common(1)[0]

        n_target = split + 1
        M = 2 ** (split - 1)
        predicted_L_next_low = (L[split] + fit_step) % M  # predicted low bits mod 2**(split-1)
        # We only know low (split-1) bits of the prediction; the true value
        # lives in [0, 2**split). Use the predicted low bits directly (top
        # bit unknown -> assume 0, i.e. predicted value = predicted_L_next_low).
        predicted_norm = predicted_L_next_low / float(2 ** split)
        true_norm = normalized[n_target]
        sq_err_model = (predicted_norm - true_norm) ** 2
        sq_err_baseline = (0.5 - true_norm) ** 2

        print(f"  split N={split}: fit_step(mode over {len(fit_deltas)} pairs, "
              f"freq={fit_count}/{len(fit_deltas)})={fit_step}")
        print(f"    predict normalized(n={n_target}) = {predicted_norm:.6f}, "
              f"true = {true_norm:.6f}")
        print(f"    squared error: model={sq_err_model:.6f}  baseline(midpoint 0.5)={sq_err_baseline:.6f}  "
              f"model_beats_baseline={sq_err_model < sq_err_baseline}")

    print()
    print("=" * 78)
    print("SUMMARY")
    print("=" * 78)
    print(f"delta(n) uniqueness: {len(set(real_deltas.values()))}/69 unique values "
          f"(null expects ~{statistics.mean(null_unique_delta_counts):.1f}/69) -> p={p_unique:.5f}")
    print(f"best repeated step frequency: {real_max_count}/{real_pairs} "
          f"(null expects ~{statistics.mean(null_max_repeat_counts):.2f}) -> p={p_repeat:.5f}")
    print(f"rank correlation n vs normalized position: rho={real_rho:.4f} -> p={p_rho:.5f}")
    print(f"low hex-digit uniformity chi2={real_chi2:.3f} -> p={p_chi2:.5f}")


if __name__ == "__main__":
    main()
