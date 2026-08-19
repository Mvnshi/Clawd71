"""Phase 3 - statistical cryptanalysis of the solved-key sequence.

Design rules (anti-numerology):
  * Every statistic is compared against an explicit null model: the offsets
    (key minus the forced leading bit) are iid uniform on [0, 2^(n-1)).
  * p-values that are hard to derive analytically come from Monte Carlo with
    the *same* puzzle-number multiset as the real data, so sample-size effects
    cannot masquerade as signal.
  * Every test in the battery is corrected for multiplicity (Benjamini-Hochberg
    FDR and Holm-Bonferroni FWER). A single p=0.03 among 40 tests is noise.

The question this phase answers is NOT "does anything look interesting" but
"is the effective entropy of puzzle #71 below 70 bits".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from scipy import stats

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RESULTS = ROOT / "results"

MC_TRIALS = 20000
SEED = 20260819


@dataclass
class TestResult:
    name: str
    statistic: float
    pvalue: float
    method: str
    detail: str = ""
    extra: dict = field(default_factory=dict)


def load() -> list[dict]:
    return json.loads((DATA / "solved_puzzles.json").read_text())


def offsets(records: list[dict]) -> list[tuple[int, int]]:
    """(puzzle_number, offset) with offset in [0, 2^(n-1))."""
    return [(r["puzzle"], int(r["offset_dec"])) for r in records]


# ---------------------------------------------------------------------------
# Bit stream helpers
# ---------------------------------------------------------------------------
def offset_bits(n: int, off: int) -> str:
    """Offset rendered as exactly n-1 bits, MSB first (zero padded)."""
    width = n - 1
    return format(off, f"0{width}b") if width > 0 else ""


def concat_bits(data: list[tuple[int, int]]) -> str:
    return "".join(offset_bits(n, off) for n, off in data)


# ---------------------------------------------------------------------------
# Individual tests
# ---------------------------------------------------------------------------
def t_uniformity_ks(data: list[tuple[int, int]]) -> TestResult:
    """Are normalized positions uniform on [0,1)?"""
    u = np.array([off / (1 << (n - 1)) for n, off in data if n >= 6])
    st, p = stats.kstest(u, "uniform")
    return TestResult(
        "normalized position ~ Uniform(0,1) [KS]", st, p, "Kolmogorov-Smirnov",
        f"n={len(u)}, mean={u.mean():.4f} (expected 0.5)",
    )


def t_uniformity_ad(data: list[tuple[int, int]]) -> TestResult:
    u = np.array([off / (1 << (n - 1)) for n, off in data if n >= 6])
    res = stats.anderson(stats.norm.ppf(np.clip(u, 1e-12, 1 - 1e-12)), dist="norm")
    # Convert to a Monte Carlo p-value against the same transform on uniforms.
    rng = np.random.default_rng(SEED)
    null = np.empty(4000)
    for i in range(null.size):
        v = rng.random(u.size)
        null[i] = stats.anderson(stats.norm.ppf(np.clip(v, 1e-12, 1 - 1e-12)), dist="norm").statistic
    p = float((null >= res.statistic).mean())
    return TestResult(
        "normalized position ~ Uniform(0,1) [AD]", float(res.statistic), p,
        "Anderson-Darling, Monte Carlo null", f"n={u.size}",
    )


def t_monobit(data: list[tuple[int, int]]) -> TestResult:
    bits = concat_bits(data)
    ones = bits.count("1")
    n = len(bits)
    st = (ones - n / 2) / np.sqrt(n / 4)
    p = 2 * (1 - stats.norm.cdf(abs(st)))
    return TestResult(
        "monobit frequency over pooled offset bits", float(st), float(p),
        "normal approximation", f"{ones}/{n} ones = {ones / n:.5f}",
    )


def t_runs(data: list[tuple[int, int]]) -> TestResult:
    bits = concat_bits(data)
    n = len(bits)
    pi = bits.count("1") / n
    runs = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i - 1])
    exp = 2 * n * pi * (1 - pi)
    var = 2 * np.sqrt(2 * n) * pi * (1 - pi)
    st = (runs - exp) / var
    p = 2 * (1 - stats.norm.cdf(abs(st)))
    return TestResult(
        "runs test over pooled offset bits", float(st), float(p),
        "NIST SP800-22 runs", f"runs={runs}, expected={exp:.1f}",
    )


def t_bitpos_from_lsb(data: list[tuple[int, int]], max_pos: int = 32) -> list[TestResult]:
    """Bias at each bit position counted from the LSB."""
    out = []
    for pos in range(max_pos):
        vals = [(off >> pos) & 1 for n, off in data if n - 1 > pos]
        if len(vals) < 20:
            continue
        ones = sum(vals)
        p = stats.binomtest(ones, len(vals), 0.5).pvalue
        out.append(
            TestResult(f"bit bias @ LSB+{pos}", ones / len(vals), float(p),
                       "exact binomial", f"{ones}/{len(vals)}")
        )
    return out


def t_bitpos_from_msb(data: list[tuple[int, int]], max_pos: int = 32) -> list[TestResult]:
    """Bias at each bit position counted from the MSB of the offset field."""
    out = []
    for pos in range(max_pos):
        vals = []
        for n, off in data:
            width = n - 1
            if width > pos:
                vals.append((off >> (width - 1 - pos)) & 1)
        if len(vals) < 20:
            continue
        ones = sum(vals)
        p = stats.binomtest(ones, len(vals), 0.5).pvalue
        out.append(
            TestResult(f"bit bias @ MSB-{pos}", ones / len(vals), float(p),
                       "exact binomial", f"{ones}/{len(vals)}")
        )
    return out


def t_hamming_weight(data: list[tuple[int, int]]) -> TestResult:
    """Standardized Hamming weights should be ~N(0,1) in aggregate."""
    z = []
    for n, off in data:
        w = n - 1
        if w < 8:
            continue
        hw = bin(off).count("1")
        z.append((hw - w / 2) / np.sqrt(w / 4))
    z = np.array(z)
    st, p = stats.kstest(z, "norm")
    return TestResult(
        "Hamming weight of offsets ~ Binomial(n-1, 1/2)", float(st), float(p),
        "KS on standardized weights", f"n={z.size}, mean z={z.mean():.3f}",
    )


def t_serial_correlation(data: list[tuple[int, int]]) -> list[TestResult]:
    """Consecutive-puzzle relationships in normalized position."""
    seq = [(n, off / (1 << (n - 1))) for n, off in data if n >= 6]
    # restrict to consecutive puzzle numbers so "adjacency" is real
    pairs = [(seq[i][1], seq[i + 1][1]) for i in range(len(seq) - 1)
             if seq[i + 1][0] == seq[i][0] + 1]
    x = np.array([a for a, _ in pairs])
    y = np.array([b for _, b in pairs])
    out = []
    r, p = stats.pearsonr(x, y)
    out.append(TestResult("lag-1 Pearson corr of normalized position", float(r), float(p),
                          "Pearson", f"{len(pairs)} consecutive pairs"))
    rho, p2 = stats.spearmanr(x, y)
    out.append(TestResult("lag-1 Spearman corr of normalized position", float(rho), float(p2),
                          "Spearman", f"{len(pairs)} consecutive pairs"))
    # lag-2
    pairs2 = [(seq[i][1], seq[i + 2][1]) for i in range(len(seq) - 2)
              if seq[i + 2][0] == seq[i][0] + 2]
    if len(pairs2) > 10:
        r3, p3 = stats.pearsonr(np.array([a for a, _ in pairs2]),
                                np.array([b for _, b in pairs2]))
        out.append(TestResult("lag-2 Pearson corr of normalized position", float(r3), float(p3),
                              "Pearson", f"{len(pairs2)} pairs"))
    return out


def t_increasing_trend(data: list[tuple[int, int]]) -> TestResult:
    """Does normalized position drift with puzzle number?"""
    d = [(n, off / (1 << (n - 1))) for n, off in data if n >= 6]
    x = np.array([n for n, _ in d], float)
    y = np.array([v for _, v in d])
    rho, p = stats.spearmanr(x, y)
    return TestResult("normalized position vs puzzle number (trend)", float(rho), float(p),
                      "Spearman", f"n={len(d)}")


def t_byte_chi2(data: list[tuple[int, int]]) -> TestResult:
    bits = concat_bits(data)
    usable = len(bits) // 8 * 8
    byts = [int(bits[i:i + 8], 2) for i in range(0, usable, 8)]
    counts = np.bincount(byts, minlength=256)
    st, p = stats.chisquare(counts)
    return TestResult("byte-value chi-square over pooled bits", float(st), float(p),
                      "chi-square (255 df)", f"{len(byts)} bytes")


def t_nested_truncation(data: list[tuple[int, int]]) -> TestResult:
    """Falsify 'all puzzles are one master value truncated to different widths'.

    Under that hypothesis key_n mod 2^(m-1) == key_m mod 2^(m-1) for all m < n.
    """
    d = dict(data)
    agree = tot = 0
    examples = []
    ns = sorted(d)
    for i, m in enumerate(ns):
        for n in ns[i + 1:]:
            if m < 4:
                continue
            mask = (1 << (m - 1)) - 1
            tot += 1
            if (d[n] & mask) == (d[m] & mask):
                agree += 1
                examples.append((m, n))
    frac = agree / tot if tot else float("nan")
    return TestResult("nested-truncation hypothesis (single masked master)",
                      frac, 0.0 if agree < tot else 1.0, "exact structural check",
                      f"{agree}/{tot} pairs consistent; hypothesis requires 100%")


def t_lcg_consistency(data: list[tuple[int, int]]) -> TestResult:
    """Test whether full keys satisfy a common LCG modulo small moduli.

    A genuine LCG x_{i+1} = a*x_i + c (mod M) implies, for consecutive triples,
    the determinant relation (x2-x1)*(x3-x2)^-1 constant. Rather than guess M,
    check whether consecutive *differences* share nontrivial common factors far
    more than chance.
    """
    seq = [off for n, off in sorted(data) if n >= 20]
    diffs = [abs(seq[i + 1] - seq[i]) for i in range(len(seq) - 1)]
    import math

    g = 0
    for dv in diffs:
        g = math.gcd(g, dv)
    # Under the null, gcd of many large random differences is 1 w.h.p.
    return TestResult("common divisor of consecutive offset differences", float(g),
                      1.0 if g == 1 else 0.0, "exact gcd",
                      f"gcd={g} over {len(diffs)} differences (null expects 1)")


def t_low_bits_repeat(data: list[tuple[int, int]]) -> TestResult:
    """Do offsets share suspicious low-order bit patterns (e.g. all even)?"""
    out = []
    for k in (1, 2, 3, 4, 8):
        vals = [off & ((1 << k) - 1) for n, off in data if n - 1 >= k]
        counts = np.bincount(vals, minlength=1 << k)
        st, p = stats.chisquare(counts)
        out.append((k, st, p, len(vals)))
    worst = min(out, key=lambda z: z[2])
    return TestResult(f"low {worst[0]}-bit value distribution", float(worst[1]), float(worst[2]),
                      "chi-square", f"n={worst[3]} (most extreme of k=1,2,3,4,8)")


def t_top_bits_repeat(data: list[tuple[int, int]]) -> TestResult:
    """Do offsets cluster in particular sub-blocks of their interval?"""
    out = []
    for k in (1, 2, 3, 4):
        vals = []
        for n, off in data:
            w = n - 1
            if w >= k:
                vals.append(off >> (w - k))
        counts = np.bincount(vals, minlength=1 << k)
        st, p = stats.chisquare(counts)
        out.append((k, st, p, len(vals)))
    worst = min(out, key=lambda z: z[2])
    return TestResult(f"top {worst[0]}-bit block distribution", float(worst[1]), float(worst[2]),
                      "chi-square", f"n={worst[3]} (most extreme of k=1,2,3,4)")


# ---------------------------------------------------------------------------
# Multiplicity correction
# ---------------------------------------------------------------------------
def correct(results: list[TestResult]) -> dict:
    p = np.array([r.pvalue for r in results])
    m = len(p)
    order = np.argsort(p)
    # Holm-Bonferroni
    holm = np.empty(m)
    running = 0.0
    for rank, idx in enumerate(order):
        val = (m - rank) * p[idx]
        running = max(running, val)
        holm[idx] = min(1.0, running)
    # Benjamini-Hochberg
    bh = np.empty(m)
    prev = 1.0
    for rank in range(m - 1, -1, -1):
        idx = order[rank]
        val = p[idx] * m / (rank + 1)
        prev = min(prev, val)
        bh[idx] = min(1.0, prev)
    return {"holm": holm, "bh": bh}


def run_battery() -> tuple[list[TestResult], dict]:
    records = load()
    data = offsets(records)
    results: list[TestResult] = []
    results.append(t_uniformity_ks(data))
    results.append(t_uniformity_ad(data))
    results.append(t_monobit(data))
    results.append(t_runs(data))
    results.append(t_hamming_weight(data))
    results.extend(t_serial_correlation(data))
    results.append(t_increasing_trend(data))
    results.append(t_byte_chi2(data))
    results.append(t_low_bits_repeat(data))
    results.append(t_top_bits_repeat(data))
    results.extend(t_bitpos_from_lsb(data))
    results.extend(t_bitpos_from_msb(data))
    structural = [t_nested_truncation(data), t_lcg_consistency(data)]
    return results, {"structural": structural, "data": data}


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    results, aux = run_battery()
    adj = correct(results)

    print("=" * 96)
    print("PHASE 3 - STATISTICAL BATTERY vs uniform-in-interval null")
    print("=" * 96)
    print(f"{'test':<52}{'stat':>11}{'p':>10}{'p_holm':>10}{'p_BH':>9}")
    print("-" * 96)
    rows = sorted(range(len(results)), key=lambda i: results[i].pvalue)
    for i in rows:
        r = results[i]
        print(f"{r.name:<52}{r.statistic:>11.4f}{r.pvalue:>10.4f}"
              f"{adj['holm'][i]:>10.4f}{adj['bh'][i]:>9.4f}")

    print("\nStructural falsification checks:")
    for r in aux["structural"]:
        print(f"  - {r.name}\n      {r.detail}")

    sig_raw = sum(1 for r in results if r.pvalue < 0.05)
    sig_holm = int((adj["holm"] < 0.05).sum())
    sig_bh = int((adj["bh"] < 0.05).sum())
    print("\n" + "-" * 96)
    print(f"tests run                       : {len(results)}")
    print(f"p<0.05 uncorrected              : {sig_raw}  (expected by chance: {0.05 * len(results):.1f})")
    print(f"significant after Holm (FWER)   : {sig_holm}")
    print(f"significant after BH (FDR 5%)   : {sig_bh}")

    payload = {
        "n_tests": len(results),
        "tests": [
            {"name": r.name, "statistic": r.statistic, "p": r.pvalue,
             "p_holm": float(adj["holm"][i]), "p_bh": float(adj["bh"][i]),
             "method": r.method, "detail": r.detail}
            for i, r in enumerate(results)
        ],
        "structural": [
            {"name": r.name, "statistic": r.statistic, "detail": r.detail}
            for r in aux["structural"]
        ],
        "summary": {"sig_raw": sig_raw, "sig_holm": sig_holm, "sig_bh": sig_bh},
    }
    (RESULTS / "phase3_statistics.json").write_text(json.dumps(payload, indent=2))
    print(f"\nwrote {RESULTS / 'phase3_statistics.json'}")


if __name__ == "__main__":
    main()
