"""Phase 7 - search-space reduction accounting and honest feasibility.

Produces the numbers that decide whether searching is rational:
  * expected keys to hit, and the geometric-distribution confidence interval
  * time to solve at measured local throughput and at plausible GPU throughput
  * the empirical aggregate throughput of the whole puzzle community, inferred
    from the observed solve dates of the consecutively brute-forced puzzles
  * what a candidate ranking would have to achieve to matter
"""

from __future__ import annotations

import datetime as dt
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RESULTS = ROOT / "results"

TARGET_N = 71
SPACE = 1 << (TARGET_N - 1)  # 2^70 candidate keys

# Measured on this machine (4 vCPU Xeon, AVX-512, no GPU) by src/engine.c,
# on an otherwise idle box: 1.16 / 2.31 / 4.51 Mkeys/s at 1 / 2 / 4 threads.
LOCAL_RATE = 4.51e6

# Published throughputs for GPU HASH160 scanning (order-of-magnitude anchors).
GPU_RATES = {
    "1x RTX 4090 (keyhunt/VanitySearch class)": 1.5e9,
    "8x RTX 4090 rig": 1.2e10,
    "1000x RTX 4090 (large pool)": 1.5e12,
}

SECONDS_PER_YEAR = 365.25 * 24 * 3600


def scan_quantile(space: int, q: float) -> float:
    """Keys scanned before hitting, at quantile q, for an exhaustive scan.

    A sequential scan visits every candidate exactly once, so for a uniformly
    placed key the number of keys examined is Uniform{1..space}; the quantile is
    simply q*space. (The geometric distribution would apply to sampling *with*
    replacement, which is strictly worse and not what the engine does.)
    """
    return q * space


def geometric_quantile(p_hit: float, q: float) -> float:
    """Random sampling with replacement; uses log1p to survive tiny p_hit."""
    return math.log1p(-q) / math.log1p(-p_hit)


def community_rate() -> list[dict]:
    """Infer aggregate community search rate from consecutive brute-force solves.

    Puzzle n has 2^(n-1) candidates; the expected work to find a uniformly
    placed key is half that. The gap between successive brute-force solves is
    therefore an estimator of aggregate throughput. Solve times are exponential,
    so single-gap estimates are noisy by design -- we report each separately
    rather than averaging them into false precision.
    """
    dates = {d["puzzle"]: d for d in json.loads((DATA / "solve_dates.json").read_text())}
    bf = sorted(n for n, d in dates.items() if d["method"] == "brute force")
    out = []
    for prev, cur in zip(bf, bf[1:]):
        t0 = dates[prev]["sweep_time"]
        t1 = dates[cur]["sweep_time"]
        gap = t1 - t0
        if gap <= 0:
            continue
        expected_keys = (1 << (cur - 1)) / 2
        out.append({
            "from": prev, "to": cur,
            "from_date": dates[prev]["sweep_date"], "to_date": dates[cur]["sweep_date"],
            "gap_days": gap / 86400,
            "expected_keys": expected_keys,
            "implied_rate_keys_per_s": expected_keys / gap,
        })
    return out


def fmt_time(seconds: float) -> str:
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < SECONDS_PER_YEAR:
        return f"{seconds / 86400:.1f} days"
    y = seconds / SECONDS_PER_YEAR
    if y < 1e3:
        return f"{y:.1f} years"
    if y < 1e6:
        return f"{y / 1e3:.1f} thousand years"
    if y < 1e9:
        return f"{y / 1e6:.1f} million years"
    return f"{y / 1e9:.3g} billion years"


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    report: dict = {}

    print("=" * 88)
    print("PHASE 7 - PUZZLE #71 FEASIBILITY")
    print("=" * 88)
    print(f"interval          : [2^70, 2^71-1]")
    print(f"candidate keys    : 2^70 = {SPACE:,}")
    print(f"public key known  : NO (address has zero outgoing value)")
    print(f"  -> Pollard kangaroo and BSGS are UNAVAILABLE; they need the pubkey.")
    print(f"  -> only generic attack is a HASH160 scan, cost O(2^70), not O(2^35).")
    print()
    report["space"] = SPACE
    report["pubkey_known"] = False

    # --- what a kangaroo attack WOULD cost if the pubkey were exposed --------
    print(f"for contrast, if the pubkey were exposed (it is not):")
    print(f"  kangaroo cost ~ 2^35.5 group ops -> minutes on one GPU")
    print(f"  this is exactly why #75..#135 fell out of order while #71 stands")
    print()

    # --- expected work ------------------------------------------------------
    print("expected work (key uniform in interval, exhaustive scan):")
    print(f"  mean keys to hit        : 2^69 = {SPACE // 2:,}")
    for q in (0.05, 0.50, 0.95):
        v = scan_quantile(SPACE, q)
        print(f"  {int(q * 100):2d}% quantile          : {v:.4g} keys = 2^{math.log2(v):.2f}")
    report["expected_keys"] = SPACE / 2

    # --- local hardware -----------------------------------------------------
    print()
    print(f"this machine (measured): {LOCAL_RATE / 1e6:.2f} Mkeys/s")
    t = (SPACE / 2) / LOCAL_RATE
    print(f"  expected time to solve  : {fmt_time(t)}")
    print(f"  keys scanned per day    : {LOCAL_RATE * 86400:.3g} "
          f"= {LOCAL_RATE * 86400 / SPACE * 100:.2e}% of the space")
    report["local"] = {"rate": LOCAL_RATE, "expected_seconds": t}

    # --- GPU scale ----------------------------------------------------------
    print()
    print("at GPU scale:")
    report["gpu"] = {}
    for label, rate in GPU_RATES.items():
        t = (SPACE / 2) / rate
        print(f"  {label:<42} {fmt_time(t)}")
        report["gpu"][label] = {"rate": rate, "expected_seconds": t}

    # --- empirical community rate ------------------------------------------
    print()
    print("empirical aggregate community throughput, from observed solve gaps:")
    cr = community_rate()
    for r in cr:
        print(f"  #{r['from']} -> #{r['to']}  ({r['from_date']} -> {r['to_date']}, "
              f"{r['gap_days']:6.1f} d)  implies {r['implied_rate_keys_per_s']:.3g} keys/s")
    report["community"] = cr
    rates = [r["implied_rate_keys_per_s"] for r in cr if r["to"] >= 66]
    if rates:
        lo, hi = min(rates), max(rates)
        print(f"\n  recent-era range: {lo:.3g} - {hi:.3g} keys/s")
        print("  expected time for the community to solve #71 at that range:")
        print(f"    fastest estimate : {fmt_time((SPACE / 2) / hi)}")
        print(f"    slowest estimate : {fmt_time((SPACE / 2) / lo)}")
        report["community_range"] = {"low": lo, "high": hi}
        # how long has #71 been the frontier?
        dates = {d["puzzle"]: d for d in json.loads((DATA / "solve_dates.json").read_text())}
        last = max(d["sweep_time"] for n, d in dates.items() if d["method"] == "brute force")
        elapsed = (dt.datetime.now(dt.timezone.utc).timestamp() - last) / 86400
        print(f"\n  #71 has been the open brute-force frontier for {elapsed:.0f} days")
        report["frontier_days"] = elapsed

    # --- what would a ranking have to do? ----------------------------------
    print()
    print("-" * 88)
    print("value of search-space reduction (Phase 4 found none, but for scale):")
    for red in (2, 10, 1000, 1e6):
        t = (SPACE / 2 / red) / LOCAL_RATE
        print(f"  a {red:>9,.0f}x reduction still leaves {fmt_time(t)} on this machine")
    print()
    print("  To bring #71 within one year on this machine you would need a")
    print(f"  {(SPACE / 2) / (LOCAL_RATE * SECONDS_PER_YEAR):.3g}x reduction, i.e. narrowing 2^70 to about")
    print(f"  2^{math.log2(LOCAL_RATE * SECONDS_PER_YEAR):.1f} keys. Phase 4 measured the achievable reduction as 1.0x.")

    (RESULTS / "phase7_feasibility.json").write_text(json.dumps(report, indent=2, default=str))
    print(f"\nwrote {RESULTS / 'phase7_feasibility.json'}")


if __name__ == "__main__":
    main()
