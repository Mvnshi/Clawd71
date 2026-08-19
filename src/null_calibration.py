"""Calibrate the walk-forward result against an explicit random null.

The Phase 4 table shows the MSB-aligned bit-bias model at a pooled search
fraction of ~0.43 (p~0.08 uncorrected). The honest question is not "is 0.43
below 0.5" but "how often does the BEST of seven models reach 0.43 or lower
when the keys are known to be uniform random?"

This script answers that by replacing the real keys with uniform random keys
drawn from the same intervals, re-running the identical walk-forward
evaluation, and recording the distribution of each model's pooled mean and of
the best-model-of-seven. Anything the real data achieves that the null matches
routinely is noise.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import numpy as np

import walkforward as wf

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

TRIALS = 200
wf.MC_SAMPLES = 20_000  # accuracy ~0.0035, plenty to resolve 0.43 vs 0.50


def evaluate_dataset(data: list[tuple[int, int]]) -> dict[str, float]:
    """Pooled mean search fraction per model over the standard folds."""
    known = dict(data)
    folds = [
        (40, range(41, 51)),
        (50, range(51, 61)),
        (60, range(61, 71)),
        (45, range(46, 56)),
        (55, range(56, 66)),
        (65, list(range(66, 71)) + [75, 80, 85, 90]),
    ]
    pooled: dict[str, list[float]] = {m.name: [] for m in wf.MODELS}
    for cutoff, test_ns in folds:
        train = [(n, o) for n, o in data if n <= cutoff]
        test = [(n, known[n]) for n in test_ns if n in known]
        if not test:
            continue
        for cls in wf.MODELS:
            model = cls()
            model.fit(train)
            rng = np.random.default_rng(wf.SEED)
            for n, o in test:
                pooled[model.name].append(wf.search_fraction(model, n, o, rng))
    return {k: float(np.mean(v)) for k, v in pooled.items()}


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    real = wf.load()
    observed = evaluate_dataset(real)
    best_observed = min(observed.values())
    print("observed pooled means (real keys):")
    for k, v in sorted(observed.items(), key=lambda kv: kv[1]):
        print(f"  {k:<40} {v:.4f}")
    print(f"\nbest model observed: {best_observed:.4f}\n")

    puzzle_numbers = [n for n, _ in real]
    rnd = random.Random(4242)
    per_model: dict[str, list[float]] = {k: [] for k in observed}
    best_null: list[float] = []

    for t in range(TRIALS):
        synth = [(n, rnd.randrange(1 << (n - 1))) for n in puzzle_numbers]
        res = evaluate_dataset(synth)
        for k, v in res.items():
            per_model[k].append(v)
        best_null.append(min(res.values()))
        if (t + 1) % 20 == 0:
            arr = np.array(best_null)
            print(f"  trial {t + 1:4d}/{TRIALS}  best-of-7 null mean={arr.mean():.4f} "
                  f"p(best<=obs)={float((arr <= best_observed).mean()):.3f}", flush=True)

    out = {"observed": observed, "best_observed": best_observed, "trials": TRIALS,
           "per_model_null": {}, "best_of_seven": {}}
    print("\n" + "=" * 78)
    print(f"{'model':<40}{'observed':>10}{'null mean':>11}{'MC p':>9}")
    print("-" * 78)
    for k in observed:
        arr = np.array(per_model[k])
        p = float((arr <= observed[k]).mean())
        out["per_model_null"][k] = {"null_mean": float(arr.mean()),
                                    "null_sd": float(arr.std()), "mc_p": p}
        print(f"{k:<40}{observed[k]:>10.4f}{arr.mean():>11.4f}{p:>9.3f}")

    arr = np.array(best_null)
    p_best = float((arr <= best_observed).mean())
    out["best_of_seven"] = {"null_mean": float(arr.mean()), "null_sd": float(arr.std()),
                            "mc_p": p_best,
                            "null_q05": float(np.quantile(arr, 0.05))}
    print("-" * 78)
    print(f"{'BEST OF SEVEN MODELS':<40}{best_observed:>10.4f}{arr.mean():>11.4f}{p_best:>9.3f}")
    print(f"\nInterpretation: a random-key dataset produces a best-of-seven pooled mean")
    print(f"of {arr.mean():.4f} on average (sd {arr.std():.4f}). The real data's {best_observed:.4f}")
    print(f"is reached or beaten by pure noise {p_best * 100:.1f}% of the time.")

    (RESULTS / "phase4_null_calibration.json").write_text(json.dumps(out, indent=2))
    print(f"\nwrote {RESULTS / 'phase4_null_calibration.json'}")


if __name__ == "__main__":
    main()
