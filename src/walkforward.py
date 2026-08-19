"""Phase 4 - walk-forward (out-of-sample) validation of predictive models.

The only thing that matters for search-space reduction is whether a model
trained on puzzles <= K concentrates probability on the true key of an unseen
puzzle > K. In-sample fit is worthless here; anything can fit 82 points.

Common metric across all models
-------------------------------
Each model exposes `score(n, candidate) -> float`, higher meaning "search this
candidate earlier". The cost of a model is then

    search_fraction = P[ score(random candidate) > score(true key) ]
                      + 0.5 * P[ score(random candidate) == score(true key) ]

i.e. the expected fraction of the interval scanned before reaching the true key
when candidates are visited in descending score order. Estimated by Monte Carlo
over candidates drawn uniformly from the puzzle's interval.

A useless model scores 0.5. A model that halves the work scores 0.25. A model
that is actively misleading scores > 0.5.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from scipy import stats

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RESULTS = ROOT / "results"

MC_SAMPLES = 200_000
SEED = 20260819


def load() -> list[tuple[int, int]]:
    recs = json.loads((DATA / "solved_puzzles_broad.json").read_text())
    return sorted((r["puzzle"], int(r["offset_dec"])) for r in recs)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class Model:
    name = "base"

    def fit(self, train: list[tuple[int, int]]) -> None:  # pragma: no cover
        raise NotImplementedError

    def score(self, n: int, bits: np.ndarray, u: np.ndarray) -> np.ndarray:
        """bits: (m, n-1) uint8 matrix, MSB-first. u: (m,) normalized position."""
        raise NotImplementedError


class UniformModel(Model):
    name = "uniform (baseline)"

    def fit(self, train):
        pass

    def score(self, n, bits, u):
        return np.zeros(len(u))


class PositionKDE(Model):
    """KDE over historical normalized positions u = offset / 2^(n-1)."""

    name = "KDE of normalized position"

    def fit(self, train):
        u = np.array([off / (1 << (n - 1)) for n, off in train if n >= 6])
        self.kde = stats.gaussian_kde(u) if len(u) > 4 else None

    def score(self, n, bits, u):
        if self.kde is None:
            return np.zeros(len(u))
        return self.kde(u)


class TrendModel(Model):
    """Linear trend of normalized position vs puzzle number; prefer near prediction."""

    name = "linear trend in normalized position"

    def fit(self, train):
        pts = [(n, off / (1 << (n - 1))) for n, off in train if n >= 6]
        x = np.array([p[0] for p in pts], float)
        y = np.array([p[1] for p in pts])
        self.slope, self.intercept = np.polyfit(x, y, 1)
        self.resid = float(np.std(y - (self.slope * x + self.intercept))) or 0.29

    def score(self, n, bits, u):
        pred = self.slope * n + self.intercept
        return -np.abs(u - pred)


class LagModel(Model):
    """Autoregressive: predict this puzzle's position from the previous one."""

    name = "lag-1 autoregression on position"

    def fit(self, train):
        seq = sorted(train)
        pairs = [
            (seq[i][1] / (1 << (seq[i][0] - 1)), seq[i + 1][1] / (1 << (seq[i + 1][0] - 1)))
            for i in range(len(seq) - 1)
            if seq[i + 1][0] == seq[i][0] + 1 and seq[i][0] >= 6
        ]
        x = np.array([p[0] for p in pairs])
        y = np.array([p[1] for p in pairs])
        self.slope, self.intercept = np.polyfit(x, y, 1)
        self.prev = {n: off / (1 << (n - 1)) for n, off in seq}

    def score(self, n, bits, u):
        if (n - 1) not in self.prev:
            return np.zeros(len(u))
        pred = self.slope * self.prev[n - 1] + self.intercept
        return -np.abs(u - pred)


class BitBiasModel(Model):
    """Independent per-bit-position model using empirical bit frequencies.

    Bits are indexed from the MSB of the offset field so that positions are
    comparable across puzzles of different widths.
    """

    name = "per-bit-position bias (MSB-aligned)"
    ALIGN = "msb"

    def fit(self, train):
        counts: dict[int, list[int]] = {}
        for n, off in train:
            w = n - 1
            for pos in range(w):
                bit = (off >> (w - 1 - pos)) & 1 if self.ALIGN == "msb" else (off >> pos) & 1
                c = counts.setdefault(pos, [0, 0])
                c[bit] += 1
        # Laplace smoothing keeps the model from asserting certainty from few samples
        self.p = {
            pos: (c[1] + 1.0) / (c[0] + c[1] + 2.0) for pos, c in counts.items() if sum(c) >= 8
        }

    def score(self, n, bits, u):
        w = n - 1
        total = np.zeros(bits.shape[0])
        for pos, p in self.p.items():
            if pos >= w:
                continue
            col = bits[:, pos] if self.ALIGN == "msb" else bits[:, w - 1 - pos]
            total += np.where(col == 1, np.log(p), np.log(1.0 - p))
        return total


class BitBiasLSB(BitBiasModel):
    name = "per-bit-position bias (LSB-aligned)"
    ALIGN = "lsb"


class HammingModel(Model):
    """Prefer candidates whose Hamming weight matches the historical mean rate."""

    name = "Hamming-weight prior"

    def fit(self, train):
        rates = [bin(off).count("1") / (n - 1) for n, off in train if n >= 10]
        self.rate = float(np.mean(rates))

    def score(self, n, bits, u):
        target = self.rate * (n - 1)
        return -np.abs(bits.sum(axis=1).astype(float) - target)


MODELS = [UniformModel, PositionKDE, TrendModel, LagModel, BitBiasModel, BitBiasLSB, HammingModel]


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
def _to_bits(value: int, w: int) -> np.ndarray:
    return np.array([(value >> (w - 1 - i)) & 1 for i in range(w)], dtype=np.uint8)


def _u_from_bits(bits: np.ndarray) -> np.ndarray:
    """Normalized position in [0,1) from an MSB-first bit matrix."""
    w = bits.shape[1]
    weights = 2.0 ** -np.arange(1, w + 1)
    return bits.astype(float) @ weights


def search_fraction(model: Model, n: int, true_off: int, rng: np.random.Generator) -> float:
    """Fraction of the interval scanned before reaching the true key.

    Candidates are drawn as uniform random bit vectors, which is exactly uniform
    on [0, 2^(n-1)) and avoids Python big-int arithmetic in the inner loop.
    """
    w = n - 1
    if w < 1:
        return 0.5
    m = MC_SAMPLES
    bits = rng.integers(0, 2, size=(m, w), dtype=np.uint8)
    u = _u_from_bits(bits)

    tb = _to_bits(true_off, w).reshape(1, w)
    tu = _u_from_bits(tb)

    s_cand = model.score(n, bits, u)
    s_true = model.score(n, tb, tu)[0]
    greater = float(np.sum(s_cand > s_true))
    equal = float(np.sum(s_cand == s_true))
    return (greater + 0.5 * equal) / m


@dataclass
class FoldResult:
    fold: str
    model: str
    fractions: list[float]
    mean: float


def run_folds() -> list[FoldResult]:
    data = load()
    folds = [
        ("train<=40 -> predict 41-50", 40, range(41, 51)),
        ("train<=50 -> predict 51-60", 50, range(51, 61)),
        ("train<=60 -> predict 61-70", 60, range(61, 71)),
        ("train<=45 -> predict 46-55", 45, range(46, 56)),
        ("train<=55 -> predict 56-65", 55, range(56, 66)),
        ("train<=65 -> predict 66-70+", 65, list(range(66, 71)) + [75, 80, 85, 90]),
    ]
    known = dict(data)
    out: list[FoldResult] = []
    for label, cutoff, test_ns in folds:
        train = [(n, o) for n, o in data if n <= cutoff]
        test = [(n, known[n]) for n in test_ns if n in known]
        if not test:
            continue
        for cls in MODELS:
            model = cls()
            model.fit(train)
            rng = np.random.default_rng(SEED)
            fr = [search_fraction(model, n, o, rng) for n, o in test]
            out.append(FoldResult(label, cls.name, fr, float(np.mean(fr))))
    return out


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    results = run_folds()

    print("=" * 92)
    print("PHASE 4 - WALK-FORWARD VALIDATION")
    print("expected fraction of interval searched before hitting the true key")
    print("0.500 = no better than uniform    <0.500 = genuine reduction    >0.500 = harmful")
    print("=" * 92)

    folds = sorted({r.fold for r in results}, key=lambda f: [r.fold for r in results].index(f))
    model_names = [m.name for m in MODELS]
    print(f"{'model':<38}" + "".join(f"{f.split('->')[1].strip():>15}" for f in folds))
    print("-" * 92)
    by_model: dict[str, list[float]] = {m: [] for m in model_names}
    for m in model_names:
        row = f"{m:<38}"
        for f in folds:
            match = [r for r in results if r.fold == f and r.model == m]
            if match:
                row += f"{match[0].mean:>15.4f}"
                by_model[m].extend(match[0].fractions)
            else:
                row += f"{'-':>15}"
        print(row)

    print("\n" + "-" * 92)
    print(f"{'model':<38}{'pooled mean':>14}{'n':>6}{'vs 0.5 (t-test) p':>20}{'verdict':>14}")
    print("-" * 92)
    summary = {}
    for m in model_names:
        vals = np.array(by_model[m])
        t, p = stats.ttest_1samp(vals, 0.5)
        better = vals.mean() < 0.5 and p < 0.05
        verdict = "USEFUL" if better else "no better"
        print(f"{m:<38}{vals.mean():>14.4f}{len(vals):>6}{p:>20.4f}{verdict:>14}")
        summary[m] = {
            "pooled_mean_search_fraction": float(vals.mean()),
            "n_predictions": int(len(vals)),
            "p_vs_uniform": float(p),
            "useful": bool(better),
        }

    (RESULTS / "phase4_walkforward.json").write_text(
        json.dumps(
            {
                "metric": "expected fraction of interval searched before hitting true key",
                "baseline": 0.5,
                "folds": [
                    {"fold": r.fold, "model": r.model, "mean": r.mean, "fractions": r.fractions}
                    for r in results
                ],
                "summary": summary,
            },
            indent=2,
        )
    )
    useful = [m for m, s in summary.items() if s["useful"]]
    print(f"\nmodels with genuine out-of-sample reduction: {useful if useful else 'NONE'}")
    print(f"wrote {RESULTS / 'phase4_walkforward.json'}")


if __name__ == "__main__":
    main()
