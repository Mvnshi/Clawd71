# Phase 4: Mandatory Walk-Forward Validation

**Task:** For any hypothesis marked `retained` in the Hypotheses phase, run a strict
three-fold walk-forward test — fit on puzzles ≤40, predict/score puzzles 41–50; refit on
≤50, predict 51–60; refit on ≤60, predict 61–70 — and reject any method that fits training
data but shows no out-of-sample edge over a uniform-random baseline.

**Result of the retention check: zero hypotheses were marked `retained`.**

| Hypothesis | Verdict (Phase 2/3) |
|---|---|
| `seq_counter` — raw arithmetic/counter sequence, masked | rejected |
| `lcg` — linear congruential generator | rejected |
| `xorshift_mt` — xorshift / Mersenne Twister PRNG | rejected |
| `hash_chain` — SHA-256/HMAC/BIP32-style hash-chain derivation | **unfalsifiable_from_data_alone** (statistically indistinguishable from uniform; no exploitable structure recovered) |
| `cross_puzzle_persistence` — inter-key bit/byte persistence, mod-k periodicity | rejected |
| `timestamp_creation` — timestamp/block-hash seeding | rejected |

Six candidate generator hypotheses were formalized, implemented, and tested against
explicit Monte Carlo null models (10,000–20,000+ simulated control datasets per test,
matched to the true per-puzzle interval structure `[2^(n-1), 2^n)`), each with multiple-
comparison correction where applicable. Five came back as clean statistical rejections
(all Monte Carlo p-values comfortably above 0.05, several with their own internal
walk-forward checks that already failed to beat a naive midpoint/uniform baseline — see
below). The sixth (`hash_chain`) was not "rejected" in the sense of a failed prediction,
because a cryptographic hash/HMAC construction makes no distinguishing statistical
prediction to test in the first place (distinguishing its output from true randomness
would require breaking SHA-256/HMAC-SHA512 as a PRF) — but it likewise produced **zero**
retained predictive structure and is functionally identical to "no edge" for this
project's purposes. No hypothesis reached the "retained" bar the Hypotheses phase used
(a real, Bonferroni/family-wise-significant deviation from the uniform-interval null).

## Why no new fold-based (≤40→41–50, ≤50→51–60, ≤60→61–70) test was run

The task instructions are explicit and are followed here: *"If NO hypothesis was
retained ... do not manufacture a walk-forward result for hypotheses that were already
rejected."* There is no fitted model, parameter set, or candidate distribution narrower
than uniform to carry forward into a train/test split — every hypothesis's own
best-fit object (a step size, an LCG modulus/multiplier, a PRNG seed, a persistence
coefficient, a timestamp/relation pair) was already shown, on the **full 70-puzzle
dataset**, to perform no better than chance. Formally splitting that already-null result
into three folds would not produce new information; it would only dilute an already
negative finding across smaller samples. Constructing a 3-fold table with placeholder
"predictions" from a rejected/non-existent model would violate the anti-bullshit rule by
implying there is something here to validate.

## Supplementary evidence (not a substitute for the missing formal folds)

Two hypotheses in Phase 2 already included their own internal walk-forward checks as
part of falsification, and these are reproduced here verbatim because they speak
directly to the same question this phase asks (does anything fit on past puzzles predict
future puzzles better than a uniform/midpoint guess), computed on the real, verified
70-puzzle dataset:

| Hypothesis | Internal walk-forward design | Result |
|---|---|---|
| `seq_counter` | Fit modal delta-step on puzzles n=10..N−1, predict puzzle N+1, for N∈{20,30,40,50,60}; compare squared error to naive midpoint (0.5) | Beat baseline in only **2 of 5** splits — a coin flip, no systematic edge |
| `lcg` | 3-consecutive-output LCG state recovery, walk-forward over n=4..69, across 5 candidate moduli (2^8..2^24); compare MSE to 0.5-midpoint baseline | Beat baseline at only **1 of 5** moduli, and only marginally (0.0531 vs 0.0573); **0 exact hits in 132 attempts** |
| `hash_chain` | Four predictors (naive midpoint, running mean, last value, OLS-on-n) fit on puzzles ≤N, scored on N+1, for N=5..69 | Naive midpoint (MSE=0.0736) was the **lowest-error predictor of the four** — nothing built from history beat guessing the interval midpoint |
| `cross_puzzle_persistence` | Lag-1 linear regression of normalized(n+1) on normalized(n), fit at 7 splits (N=10,20,30,40,50,60,65), predict next ≤10 puzzles, compare MSE to 0.5 baseline | Beat baseline in only **2 of 7** splits; fitted slope not even sign-stable across splits (−0.31 at N=10 vs +0.21 at N=40) |
| `timestamp_creation` | Best (timestamp, relation) selected using training puzzles n=2..50 only (full 5.1M-candidate search), evaluated with no further fitting against held-out n=51..70 | **0/20 exact held-out hits**; mean held-out bit-agreement = 0.4861, *below* the 0.5000 chance baseline — the fitted predictor did worse than guessing out of sample |

Every one of these independently-run, differently-designed walk-forward checks reaches
the same conclusion: nothing fit on earlier puzzles carries predictive information into
later puzzles beyond what a coin flip / naive midpoint already provides. This is fully
consistent with, and reinforces, the decision not to run a redundant formal 3-fold split
here.

## Sanity check on the baseline itself (real data, newly computed for this report)

To make sure "uniform baseline" is not just an assumption, the actual walk-forward
folds specified by this task (≤40→41–50, ≤50→51–60, ≤60→61–70) were used to confirm what
a uniform-random guess achieves in this project's own bits-saved metric, using the real,
verified `normalized(n)` values from `data/solved_puzzles.json`. A uniform prior over
`[0,1)` for `normalized(n)` has, by construction, zero expected bits-saved relative to
itself (0 bits of search-space reduction is the reference point every hypothesis was
measured against in Phase 2/3). This was re-confirmed directly:

```
train<= 40: n=10 mean=0.4275 std=0.2182 (uniform ref: mean=0.5, std=0.2887)
train<= 50: n=10 mean=0.6302 std=0.2907 (uniform ref: mean=0.5, std=0.2887)
train<= 60: n=10 mean=0.5664 std=0.2978 (uniform ref: mean=0.5, std=0.2887)
```

(actual output of the script below, run against `data/solved_puzzles.json` on 2026-08-19)

The three held-out folds' means (0.428, 0.630, 0.566) bounce around the uniform
expectation of 0.5 in both directions with no consistent trend, and the standard
deviations (0.218, 0.291, 0.298) are close to (fold 1 somewhat below, folds 2-3 almost
exactly at) the uniform-distribution reference of `1/sqrt(12) ≈ 0.2887` — the fold-1 mean
sitting at 0.43 rather than 0.50 is the ordinary sampling variance of a mean over only 10
uniform draws (a std of ~0.29 over n=10 gives a standard error of the mean of ~0.09, so a
deviation of 0.07 is unremarkable) and is not evidence of structure, since it is exactly
the kind of fluctuation the Monte Carlo nulls in Phase 2/3 (tens of thousands of
independent-uniform 70-puzzle simulations) already showed real data of this size routinely
produces by chance. Critically, there is no candidate model from Phase 2/3 to plug into
these three folds — every hypothesis's own best-fit parameters were already shown, on the
full dataset, to carry no out-of-sample information — so no bits-of-search-space-saved
number can honestly be reported for any method other than 0 (the uniform baseline itself).

## Verdict for Puzzle #71

No generator hypothesis tested in this research program — sequential/arithmetic counter,
linear congruential generator, xorshift/Mersenne-Twister PRNG, hash/HMAC/BIP32 chain,
cross-puzzle bit persistence, or timestamp/block-hash seeding — produced a
statistically-significant, Monte-Carlo-validated deviation from the null model implied by
the puzzle creator's own stated construction (each key drawn uniformly at random within
its forced bit-length interval). Because nothing was retained, this mandatory walk-forward
phase has nothing to validate, and manufacturing fold-by-fold "predictions" from
already-rejected models would misrepresent the state of the evidence. Consistent with
every rejected hypothesis's own internal robustness/walk-forward checks (summarized
above), **the honest, evidence-based conclusion is that no tested candidate generator
beats randomness out-of-sample, and the best available prior for puzzle #71's private key
remains the uniform distribution over `[2^70, 2^71)`** implied directly by the puzzle's
construction — i.e., there is no statistical shortcut through this dataset that narrows
the ~2^70-key search space below its full width, and any attack on puzzle #71 must rely on
brute-force/computational search over the full interval (or on a source of information
outside this dataset), not on a bit-pattern or generator-recovery shortcut.

## Reproducibility

```python
import json, statistics as st

data = json.load(open("/home/user/Clawd71/data/solved_puzzles.json"))
by_n = {d["n"]: d["normalized"] for d in data}

folds = [(40, range(41, 51)), (50, range(51, 61)), (60, range(61, 71))]
for train_max, test_range in folds:
    vals = [by_n[n] for n in test_range if n in by_n]
    print(f"train<= {train_max}: n={len(vals)} mean={st.mean(vals):.4f} "
          f"std={st.pstdev(vals):.4f} (uniform ref: mean=0.5, std={1/12**0.5:.4f})")
```

Output reproduced above under "Sanity check on the baseline itself."

## Source hypothesis/statistics artifacts referenced

- `/home/user/Clawd71/research/hypotheses/seq_counter.py` / `.md`
- `/home/user/Clawd71/research/hypotheses/lcg.py` / `.md`
- `/home/user/Clawd71/research/hypotheses/xorshift_mt.py` / `.md` / `_results.json`
- `/home/user/Clawd71/research/hypotheses/hash_chain.py` / `.md` / `_results.json`
- `/home/user/Clawd71/research/hypotheses/cross_puzzle_persistence.py` / `.md` / `_results.json`
- `/home/user/Clawd71/research/hypotheses/timestamp_creation.py` / `.md` / `_nearby_blocks_cache.json`
- `/home/user/Clawd71/research/stats/bit_frequency_runs.py` / `.md`
- `/home/user/Clawd71/research/stats/hamming_weight_distance.py` / `.md`
- `/home/user/Clawd71/research/stats/modular_diff_recurrence.py` / `.md`
- `/home/user/Clawd71/data/solved_puzzles.json` (70 verified puzzles, ground truth for all of the above)
