# Hypothesis: Sequential/Arithmetic Counter in the "Deterministic Wallet"

**Status: REJECTED** (falsified by direct test against 70 verified keys, confirmed
against a Monte Carlo random-key null model)

Script: `research/hypotheses/seq_counter.py` (deterministic given `random.seed(20260819)`,
runtime ~4s for the full 20,000-iteration Monte Carlo on this machine).

## Hypothesis being tested

The puzzle creator states the keys are "consecutive keys from a deterministic
wallet (masked with leading 000...0001 to set difficulty)." Taken literally,
this could mean there exists a "raw" arithmetic sequence

```
raw(n) = base + step * n        (step small, e.g. 1)
```

and that "masking to set difficulty" for puzzle `n` means: take the low
`n-1` bits of `raw(n)` unchanged, and force bit `n-1` high, landing the key
in `[2^(n-1), 2^n)`. If so, the **low bits should be literally carried
forward** from one puzzle to the next, offset by a small constant step.

## Why this is testable directly (the math)

If `L(n) = lower_bits_hex(n)` as an integer, and `M(n) = 2^(n-1)`, then under
the hypothesis:

```
L(n) = raw(n) mod M(n)
raw(n+1) = raw(n) + step
=> L(n+1) mod M(n) = (L(n) + step) mod M(n)
```

Define `delta(n) = (L(n+1) mod M(n)) - L(n)`. Under the hypothesis, `delta(n)`
should equal the **same constant `step`** for (almost) every one of the 69
consecutive pairs (`M(n)` is astronomically larger than any plausible small
step once `n` gtr 15 or so, so wraparound is a non-issue at that point — if the
hypothesis were true we'd see the *exact same integer* recur roughly 55-60
times out of the ~60 pairs with `n>=10`). This gives a strong, sharp,
directly falsifiable prediction, not a fuzzy "does it fit" check.

We also computed the diff2(n) = `key_int(n+1) - 2*key_int(n)` statistic
requested explicitly in the task (a related but distinct linear combination),
Spearman rank correlation of puzzle index `n` vs. `normalized` key position,
an ascending/descending run count, and a chi-square test of the last hex
digit of `key_int` for uniformity.

## Real-data results

Full per-pair table is in the script output; representative rows:

| n | L(n) | L(n+1) mod 2^(n-1) | delta(n) |
|---|---|---|---|
| 10 | 2 | 131 | 129 |
| 20 | 339029 | 238900 | -100129 |
| 30 | 496291172 | 491775815 | -4515357 |
| 40 | 453895599062 | 358740577371 | -95155021691 |
| 50 | 48190542746452 | 369919654889940 | 321729112143488 |
| 60 | 558580597916072894 | 272866038011808006 | -285714559904264888 |
| 69 | 2126586741023079948 | 84993258466965212913 | 82866671725942132965 |

Key findings:

- **Unique delta values: 68 out of 69.** Under a true arithmetic-sequence
  hypothesis we would expect ~1 unique value (all deltas equal to `step`).
  68/69 is essentially "every pair has its own unrelated delta" — indistinguishable
  from noise.
- **Best repeated constant step among the 60 pairs with n>=10: appears only
  1 time out of 60** (i.e. literally *no* integer step repeats even twice).
  This is the direct, comprehensive test of "does ANY small/large constant
  step fit more than one consecutive pair" — searched over every value that
  actually occurred as a delta (which covers all candidate steps by
  construction) — and the answer is **no step fits more than a single pair**.
- `diff2(n) = key_int(n+1) - 2*key_int(n)`: values swing from `+1` (n=1,
  trivial) to magnitudes like `+130,170,630,125` (n=39) and `-1,956,411,295,493,072`
  (n=52) — full expected O(2^n) magnitude and both signs, no small/structured values.
- Spearman rho(n, normalized position) = **0.1814** (weak, and — per the Monte
  Carlo below — well within the range random data produces).
- Ascending steps in normalized value: 39/69 (56.5%) vs. 50% expected under
  pure randomness — a small, not-significant excursion.
- Chi-square (16 buckets, last hex digit of `key_int`, n>=8, N=63):
  **chi2 = 17.000** (df=15; critical value at p=0.05 is 24.996 — not
  significant on its own, and confirmed unremarkable by the null below).

## Monte Carlo null model

20,000 synthetic 70-puzzle datasets were generated, each puzzle `n`'s key
drawn **independently uniformly at random** from `[2^(n-1), 2^n)` (exactly
matching the real interval structure), and the identical statistics computed
on each synthetic dataset.

| Statistic | Real value | Null mean ± stdev | Monte Carlo p-value |
|---|---|---|---|
| Max repeated-delta frequency (n>=10, 60 pairs) | 1 | 1.003 ± 0.056 | **p = 1.000** (20000/20000 null sims >= real) |
| Unique delta count (out of 69) | 68 | 67.53 ± 0.87 | **p = 0.880** (fraction of null sims with unique <= real) |
| \|Spearman rho(n, normalized)\| | 0.1814 | 0.1145 ± 0.0828 | **p = 0.209** |
| Chi-square, last hex digit | 17.000 | 14.97 ± 5.44 | **p = 0.322** |
| Ascending-step fraction | 56.5% | 50.0% ± 3.5% | consistent with null (< 2 sigma) |

Every single statistic computed on the real dataset falls squarely inside
the distribution produced by pure independent-uniform-random keys. The
headline statistic — "does any constant step recur across consecutive
pairs" — is as far from the arithmetic-sequence prediction as possible: the
real data ties the null's modal outcome (a step recurring exactly once,
i.e., never recurring at all) precisely.

## Walk-forward test

Fit the modal `delta(n)` step from pairs `n=10..N-1`, use it to predict
puzzle `N+1`'s normalized position, and compare squared error to the naive
baseline of guessing the interval midpoint (`normalized = 0.5`):

| Split N | Fit step | Predicted norm(N+1) | True norm(N+1) | Model SqErr | Baseline SqErr | Model beats baseline? |
|---|---|---|---|---|---|---|
| 20 | 129 | 0.3234 | 0.7278 | 0.1635 | 0.0519 | No |
| 30 | 129 | 0.4622 | 0.9580 | 0.2458 | 0.2098 | No |
| 40 | 129 | 0.4128 | 0.3263 | 0.0075 | 0.0302 | Yes |
| 50 | 129 | 0.0428 | 0.8286 | 0.6174 | 0.1079 | No |
| 60 | 129 | 0.4845 | 0.2367 | 0.0614 | 0.0693 | Yes |

The model "wins" 2 of 5 splits — a coin flip, exactly what a spurious fitted
constant (the modal step here, 129, was already only a 1-of-10-or-more
tie-broken artifact, not a real repeating pattern) would produce by chance.
No systematic edge over the naive midpoint guess.

## Verdict

**Rejected.** There is no detectable arithmetic-sequence / small-constant-step
relationship between consecutive puzzle keys' low bits, key_int values, or
any simple linear combination thereof. Every statistic tested lands squarely
within the distribution generated by a pure independent-uniform-random-key
null model (all Monte Carlo p-values in the 0.2-1.0 range — nowhere near a
conventional significance threshold, and several essentially at the null's
own median). The walk-forward fit does not beat the naive midpoint baseline
on net. This is fully consistent with the puzzle creator's stated claim
("no pattern... masked with leading 000...0001 to set difficulty" simply
describing the truncate-and-force-top-bit construction that defines each
puzzle's *interval*, not an exploitable arithmetic relationship between
consecutive keys' values) and with prior community consensus after years of
public scrutiny of this puzzle series. Per the anti-bullshit rule: this null
result is reported plainly as a valid, non-actionable finding — it does not
narrow the candidate distribution for puzzle #71's private key at all beyond
the uniform prior over `[2^70, 2^71)` already implied by the puzzle's
construction.
