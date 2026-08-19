# Hypothesis: Linear Congruential Generator (LCG) origin

**Status: REJECTED** (no test shows structure beyond a properly-controlled
random null; all four independent lines of attack are consistent with pure
chance)

Script: `research/hypotheses/lcg.py` (deterministic given
`random.seed(20260819)` / `np.random.seed(20260819)`, runtime ~3s on this
machine).

## Hypothesis being tested

Keys were generated (before masking) by a linear congruential generator

```
x_{i+1} = (a * x_i + c) mod m
```

and puzzle `n`'s key relates to LCG output `n` via the stated masking
transform: `key(n) = 2^(n-1) + (raw_lcg_output(n) mod 2^(n-1))`. Working
sequence, per the task spec: `normalized(n) = lower_bits(n) / 2^(n-1)` for
`n = 1..70`, read directly from `data/solved_puzzles.json` (70/70
cryptographically re-verified keys).

## Why this hypothesis has a structural wrinkle worth flagging up front

`normalized(n)` is computed with a **different denominator for every n**
(`2^(n-1)`), not a fixed modulus. A textbook LCG has one fixed `m`. This
means the "normalized sequence" isn't literally consecutive LCG outputs
under a shared modulus even if the underlying raw generator is an LCG --
it's the low `(n-1)` bits of output `n`, re-scaled. We tested it anyway,
exactly as instructed, because it's still the natural falsifiable
prediction if the masking-transform story is true (the classic LCG defects
-- lattice structure, small state-recovery via triples, GCD-recoverable
modulus -- should still leak through this transform if a real LCG with a
moderate modulus were in play). But this structural point matters a lot
for Test B below, where it produced a genuine artifact that had to be
explicitly corrected for (see "methodological pitfall" there) -- flagging
it here so the fix doesn't look like it came out of nowhere.

## Test A: direct search over small-to-moderate power-of-two moduli

For each candidate modulus `m` (`2^4` through `2^24`, 21 values), convert
`normalized(n)` to an integer state `X_n = round(normalized(n)*m) mod m`.
For every consecutive triple `(X_i, X_{i+1}, X_{i+2})`, solve for `(a, c)`
via modular inverse (`a = (X_{i+2}-X_{i+1}) * inv(X_{i+1}-X_i, m) mod m`),
then score that `(a,c,m)` by how many of **all 69** transitions in the
whole sequence it correctly predicts. Take the best-fitting modulus's match
fraction as the real-data statistic, and compare to the same statistic
computed on 300 Monte Carlo random control sequences (uniform floats,
identical length, identical search).

**Real data**, best-fitting modulus and match fraction:

| m | best matches / 69 | (a, c) |
|---|---|---|
| 2^4 (16) | 10 | (14, 15) |
| 2^5 (32) | 7 | (0, 21) |
| 2^6 (64) | 6 | (13, 41) |
| 2^7..2^10 | 4 | various |
| 2^11..2^24 | 2-3 | various |

Best overall: **modulus 2^4, match fraction 0.1449** (10/69).

Monte Carlo null (n=300 random sequences, identical search over all 21
moduli): mean best-match fraction = **0.1484**, max seen = 0.2174.

**P-value (real >= null): 0.7176.** The real data's best-fitting modulus
performs *worse than the average* random control sequence at this same
search. No evidence of LCG structure recoverable this way, at any modulus
tested.

## Test B: determinant/GCD modulus-recovery method

Classic LCG cryptanalysis (Plumstead/Boyar): for a true LCG, differences
`d_i = X_{i+1} - X_i` satisfy `d_{i+1}*d_{i-1} - d_i^2 ≡ 0 (mod m)` for
every `i`, so `m` divides `gcd` of all these determinants across the whole
sequence. If the real data came from an LCG with modulus `<= 2^69` (2^69 is
the maximum precision actually present in the data -- puzzle #70 has 69
free/lower bits, so this is the natural upper bound, not an arbitrary
choice), `gcd(z_i)` should come out close to `2^69`, or an interesting
"nice" divisor thereof, not noise.

To keep this exact (float64 mantissa is only 53 bits, insufficient for a
2^69-scale test), we recomputed the sequence directly from `key_int`/`n` as
arbitrary-precision Python integers on a common denominator `2^69`, with
zero float rounding anywhere in this test.

### Methodological pitfall caught and fixed

The first version of this test used a naive null: draw 70 fully random
integers uniform on `[0, 2^69)` at every position. That gave `gcd(z_i) = 4`
for the real data against a null where **all 2000 trials had gcd exactly
1** -- an apparently damning p-value of 0.0005. Investigating *why*
(printing the 2-adic valuation of every `z_i`) showed the real result was
an artifact, not a signal: because `normalized(n)`'s denominator is
`2^(n-1)`, embedding position `n` on the common `2^69` scale forces
`(69-(n-1))` trailing zero bits on every early-n value **by construction**
-- nothing to do with any generator. Valuations of the 67 `z_i` in the real
data:

```
[134, 132, 130, 128, 128, 125, 122, 120, 118, 116, 116, 113, 110, 108,
 106, 105, 107, 100, 98, 96, 98, 94, 90, 88, 86, 85, 84, 81, 78, 78, 78,
 72, 73, 69, 66, 64, 62, 60, 58, 58, 56, 54, 50, 49, 47, 44, 42, 44, 41,
 41, 36, 32, 30, 28, 26, 24, 22, 21, 20, 18, 17, 14, 10, 9, 8, 4, 2]
```

This monotonic decrease from 134 down to 2 is exactly what mechanical
zero-padding produces regardless of the source of the "real" bits, and it
is entirely determined by the *last* (highest-n, least-padded) triple in
the sequence. The naive null (uniform at full 69-bit precision at
*every* position, including small n) never reproduces this padding, so
it under-estimates the achievable gcd across the board -- comparing real
data against it is not apples-to-apples, exactly the kind of "does it fit
the 70 known keys" trap the anti-bullshit rule warns about, just one level
removed (it showed up in the null construction, not the pattern claim
itself).

**Fix**: the null control must replicate the real data's own varying
per-position precision -- position `n` draws its lower bits uniformly from
`[0, 2^(n-1))`, exactly like the real puzzles, before embedding on the
common scale. Re-run with this corrected null:

- Real data: `gcd(z_i) = 4` (log2 = 2.00)
- Monte Carlo null (2000 trials, matched structure): mean log2(gcd) =
  **3.01**, max log2(gcd) seen = 8.00 (raw gcd up to 256)
- **P-value (real >= null): 1.0000.**

The real value is *below* the null's average once the structural
confound is removed -- no signal.

**Robustness check**: repeating on puzzles n=20..70 only (49 points, so no
position contributes fewer than 19 bits of genuine precision, eliminating
any residual small-n padding effect) gives the same result: real
`gcd = 4` (log2 = 2.00) vs. null mean log2 = 3.06 (500 trials), **p =
1.0000**.

## Test C: lattice / spectral-test structure (2D scatter statistic)

Classic LCGs plotted as consecutive pairs `(x_n, x_{n+1})` fall on a small
family of parallel lines `p*x + q*y ≡ k/m` for some small integer direction
`(p, q)` -- the textbook spectral-test defect. We projected the 69 real
`(normalized(n), normalized(n+1))` pairs onto every small coprime integer
direction with `|p|, |q| <= 12` (184 directions after removing collinear
duplicates and sign-mirrors), binned each projection mod 1 into 20 bins,
and computed a chi-square deviation from uniform for each direction. The
test statistic is the **worst (largest) chi-square found over all 184
directions searched** -- this automatically corrects for the
multiple-comparisons problem, since the Monte Carlo null undergoes the
identical 184-direction search.

- Real data: max chi-square over all directions = **41.43**, at direction
  `(p, q) = (11, -8)`
- Monte Carlo null (3000 random 69-point 2D sets, same 184-direction
  search): mean = **40.70**, 95th percentile = 48.97
- **P-value (real >= null): 0.3905.** Not significant -- the real data's
  worst-fitting direction is unremarkable next to what pure chance
  produces when you search 184 directions.

A second, more literal "minimum lattice spacing" statistic: minimum
pairwise Euclidean distance among the 69 `(normalized(n), normalized(n+1))`
points.

- Real data: minimum nearest-neighbour distance = **0.017109**
- Monte Carlo null (3000 random 69-point sets): mean = 0.010455, 5th
  percentile = 0.002616
- **P-value (real is anomalously clustered): 0.8824.** The real points are
  actually *more spread out* than a typical random control (consistent
  with ordinary randomness, not LCG-lattice clustering, which would show
  up as an anomalously *small* nearest-neighbour distance).

## Test D: walk-forward prediction (3-consecutive-output LCG attack)

If it really were an LCG with a known-ish modulus, 3 consecutive outputs
are sufficient to solve for `(a, c)` exactly and predict every subsequent
output exactly (this is the textbook LCG state-recovery attack). Walking
forward through the sequence, for `n = 4..69` and a handful of moduli, we
used `(X_{n-2}, X_{n-1}, X_n)` to solve for `(a, c)` and predicted
`X_{n+1}`, then compared to the trivial baseline "always guess the
interval midpoint, 0.5" (the variance-minimizing constant predictor for a
uniform distribution on `[0, 1)`).

| m | attempts | exact hits | chance-expected hits | LCG walk-forward MSE | baseline (0.5) MSE |
|---|---|---|---|---|---|
| 2^8 | 31 | 0 | 0.1211 | 0.10387 | **0.07027** |
| 2^12 | 25 | 0 | 0.0061 | **0.05310** | 0.05728 |
| 2^16 | 28 | 0 | 0.0004 | 0.06773 | 0.06674 |
| 2^20 | 21 | 0 | 0.0000 | 0.09377 | **0.07895** |
| 2^24 | 27 | 0 | 0.0000 | 0.09257 | **0.08806** |

- **Zero exact hits** across all 132 attempts, at every modulus tested --
  fully consistent with the chance-expected rate (itself ~0 for the larger
  moduli).
- LCG walk-forward beats the naive midpoint baseline at only **1 of 5**
  moduli tested (2^12, and only marginally: 0.0531 vs 0.0573 -- well within
  noise given the small sample of ~25 predictions). At the other 4 moduli
  the LCG-based predictor is *worse* than just guessing 0.5 every time.

## Overall verdict

All four independent, pre-registered tests -- direct moduli search (A),
determinant/GCD modulus recovery (B, with a caught-and-fixed methodological
pitfall that itself illustrates why the anti-bullshit rule matters), 2D
lattice/spectral structure (C), and walk-forward 3-output state-recovery
prediction (D) -- come back consistent with pure chance once measured
against matched Monte Carlo random-control nulls. None beats a naive
baseline out of sample. No LCG structure, of the forms tested, is
detectable in the 70 verified puzzle keys.

This does not prove no LCG of any kind, at any modulus, with any
transform, could have produced this data -- that space is infinite and
unfalsifiable in full generality. It does mean: none of the standard,
well-established LCG-breaking techniques (small-modulus search, GCD/
determinant modulus recovery, spectral/lattice detection, short-window
state-recovery prediction), applied directly and honestly to the
normalized sequence as specified, finds anything. Combined with the
creator's own statement that the masking is "deterministic wallet"-derived
(sequential/BIP32-style keys, not an LCG), and the prior rejection of the
naive sequential-counter hypothesis (`seq_counter.md`), this hypothesis is
**rejected** for practical search-space-reduction purposes.
