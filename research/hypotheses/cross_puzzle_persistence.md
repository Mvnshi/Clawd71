# Hypothesis: Cross-Puzzle Bit Persistence

**Status: REJECTED** (no statistic survives multiple-comparison correction against
a Monte Carlo random-key null model; walk-forward test does not beat the naive
midpoint baseline)

Script: `research/hypotheses/cross_puzzle_persistence.py` (deterministic given
`random.seed(20260819)` / `np.random.seed(20260819)`; runtime ~2m15s for the
full 20,000-iteration Monte Carlo + family-wise correction on this machine).
Raw results: `research/hypotheses/cross_puzzle_persistence_results.json`.

## Hypothesis being tested

A weaker, more general version of the sequential-counter idea (already
rejected in `seq_counter.md`): rather than requiring an exact arithmetic
relationship, does *some* bit position or byte-level pattern in the free
(post-leading-bit) portion of key `n` correlate with the corresponding
portion of key `n+1, n+2, ...`? Separately: does the puzzle index `n` itself
predict the normalized key position `normalized(n) = lower_bits(n) / 2^(n-1)`
— a linear trend, or periodicity at `n mod 8/16/32` (byte- or word-aligned
generation artifacts)?

## Statistics computed (19 tests total, all on the real 70-puzzle dataset
and on every Monte Carlo null replicate)

1. `spearman_n_vs_norm`, `pearson_n_vs_norm` — \|correlation\| of puzzle
   index `n` against `normalized(n)`.
2. `autocorr_lag{1..5}` — \|Pearson autocorrelation\| of the `normalized`
   sequence at lags 1 through 5.
3. `anova_F_mod{8,16,32}` — one-way ANOVA F-statistic of `normalized`
   grouped by `n mod k`, for `k in {8, 16, 32}` (byte/word-alignment
   periodicity test).
4. `hamming_meanfrac_dev` — mean Hamming-distance fraction between
   **consecutive** keys' free bits, right-justified (comparing the low
   `min(n1-1, n2-1)` bits of `lower_bits(n1)` and `lower_bits(n2)`),
   deviation from the 0.5 expected under independence.
5. `hamming_lag{2,3,4,5}_dev` — same, at lags 2 through 5.
6. `popcount_pooled_dev` — deviation from 0.5 of the pooled fraction of set
   bits across all free bits of all 70 keys (aggregate Hamming-weight test).
7. `popcount_mean_abs_z` — mean of \|z\| where each key's popcount is
   standardized against `Binomial(k, 0.5)` (`k` = free-bit count for that
   key), i.e. per-key Hamming-weight test against the binomial null.
8. `max_bitpos_corr`, `mean_bitpos_corr` — for each LSB-aligned bit offset
   `j` in 0..19, the Pearson correlation between bit `j` of key `n`'s free
   bits and bit `j` of key `n+1`'s free bits (over all valid consecutive
   pairs with enough bits); max and mean \|correlation\| across offsets.

## Real-data results

```
spearman_n_vs_norm:   0.181247
pearson_n_vs_norm:    0.188885
autocorr_lag1:        0.058059
autocorr_lag2:        0.132936
autocorr_lag3:        0.301600   <- largest raw statistic
autocorr_lag4:        0.090181
autocorr_lag5:        0.040095
anova_F_mod8:         1.204882
anova_F_mod16:        1.519181
anova_F_mod32:        1.717618
hamming_meanfrac:     0.502894   (dev from 0.5: 0.002894)
popcount_pooled_frac: 0.493996   (dev from 0.5: 0.006004)
popcount_mean_abs_z:  0.785329
max_bitpos_corr:      0.252516
mean_bitpos_corr:     0.130318
hamming_lag2_dev:     0.000339
hamming_lag3_dev:     0.004048
hamming_lag4_dev:     0.000190
hamming_lag5_dev:     0.013144
```

Hamming distances between consecutive keys' free bits, and pooled/per-key
Hamming weights, sit almost exactly at the 50%/binomial-mean expectation —
no detectable bit-copying or biased-weight signal at all. The two
numerically largest excursions are `autocorr_lag3` (0.302) and
`anova_F_mod32` (1.718, i.e. does `normalized(n)` differ by `n mod 32`
group).

## Monte Carlo null model

20,000 synthetic 70-puzzle datasets were generated, each puzzle `n`'s key
drawn independently and uniformly at random from `[2^(n-1), 2^n)` — done via
Python's arbitrary-precision `random.getrandbits(n-1)` for the free-bit
portion (numpy's `randint` cannot represent ranges beyond 64 bits, which
matters starting around puzzle #65). All 19 statistics above were computed
identically on each synthetic dataset.

| Statistic | Real | Null mean ± std | Monte Carlo p (one-sided, larger=more extreme) |
|---|---|---|---|
| autocorr_lag3 | 0.30160 | 0.09755 ± 0.07250 | **0.01150** |
| anova_F_mod32 | 1.71762 | 1.03310 ± 0.36873 | 0.05000 |
| mean_bitpos_corr | 0.13032 | 0.10568 ± 0.01771 | 0.08760 |
| anova_F_mod16 | 1.51918 | 1.02588 ± 0.44002 | 0.12650 |
| pearson_n_vs_norm | 0.18888 | 0.11398 ± 0.08232 | 0.18805 |
| spearman_n_vs_norm | 0.18125 | 0.11448 ± 0.08275 | 0.20925 |
| autocorr_lag2 | 0.13294 | 0.09713 ± 0.07260 | 0.27850 |
| anova_F_mod8 | 1.20488 | 1.01759 ± 0.59377 | 0.30220 |
| hamming_lag5_dev | 0.01314 | 0.01381 ± 0.01022 | 0.45220 |
| autocorr_lag4 | 0.09018 | 0.09838 ± 0.07395 | 0.46700 |
| popcount_pooled_dev | 0.00600 | 0.00814 ± 0.00613 | 0.57040 |
| popcount_mean_abs_z | 0.78533 | 0.79984 ± 0.07173 | 0.57350 |
| autocorr_lag1 | 0.05806 | 0.09625 ± 0.07277 | 0.62795 |
| max_bitpos_corr | 0.25252 | 0.28680 ± 0.06164 | 0.69255 |
| autocorr_lag5 | 0.04010 | 0.09871 ± 0.07438 | 0.74535 |
| hamming_lag3_dev | 0.00405 | 0.01321 ± 0.00985 | 0.80560 |
| hamming_meanfrac_dev | 0.00289 | 0.01291 ± 0.00960 | 0.85810 |
| hamming_lag2_dev | 0.00034 | 0.01309 ± 0.00975 | 0.98305 |
| hamming_lag4_dev | 0.00019 | 0.01341 ± 0.00994 | 0.99270 |

Full 19 of 19 statistics land inside the null-generated distribution; none
crosses the conventional (uncorrected) `p < 0.05` threshold except
`autocorr_lag3` (p = 0.0115) and marginally `anova_F_mod32` (p = 0.0500,
right at the boundary).

## Multiple-comparison correction

19 tests were run on the same 70-puzzle dataset, so a raw `p < 0.05` on the
single best statistic is exactly what unrelated-noise multiple testing
predicts. Two corrections were applied:

**Bonferroni.** `alpha_corrected = 0.05 / 19 = 0.002632`. The most extreme
real statistic, `autocorr_lag3` at `p = 0.01150`, is **not significant**
after correction (0.01150 > 0.002632). No other statistic comes close.

**Family-wise Monte Carlo correction (exact, accounts for correlation
between the 19 statistics — more rigorous than Bonferroni, which assumes
independence).** For each of the 20,000 null replicates, its own per-statistic
p-values were computed against the same null distribution used for the real
data, and the minimum p-value across the 19 statistics for that replicate
was recorded, building an empirical null distribution of "best result out of
19 correlated tests run on pure noise":

```
Null distribution of min-p across 19 tests:
  mean   = 0.05684
  median = 0.04055
  5th pct = 0.00300
Real data's min p (autocorr_lag3) = 0.01150
Family-wise Monte Carlo p-value = 0.17965
```

I.e., **17.97% of purely-random 70-puzzle datasets produce a "best of 19
tests" result at least as extreme as what the real data shows.** This is a
direct, assumption-free demonstration that the `autocorr_lag3 = 0.302`
excursion is unremarkable multiple-testing noise, not evidence of
persistence — a noise-generated dataset produces an equally strong "best"
statistic roughly one time in six.

## Walk-forward test

Fit a linear regression `normalized(n+1) = slope * normalized(n) + intercept`
on puzzles `n <= split` (the natural operationalization of "lag-1
persistence"), use it to predict `normalized` for the next up-to-10 puzzles,
and compare squared error to the naive baseline of guessing the interval
midpoint (`normalized = 0.5`):

| Split N | slope | intercept | MSE (model) | MSE (baseline) | Model beats baseline? |
|---|---|---|---|---|---|
| 10 | -0.3065 | 0.5601 | 0.04303 | 0.03376 | No |
| 20 | -0.0517 | 0.4443 | 0.09848 | 0.06230 | No |
| 30 | +0.1649 | 0.4274 | 0.07755 | 0.08370 | Yes |
| 40 | +0.2099 | 0.3955 | 0.05916 | 0.05287 | No |
| 50 | +0.1446 | 0.4118 | 0.11265 | 0.10146 | No |
| 60 | +0.0757 | 0.4693 | 0.09307 | 0.09312 | Yes |
| 65 | +0.0963 | 0.4719 | 0.09268 | 0.08236 | No |

The fitted slope isn't even stable in sign across splits (-0.31 at N=10 vs.
+0.21 at N=40), and the model beats the naive midpoint baseline in only
**2 of 7 splits** — worse than a coin flip, and consistent with a slope
that is fit to noise each time rather than tracking a real relationship.

## Verdict

**Rejected.** Across 19 distinct statistics probing every angle of the
stated hypothesis — direct bit-position persistence between consecutive
keys' free bits, right-justified Hamming distance at lags 1-5, pooled and
per-key Hamming-weight bias, autocorrelation of the normalized position at
lags 1-5, and periodicity of the normalized position at `n mod 8/16/32` —
none survives multiple-comparison correction against an explicit
independent-uniform-random-key null model built from 20,000 Monte Carlo
replicates. The single nominally-interesting statistic (`autocorr_lag3`,
raw `p = 0.0115`) is fully explained by testing 19 things at once: an
exact family-wise Monte Carlo correction shows purely random data produces
an equally-strong "best of 19" result 17.97% of the time — nowhere near a
real detection. The walk-forward lag-1 predictor beats the naive midpoint
guess in only 2 of 7 out-of-sample splits, with a slope that isn't even
sign-stable across splits.

This is fully consistent with the puzzle creator's stated claim ("no
pattern... consecutive keys from a deterministic wallet, masked with
leading 000...0001 to set difficulty") and with the prior rejection of the
literal sequential-counter hypothesis in `seq_counter.md`. Per the
anti-bullshit rule: this null result is reported plainly. It does not
narrow the candidate distribution for puzzle #71's private key — the
uniform prior over `[2^70, 2^71)` implied by the puzzle's construction
remains the best available model. No bit position, byte alignment, or
consecutive-key relationship tested here provides any exploitable edge.
