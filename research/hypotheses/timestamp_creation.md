# Hypothesis: January 2015 real-world timing (Unix timestamps / block hashes) as generator seed

**Status: REJECTED** (no test shows structure beyond a properly-controlled random
null; all three independent test families, covering a fixed known value, a
handful of real nearby blocks, and a full brute-force scan of the entire
plausible creation window, are consistent with pure chance)

Script: `research/hypotheses/timestamp_creation.py` (deterministic given
`random.seed(20260819)` / `np.random.seed(20260819)`; network calls are
cached in `research/hypotheses/_nearby_blocks_cache.json`, fetched once from
blockstream.info on 2026-08-19, so re-runs are network-independent).

## Hypothesis being tested

The generator was seeded or otherwise influenced by real-world timing around
the January 2015 creation date -- Unix timestamps, Bitcoin block
hashes/heights around the funding transaction, or system-clock jitter from a
script that generated all 160-256 keys in a tight loop (which for some naive
RNGs -- e.g. seeding per-key with `time()`-based seeds at high call rate --
could produce correlated or even identical seeds for nearby puzzle numbers).

## Ground-truth anchor: the exact funding event, independently verified on-chain

Before searching a wide "plausible" window, we used the project's own prior
on-chain forensics (`research/onchain/funding_transactions.md`) plus a fresh
re-fetch against `blockstream.info` (2026-08-19) to pin down the **exact**
real-world event this hypothesis is actually about, rather than guessing:

| Field | Value |
|---|---|
| Funding tx | `08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15` |
| Block height | **339085** |
| Block hash | `0000000000000000188de542fd76b1676c4be6c380b39ddea119358c290cebd7` |
| Block time | **1421345234** (2015-01-15T18:07:14 UTC) |
| Block mediantime | 1421342061 |

All 71 puzzle addresses (#1-#71) were funded in this single transaction, in
strict puzzle-number order (see `funding_transactions.md`) -- this is the
one non-searched, independently-confirmed timestamp/height/hash the task's
"plausible timestamp" language could concretely refer to, so it is tested
first, on its own, with no search involved at all.

## Test 1: fixed-value comparison (no search) against the funding block

For four independently-known values (block time, block mediantime, block
height, block hash treated as a big integer) we computed, for every puzzle
`n = 2..70`: `value mod 2^(n-1)` and compared it bitwise against
`lower_bits(n)`. Two statistics per value: (a) mean bit-agreement fraction
across all 69 puzzles (expected 0.5 under the null -- a real relationship
would push this toward 0 or 1), and (b) count of puzzles where the two are
**exactly** equal (expected ~1, dominated by the smallest `n`, under the
null). Because these four comparison values are fixed *a priori* by
independent on-chain forensics -- not selected by scanning the key data --
this test needs only a small Bonferroni correction (4 values x 2 statistics
= 8 comparisons), not a full search-matched null.

Monte Carlo null: 8,000 random control key sequences per value, each drawing
puzzle `n`'s free bits uniformly from `[0, 2^(n-1))` (matching every
puzzle's real per-position precision, not a flat/naive draw).

| Source value | mean bit-agreement (real) | null mean (std) | p (two-sided) | exact hits (real) | null mean (max) | p |
|---|---|---|---|---|---|---|
| block time | 0.4879 | 0.5002 (0.0157) | 0.4391 | 0 | 0.998 (4) | 1.0000 |
| block mediantime | 0.4948 | 0.4999 (0.0159) | 0.7402 | 1 | 1.005 (4) | 0.7149 |
| block height | 0.5209 | 0.4999 (0.0161) | 0.1994 | 1 | 0.986 (5) | 0.7038 |
| block hash (int) | 0.5118 | 0.5001 (0.0158) | 0.4617 | 2 | 1.002 (4) | 0.2497 |

Smallest raw p-value across all 8 comparisons: **0.1994** (block height, bit
agreement). Bonferroni-corrected: **1.0000**. No signal -- every statistic
lands comfortably inside the range random control keys produce.

## Test 2: nearby-blocks handful search

Fetched 21 real blocks from `blockstream.info` around the funding block: an
11-block fine window (heights 339080-339090, funding block +/-5) plus a
10-block coarse window at roughly 1-day spacing (~144 blocks) spanning +/-5
days around the funding event, to also cover the possibility that key
*generation* (as opposed to the funding payout) happened somewhat earlier.
For each block we tested its hash (as integer), timestamp, and height (63
combos total) against every puzzle with the same bit-agreement and
exact-match statistics as Test 1, plus a hex-substring-match test: does
`hex(lower_bits(n))` (stripped of leading zeros, minimum 4 hex digits to
avoid trivial short-string false positives, `n >= 17` only) appear as a
substring of any block's hash hex string or its byte-reversed form (42
hash-strings total)?

Because this test **searches** over 21 blocks x 3 value types (and 42 hash
strings for the substring test), the real-data statistic is the *best*
(maximum) value found across the whole search, and the Monte Carlo null
re-runs the identical 21-block search on random control key sequences --
this automatically corrects for the multiple-comparisons problem built into
"pick the best of many blocks."

| Statistic | Real (best over search) | Null mean (max) | p-value |
|---|---|---|---|
| Bit-agreement fraction | 0.5357 | 0.5322 (0.5675) | 0.3209 |
| Exact-match count | 2 | 2.630 (5) | 0.9998 |
| Hex-substring matches | 0 (of 2,268 checked) | 0.068 (2) | 1.0000 |

No signal. The real data's best-of-21-blocks result is unremarkable next to
what an equally aggressive search on random keys turns up routinely -- and
for the substring test, the real data has **zero** hits at all, while random
control sequences occasionally (rarely) get 1-2 by pure chance.

## Test 3: full timestamp-range search (Jan-Mar 2015)

The heaviest and most literal test of the "plausible Unix timestamp" wording
in the hypothesis: brute-force every candidate creation timestamp `T` in the
full task-specified window `1420070400 <= T < 1425168000`
(2015-01-01 -- 2015-03-01 UTC, **5,097,600** candidates), for puzzles
`n = 2..63` (`n = 64..70` excluded from this specific vectorized scan only
because a `2^63`+ modulus does not fit in a signed 64-bit integer -- those 7
puzzles are still covered by Tests 1 and 2 above via exact-precision Python
bigints), testing two candidate relations per `T`:

```
R1 (direct):    lower_bits(n) == T mod 2^(n-1)
R2 (additive):  lower_bits(n) == (T + n) mod 2^(n-1)
```

The real-data statistic is the single **best** match count found anywhere
across the entire 5.10M x 2-relation search (i.e. "how many of the 62
puzzles can the single best-fitting `T` explain at once"). The Monte Carlo
null re-runs the *identical* full 5.10M-candidate search against 100 random
control key sequences (matching each puzzle's real per-position precision)
-- this is what makes the comparison fair despite scanning millions of
candidates: the null undergoes exactly the same search, so it already
absorbs the multiple-comparisons inflation from trying 5.1M x 2 = ~10.2M
candidate relationships.

| Relation | Real best (of 62 puzzles) | Null mean (max, 100 trials) | p-value |
|---|---|---|---|
| `T mod 2^(n-1)` | 3 | 3.440 (5) | 0.9901 |
| `(T+n) mod 2^(n-1)` | 3 | 3.360 (6) | 1.0000 |
| Combined (best of both) | 3 | 3.690 (6) | **1.0000** |

The real data's best-fitting timestamp across the *entire* plausible
creation window explains only **3 of 62** puzzles' free bits -- and that is
**below the average** a random 62-puzzle control sequence achieves against
the same 5.1-million-candidate search (3.69), let alone its max (6). There
is no timestamp anywhere in the two-month window that predicts the real
keys better than chance predicts random keys.

## Test 3b: walk-forward (fit on n<=50, evaluate on held-out n=51..70)

Per the task's walk-forward requirement: the single best `(T, relation)`
pair is *selected* using only the training puzzles `n = 2..50` (49 puzzles,
via the same full 5.10M-candidate search restricted to that training data),
then evaluated -- with **no further fitting** -- against the untouched
held-out puzzles `n = 51..70` (20 puzzles, using exact Python bigints so all
20 held-out puzzles are covered despite the int64 ceiling on the training
search).

- Best `(T, relation)` selected on training data alone: `T = 1420070611`
  (2015-01-01T00:03:31 UTC -- notably just the very first few seconds of
  the scanned window, i.e. an edge-of-range artifact typical of pure noise,
  not a meaningful date), relation = direct mod, training match count = 3
  (of 49 -- already unremarkable on its own).
- Held-out exact hits: **0 of 20** (chance-expected: 0.0000 -- for `n>50`
  the modulus is astronomically larger than 1, so exact agreement by chance
  is not expected at all; getting 0 is uninformative on its own but at
  least rules out a "surprisingly good" outcome).
- Held-out mean bit-agreement fraction: **0.4861**, against a chance
  baseline of **0.5000** -- the walk-forward predictor performs *worse*
  than the naive baseline out of sample, not better.

This fails the walk-forward test outright: whatever partial fit the search
found on the training half is pure overfitting to noise -- it carries zero
predictive value onto held-out puzzles, exactly what the anti-bullshit rule
warns fitting-only evidence looks like.

## Overall verdict

Three independent test families -- (1) a single fixed, independently
verified real-world value (the actual funding block's timestamp,
mediantime, height, and hash, with no search at all), (2) a focused
21-block search of real Bitcoin blocks around the funding event (hash,
height, timestamp, plus hex-substring matching), and (3) an exhaustive
brute-force scan of all 5,097,600 candidate Unix timestamps in the full
task-specified Jan-Mar 2015 window under two relation forms, with a
walk-forward out-of-sample check -- **all come back indistinguishable from
chance** once measured against properly search-matched Monte Carlo null
models:

| Test | Smallest p-value found | Corrected/context |
|---|---|---|
| 1: fixed funding-block values (no search) | 0.1994 | Bonferroni (x8) -> 1.0000 |
| 2: 21 nearby blocks (search-matched null) | 0.3209 | already search-corrected |
| 3: full 5.10M-timestamp range (search-matched null) | 0.9901 | already search-corrected; real data is *below* the null average |
| 3b: walk-forward (train n<=50, test n=51..70) | -- | held-out bit-agreement 0.4861 < chance baseline 0.5000 |

No candidate timestamp, block hash, block height, or simple derived
relationship (direct mod, additive mod, XOR mod, hex substring) shows any
detectable correlation with the real puzzle keys' free bits beyond what
equally aggressive searches turn up on pure random noise -- and the one
walk-forward check performed actually underperforms the trivial baseline
out of sample. This includes the single most literally "real" test of the
hypothesis available: the *exact*, independently on-chain-verified funding
block that paid out every puzzle in this dataset in one transaction.

This does not prove no timestamp-based influence of any kind, under any
transform, could have touched key generation -- that space (arbitrary hash
functions, arbitrary byte encodings, arbitrary offsets) is unbounded and not
fully searchable. It does mean: the direct, substring, and simple modular
relationships specified by the task, searched honestly across the entire
plausible creation window plus the one real, verified funding event and its
immediate neighborhood, find nothing. Combined with the creator's own
statement ("no pattern... consecutive keys from a deterministic wallet") and
the prior rejections of the sequential-counter and LCG hypotheses, this
hypothesis is **rejected** for practical search-space-reduction purposes.
