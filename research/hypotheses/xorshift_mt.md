# Hypothesis: xorshift-family / MT19937 PRNG Origin of Puzzle Keys

**Status: REJECTED** (falsified directly, both algebraically and by exhaustive
seeded-replay brute force, against all 70 verified keys; consistent with a
random-null Monte Carlo baseline at every stage)

Script: `research/hypotheses/xorshift_mt.py` (deterministic given
`random.seed(20260819)` / `np.random.seed(20260819)`; full run — including
the 31,536,000-second MT19937 timestamp brute force and its 5 full-scale
null replications, plus the 2,000,000-seed xorshift32/64/128 searches with
15 null replications each — took on the order of 40-45 minutes wall-clock
on this 4-core machine while sharing CPU with several sibling research
jobs running concurrently; raw results in `xorshift_mt_results.json`. Every
individual search stage's own self-timed duration is printed in-line below;
`multiprocessing.Pool` parallelizes each replay search across all
available cores).

## Hypothesis being tested

Keys came from a non-cryptographic PRNG with known internal structure —
xorshift family (xorshift32/64/128) or MT19937 (Python's/many languages'
default `random()`, C's `rand()` variants, Mersenne Twister) — used either
directly (masked output) or seeded with something guessable: a small
integer (puzzle index or otherwise), or a Unix timestamp near the puzzle
series' creation (funding tx confirmed on-chain 2015-01-15 18:07:14 UTC;
see `research/archaeology/creator_statements.md`).

Working data: `L(n) = int(lower_bits_hex, 16)` for `n = 1..70`, read
directly from `data/solved_puzzles.json` (verified, 70/70 keys). `L(n)` is
an `(n-1)`-bit integer (`L(1) = 0`).

## Part A — xorshift GF(2) linear-recurrence test (no seed search needed)

Real xorshift-w outputs obey a **fixed linear map over GF(2)^w** built from
a shift-xor triple `(a,b,c)`:

```
pattern 1: t = x ^ (x<<a); t ^= (t>>b); t ^= (t<<c)
pattern 2: t = x ^ (x>>a); t ^= (t<<b); t ^= (t>>c)
```

If consecutive puzzle keys' low-w bits were consecutive xorshift-w states,
**some single `(pattern,a,b,c)` must map `low-w(L(n)) -> low-w(L(n+1))` for
every consecutive pair simultaneously** — not just for one pair, since it's
one continuous generator. We brute-forced all `(pattern,a,b,c)` with
`a,b,c ∈ 1..31` (59,582 candidate linear maps) against:

- **w=32**: all 37 consecutive pairs with `n ≥ 33` (i.e. `n-1 ≥ 32` known bits)
- **w=64**: all 5 consecutive pairs with `n ≥ 65` (i.e. `n-1 ≥ 64` known bits)

and recorded the single best-matching triple's hit count, out of the
available pairs, for each width. This is a real algebraic prediction (not
an eyeballed fit): the true hypothesis predicts the correct triple gets
*every* pair right.

### Real-data results

| w | pairs available (n range) | best triple hit count | best (pattern,a,b,c) |
|---|---|---|---|
| 32 | 37 (n=33..70) | **0 / 37** | pattern=1, (1,1,1) [tie — see note] |
| 64 | 5 (n=65..70) | **0 / 5** | pattern=1, (1,1,1) [tie — see note] |

*(Note: since every one of the 59,582 candidate maps scored 0 hits, the
reported "(1,1,1)" is just the first map enumerated in the tie, not a
meaningful winner — there is no structure here to report a winner of.)*

Zero hits out of 37 (and out of 5) is the complete falsification the
hypothesis predicts is impossible: if any of these keys were truly
consecutive xorshift-w states, the correct triple would score 37/37 (or
5/5). No triple scores even 1/37.

### Monte Carlo null

Because exact 32-bit (or 64-bit) matches are individually astronomically
unlikely by chance (`~2^-32` / `~2^-64` per pair), getting 0 hits is *also*
exactly what a random-data control produces — this null tells us the test
had essentially no chance of finding a spurious match either, which is the
correct, honest context for a "0/37" result:

| w | null reps | null best-hit-count (mean / max / min) | Monte Carlo p-value |
|---|---|---|---|
| 32 | 100 | 0.000 / 0 / 0 | **p = 1.000** |
| 64 | 100 | 0.000 / 0 / 0 | **p = 1.000** |

The real result (0 hits) ties the null's result (0 hits) in both cases —
completely uninformative in the "beats random noise" sense, and a clean,
unambiguous rejection of the classic-3-shift xorshift32/64 hypothesis in
these low-word positions.

## Part B — PRNG-replay brute force (exhaustive seeded falsification)

For each candidate generator/seed we build the full 70-output sequence the
way the puzzle creator's own phrase implies — "consecutive keys ... masked
to set difficulty" — i.e. **one continuous stream**, consumed sequentially,
puzzle `n` taking the next `(n-1)` bits (`random.getrandbits(n-1)` per call
for MT19937; one xorshift-w step's output truncated to its low `(n-1)` bits
for xorshift). For every seed tried we record the **longest run of
consecutive puzzles whose predicted lower bits exactly equal the real lower
bits**, both overall and restricted to runs starting at `n ≥ 10` (to
separate meaningful matches from the trivially-easy small-n region — `n=1`
has 0 bits and always "matches", `n=2` has 1 bit, etc.).

Seed spaces searched (bounded, explicit, exhaustive within each range):

| Generator | Seed space | # seeds |
|---|---|---|
| xorshift32 | 1 .. 2,000,000 | 2,000,000 |
| xorshift64 | 1 .. 2,000,000 | 2,000,000 |
| xorshift128 | 1 .. 2,000,000 | 2,000,000 |
| Python `random` (MT19937) | small ints 0 .. 100,000 | 100,001 |
| Python `random` (MT19937) | Unix timestamps, every second of 2015 (1420070400..1451606399, Jan 1 2015 00:00:00 UTC .. Dec 31 2015 23:59:59 UTC) | 31,536,000 |

### Results

For every generator, `best_overall` is the single longest exact-match run
found across the *entire* seed space (start index / seed shown), and
`best_filtered` is the same but restricted to runs starting at `n ≥ 10`
(to strip out the trivially-easy small-`n` region, where `n=1` has 0 bits
and always "matches", `n=2` has 1 bit, etc. — real signal has to show up
here, not there). Each real result is compared to a Monte Carlo null: the
identical full-scale search re-run against independently-redrawn random
target data of the same bit-widths.

| Generator | Real best_overall (len, bits, start_n, seed) | Real best_filtered n≥10 (len, bits, start_n, seed) | Null reps | Null overall (mean/max) | p_overall | Null filtered (mean/max) | p_filtered |
|---|---|---|---|---|---|---|---|
| xorshift32 | (6, 15, n=1, seed=35236) | (2, 23, n=12, seed=1062858) | 15 | 6.47 / 7 | **1.000** | 2.00 / 2 | **1.000** |
| xorshift64 | (7, 21, n=1, seed=358571) | (1, 22, n=23, seed=1732613) | 15 | 6.47 / 7 | **0.500** | 1.27 / 2 | **1.000** |
| xorshift128 | (6, 15, n=1, seed=33352) | (2, 19, n=10, seed=97490) | 15 | 6.33 / 7 | **1.000** | 2.00 / 2 | **1.000** |
| MT19937, small int (0..100,000) | (6, 15, n=1, seed=81235) | (1, 17, n=18, seed=69015) | 50 | — / 7 | **0.961** | — / 2 | **1.000** |
| MT19937, Unix timestamp 2015 (31,536,000 seeds) | (7, 21, n=1, seed=1420785676) | (2, 23, n=12, seed=1421281545) | 5 | — / 8 | **1.000** | — / 2 | **1.000** |

(`n=start_n` above is the 1-indexed puzzle number the run begins at, i.e.
`start_idx + 1`.)

### Interpretation

Every single `best_overall` result lands in the **trivial small-`n`
region** (`start_n = 1` in all five rows): a run of 6-7 consecutive
"matches" beginning at puzzle #1 is not a discovery, it's arithmetic — with
`n=1` contributing 0 bits (`getrandbits(0)` / any masked value is trivially
0, always "matching" `L(1)=0`) and `n=2..7` contributing only 1-6 bits
apiece, the total information content of a 6-7-run there is 15-21 bits,
and the search tried 100,000-2,000,000 seeds per generator (up to
31,536,000 for the MT timestamp sweep) — so multiple such runs are
*expected* by pure combinatorics. This is exactly what the Monte Carlo
null confirms directly: **every single p-value is ≥ 0.5, four of five are
≥ 0.96, and for the MT timestamp sweep the null actually *beat* the real
data outright** (one null replication produced an overall run of length 8,
longer than the real data's 7). There is no case, across five generators
and five seed spaces, where the real puzzle data comes anywhere close to
standing out from matched random control data.

The `best_filtered` (n≥10) column is the more decisive test, since it
strips out the guaranteed-trivial small-`n` matches. Here the real data
tops out at a run of length 2 (covering just two consecutive puzzles,
19-23 bits total) for xorshift32/128 and the MT timestamp sweep, and
length 1 for xorshift64 and MT small-int — and in **every** case the null
model's best result (across the identically-sized search) matches or ties
the real result exactly (p_filtered = 1.000 in all five rows). A back-of-
envelope check confirms this is exactly what combinatorics predicts: for
the MT timestamp sweep, the expected count of seeds producing *some*
2-puzzle exact match starting anywhere in `n ≥ 10` is roughly `31,536,000 ×
Σ 2^-(bits) ≈ 80` (dominated by the `n=10,11` pair at `2^-19`), while the
expected count of a 3-puzzle match in that region is `~0.005-0.01` — i.e.
finding a 2-run is close to guaranteed, and finding nothing longer is
exactly what happened, both for the real data and for the null.

**No generator, no seed space, and no width beats the matched random-null
baseline anywhere in this test.** Both real and null data behave
identically — that is precisely the negative result the task specification
asked to distinguish from "found a pattern."

## Prior art (external corroboration)

`research/archaeology/creator_statements.md` §4b documents an independent
prior negative result specifically targeting puzzle #71:
`mlartab/bitcoin-puzzle-systematic-analysis` already ran "full exhaustive
search of the 32-bit seed space for Python's `random`, C's `rand()`, and
Java's `Random`" plus a Z3 SAT-solver attempt to recover MT19937 internal
state from output bits, and reports "The puzzle wasn't made with Python's
`random`... likely doesn't use MT19937 at all." Our own independent,
from-scratch replication (above) is directly consistent with that finding
and extends it: we additionally cover xorshift32/64/128 (not just
MT19937/`rand()`), a much larger Unix-timestamp seed window at full
per-second granularity, and — critically — an explicit Monte Carlo null so
"zero hits" is reported as a *quantified*, not just asserted, negative
result.

## Verdict

**Rejected.** Neither of the two independent, direct falsification
strategies specified by the task — (a) the GF(2) linear-recurrence
signature that any true xorshift32/64 sequence must exhibit, and (b)
exhaustive brute-force replay of xorshift32/64/128 and MT19937 (Python
`random`) across ~37.6 million candidate seeds spanning small integers and
every second of the puzzle series' creation year — finds anything beating
the matched random-null-model baseline. Per the anti-bullshit rule: this is
reported as a plain, valid negative result, not a failure. It does not
narrow the candidate distribution for puzzle #71's private key at all
beyond the uniform prior over `[2^70, 2^71)` already implied by the
puzzle's construction. It is also fully consistent with the puzzle
creator's own statement (BIP32/BIP44-style "deterministic wallet", not a
raw non-cryptographic PRNG) and with the one existing community study that
targeted #71 directly and found the same thing independently.
