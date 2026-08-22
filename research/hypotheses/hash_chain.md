# Hypothesis: Hash / HMAC-based key derivation (SHA256 salted, hash chain, or BIP32 non-hardened)

**Status: unfalsifiable from ciphertext-only data (as expected for a well-formed PRF); no evidence of exploitable structure.**

## The hypothesis class

Three related constructions were tested as a single class, because they share the
property that matters for this analysis:

- **(a) Salted hash**: `k_n = SHA256(seed || n) mod range_n`
- **(b) Hash chain**: `k_n = SHA256(k_{n-1}) mod range_n`
- **(c) BIP32 non-hardened child derivation**:
  `child_priv = (parent_priv + HMAC-SHA512(chaincode, parent_pub || n)[:32]) mod secp256k1_order`,
  restricted to whatever range puzzle `n` imposes.

With an **unknown** seed / master key / chaincode, all three are computationally
indistinguishable from independent uniform random integers in range under the
standard PRF assumption for SHA-256 and HMAC-SHA512. This is not a hopeful guess —
it is the literal security property those primitives are designed to provide. So
this hypothesis class makes exactly one falsifiable empirical prediction:
**the revealed free bits of k_1..k_70 should look statistically like fair coin
flips, with no exploitable serial structure.** It also makes one *structural*
prediction that is true by definition and not worth testing: it is
computationally infeasible to recover the seed/chaincode from 70 outputs (that
would break SHA-256/HMAC-SHA512 as a PRF/MAC), so this analysis does **not**
attempt seed recovery — only randomness-of-output testing, which is the only
thing about this hypothesis that data can speak to at all.

## Anti-bullshit compliance

Per the standing rule: nothing below is claimed as "useful" merely because it
"fits" the 70 known keys. Every statistic reported is checked against an
**explicit Monte Carlo null** (20,000 synthetic 70-puzzle datasets drawn as
independent uniform integers in each puzzle's correct `[2^(n-1), 2^n)` range —
i.e., exactly what this hypothesis class predicts and also exactly what the
puzzle creator's own stated construction predicts), and a walk-forward
comparison against the naive interval-midpoint baseline.

## Data and method

Source: `/home/user/Clawd71/data/solved_puzzles.json` (70 verified puzzles, #1-70).
For each puzzle `n`, the "free bits" are `lower_bits_hex` interpreted as an
`(n-1)`-bit binary string (puzzle `n=1` has zero free bits and is excluded from
bit/autocorrelation tests as degenerate). Code: `hash_chain.py` in this directory;
raw numeric results: `hash_chain_results.json`.

### Test 1 — Bit-frequency-by-position, chi-square with Bonferroni correction

Free bits are indexed from the MSB of the free-bit field (position 0 = the bit
immediately below the forced leading `1`), because this is the position that is
comparable across puzzles of different bit-length (it is the first bit whose
value the puzzle setter had freedom over, regardless of how many total free bits
puzzle `n` has). For each position `k`, pooled the bit across every puzzle with at
least `k+1` free bits, restricted to positions with **support ≥ 30** samples
(disclosed threshold — high positions have too few samples for a meaningful test
and are silently dropped rather than reported with misleading power).

- **40 positions tested** (support 30-69).
- Bonferroni-corrected α = 0.05 / 40 = **0.00125**.
- **0 / 40 positions significant** after correction. (Two positions — #8 support 61,
  p=0.0072; #29 support 40, p=0.0044 — are nominally below 0.05 uncorrected, which
  is exactly what you'd expect from 40 independent tests by chance (~2 false
  positives expected at α=0.05); neither survives Bonferroni, and Monte Carlo
  confirms below that a max-chi2 this large is unremarkable.)

### Test 2 — Serial autocorrelation between consecutive normalized keys

`normalized_n = lower_bits_n / 2^(n-1)` for `n=2..70` (68 consecutive pairs,
n=1 excluded as degenerate).

| statistic | value | asymptotic p | permutation p (20,000 resamples) |
|---|---|---|---|
| Pearson r | 0.0580 | 0.638 | 0.638 |
| Spearman r | 0.0543 | 0.660 | 0.659 |

No detectable linear or rank correlation between consecutive keys' relative
position in their interval.

### Test 3 — NIST-style runs test on concatenated free-bit sequence

All 2,415 free bits from puzzles #2-70 concatenated in order: 1,193 ones
(π = 0.4940, within the NIST SP 800-22 pre-check band), **1,231 runs**,
runs-test **p = 0.335**. No excess or deficit of runs vs. what a fair random
bitstream would produce.

### Monte Carlo null (20,000 synthetic datasets)

Each synthetic dataset draws, for every `n=1..70`, `lower_bits_n` uniformly at
random from `{0, ..., 2^(n-1)-1}` — the exact null that a hash/HMAC-based
generator (with unknown seed) and the puzzle creator's own stated "consecutive
deterministic-wallet keys" claim both predict. The real dataset's summary
statistics were compared against this null distribution:

| statistic | observed | null mean | MC p-value |
|---|---|---|---|
| max χ² across the 40 tested bit positions | 8.10 | 6.02 | 0.151 |
| # positions Bonferroni-significant | 0 | 0.044 | 1.000 |
| \|Pearson r\| (consecutive normalized) | 0.0580 | 0.0967 | 0.630 |
| \|Spearman r\| (consecutive normalized) | 0.0543 | 0.0968 | 0.652 |
| runs-test deviation from expectation | 23.67 | 19.72 | 0.335 |

**None of the five Monte Carlo p-values approach significance** (all ≥ 0.15, most
≥ 0.3-1.0). The real dataset is a completely unremarkable draw from the
uniform-in-range null — exactly what this hypothesis class predicts, and
equally what plain independent-uniform sampling (the creator's stated method)
predicts. This is expected, not a discovery.

### Walk-forward test

For each `N = 5..69`, fit on puzzles `2..N`, predict puzzle `N+1`'s normalized
position four ways, compare mean squared error over 65 predictions:

| predictor | MSE |
|---|---|
| **naive baseline (always guess 0.5, interval midpoint)** | **0.0736** |
| running mean of normalized_2..N | 0.0772 |
| last value (normalized_N, tests momentum/autocorrelation) | 0.1369 |
| OLS linear regression of normalized on n | 0.0888 |

**The naive midpoint baseline wins** — every "smarter" predictor built from
puzzles `≤N` does *worse* than just guessing 0.5. This is the walk-forward
signature of a process with zero exploitable serial structure, consistent with
(not merely "not contradicting") a PRF/hash-based generator.

## Analytical question: is BIP32 non-hardened derivation distinguishable from an ideal PRF given only child outputs?

**No — not given only child private/public key outputs, and not with 70 samples
or any polynomial number of samples, under standard cryptographic assumptions.**

Reasoning from first principles:

1. `child_priv = (parent_priv + HMAC-SHA512(chaincode, parent_pub || index)[:32]) mod n`
   is an **addition of a PRF output modulo the group order** `n` (secp256k1's
   order, a ~256-bit prime). HMAC-SHA512 is a PRF under the standard HMAC
   security proof (assuming SHA-512's compression function behaves as expected);
   its first 256 output bits, taken mod a ~256-bit prime that is extremely close
   to `2^256` (order/2^256 ≈ 0.9999999999999999), are statistically
   indistinguishable from uniform over `Z_n` — the "modular bias" from taking
   `HMAC output mod n` is astronomically small (< 2^-127) and undetectable by
   any test on 70 samples, or realistically any number of samples a physical
   computer could gather.
2. Adding a value indistinguishable-from-uniform to *any* fixed `parent_priv`
   (mod the group order) yields a value that is itself indistinguishable from
   uniform over `Z_n` — this is the classic "one-time-pad-style" masking
   argument: `X + U mod n` is uniform whenever `U` is uniform mod `n`,
   regardless of the distribution of `X`. So each child key looks uniform
   individually.
3. Chaining this across siblings/generations (`child_i` all derived from the
   same `parent_priv`/`chaincode`, or `child_{n+1}` derived from `child_n`) adds
   **no** correlation an adversary without the chaincode can detect, because
   distinguishing the HMAC outputs from independent random strings *is* the PRF
   distinguishing game — winning it non-negligibly better than guessing would be
   a break of HMAC-SHA512 as a PRF, a result that would be a major cryptographic
   result, not something 70 puzzle keys are going to demonstrate.
4. The one scenario where BIP32 non-hardened derivation *is* distinguishable/
   exploitable is the well-known attack where an attacker holds **both** a
   parent's public key *and* one non-hardened child's private key — then
   `chaincode` and hence every other child's private key is recoverable in
   closed form, because `HMAC-SHA512(chaincode, parent_pub||index)` becomes a
   *known* quantity once `chaincode` leaks via `child_priv - parent_priv`. This
   is irrelevant here: puzzle #71's parent would be puzzle #70 (or some earlier
   ancestor) under this hypothesis, but recovering that "parent" requires
   already knowing #70's *and* the wallet's chaincode/xpub, which are not public
   (only the address/pubkey-hash is on-chain for solved puzzles that HAVE moved,
   and #71 itself has never revealed even that). Nothing in the public dataset
   gives the chaincode.

So the analytical answer and the empirical results agree: **this hypothesis
class predicts exactly the featureless randomness observed, and the
observation cannot be used to distinguish "well-formed hash/HMAC derivation"
from "true uniform random sampling," nor can it be used to predict puzzle #71.**

## Verdict

**Unfalsifiable from ciphertext-only data** — distinct from "retained" (which
would imply the data actively supports this mechanism over alternatives) and
"rejected" (which would require a detected deviation from what the hypothesis
predicts). All three empirical batteries (bit-frequency-by-position, serial
autocorrelation, NIST runs test) came back statistically indistinguishable from
the uniform-in-range null across 20,000 Monte Carlo control datasets, and the
walk-forward test shows no feature derived from puzzles ≤N beats the naive
midpoint guess for puzzle N+1. This is the expected, uninteresting result for
any well-formed hash/HMAC-based generator — it neither confirms nor refutes
this specific mechanism over the creator's plainly-stated "just consecutive
deterministic-wallet keys," and critically **it offers no exploitable edge for
predicting puzzle #71's private key.** Any real reduction in the #71 search
space, if one exists, must come from a hypothesis this class of tests can
actually falsify (e.g., a low-entropy generator like an LCG or seq-counter,
tested by sibling agents) — not from this one, which is unfalsifiable by
construction once the seed is unknown.
