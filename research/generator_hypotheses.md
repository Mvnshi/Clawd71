# Generator Hypothesis Ledger — Bitcoin Puzzle #71

Every hypothesis tested, with its outcome. Nothing is removed once entered, so
failed ideas are not silently retried.

Reproduce with:

```
PYTHONPATH=src python3 src/generators.py     # Phase 2
PYTHONPATH=src python3 src/analysis.py       # Phase 3
PYTHONPATH=src python3 src/walkforward.py    # Phase 4
PYTHONPATH=src python3 src/null_calibration.py
```

---

## Primary-source evidence

The most-cited statement attributed to the puzzle creator:

> "A few words about the puzzle. There is no pattern. It is just consecutive
> keys from a deterministic wallet (masked with leading 000...0001 to set
> difficulty). It is simply a crude measuring instrument, of the cracking
> strength of the community."
>
> — attributed to `saatoshi_rising`, Bitcointalk

**Provenance caveat, recorded deliberately.** I could not retrieve this text
from a Bitcointalk page directly; the fetches of topics 1306983 and 5218972
did not surface it. It is reproduced consistently across multiple secondary
sources, and one of those sources itself flags the attribution as
"influential but unverified". Treat it as a strong lead, not as fact. The
program therefore tests the claim rather than assuming it.

Two things *are* established directly from the blockchain and need no trust:

| Fact | Evidence |
|---|---|
| Puzzle #n's address is output n−1 of the 2015 genesis tx | `08389f34…cd15`, 256 outputs, output n−1 pays exactly n×100 000 sat — the value is a checksum on the ordering |
| Addresses use **compressed** public keys | 82 verified keys reproduce their address only under compressed encoding |
| #71's public key has never been exposed | address total_sent = 0; #71 absent from the 2019 exposure tx |
| Multiples of 5 (65…160) had pubkeys deliberately exposed | tx `17e4e323…b3d3`, 2019-06-01, spends 1000 sat from exactly those 20 addresses |

That last row explains the entire out-of-order solve history and is the single
most strategically important fact in this document.

---

## Testing method

For a candidate generator producing values `v_n`, the hypothesised puzzle key is
`mask(v_n, n)`. Three masking conventions and three index offsets (0, ±1) are
tried, and the best-scoring variant is kept — with the chance expectation
inflated accordingly.

Candidates are screened on the low `min(24, n−1)` bits. A genuine generator
matches every puzzle; a false generator matches a given puzzle with probability
2^−24 (less for small n, which is why the expectation is summed per-puzzle
rather than assumed uniform). Retention threshold: ≥2 hits.

**Harness controls.** A positive control (a generator defined to return the true
keys) is retained at 71/71, and a negative control (fresh `secrets.randbits`
values) is rejected. Without both, the rejections below would be unfalsifiable.

---

## Phase 2 results — 87 hypotheses, 0 retained

| Family | Variants | Result |
|---|---|---|
| Counter / arithmetic progression | 1 | rejected, 0 hits |
| SHA256(counter), BE / LE / ASCII / 0-based / double | 5 | rejected, 0 hits |
| Brainwallet `SHA256(template)` | 8 templates | rejected, 0 hits |
| SHA256(seed ‖ counter), SHA256(counter ‖ seed) | 14 | rejected, 0 hits |
| Hash chain SHA256ⁿ(seed) | 7 seeds | rejected, 0 hits |
| LCG: glibc, MSVC, Numerical Recipes, MINSTD, java.util.Random | 25 | rejected (see note) |
| MT19937 (Python `random.Random`), 1/3/8 words per key | 18 | rejected, 0 hits |
| BIP32 hardened children m/i′ | 6 seeds | rejected, 0 hits |
| Electrum 1.x deterministic derivation | 3 seeds | rejected, 0 hits |

**Note on the one non-zero result.** `LCG glibc rand, seed=2015` produced a
single hit — at puzzle **#14**, where the screen is only 13 bits wide. Chance
expectation is 0.0088 hits per hypothesis, so across 87 hypotheses ≈0.77 hits
were expected. Observing exactly one is the null model behaving normally. It is
recorded here specifically so nobody rediscovers it and mistakes it for a lead.

### Structural falsifications

- **"One master value truncated to different widths."** If every puzzle were the
  same number masked to different lengths, then `key_n mod 2^(m−1) == key_m mod
  2^(m−1)` for all m < n. Observed: **19 of 3081 pairs** consistent, where the
  hypothesis requires 3081/3081. Falsified outright.
- **Common divisor among consecutive offset differences.** gcd = 1 over 62
  differences, exactly as expected for unrelated values. No shared modulus.

### What Phase 2 does *not* rule out

If the creator's statement is literally true, the underlying wallet is seeded
with 128–256 bits of real entropy, and each puzzle key is a *different* wallet
key truncated. Distinct truncated keys share no recoverable relationship, so the
hypothesis is **consistent with the data and simultaneously useless** — it
predicts exactly the structurelessness observed. Confirming it would require the
wallet seed, which is not derivable from the puzzle keys. This is the honest
ceiling on Phase 2.

---

## Phase 3 — statistical battery (76 tests)

Null model: offsets iid uniform on [0, 2^(n−1)). Multiplicity handled with
Holm (FWER) and Benjamini-Hochberg (FDR).

| | |
|---|---|
| tests run | 76 |
| p < 0.05 uncorrected | **2** (chance expectation 3.8 — *fewer* than expected) |
| significant after Holm | **0** |
| significant after BH (5% FDR) | **0** |

Most extreme single result: bit bias at MSB−8, 23/73 ones, raw p = 0.0021 —
which Holm corrects to p = 0.16. This is the canonical shape of a numerological
"discovery": impressive in isolation, unremarkable as the minimum of 76 tests.

Tests covered: KS and Anderson-Darling uniformity, monobit, runs, per-bit bias
at 64 positions (MSB- and LSB-aligned), Hamming weight, lag-1/lag-2 serial
correlation, trend vs puzzle number, byte-value chi-square, low-k and top-k
block distributions.

---

## Phase 4 — walk-forward validation (the part that decides everything)

Metric: expected fraction of the interval scanned before reaching the true key,
under the model's own candidate ordering. 0.5 = no better than uniform.
Estimated by Monte Carlo over uniformly drawn candidates. Six folds, 59
out-of-sample predictions.

| model | pooled mean | verdict |
|---|---|---|
| per-bit-position bias (MSB-aligned) | 0.429 | not significant |
| Hamming-weight prior | 0.483 | not significant |
| **uniform (baseline)** | **0.500** | — |
| lag-1 autoregression | 0.505 | not significant |
| KDE of normalized position | 0.508 | not significant |
| linear trend | 0.519 | worse than baseline |
| per-bit-position bias (LSB-aligned) | 0.579 | worse than baseline |

The MSB-aligned bit-bias model looks like a 14% reduction. Two things kill it:

1. **Its mirror image is equally wrong in the other direction.** LSB-aligned
   scores 0.579 — as far *above* 0.5 as MSB-aligned is below. Two arbitrary
   alignments of one idea landing symmetrically around the baseline is the
   signature of noise, not of structure.
2. **The explicit null says so.** Replacing the real keys with uniform random
   keys and re-running the identical pipeline 100+ times: the best-of-seven
   models averages **0.442** on random data, and reaches 0.4294 or better
   **≈35% of the time**. The observed "best model" is what noise produces
   routinely.

**No model achieves out-of-sample search-space reduction. Measured reduction:
1.0×.**

---

## Standing conclusion

The solved-key sequence is statistically indistinguishable from uniform random
draws within each interval. 87 generator hypotheses are falsified; the one
family consistent with the evidence (a seeded deterministic wallet) yields no
exploitable structure by construction.

The effective entropy of Puzzle #71 remains **70 bits**. Search-space
prioritisation is not justified by any evidence gathered here — Tier A through
Tier D would all be the same tier, and any "ranked region" produced would be
decoration over a uniform prior.

---

## Ideas explicitly retired (do not retry without new evidence)

- Any claim that solved keys "look like" they follow a pattern, absent an
  out-of-sample test.
- Per-bit-position bias as a search prioritiser — measured, null-calibrated,
  dead.
- Nested-truncation / single-master-value schemes — structurally falsified.
- Small-integer-seeded MT19937 and classic LCGs — swept, nothing.
- Reading anything into the 2017 and 2023 top-up transactions as key hints;
  they are prize-funding events (see `research/findings.md`).

## Open leads that would change the picture

- **#135's private key** (solved 2026-07-28, not yet published anywhere I could
  find). One more sample does not change a 70-bit search, but it is the only
  new data point in the pipeline.
- **A wider seed sweep** over MT19937 / LCG seed spaces (2³²) implemented in C.
  Cost is hours, prior probability is low, and success would be visible only if
  the creator used an unseeded-or-trivially-seeded RNG — which the "deterministic
  wallet" statement argues against. Logged as low priority, not as promising.
