# Puzzle #71 — Verified Facts, Forensics, and Feasibility

All claims here are reproducible from this repository. Chain data is cached
under `data/raw_*.json`.

---

## 1. Target facts (independently derived, not taken on trust)

| Property | Value | How established |
|---|---|---|
| Address | `1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU` | output **70** of the 2015 genesis tx |
| HASH160 | `f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8` | base58check decode; confirmed by chain API |
| Interval | `[0x400000000000000000, 0x7FFFFFFFFFFFFFFFFF]` = `[2^70, 2^71−1]` | puzzle-n convention, verified against all 82 solved keys |
| Search space | 2^70 = 1 180 591 620 717 411 303 424 | — |
| Encoding | **compressed** P2PKH | 82/82 solved keys reproduce their address only when compressed |
| Balance | 7.10182686 BTC, unspent | chain |
| **Public key** | **NOT exposed** | `total_sent == 0`; absent from the 2019 exposure tx |

The last row is the decisive one and is developed in §3.

## 2. Dataset

`data/solved_puzzles.csv` / `.json` — **82 private keys**, each accepted only
after passing all of:

1. key lies in `[2^(n−1), 2^n − 1]`;
2. key → compressed pubkey → HASH160 → base58check equals the canonical address
   taken from genesis-tx output n−1 (whose value, n×100 000 sat, checksums the
   ordering);
3. where a public key was exposed on chain, the derived pubkey matches it byte
   for byte;
4. the whole derivation is reproduced by libsecp256k1 as a second
   implementation.

Zero candidates were rejected; one recalled key (#95) failed verification during
assembly and was replaced by a sourced value that passed all four checks.

**Known gap:** #135 was solved 2026-07-28 and its key is not yet published
anywhere I could find. It is the only solved puzzle missing from the dataset.

Solve status, corrected for two traps that inflate naive counts:

- `total_sent > 0` does **not** imply solved — the creator spent 1000 sat from
  every multiple of 5 in 2019, so #140–#160 look "spent" while still holding
  their full prize.
- #161–#256 have zero balance because the **creator reclaimed them** in 2017 to
  fund the prize increase, not because anyone cracked them.

Correct count: **83 solved** (1–70 consecutively, plus multiples of 5 up to 135).

## 3. On-chain forensics — why #71 is hard and #135 was not

Three creator transactions define the puzzle's history:

| Date | txid | Shape | Meaning |
|---|---|---|---|
| 2015-01-15 | `08389f34…cd15` | 1 in, **256 out**, v1, locktime 0 | genesis: output n−1 = puzzle n, value n×0.001 BTC |
| 2017-07-11 | `5d45587c…4164` | **97 in**, 109 out | reclaimed #161–#256 (96 addrs) + one non-puzzle input, to fund a 10× prize increase on #1–#160 |
| 2019-06-01 | `17e4e323…b3d3` | **21 in**, 1 out | spent 1000 sat from **exactly** #65, #70, #75, … #160 — all 20 multiples of 5 |

The 2019 transaction is the whole story of the solve order. Spending from an
address publishes its public key. For those 20 puzzles the attack collapses from
a HASH160 preimage scan costing O(2^(n−1)) to Pollard kangaroo costing
O(2^((n−1)/2)):

- #135 with a known pubkey ≈ 2^67 group operations — hard but done (2026-07-28).
- #135 *without* the pubkey would be 2^134 — permanently out of reach.

**#71 is not a multiple of 5, has never sent a transaction, and therefore has no
exposed public key.** Kangaroo and BSGS are unavailable; only the generic
2^70 HASH160 scan applies. Any tool or claim that proposes kangaroo for #71 is
category-error wrong.

This also explains the otherwise puzzling solve history: the consecutive
brute-force frontier is 64 → 66 → 67 → 68 → 69 (#65 and #70 fell to kangaroo in
2019), leaving **#71 as the next brute-force target**, open since 2025-04-30.

## 4. Is there exploitable structure? No.

Three independent lines of attack, all negative — details in
`research/generator_hypotheses.md`.

- **87 generator hypotheses** (counter hashing, brainwallets, hash chains, five
  classic LCG families, MT19937, BIP32, Electrum 1.x) — **all falsified**. A
  positive control was retained 71/71 and a negative control rejected, so the
  harness demonstrably can detect a true generator.
- **76 statistical tests** vs a uniform-in-interval null — **0 significant**
  after Holm or Benjamini-Hochberg. Raw p<0.05 count was 2, *below* the 3.8
  expected by chance.
- **Walk-forward validation**, 6 folds, 59 out-of-sample predictions — **no
  model beats uniform**. The best-looking model (per-bit bias, MSB-aligned,
  0.429) is matched or beaten by pure noise ~35% of the time, and its
  LSB-aligned mirror lands symmetrically *worse* than baseline at 0.579.

**Measured search-space reduction: 1.0×. The effective entropy of #71 is 70
bits.** Per Phase 7's brief, no Tier A/B/C ranking is published, because
producing one would mean dressing a uniform prior as evidence.

## 5. Feasibility

Expected work: 2^69 keys (median), 2^69.93 at the 95th percentile.

| Configuration | Rate | Expected time |
|---|---|---|
| **This machine** (4 vCPU Xeon, no GPU) — *measured* | 2.18 Mkeys/s | **8.6 million years** |
| 1× RTX 4090 class | ~1.5 Gkeys/s | ~12 500 years |
| 8× RTX 4090 rig | ~1.2×10¹⁰/s | ~1 600 years |
| ~1000-GPU pool | ~1.5×10¹²/s | ~12.5 years |

Empirical community throughput, inferred from observed solve-date gaps, has
grown from ~10⁷ keys/s (2015) to ~10¹³ keys/s (2025):

```
#66 -> #67  161.1 d   2.65e12 keys/s
#67 -> #68   44.9 d   1.90e13 keys/s
#68 -> #69   23.7 d   7.22e13 keys/s
```

At that recent-era range the community's expected time on #71 is **95 days to
64 years** — a spread that reflects genuinely noisy exponential solve times, not
false precision. #71 has been open for **476 days**, which sits unremarkably
inside that interval.

To bring #71 within one year on this machine would require an **8.6-million-fold**
search-space reduction — narrowing 2^70 to about 2^46. The measured achievable
reduction is 1×.

## 6. What was built

| Component | Status |
|---|---|
| `src/crypto.py` — independent secp256k1 + address pipeline | 1464 assertions pass, 0 fail |
| `src/engine.c` — batched-inversion HASH160 scanner | recovers known keys across thread counts and batch boundaries |
| `src/coordinator.py` — distributed work allocation | non-overlapping leases, expiry reclaim, short-unit rejection, 0600 hit handling |

Engine design: incremental EC addition (never a fresh scalar multiplication per
candidate), 1024 additions per shared modular inversion, SHA256 and RIPEMD160
specialised to their single fixed block, 4-byte HASH160 prefix rejection.

Two defects were found and fixed by testing rather than inspection: `fe_sub`
computed `a − b + p`, which overflows 256 bits; and `build_table` used point
addition for `G + G`, which divides by zero. A third — per-thread range rounding
leaving the tail of a range unscanned — was caught by a boundary test and is the
exact failure mode that would let a distributed search skip the key.

## 7. Honest bottom line

No tested hypothesis beats randomness. The puzzle is, as far as this program can
measure, exactly what its creator is quoted as saying: a crude measuring
instrument with no pattern. Solving #71 from this environment is not achievable
by 11 orders of magnitude; the realistic paths are contributing to a
GPU pool at ~10¹³ keys/s, or nothing.

Recovering the key would require either hardware not present here or a
structural break that three independent lines of evidence say does not exist.
