# Puzzle Funding Transaction Forensics

**Scope:** Puzzle #71 target `1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU`, plus a sample of solved
puzzles across the range (#1, #10, #20, #30, #40, #50, #60, #70), addresses taken from
`/home/user/Clawd71/data/solved_puzzles.json`.

**Method:** Direct queries against the public Blockstream Esplora API
(`https://blockstream.info/api/address/<addr>/txs` and `/txs/chain/<last_txid>` for
pagination beyond 25 results, `/api/tx/<txid>`, `/api/tx/<txid>/outspend/<vout>`). All
addresses were queried for their *complete* transaction history (paginated where >25 txs
existed) so the earliest-ever receiving transaction could be identified with certainty,
not just the most recent page. Raw JSON responses are preserved in the scratchpad for this
session; the key derived facts are reproduced below with exact txids so they are
independently re-verifiable by anyone against the same public API.

Fetched: 2026-08-19.

---

## 1. Headline result: one funding transaction for puzzles 1-71 (at least)

All 9 sampled addresses (#1, #10, #20, #30, #40, #50, #60, #70, #71) received their puzzle
principal in the **same single transaction**:

```
txid:         08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15
block height: 339085
block time:   2015-01-15T18:07:14 UTC
block hash:   0000000000000000188de542fd76b1676c4be6c380b39ddea119358c290cebd7
inputs:       1  (from 1Czoy8xtddvcGrEhUUCZDQ9QqdRfKh697F, 32.9 BTC in)
outputs:      256
total out:    32.896 BTC
fee:          0.004 BTC (400,000 sat)
```

This is one input consolidating 32.9 BTC, fanned out into 256 outputs in a single
transaction — a classic "one-shot batch payout" pattern, consistent with a script that
derived 256 addresses from a deterministic wallet and paid all of them in one transaction.

### Exact match check, all 71 sampled/available puzzles

For every puzzle N in {1,...,70} (all addresses we have verified key material for) plus
N=71 (target address), output index `N-1` (0-based) of tx `08389f34...` was checked
against both the expected address **and** the expected value:

| Check | Result |
|---|---|
| Puzzles checked | 71 (all of #1-#70 from the dataset + #71) |
| Exact match (address AND value at vout index N-1) | **71 / 71 (100%)** |
| Mismatches | none |

Value pattern: `vout[i].value = (i+1) * 100,000 sat = (i+1) * 0.001 BTC`, i.e. puzzle N was
funded with exactly `N * 0.001 BTC`. Confirmed for N=1 (0.001 BTC) through N=71 (0.071 BTC).
Output values continue climbing linearly all the way to output 255 (0.256 BTC), consistent
with the batch having been generated for up to 256 puzzle slots even though public
puzzle-difficulty tables/rewards beyond ~160 are not otherwise documented; that is outside
this task's scope and not further verified here.

**Sample of the matched rows** (full 71-row match confirmed programmatically):

| Puzzle N | vout index | Address | Value (sat) | Value (BTC) |
|---|---|---|---|---|
| 1  | 0  | 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH | 100,000   | 0.001 |
| 10 | 9  | 1LeBZP5QCwwgXRtmVUvTVrraqPUokyLHqe | 1,000,000 | 0.01  |
| 20 | 19 | 1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum | 2,000,000 | 0.02  |
| 30 | 29 | 1LHtnpd8nU5VHEMkG2TMYYNUjjLc992bps | 3,000,000 | 0.03  |
| 40 | 39 | 1EeAxcprB2PpCnr34VfZdFrkUWuxyiNEFv | 4,000,000 | 0.04  |
| 50 | 49 | 1MEzite4ReNuWaL5Ds17ePKt2dCxWEofwk | 5,000,000 | 0.05  |
| 60 | 59 | 1Kn5h2qpgw9mWE5jKpk8PP4qvvJ1QVy8su | 6,000,000 | 0.06  |
| 70 | 69 | 19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR | 7,000,000 | 0.07  |
| **71** | **70** | **1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU** | **7,100,000** | **0.071** |

---

## 2. Was puzzle #71 funded in the same original transaction, or separately/later?

**Same original transaction.** Puzzle #71's principal (0.071 BTC) is output index 70 of
`08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15`, the identical
transaction that funded puzzles #1-#70. There is no separate/later "official" funding
transaction for #71 — it was part of the same 2015-01-15 batch.

Confirmed unspent: querying `blockstream.info/api/address/1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU`
returns `spent_txo_count: 0` — the original 0.071 BTC output (and every later top-up, see
§4) remains fully unspent, consistent with "coin has never moved."

Explicitly checked the spend-status of that specific output:
`GET /api/tx/08389f34.../outspend/70` → `{"spent": false}`. The original puzzle #71 principal
sits untouched in the address to this day.

---

## 3. Does output order match increasing puzzle number?

**Yes, exactly**, for every puzzle checked (1-71): output index `i` (0-based) is puzzle
`i+1`, both by address and by the linearly-scaling value. This is strong, independently
verifiable on-chain evidence that:

- Puzzle addresses were generated and paid out in strict numeric sequence, in one script
  pass, in one transaction — not shuffled, not funded opportunistically over time, not
  reordered.
- This is consistent with (though does not by itself prove) the puzzle creator's stated
  claim that these are "consecutive keys from a deterministic wallet" — a deterministic
  wallet index that increments 1, 2, 3, ... and is paid out in that same iteration order
  would produce exactly this on-chain signature. It is a fact about **generation/funding
  order**, not about the numeric structure of the private keys themselves, and does not by
  itself leak any information about key #71's value — it is offered here purely as
  independently verifiable provenance, not as a cryptanalytic shortcut.

---

## 4. Puzzle #1's address: an unrelated, pre-existing transaction from 2013

Puzzle #1's private key is `1` — literally the secp256k1 generator point `G` — the single
most trivially-guessable private key that exists. Its address
`1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` has an extensive transaction history *outside* the
puzzle: **100 receiving transactions total** (of 197 fetched, spanning full pagination),
ranging from **2013-01-09 to 2026-07-15** — i.e. activity both well before the puzzle
existed and continuing to the present, presumably as recurring "gifts"/curiosity dust sent
by people demonstrating they can spend from the best-known private key in Bitcoin.

The single earliest transaction on this address predates the puzzle's official funding by
**over two years**:

```
txid:  9223da07e858c6f153fbb8a24db52374ca19d2639098207c71710610cfda808e
block height: 215848
block time:   2013-01-09T11:59:15 UTC
vin:   2 inputs (from 14H7EwyxZ1tzhVFYQDQw28ETLfJryLYVmy, 1ME3CFDckhzAknUhua4g8FLTVBfYp4wSqA)
vout:  2 outputs -- 0.00728968 BTC to 1AuzLKnuKaU8o3eVuydXEzNgN8weMEvgaQ (change),
                    0.03 BTC to 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

This looks like an ordinary 2-in/2-out wallet transaction that happened to send 0.03 BTC to
the well-known private-key-1 address, unrelated to puzzle infrastructure (no batch fan-out,
wrong shape, two years too early, no round `N * 0.001 BTC` value). That output was itself
swept the very next day (spent in tx `3da9b8e4a9c056b22d4fd09784402fd1caab1ecf621ba074efc20dc03ff04277`,
block 215929, 2013-01-10T02:54:44 UTC) — long before the 2015 puzzle even existed, so the
two histories never actually commingled inside an active puzzle balance.

**Conclusion:** this is noise from the address's fame/triviality, not evidence about puzzle
funding mechanics. The actual puzzle #1 principal is unambiguously the 2015-01-15 batch
transaction identified in §1, output index 0, and (as expected for the trivial key=1) it
was swept again in that very same block (339085) — see §5.

---

## 5. Puzzle #1 was drained in the same block it was funded

Checking the spend status of the puzzle-#1 output from the mega funding tx:

```
GET /api/tx/08389f34.../outspend/0
-> spent: true, spending txid ad12f6bc9019330dd2407e7ac5bfe7a261c0efe80cb278a6bb0c34f06ec12774
   block height: 339085 (same block as funding), block time: 1421345234 (same block time)
```

Puzzle #1's 0.001 BTC was claimed in the *same block* it was created in. This is exactly
what you'd expect for a private key of literal value `1` (bots/scripts scanning new blocks
for spendable trivial keys), and has no bearing on puzzle #71 (whose key is a ~71-bit
unknown, not brute-forceable this way). Included here only as confirmation the funding
identification methodology is sound (the mega-tx really is "the" puzzle funding event, not
an artifact).

---

## 6. Puzzle #71 address: crowd top-ups since 2015, but principal never moved

`1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU` address summary (`chain_stats` from Blockstream):

```
funded_txo_count: 56
funded_txo_sum:   710,182,686 sat  (~7.10182686 BTC)
spent_txo_count:  0
spent_txo_sum:    0
tx_count:         56
```

All 56 transactions ever received by this address are still fully unspent — matches the
task's premise that the coin has never moved. The **first** of the 56 is the official
0.071 BTC batch-funding output from §1/§2 (2015-01-15). The remaining 55 transactions are
later top-ups/donations (dates ranging 2015-01-15 through 2026-08-07, i.e. essentially up to
present day), pushing the balance from the original 0.071 BTC up to the ~7.10 BTC total
reward cited in the task brief. This is the well-documented community practice of adding
bounty incentives to unsolved higher-numbered puzzles; it is a change in *reward size* only,
not a second "generation" event, and none of it touches the original private key material.

---

## 7. Summary answers to the specific questions asked

| Question | Answer |
|---|---|
| Were puzzles funded in the same original tx (the "one big transaction" claim)? | **Confirmed** for #1-#71 (all sampled + all available dataset addresses): single tx `08389f34c9...`, block 339085, 2015-01-15T18:07:14 UTC, 256 outputs. |
| Exact block height / timestamp of that funding tx | Block **339085**, **2015-01-15 18:07:14 UTC** (block hash `0000000000000000188de542fd76b1676c4be6c380b39ddea119358c290cebd7`). |
| Does output order match increasing puzzle number? | **Yes, exactly** — output index `i` = puzzle `i+1` for all 71 checked, both by address and by the linear `N*0.001 BTC` value pattern. Strong, independently verifiable evidence of a single deterministic, sequential generation-and-payout pass, consistent with the creator's "consecutive keys" claim about *provenance*, not the key values themselves. |
| Was puzzle #71 funded in that same tx, or separately/later? | **Same transaction**, output index 70, value 0.071 BTC. No separate/later official funding event; only later voluntary community top-ups (§6), which don't touch the original key. |

### Caveat / anti-overclaim note

This on-chain evidence is a verifiable **fact about how the puzzle set was generated and
paid out** (sequential batch, single transaction, strictly increasing order). It is
independent of, and gives **no shortcut into**, the cryptanalytic question of what the
71-bit private key value actually is. It corroborates the *low-order-bit* of the creator's
claim ("consecutive... from a deterministic wallet") as far as address-generation order and
payout order go, but says nothing about whether the underlying key-derivation index maps
onto key values in a way that reduces the effective search space below 2^70 — that question
is addressed separately by the statistical/cryptanalytic phases of this project, under the
same anti-bullshit, null-model-tested standard.
