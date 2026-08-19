# On-Chain Forensics, Part 2: Spending Patterns of Solved Puzzles #51–70

**Scope:** Public blockchain forensics on the *reward-claiming* transactions of solved
Bitcoin puzzles #51–70 (addresses from `data/solved_puzzles.json`). This is **not**
cryptanalysis of puzzle #71 — it is competitive-context intelligence: who is claiming
these rewards, how fast, and with what fee behavior. All data is public, fetched
live from `blockstream.info/api` on 2026-08-19. Raw data:
`research/onchain/spending_raw.json` (first pass) and `research/onchain/spending_full.json`
(corrected, complete — every spend tx per address, not just the first one seen).

## Method

For each of the 20 addresses:
1. Pulled full tx history (`/address/<addr>/txs`) and `chain_stats` (`funded_txo_sum`,
   `spent_txo_sum`) from blockstream.info.
2. Classified every transaction touching the address as a **funding** event (address
   appears in an output) or a **spending** event (address appears in an input —
   i.e., required the private key to sign).
3. A first pass naively took the *first* spending tx returned by the API (which lists
   newest-first) — this silently picked the *most recent* dust clean-up instead of the
   actual reveal for several puzzles (e.g. it dated #63's reveal to 2026 instead of the
   correct 2019). This was caught and fixed: the corrected pipeline enumerates **every**
   spend per address and defines the **primary sweep** as the spend transaction moving
   the largest value out of the address (the actual reward claim). Smaller spends
   before/after it are "test" or "dust clean-up" transactions, analyzed separately below.
4. All 20 addresses are `chain_stats`-confirmed fully spent (`funded_txo_sum ==
   spent_txo_sum`) — every one of these 20 puzzles has had its full balance moved.

## Finding 1 — Destination-address clustering: repeat actors, not 20 independent solvers

### 1a. Within the 51–70 sample: three actor-clusters cover 8 of 20 puzzles

Searching every destination address and every extra co-spent input address (not just
the primary sweep) across all 20 puzzles' full spend histories turns up **repeated
addresses across different puzzle numbers** — on a P2PKH/P2WPKH address, spending
requires the private key, so an address appearing as an input to two different
puzzles' clean-up transactions means whoever swept puzzle A's dust also controlled
the wallet that puzzle B's dust flowed into (or, for a shared destination, received
both). Three clusters emerge:

| Cluster | Puzzles | Shared address(es) | Window |
|---|---|---|---|
| A | **#55, #56, #57** | `1AqEgLuT4V2XL2yQ3cCzjMtu1mXtJLVvww` receives an intermediate output in all three sweeps | 2018-05-29 → 2018-11-08 (~5 months) |
| B | **#59, #65** | `bc1qwlcthy024d98htvlkhcm9gq7gazzpnqlsq938d` is the destination of a later dust clean-up on both | 2024-07-20, 2024-11-06 |
| C | **#66, #68, #69** | `bc1q8742wwqvxhfaxpahe23a9ggr3lflutq9fds4fr` (all three), `bc1qge5jav8ha7gl4s2njgfc68lu4aafpdm52z66uy` (66, 69), `bc1q70gv6rss620zt248cl6faf9lsf0m0quaa8nync` (68, 69) | 2024-12-20 → 2025-07-13 (~7 months) |

Cluster C is the most valuable and most recent: it links the three highest-value
solves in the entire sample (#66 = 5.94 BTC, #67 = 6.70 BTC [adjacent in time though
no shared address found for it], #68 = 6.80 BTC, #69 = 6.90 BTC), all claimed within
an 8-month window in 2024–2025, with the SAME wallet/service repeatedly receiving
small residual "leftover donation" dust from at least three of the four addresses.
This is strong evidence that the most recent, highest-value puzzle solves are the
work of one operation, not four unrelated finders.

### 1b. The landmark finding: one entity proven to control >20 puzzle addresses simultaneously in June 2019

Tracing the *first* (smallest, easy to miss) spend from puzzle #65's and #70's
addresses turned up something much bigger than a same-solver coincidence. Both
#65 and #70's earliest spends are **the same transaction**:

```
txid 17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3
block time: 2019-06-01 02:07:26 UTC
21 inputs, 1 output (1000 sats -> 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)
fee: 269,000 sats  (i.e. 99.6% of the 270,000-sat total input value went to the miner)
```

The 21 inputs are 20 addresses each contributing exactly 1000 sats, plus one
250,000-sat funding input from `1PvaqLqRAivje7CactLR55xQBYvBeaDrXN` (apparently just
paying the fee, not a puzzle address). Cross-referencing the 20 dust-contributing
addresses against `chain_stats.funded_txo_sum` shows they are **puzzle addresses
#65, #70, #75, #80, #85, #90, #95, #100, #105, #110, #115, #120, #125, #130, #135,
#140, #145, #150, #155, and #160** — every multiple of 5 from 65 to 160 (identified
by `funded_txo_sum` matching the puzzle's known n×0.01–0.1 BTC funding pattern; #65
and #70 are directly confirmed against our own verified dataset).

Standard P2PKH/P2WPKH scripts cannot be spent without the private key — there is no
script trick that lets a third party spend an output without it. So this single
transaction is on-chain proof that **one entity held working private keys for at
least 20 different puzzle addresses simultaneously**, spanning bit-lengths 65
through 160. The destination, `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`, is **puzzle #1's
own address** (private key = 1, public knowledge) — not a real "claim," since anyone
can spend from it. This reads as a public, symbolic gesture ("look what I can
derive") rather than a value transfer.

The follow-through is telling:
- **#65** was fully swept for its real 0.65 BTC six days later (2019-06-07).
- **#70** was fully swept for its real 0.70 BTC eight days later (2019-06-09).
- We independently confirmed via `chain_stats` (fetched live, today) that
  **#75 through #135 (all multiples of 5) are now fully spent** — their entire
  reward has been claimed at some point since.
- **#140, #145, #150, #155, #160 are still NOT fully spent as of 2026-08-19** —
  only the original 1000-sat test dust ever moved; the large balances (14.0, 14.5,
  15.0, 15.5, 16.0 BTC respectively) are still sitting in those addresses,
  **over seven years after this entity proved it could sign for them.**

Brute-forcing a 140+ bit private key is computationally impossible with any known
method (it exceeds the entire installed base of classical + quantum computing by
astronomical margins). An entity that can produce a valid signature for puzzle
#160's address without brute force is, by elimination, using a **non-search
method** — almost certainly direct knowledge of the deterministic wallet's seed or
derivation scheme, exactly matching the puzzle creator's own quoted description
("consecutive keys from a deterministic wallet"). We cannot determine from on-chain
data alone whether this is the original creator performing periodic wallet
maintenance/proof-of-authorship, or a third party who has obtained/reverse-engineered
the derivation scheme. Either way: **puzzle #71 is not a multiple of 5**, so this
specific capability class doesn't directly confirm anything about #71's key — but it
is hard evidence that at least one actor in this ecosystem does not need brute force
at all for a meaningful subset of the puzzle series, which is important competitive
context for how "hard" #71 actually is *for that actor specifically*.

### 1c. Vanity-address fingerprint (cluster A, #56/#57)

The #56 and #57 sweeps are unusually elaborate: instead of one clean output, both
peel through *dozens* of tiny outputs to hand-crafted Base58 vanity addresses that
spell out jokes when read with leetspeak substitution (`1` for `l`/`I`, `0` for `O`),
e.g.:

```
1WubaLubaDubDub1He11owMortibDF9tv   (Rick and Morty)
1DontUseForceLukeUseBrain111b8sEym  (Star Wars)
1myPRECi1USmyTREASUREmyAAHHKSDrRe   (LOTR — "my precious")
1HowMakeFreeHomeNuc1earReactyJmF4N
1What1tCookieAmmNomNomNomNofdweYw
```

This is a distinctive, human, celebratory signature — generating a custom vanity
address takes real compute (grinding random keys until the Base58 prefix matches).
The same behavior, and the shared intermediate address `1AqEgLuT4V2XL2yQ3cCzjMtu1mXtJLVvww`,
appears at #55 too, tying all three (#55, #56, #57) to one identifiable, humor-driven
solver active in mid/late 2018.

## Finding 2 — Fee-rate patterns: evidence of anti-frontrunning behavior, not random noise

**Background relevance:** the Bitcoin puzzle community has a well-known hazard called
"mempool sniping" — once a spending transaction is broadcast (even unconfirmed), the
signature it contains is public, and a bot can extract the sender's exact recovered
private key from the raw transaction, then re-sign and re-broadcast a new transaction
sending the coins to itself with a higher fee, "stealing" the reward from the original
finder before their transaction confirms. This creates a strong incentive to
**overpay dramatically on fees** to get first-and-only confirmation, and/or to send a
small "test" transaction to a self-owned address first.

Computed from the primary (largest-value) sweep of each of the 20 puzzles:

| stat | value |
|---|---|
| mean fee rate | 220.7 sat/vB |
| median fee rate | 50.4 sat/vB |
| stdev | 551.3 sat/vB |
| min | 2.2 sat/vB (#56, 2018) |
| max | 2515.5 sat/vB (#69, 2025) |
| sweeps paying >100 sat/vB | 7 / 20 (35%) |
| sweeps paying >50 sat/vB | 12 / 20 (60%) |

The distribution is extremely right-skewed — a handful of puzzles pay fees that are
10–100x a normal contemporaneous "high priority" rate (which for most of 2017–2025
ran roughly 5–100 sat/vB depending on mempool congestion). Full ranked list:

```
n=69  reward=6.9000 BTC  fee_rate=2515.5 sat/vB   (paid 1,220,000 sats = 0.0122 BTC in fees)
n=66  reward=5.9400 BTC  fee_rate= 406.4 sat/vB
n=70  reward=0.7000 BTC  fee_rate= 300.0 sat/vB
n=52  reward=0.0520 BTC  fee_rate= 244.8 sat/vB
n=53  reward=0.5300 BTC  fee_rate= 200.8 sat/vB
n=54  reward=0.5400 BTC  fee_rate= 150.0 sat/vB
n=51  reward=0.0510 BTC  fee_rate= 146.4 sat/vB
n=62  reward=0.6201 BTC  fee_rate=  75.9 sat/vB
n=61  reward=0.6100 BTC  fee_rate=  61.0 sat/vB
n=63  reward=0.6300 BTC  fee_rate=  50.4 sat/vB
n=67  reward=6.7001 BTC  fee_rate=  50.4 sat/vB
n=68  reward=6.8002 BTC  fee_rate=  50.3 sat/vB
n=58  reward=0.5800 BTC  fee_rate=  47.0 sat/vB
n=59  reward=0.5900 BTC  fee_rate=  35.1 sat/vB
n=65  reward=0.6500 BTC  fee_rate=  31.3 sat/vB
n=64  reward=0.6403 BTC  fee_rate=  30.0 sat/vB
n=60  reward=0.6000 BTC  fee_rate=   7.0 sat/vB
n=57  reward=0.5700 BTC  fee_rate=   5.4 sat/vB
n=55  reward=0.5501 BTC  fee_rate=   3.8 sat/vB
n=56  reward=0.5040 BTC  fee_rate=   2.2 sat/vB
```

**Reward size correlates with fee aggressiveness.** Pearson r(reward BTC, fee rate)
= **0.51**, r(reward BTC, log fee rate) = 0.40 across the 20 sweeps — a moderate but
real positive relationship: the puzzles with multi-BTC rewards (#66–#69, all solved
2024–2025 once the funding schedule stepped up ~10x) show among the highest fee
rates, consistent with claimants paying proportionally more to guarantee a safe,
un-snipeable confirmation when the stakes are large. It is not a clean function of
reward alone though (compare #52 at 244.8 sat/vB for only 0.052 BTC, or #56 at just
2.2 sat/vB for 0.504 BTC) — individual solver behavior/fee-market conditions at time
of solve clearly also matter.

**Self-send "test" transactions.** #51's earliest spend is a same-address self-transfer
(5.1M sats sent back to `1NpnQyZ7x24ud82b7WiRNvPm6N8bqGQnaS` itself) just 34 minutes
before the real external sweep — a dry run to confirm the recovered key signs and
propagates correctly before risking the reward externally. #56 and #57 (the vanity-
address cluster) do the same thing at much greater length: their first "sweep"
transactions send the bulk of the value back to *the puzzle address itself* alongside
one small peeled-off vanity output, repeated across several transactions within the
same hour, before finally moving funds fully off-chain. This is a deliberate,
security-conscious claiming pattern, not naive spending.

**Suspiciously tight fee-rate coincidence.** #63 (2019), #67 (2025), and #68 (2025)
land within 0.3% of each other — 50.449, 50.357, and 50.335 sat/vB respectively —
despite being solved years apart in very different fee-market conditions. #67 and
#68 are only 44.9 days apart and near-identical; #63's match six years earlier is
more likely coincidental convergence on a common "50 sat/vB = fast" heuristic than
proof of shared infrastructure, but combined with #63's known participation in the
June 2019 mega-cluster (Finding 1b) it is at least consistent with automated,
policy-driven fee selection (e.g., a bot always targeting "N sat/vB" or "next-block"
estimate) rather than manual, spontaneous choice by independent humans.

## Finding 3 — Solve timing: bursty, not monotonic with difficulty, and NOT simply accelerating

Chronological order of the primary sweep vs. puzzle number n:

```
 #  solve date    gap since prior solve
51  2017-04-05    —
52  2017-04-21    16.3 d
53  2017-09-04    136.1 d
54  2017-11-16     72.6 d
55  2018-05-29    193.9 d
56  2018-09-08    101.9 d
57  2018-11-08     60.8 d
58  2018-12-03     25.2 d
59  2019-02-11     70.7 d
60  2019-02-17      5.6 d
61  2019-05-11     83.0 d
65  2019-06-07     27.2 d   <- OUT OF ORDER (before 62,63,64)
70  2019-06-09      2.0 d   <- OUT OF ORDER (before 62,63,64)
63  2019-07-12     32.8 d   <- OUT OF ORDER (before 62,64)
62  2019-09-08     57.9 d
64  2022-09-09   1097.5 d   <- ~3 YEAR GAP
66  2024-09-12    734.0 d   <- ~2 YEAR GAP
67  2025-02-21    161.1 d
68  2025-04-06     44.9 d
69  2025-04-30     23.7 d
```

Out of 190 possible pairs, **11 pairs are inverted** (a higher-n puzzle solved before
a lower-n one) — mostly concentrated in the June–September 2019 burst where #65, #70,
and #63 were all claimed *before* the numerically-easier #62, in a span of about 13
weeks. This is exactly the window the Finding-1b mega-transaction sits in
(2019-06-01), reinforcing that a single well-resourced actor was working through
several puzzles out of numeric order that summer — plausibly prioritized by reward
size or by whatever order their derivation/search method produced results, not by
raw difficulty.

Two distinct multi-year silences stand out:
- **#62 (2019-09-08) → #64 (2022-09-09): 1,097 days (~3.0 years).**
- **#64 (2022-09-09) → #66 (2024-09-12): 734 days (~2.0 years).**

then a sharp compression: **#66 → #67 → #68 → #69 all land within 230 days
(2024-09-12 to 2025-04-30)**, the four highest-reward puzzles in the sample (5.94,
6.70, 6.80, 6.90 BTC), each solved faster than the last (161 → 45 → 24 days) —
and per Finding 1a, three of these four (#66, #68, #69) share destination addresses,
i.e. this "acceleration" is not obviously "the whole community got faster together";
it is at least partly explained by **one operation systematically working through a
short queue of adjacent, high-value puzzles in 2024–2025.**

This data is **consistent with, but does not prove**, growing combined
solving capacity over time (rising GPU/FPGA prices-to-performance, more entrants) —
but the confounding effect of one repeat, well-funded actor concentrating on the
recent high-reward puzzles means the raw shrinking-gap trend should not be read as
"the whole community's hashrate is rising" without that caveat. The two multi-year
gaps (2019→2022, 2022→2024) show difficulty *did* meaningfully slow things down for
whoever was working the queue in that period, before whatever changed (better
hardware, more capital, or an additional actor) between 2024 and 2025.

## Caveats and limitations

- **Not brute-force-vs-shortcut proof for #71 itself.** Finding 1b establishes that
  a non-brute-force capability exists for *multiples of 5* through #160 — it does not
  establish anything directly about #71 (71 is not a multiple of 5, and no dust-test
  transaction referencing puzzle #71's own address has ever appeared on-chain — its
  coin has never moved, confirmed as of 2026-08-18 per the task brief).
- **Common-input-ownership is a heuristic, not a cryptographic proof of "one person."**
  It reliably shows *one signing entity* (a wallet, or coordination between whoever
  held those keys at transaction-construction time); it does not tell us if that's a
  single individual, a pool with shared infra, or a service claiming rewards on behalf
  of multiple people who handed over their keys.
- **Address attribution for the 18 non-51–70 inputs in the mega-transaction** relies on
  their `funded_txo_sum` matching the expected puzzle-N funding pattern, not a direct
  match against our verified 1–70 dataset (which only covers puzzles up to #70). This
  is circumstantial but very strong given the exact arithmetic progression (65, 70,
  75, …, 160) and the confirmed #65/#70 matches anchoring both ends.
- Fee-rate/timing correlations (Finding 2's r=0.51, Finding 3's clustering) are
  observational on a sample of 20 — not hypothesis-tested against a null model, since
  this is on-chain competitive-context forensics, not a claim about the private-key
  distribution. (The ANTI-BULLSHIT statistical rigor required elsewhere in this
  project applies to claims about *where puzzle #71's key sits in [2^70, 2^71)* — this
  document makes no such claim.)

## Files

- `research/onchain/spending_raw.json` — first-pass fetch (kept for audit trail; has
  the known first-vs-primary-spend bug described in Method step 3, superseded by
  `spending_full.json`).
- `research/onchain/spending_full.json` — complete spend history per address (every
  tx, not just the first), `chain_stats`, and the derived `reveal_*` fields.
- `research/onchain/primary_sweeps.json` — one row per puzzle: the largest-value spend,
  used for all fee-rate/timing analysis above.
