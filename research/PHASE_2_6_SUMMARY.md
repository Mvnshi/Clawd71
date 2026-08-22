# Bitcoin Puzzle #71 — Phase 2-6 Research Summary

**Target:** `1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU`, private key in
`[2^70, 2^71)`, unsolved as of 2026-08-18, ~7.10 BTC. Never moved — no
public key exposed on-chain, so kangaroo/BSGS methods do not apply.
This document is the honest, non-hyped synthesis of everything found in
the generator-hypothesis (Phase 2), statistics (Phase 3), walk-forward
(Phase 4), archaeology (Phase 5), and on-chain forensics (Phase 6)
phases of this research program.

---

## (a) Headline finding: no out-of-sample predictive power found, anywhere

**No hypothesis, statistic, or model tested in this entire research
program beat random guessing on withheld/held-out puzzle data.** This is
stated first and plainly, per the project's anti-bullshit rule, because
it is the single most important fact in this report — not a footnote.

Six formalized generator hypotheses were implemented and tested end to
end against the 70 cryptographically verified solved puzzles
(`data/solved_puzzles.json`), each with real Monte Carlo null models
(10,000-20,000+ simulated control datasets per test, matched to the
exact interval structure of the real data) and, where applicable,
walk-forward out-of-sample checks:

| Hypothesis | Verdict | Walk-forward result |
|---|---|---|
| Sequential/arithmetic counter | rejected | beat naive-midpoint baseline in 2/5 splits (coin flip) |
| Linear congruential generator (LCG) | rejected | beat baseline at 1/5 moduli tested, 0/132 exact hits |
| xorshift / Mersenne Twister PRNG | rejected | longest exact match outside trivial region: 2 puzzles, out of ~37.6M seed/generator combinations searched |
| Hash / HMAC / BIP32 chain | unfalsifiable from data alone, zero exploitable structure | naive midpoint was the single *best* of 4 candidate predictors |
| Cross-puzzle bit/byte persistence | rejected | beat baseline in 2/7 splits, sign-unstable fitted slope |
| Timestamp / block-hash seeding at creation | rejected | scored **below** the 0.5 chance baseline on held-out puzzles 51-70 |

Three additional statistical batteries (bit-frequency/runs,
Hamming-weight/distance, modular/polynomial/recurrence search) were run
independently of the six named hypotheses, covering per-bit-position
bias, cross-key bit reuse, modular residues, low-degree polynomial
trends, and exact small-order linear recurrences. **All returned clean
null results** — every corrected p-value was well above 0.05, several
using an assumption-free, correlation-aware Monte Carlo family-wise
correction (not just Bonferroni) specifically to guard against the
"testing enough things eventually finds something" trap.

The dedicated Phase 4 walk-forward validation (3 folds: train ≤40/test
41-50, train ≤50/test 51-60, train ≤60/test 61-70) found **no
hypothesis to formally test**, because none survived Phase 2/3 — fitting
a rejected model to a train/test split would manufacture a result the
anti-bullshit rule explicitly forbids. As a sanity check, the raw
held-out normalized-key statistics were computed directly: means 0.428,
0.630, 0.566 and standard deviations 0.218, 0.291, 0.298 across the
three folds, scattering around the uniform-distribution reference (mean
0.5, std 1/√12 = 0.2887) with no consistent trend — exactly consistent
with chance.

One genuinely useful methodological finding came out of this process: an
early version of the LCG test's Monte Carlo null (GCD/determinant
modulus-recovery) produced an apparently significant result (p=0.0005)
purely from an uncontrolled confound — small-`n` puzzles have
mechanically forced trailing-zero bits from the varying `2^(n-1)`
denominator, unrelated to any generator. Once the null was corrected to
match that structural feature, the result flipped to fully
non-significant (p=1.0000), independently confirmed on an `n≥20`
subset immune to the confound. This is exactly the kind of spurious
"pattern" the anti-bullshit rule is designed to catch, and catching it
here increases confidence that the other negative results are real
negatives, not artifacts of a too-permissive null.

**Bottom line: every angle tried — arithmetic, algebraic (LCG),
algorithmic (xorshift/MT19937 PRNG replay across ~37.6 million
seed/generator combinations), cryptographic (hash/HMAC/BIP32, ruled
unfalsifiable rather than confirmed), cross-puzzle bit correlation, and
timestamp/block-hash seeding (exhaustively searched across all 5.1
million candidate seconds in the Jan-Mar 2015 creation window) — failed
to beat chance out of sample.**

---

## (b) What archaeology found about the creator's stated method

The task's quoted creator statement — *"There is no pattern. It is just
consecutive keys from a deterministic wallet (masked with leading
000...0001 to set difficulty). It is simply a crude measuring
instrument, of the cracking strength of the community."* — was traced to
a specific, dateable primary source: BitcoinTalk account `saatoshi_rising`
(profile `u=991321`), registered 2017-04-27T05:43:11Z, with exactly one
lifetime post made 56 minutes later at 2017-04-27T06:41:08Z containing
this exact text.

**Corroboration status: medium-high, not fully verified.** The quote's
wording is confirmed directly from the account's post history and
triangulates identically across many independent secondary
reproductions (e.g. an X/Twitter repost from 2024). It is **behaviorally
corroborated**: the same post promised to move funds from puzzles
#161-256 down into the unsolved lower range, and on 2017-07-11 that
exact on-chain movement happened — strong circumstantial evidence the
poster had genuine control over the puzzle series. However, the
statement is **not cryptographically signed** by the original
puzzle-funding address, so the poster's identity as *the* creator (as
opposed to someone with privileged knowledge, or the creator using a
pseudonym) remains formally unproven. A speculative 2020 forum thread
floats "saatoshi_rising is Satoshi Nakamoto" but supplies no new
evidence and was recorded only as color, not fact.

Two important things this statement gets right, independently verified
on-chain rather than by trusting the claim:
- **"Consecutive keys" / generation order** is independently confirmed:
  the single 2015-01-15 funding transaction pays puzzle `n`'s address
  exactly `n × 0.001 BTC` at output index `n-1`, for all 71 checked
  puzzles with zero mismatches — strong evidence of one deterministic,
  sequential generation-and-payout script.
- **"Masked with leading 000...0001"** was independently visible on-chain
  from day one (contemporary 2015 forensic write-ups noted the
  structure), so this part of the claim does not depend on trusting the
  2017 statement at all.

What remains **unverified** (and what this research program tested and
found no support for): the specific numeric mechanism behind "a
deterministic wallet." A literal sequential/arithmetic counter reading
of that phrase was explicitly tested and **rejected** (Hypothesis 1 in
`generator_hypotheses.md`) — real consecutive-puzzle deltas show no
shared constant step across 60 testable pairs, contradicting the
simplest literal interpretation while remaining consistent with the
statement's own "no pattern" framing (i.e., consistent with each key
being an independent draw from a real HD wallet's derivation, which is
cryptographically indistinguishable from random to an outside observer
by design — see the `hash_chain` hypothesis's unfalsifiability finding).

Archaeology also surfaced and **ruled out** several concrete alternative
mechanisms:
- Small-seed PRNG (Python `random`/C `rand()`/Java `Random`, MT19937
  state recovery via Z3 SAT solver) — ruled out by an independent prior
  community study (`mlartab/bitcoin-puzzle-systematic-analysis`)
  targeting puzzle #71 specifically, and independently re-confirmed
  from scratch in this program's `xorshift_mt` hypothesis test.
- bitaddress.org's "Bulk Wallet" tab — ruled out by direct source
  inspection: its numeric index is only a CSV row label, never fed into
  key derivation, despite superficially matching the "sequential
  index" narrative.
- A `saatoshirising.wiki` site claiming to be the creator and soliciting
  a "$5000 contribution" to reveal puzzle #71's key was identified and
  flagged as a scam/phishing page, unconnected to the verified 2017
  account — recorded as a warning, not a lead.

Two concrete, testable specific mechanisms were flagged in archaeology
as **not yet run to completion** and remain open follow-up work, not
part of this phase's tested/rejected set: Electrum's Type-1
`old_mnemonic.py` additive scheme, and the classic Type-1
deterministic-wallet formula `SHA256(masterstring + str(n))`. Both
require a dictionary/guessing attack on an unknown seed/passphrase
rather than pure statistical pattern-mining of the 70 known keys, so
they were not resolved by the Phase 2 statistical hypothesis tests (see
`hash_chain`'s unfalsifiability note) and are flagged for anyone
continuing this research.

**In short: the "consecutive" and "masked leading bit" parts of the
creator's claim are independently on-chain-verified; the deeper claim
that this makes the key values themselves patternless-but-derivable by
some accessible formula was tested every way this program could devise,
and no exploitable structure was found — which is itself consistent
with, not contradictory to, "there is no pattern."**

---

## (c) What on-chain forensics found, and whether it constrains the generator

On-chain analysis (Phase 6) focused on funding and spending patterns
across the wider puzzle series (with emphasis on puzzles #51-70 and
puzzle #71 itself) using live blockstream.info data re-fetched
2026-08-19. Key findings:

1. **Puzzle #71's funding history has no anomaly.** It was funded in the
   identical single 2015-01-15 mega-transaction as puzzles #1-70 (output
   index 70, 0.071 BTC), remains fully unspent (`spent_txo_count: 0`
   across all 56 lifetime receiving transactions), and its current
   ~7.10182686 BTC balance is explained entirely by 55 later voluntary
   community donations/top-ups (spanning 2015 through 2026-08-07), not
   any second "generation" or re-funding event.

2. **A single entity has proven control of 20 puzzle private keys
   simultaneously** (multiples of 5 from #65 to #160), demonstrated by a
   June 2019 transaction consolidating 1000-sat test spends from all 20
   addresses in one transaction. Since brute-forcing a 160-bit key is
   computationally impossible, this confirms at least one actor in this
   ecosystem has a non-search method for a meaningful subset of the
   series — important competitive context, but **puzzle #71 is not a
   multiple of 5 and has never had a dust-test transaction**, so this
   does not directly imply #71 is already known to this or any actor.

3. **Reward-destination clustering:** three distinct repeat-operator
   clusters account for 8 of the 20 puzzles sampled in the #51-70 range,
   including all three of the most recent, highest-value solves (#66,
   #68, #69, worth 5.94/6.80/6.90 BTC respectively) within one 2024-2025
   operation. This means the current competitive field for a high-value
   unsolved puzzle like #71 (~7.10 BTC) is likely dominated by a small
   number of well-resourced, serious operators rather than a broad
   crowd — an operational fact, not a cryptanalytic one.

4. **A distinct human solver was identified by vanity-address "troll
   signature"** (puzzles #55-57, hand-ground Base58 addresses spelling
   pop-culture jokes), contrasted against more clinical, high-fee,
   likely-automated behavior in the 2024-2025 cluster — useful color on
   who is competing for these puzzles, not on the generator.

5. **Fee-rate behavior indicates deliberate anti-frontrunning
   ("mempool sniping") defense** by serious solvers (mean 220.7 sat/vB,
   max 2515.5 sat/vB for the #69 claim, i.e. 0.0122 BTC paid in fees
   alone), including same-address "test" transactions before the real
   sweep in several cases. Anyone eventually solving #71 should expect
   and plan for this same threat.

6. **Solve timing is bursty and non-monotonic with difficulty** — not a
   clean signal of accelerating community-wide capacity. The apparent
   2024-2025 acceleration is partly explained by one repeat operator
   working through a queue of adjacent high-value puzzles rather than
   broad-based progress; two multi-year silences (2019-2022, 2022-2024)
   show difficulty genuinely slowed whoever was working the series in
   those windows.

**Does any of this constrain the generator? No.** Every on-chain finding
in this phase is about funding provenance, spending behavior, and solver
identity/competitive dynamics — none of it touches the numeric structure
of unsolved private keys, and none of it was used (or is usable) as
input to narrow the candidate distribution for #71's key value itself.
The one item most relevant to generator hypotheses — the funding
transaction's exact block time/hash/height — was already fed into the
`timestamp_creation` hypothesis test and found to produce no better than
chance predictions (see above and `generator_hypotheses.md` §6). The
20-key-control finding (#2 above) is important *competitive* context
(another party may have an advantage via a non-search method on other
puzzles) but supplies no technical lead into #71's key value, since #71
falls outside the demonstrated multiples-of-5 pattern of that actor's
known control set.

---

## (d) Effective search-space reduction for Puzzle #71

**0 bits.** No hypothesis survived walk-forward validation, and no
statistical test showed a corrected-significant deviation from a
uniform-random null. The honest, final answer is:

> **The candidate interval for Puzzle #71's private key remains the
> full `[2^70, 2^71)` — 2^70 (≈1.18 × 10^21) candidates — uniformly
> weighted by all evidence gathered in this research program.** No
> region of that interval is more or less likely than any other based
> on anything found in Phases 2 through 6.

This is not a failure of the analysis; it is the expected, honest
result of a genuinely rigorous search for structure in what is, by the
creator's own account and by every statistical test applied, an
unpatterned deterministic-wallet output. Per the project's anti-bullshit
rule, this negative result is reported as the headline finding, not
buried under hedged language.

**What would change this conclusion:**
- A successful dictionary/guessing attack recovering the seed/passphrase
  or master extended key behind a specific hash-chain construction
  (Electrum Type-1, classic `SHA256(master+n)` Type-1, or BIP32 with a
  leaked/guessable chaincode) — flagged as open follow-up work in
  Archaeology, not run to completion here. Any of these, if it produced
  an exact match reproducing several of the 70 known keys simultaneously
  (a `p < 1e-6`-class event, not a fuzzy statistical fit), would be a
  decisive, non-fuzzy result rather than another null.
- Direct exposure of the public key for puzzle #71 (e.g. via a partial
  spend or address reuse elsewhere) — has not occurred; the address has
  never sent a transaction.
- New primary-source information from the actual creator beyond the
  single 2017 forum post, which remains unsigned and thus not
  cryptographically authenticated.

Absent any of those, the technically correct, non-inflated strategy for
Puzzle #71 remains brute-force search (or waiting) over the full
2^70-candidate uniform interval — no shortcut discovered in this program
reduces that.

---

## Artifact index

- `research/generator_hypotheses.md` — full ledger, all 6 hypotheses
- `research/hypotheses/*.py`, `*.md`, `*_results.json` — implementation and full results per hypothesis
- `research/stats/*.py`, `*.md` — bit-frequency/runs, Hamming weight/distance, modular/polynomial/recurrence analyses
- `research/walk_forward_validation.md` — Phase 4 walk-forward validation
- `research/archaeology/creator_statements.md`, `research/archaeology/period_wallets.md` — primary-source tracing
- `research/onchain/funding_transactions.md`, `spending_patterns.md`, plus raw JSON — on-chain forensics
- `data/solved_puzzles.json` — the underlying verified 70-puzzle dataset all analysis is built on
