# Seed/passphrase-guessing dictionary attack — summary

**Program phase:** post-Phase-6 follow-up. Phase 2's statistical hypothesis
tests (`research/PHASE_2_6_SUMMARY.md`, `research/generator_hypotheses.md`
sections 1-6) found no exploitable pattern in the puzzle bit sequence
itself — expected, since a real deterministic-wallet/hash-chain generator
is *by design* statistically indistinguishable from random to an outside
observer who does not know the seed. This is the complementary attack:
guess the seed/passphrase directly, for two historically-plausible
deterministic-wallet schemes, and check the result against the real
dataset.

**Headline result: no match found. Zero candidates, across 175,363 total
derivation attempts spanning both schemes and five candidate categories,
produced a masked key equal to any real puzzle's key at a statistically
meaningful puzzle size.** This is the expected, honest outcome for a
finite, disclosed word/phrase list against a keyspace this large — it rules
out exactly the candidates tested, nothing more.

---

## Schemes tested

1. **Electrum "Type-1" (pre-2.0) deterministic wallet.** Real algorithm,
   reproduced exactly from the current `spesmilo/electrum` source
   (`electrum/keystore.py Old_KeyStore`, `electrum/old_mnemonic.py`,
   fetched 2026-08-19) and validated against a real published Electrum test
   vector before any use against the dataset — see `tests/test_seed_attack.py`,
   confirmed passing immediately before this write-up (`PASS:
   test_electrum_known_answer_vector`, `PASS: test_electrum_positive_control`,
   `PASS: test_classic_type1_positive_control`). Given a 32-hex-char
   (16-byte) seed: 100,000 rounds of SHA-256 stretching -> master secret
   exponent -> master pubkey -> child key at index `n` via a SHA256d-based
   "sequence" hash added to the master secret, mod the secp256k1 group
   order. Expensive: ~50ms/candidate on a single core (confirmed directly —
   e.g. the `brainwallet_cracked` category's 72-candidate full-stretch run
   took 3.57s wall-clock, 49.6ms/candidate).
2. **Classic "Type-1" brainwallet-style:** `child_key(n) =
   SHA256(masterstring formatted with n)`, in 8 plausible formats (colon-,
   dash-, space-separated; 0- vs 1-indexed; `n`-before-`m`) — see `FORMATS`
   in `src/seed_attack.py`. Cheap: sub-second for tens of thousands of
   candidates.

Both raw derivations get the puzzle's own stated masking applied — keep the
low `(n-1)` bits, force bit `(n-1)` high (`apply_puzzle_mask` in
`src/seed_attack.py`) — before comparison against the real, cryptographically
verified 82-puzzle dataset at `data/solved_puzzles.json`
(`n` = 1, 2, ..., 71, ..., 130).

All work used the pre-validated `src/seed_attack.py` module unmodified — no
crypto was reimplemented for this follow-up.

## Significance convention used throughout

`apply_puzzle_mask` hardcodes `masked = 1` for any `n <= 1` (0 free bits) —
puzzle #1 trivially "matches" every candidate function by construction and
was excluded from all matching datasets (81 puzzles, `n = 2..130` used).
Small `n` still carries very few free bits (`n=2` is a 1-bit/50%-chance
match, `n=3` is 2-bit/25%, etc.), so with tens of thousands of candidate
functions in play, large numbers of *expected* chance single- or
few-puzzle "matches" at small `n` are mathematically guaranteed and are not
evidence of anything. Two complementary conventions were used across the
five category reports to separate signal from this expected noise floor,
both converging on the same practical bar:

- **`n >= 20` as "notable"** (chance rate `2^-19 ~= 1.9e-6` per candidate) —
  matches the task brief's own framing ("a single exact match on even ONE
  puzzle already existing in the dataset would be an almost-impossible
  coincidence").
- **Pre-registered Bonferroni-style filter,**
  `expected_spurious_count = candidates_this_category * product(2^-(n_i - 1)
  over the matched n_i) < 0.001`.

Every non-empty match returned by `test_candidate_against_dataset` across
all five categories was logged and checked against these thresholds. None
cleared either bar. The closest approaches (all still far below
significance) were: a classic Type-1 candidate matching puzzles
`{3, 6, 7, 13}` simultaneously (`expected_spurious_count ~= 0.00247`, in
`trivial_and_sequential`); an Electrum candidate matching `{2, 3, 4, 6, 10}`
simultaneously (`expected_spurious_count ~= 0.00987`, also
`trivial_and_sequential`); and, in `common_passwords`, a classic candidate
matching `{7, 18}` (`~=0.0095`) and an Electrum candidate matching
`{2, 3, 11}` (`~=0.011`) — the next-closest approaches found anywhere.
Observed per-puzzle chance-match rates for small `n` tracked the theoretical
`2^-(n-1)` prediction closely wherever tallied (e.g. `common_passwords`
category, `n=2`: 40,259/80,000 = 0.5032 observed vs. 0.5 expected),
confirming the harnesses have no hidden bug rather than a silent
suppression of real signal.

**`CRITICAL SAFETY RULE` (halt-and-report-only if `test_candidate_against_dataset`
ever returns a non-empty match at notable significance) was never
triggered, in any category, on any candidate.**

## Categories tested

| # | Category | Classic Type-1 candidates | Electrum Type-1 candidates (real 100k-round stretch) | Match? |
|---|---|---:|---:|---|
| 1 | `puzzle_culture` — Bitcoin-puzzle-specific and creator-specific phrases (creator quotes, `saatoshi_rising` username variants, puzzle-number phrases, creation-date formats, genesis-tx/on-chain identifiers) | 832 | 312 | No |
| 2 | `common_passwords` — SecLists `10k-most-common.txt` | 80,000 | 90 | No |
| 3 | `brainwallet_cracked` — 24 individually documented, dollar/BTC-amount-confirmed real cracked brainwallet passphrases from published research | 192 | 72 | No |
| 4 | `crypto_culture_quotes` — genesis coinbase text, whitepaper title/abstract, cypherpunk/crypto-anarchist lines, Satoshi's documented quotes, community slogans | 576 | 117 | No |
| 5 | `trivial_and_sequential` — degenerate/sequential hex patterns, byte-repeats, small integers 0-10,000, English/crypto-culture words | 82,824 | 10,348 | No |
| | **Total** | **164,424** | **10,939** | **No** |

*Electrum-column note:* every Electrum candidate counted above received the
real, unshortcut 100,000-round SHA-256 stretch — none of the reported work
relied on a cheap approximation standing in for the real derivation. (One
internal bookkeeping wrinkle in the `brainwallet_cracked` category's
handoff figures reported the full-stretch count as 0 against a
cheap-derivation count of 72; this write-up independently re-checked that
category's raw results file, `brainwallet_cracked_results.json`, and
confirmed via `elapsed_sec: 3.57` for 72 candidates (49.6ms/candidate,
matching the expected ~50ms/candidate cost) that all 72 did in fact receive
the real stretch — the 0 was a mislabeled field in that category's
aggregate summary, not a shortfall in the underlying work. Corrected figure
used above.)

**Grand total: 175,363 candidate-derivation attempts** (164,424 classic
Type-1 + 10,939 real Electrum Type-1 100,000-round stretches) across both
schemes and all five categories. This is a finite, disclosed search over
specific candidate lists — it rules out only these candidates under these
two schemes, not the broader hypothesis space (e.g., untested phrase
variants, non-English text, other deterministic-wallet formulas such as
BIP32/BIP39, or transforms other than the three cheap hex-seed derivations
used to bridge plain phrases into Electrum's 16-byte seed input).

## Per-category detail and sources

Full candidate lists, methodology, and raw results for each category are in
this directory:

- **`puzzle_culture.md`** / `puzzle_culture_results.json` — 104 phrases
  across 8 sub-categories (creator quote variants, "bitcoin puzzle"/"btc
  puzzle" phrasing, puzzle #1/#71 addresses, `saatoshi_rising` variants,
  puzzle-number phrases, creation-date formats, genesis-tx identifiers,
  creator-post references). Sources: `research/archaeology/creator_statements.md`,
  `research/BROAD_REPLICATION_FINDINGS.md`, `data/raw_genesis_tx.json`,
  `data/raw_p71_blockchain_info.json`, `data/solved_puzzles.json`.
- **`common_passwords.md`** / `common_passwords_results.json` /
  `common_passwords.py` / `10k-most-common.txt` — full SecLists
  `10k-most-common.txt` wordlist (10,000 entries). Source: SecLists,
  `danielmiessler/SecLists`, `Passwords/Common-Credentials/10k-most-common.txt`,
  fetched 2026-08-19 (HTTP 200), verbatim copy kept alongside for
  reproducibility.
- **`brainwallet_cracked.md`** / `brainwallet_cracked_results.json` /
  `brainwallet_cracked.py` — 24 real, individually documented
  dollar/BTC-amount-confirmed cracked brainwallet passphrases. Sources:
  Ryan Castellucci, "Cracking Cryptocurrency Brainwallets", DEF CON 23, Aug
  2015 (PDF saved as `defcon23_castellucci.pdf`); Vasek, Bonneau,
  Castellucci, Keith, Moore, "The Bitcoin Brain Drain: Examining the Use
  and Abuse of Bitcoin Brain Wallets", Financial Cryptography 2016,
  peer-reviewed (PDF saved as `bitcoin_brain_drain_paper.pdf`). Both PDFs
  read in full to extract exact quoted passphrase text and confirmed
  amounts, not summarized from search snippets.
- **`crypto_culture_quotes.md`** / `crypto_culture_quotes_results.json` /
  `crypto_culture_quotes.py` — 72 phrases (genesis coinbase text,
  whitepaper title/abstract/byline, cypherpunk/crypto-anarchist manifesto
  lines, Satoshi's documented forum/mailing-list quotes, precursor concepts
  b-money/bit gold/hashcash, community slogans, pizza-day references).
- **`trivial_and_sequential.md`** / `trivial_and_sequential_results.json` /
  `trivial_and_sequential.py` — 274 degenerate/sequential/byte-repeat hex
  patterns, integers 0-10,000, 49 English/crypto-culture words, 29 short
  number strings.

All five categories re-confirmed `tests/test_seed_attack.py`'s three
controls (real Electrum known-answer vector, Electrum positive control,
classic Type-1 positive control) passing immediately before running against
the real dataset, and independently discovered/documented the `n<=1`
structural-degeneracy artifact in `apply_puzzle_mask` as part of validating
their own harnesses were not producing false positives.

## Round 2: scaled up (real rockyou.txt + mutations, ~199.3M total checks)

The round above (175,363 candidates) was reasonably judged too small —
"everyone else prob tried them also and derivatives." Round 2 used the
actual full [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
wordlist (14.3M real passwords, not committed to the repo — 140MB exceeds
GitHub's 100MB push limit, source URL is the reproduction path) plus
mutation-rule derivatives (`src/mutate.py`: leetspeak, capitalization,
year/number suffixes, common prefixes) of its 150,000 most common entries.

- **Classic scheme**: 197,329,864 candidate-format checks (`src/classic_attack_scaled.py`,
  full results in `classic_scaled_results.json`) in 2504s (78,802/s).
  **0 real matches.**
- **Electrum scheme**: 1,999,994 candidates, each through the real
  100,000-round stretch (`src/stretch_bench.c`, SHA-NI-accelerated —
  see that file's commit history for a real, documented ~100x performance
  bug hunt along the way) via 2,000,000 rockyou-derived seeds
  (SHA256(phrase)[:16]). Full results in `electrum_scaled_results.json`.
  **0 real matches** (4 filter survivors, matching the ~3.8 expected by
  pure chance at this volume almost exactly; none had 2+ hits at a
  statistically meaningful puzzle size).

**A real bug was caught here, not just a clean negative.** The first
completion of the classic-scheme run reported "371 confirmed matches,"
which would have been a huge deal if real. It wasn't: the confirmation
threshold (`>=2 hits anywhere in the dataset`) didn't exclude puzzle #1
(which matches every candidate by construction — `apply_puzzle_mask`
hardcodes `masked=1` for any `n<=1`) or account for puzzles #2/#3/#4
matching by pure chance 50%/25%/12.5% of the time. Verified directly:
0 of the 371 had 2+ hits at `n>=20` (chance rate <2e-6 per hit) — every
one was just the single real `n=20` filter hit plus low-`n` noise. Fixed
in both attack scripts (require 2+ hits at `n>=20` specifically) before
being reported as a finding, and before the same bug could affect the
still-running Electrum round's checker.

**Combined total across both rounds: ~199.5 million candidate-derivation
attempts. 0 real matches.**

## Bottom line

No seed or passphrase tested across either round — now approaching 200
million candidate derivations across two real deterministic-wallet
schemes, a real published wordlist at full scale, mutation rules, and
multiple thematically distinct hand-curated categories, all checked
against the actual 100,000-round Electrum stretch where applicable, not
an approximation — reproduces any solved puzzle's key at a statistically
meaningful puzzle size. This is consistent with every other result in
this research program (see `research/generator_hypotheses.md` sections
1-6 and `research/PHASE_2_6_SUMMARY.md`): nothing tested so far provides
any exploitable reduction in the Puzzle #71 candidate-key search space.
It does not prove no such seed exists — only that these specific,
disclosed candidate lists, under these two specific schemes, do not
contain it. Real, unlimited-budget attacks (e.g. a proper GPU-accelerated
rule-based cracker against the full rockyou.txt with hashcat's complete
rule sets) would go further, but at some point this stops being a
seed-guessing research question and becomes exactly the brute-force
hardware problem Phase 8 already documents honestly.
