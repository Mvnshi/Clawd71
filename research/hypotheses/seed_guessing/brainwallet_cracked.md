# Seed-guessing attack: known historically-cracked brainwallet passphrases

**Status: no exploitable match found. 288 candidates tested (192 classic
Type-1 + 72 Electrum Type-1 + 24 literal-mnemonic-parse attempts) against the
real 82-puzzle dataset, using 24 REAL, individually documented, dollar/BTC-
amount-confirmed brainwallet passphrases as masterstring candidates. The
observed chance-level coincidence rates track the theoretical null closely,
which is itself a useful confirmation the harness has no hidden bug
inflating or suppressing matches.**

## What this tests

Phase 2's statistical hypothesis tests (`research/PHASE_2_6_SUMMARY.md`)
found no exploitable pattern in the puzzle's *bit sequence itself*. This is
the complementary seed-guessing attack (see also
`research/hypotheses/seed_guessing/common_passwords.md` for the generic-weak-
password variant of this same attack). Unlike that run, every candidate
tested here is not a generic dictionary word but a **real brainwallet
passphrase that a real deterministic wallet address received funds under and
was subsequently drained** — the specific category the task calls out:
someone picking a "memorable" deterministic-wallet seed around 2013-2015
plausibly drew from the same cultural pool of phrases early Bitcoin users
actually used (and lost money with) for brainwallets.

Both schemes use the already-validated harness in `src/seed_attack.py`
(validated against a real published Electrum test vector and positive-control
synthetic datasets — see `tests/test_seed_attack.py`, all 3 controls
re-confirmed passing immediately before this run):

1. **Classic Type-1 brainwallet-style**: `child_key(n) = SHA256(masterstring
   formatted with n)`, across all 8 formats in `FORMATS` (`plain`, `colon`,
   `dash`, `space`, `zero_indexed`, `colon_zero_indexed`, `n_then_m`,
   `sha256d`). Cheap — pure SHA256, no stretching.
2. **Electrum "Type-1" (pre-2.0) wallet**: 100,000-round SHA256 stretch of a
   32-hex-char (16-byte) seed → master secret → master pubkey → per-index
   child key. Expensive (~50ms/seed), so run against **all 24** candidate
   phrases (not a subset — the list is short enough that "escalate your best
   candidates" is trivially satisfied by escalating everything), each turned
   into a 16-byte hex seed via three cheap transforms: `SHA256(phrase)[:16]`
   as hex, `MD5(phrase)` as hex, and raw UTF-8 bytes of `phrase`
   zero-padded/truncated to 16 bytes as hex.
3. **Bonus (free)**: for each phrase, attempt Electrum's actual literal
   mnemonic-word path (`hex_seed_from_words`) — only succeeds if the phrase
   happens to be exactly 12 words, every one drawn from Electrum's specific
   1626-word old-mnemonic wordlist. Costs nothing to attempt; expected to
   reject essentially everything.

Both raw derivations get the puzzle's own stated masking applied
(`apply_puzzle_mask`: keep the low `n-1` bits, force bit `n-1` high) before
comparison against `data/solved_puzzles.json`'s real `key_int` for that `n`.

## Sources (real, primary, individually cited per candidate)

**Source A**: Ryan Castellucci, *"Cracking Cryptocurrency Brainwallets"*,
DEF CON 23, August 2015.
<https://rya.nc/files/cracking_cryptocurrency_brainwallets.pdf>
(mirror: <https://media.defcon.org/DEF%20CON%2023/DEF%20CON%2023%20presentations/DEF%20CON%2023%20-%20Ryan-Castellucci-Cracking-Cryptocurrency-Brainwalletsll.pdf>).
Fetched 2026-08-19, HTTP 200, saved verbatim at
`research/hypotheses/seed_guessing/defcon23_castellucci.pdf` (268KB).
Slides explicitly titled "Some results" / "Some more results" / "A few more
results (for the lulz)" list passphrases Castellucci's own custom cracker
(and later, Brainflayer) found real funded brainwallets for, several with
exact BTC/USD amounts and dates quoted directly off the slide text.

**Source B**: Vasek, Bonneau, Castellucci, Keith, Moore, *"The Bitcoin Brain
Drain: Examining the Use and Abuse of Bitcoin Brain Wallets"*, Financial
Cryptography and Data Security 2016 (peer-reviewed).
<https://jbonneau.com/doc/VBCKM16-FC-bitcoin_brain_wallets.pdf>. Fetched
2026-08-19, HTTP 200, saved verbatim at
`research/hypotheses/seed_guessing/bitcoin_brain_drain_paper.pdf` (243KB).
This is the first large-scale academic measurement of brainwallet use: ~300
billion candidate passwords tested via Brainflayer against the full Bitcoin
blockchain, identifying 884 real brainwallets ($103K total, 98% drained,
usually within 21 minutes). Table 2 ("Top 10 drain addresses from brain
wallets") names the exact passphrase-derived description for several of the
largest confirmed drains, with USD/BTC amounts and drain-event counts.

Both PDFs were fetched directly (not summarized from search-result snippets)
and read in full via the PDF reader to extract the exact candidate text —
important because this task's WebFetch tool could not parse either PDF's
compressed text streams; the raw files were downloaded and read directly
instead, and are kept alongside this report for anyone who wants to verify
the quotes independently.

## Candidates actually tested (24 total)

23 confirmed-cracked (each individually cited to a specific slide or table
row) + 1 flagged lower-confidence bonus:

| # | phrase | source |
|---|---|---|
| 1 | `""` (empty string) | A slide 7 — $14K sent to it, stolen in seconds |
| 2 | `how much wood could a woodchuck chuck if a woodchuck could chuck wood` | A slides 24-31 — 250 BTC (~$20K); independently confirmed in B Table 2 rank #1-2 ($22,466 + $15,267, two separate drains) |
| 3 | `Down the Rabbit-Hole` | A slide 43 — held ~85 BTC, July 2012 |
| 4 | `The Quick Brown Fox Jumped Over The Lazy Dot` | A slide 43 — held ~85 BTC, December 2011 (exact slide text — "Dot", not "Dog") |
| 5 | `gate gate paragate parasamgate bodhi svaha` | A slide 44 |
| 6 | `The Persistence Of Memory` | A slide 44 |
| 7 | `QTC` | A slide 44 |
| 8 | `644122178` | A slide 44 |
| 9 | `8964009` | A slide 44 |
| 10 | `que me lleve la muerte` | A slide 44 |
| 11 | `one two three four five six seven` | A slide 44; independently confirmed in B §3 as the **first brain wallet ever observed**, September 2011 |
| 12 | `it's a secret to everybody` | A slide 44 |
| 13 | `Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn` | A slide 44 |
| 14 | `my hovercraft is full of eels` | A slide 45 |
| 15 | `Interior Crocodile Alligator` | A slide 45 |
| 16 | `No need to worry, my accountant handles that` | A slide 45 |
| 17 | `tomb-of-the-unknown-soldier-identification-badge` | A slide 45 |
| 18 | `permit me to issue and control the money of a nation and i care not who makes its laws` | A slide 45 |
| 19 | `who is john galt` | A slide 45 |
| 20 | `Live as if you were to die tomorrow. Learn as if you were to live forever.` | A slide 45 |
| 21 | `bitcoin is awesome` | B Table 2 rank #6 — $5,800 / 500 BTC, 1 drain |
| 22 | `deadsheep` | B Table 2 rank #9 — $1,429 / 14.29 BTC, 1 drain |
| 23 | `thequickbrownfoxjumpedoverthelazydog` | B Table 2 rank #10 — $1,322 / 97.66 BTC, **59 drains** (all-lowercase, no-space — a distinct string from #4 above) |
| 24 | `correct horse battery staple` | **LOWER CONFIDENCE**: Castellucci's own canonical xkcd running-demo phrase (A slides 8-13), not individually confirmed as a find by him. Included because B Table 1 documents the broader "xkcd" word-list category (90 wallets, $29,140 total, "passwords derived from xkcd are drained repeatedly the most") as a real cracked category |

Full phrase list with sources is also embedded in
`research/hypotheses/seed_guessing/brainwallet_cracked.py` (`CANDIDATES`)
and in the raw results JSON.

## Runs

| category | candidates | breakdown | wall time |
|---|---|---|---|
| Classic Type-1 | 192 | 24 phrases × 8 formats | 0.02s |
| Electrum Type-1 (cheap-derivation) | 72 | 24 phrases × 3 hex-seed transforms, each run through the full real 100k-round stretch | 3.6s |
| Electrum literal mnemonic-word (bonus) | 24 | each phrase checked for a valid 12-word Electrum-wordlist parse | <0.01s |
| **Total** | **288** | | **~3.6s** |

Code: `research/hypotheses/seed_guessing/brainwallet_cracked.py` (reproducible
— re-running regenerates the same results). Full per-candidate log (every
phrase × format/derivation combination and its match list) in
`research/hypotheses/seed_guessing/brainwallet_cracked_results.json`.

## Results

Harness controls (`tests/test_seed_attack.py`) re-confirmed passing
immediately before this run — the Electrum known-answer vector, the Electrum
positive control (harness detects a planted seed), and the classic Type-1
positive control all pass, so a negative result below is trustworthy rather
than a symptom of a broken harness.

**Classic Type-1**: 192 candidates, **0 significant matches**. 145 candidate
× puzzle-set combinations produced at least one *chance-level* coincidence
(expected — see the multiple-testing section below), dominated by `n=2`
alone (59/192 ≈ 31% hit rate, consistent with its 50% marginal chance rate
given overlap with multi-puzzle matches). The largest single coincidence
pattern, matching `n=2` alone, has `expected_spurious_count = 96.0` (i.e.
~96 candidates were expected to hit this by pure chance out of 192 tested,
and 59 did — well within normal variance, nowhere near the 0.001
significance bar).

**Electrum Type-1 (cheap hex-seed derivations)**: 72 candidates, each run
through the real, unavoidable 100k-round stretch. **0 significant matches**.
49/72 candidate×puzzle-set combinations hit at chance level, again dominated
by `n=2` (23/72 ≈ 32%, `expected_spurious_count = 36.0`).

**Electrum literal mnemonic-word path (bonus)**: 0/24 phrases parsed as a
valid 12-word entry from Electrum's specific old-mnemonic wordlist (expected
— none of these phrases are 12 words of Electrum-wordlist vocabulary), so
this path tested 0 additional derived keys.

No candidate — across all formats, all hex-seed derivations, the literal
mnemonic path, and all 24 individually-sourced real cracked-brainwallet
phrases — produced a masked derived key matching any real puzzle's key at a
level distinguishable from chance.

## Multiple-testing / degenerate-puzzle handling (read before judging "0 matches")

Identical, pre-registered methodology to
`research/hypotheses/seed_guessing/common_passwords.md`, reused deliberately
for a consistent decision rule across this research line:

- `apply_puzzle_mask(raw, n)` keeps only the low `n-1` bits of `raw` and
  forces bit `n-1` high, so puzzle `n` has exactly `n-1` "free" bits and an
  arbitrary candidate matches it by pure chance with probability `2^-(n-1)`.
- `n=1` has 0 free bits: `apply_puzzle_mask(raw, 1) == 1` for **every**
  possible `raw` (confirmed directly by direct computation on 5 probe values
  including `0`, `1`, and `2**200`, not assumed from a description), and the
  real dataset's puzzle #1 key genuinely is `1` — so `n=1` "matches"
  unconditionally for every candidate, always. Excluded from the 81-puzzle
  matching dataset entirely (n=2..130 used).
- `n=2` has 1 free bit: matches by pure chance ~50% of the time. Not
  degenerate like `n=1`, but across hundreds of candidates this produces
  real, expected, non-alarming chance "matches" on `n=2` alone — exactly
  what's observed (31-32% hit rate on `n=2`, tracking the ~50% marginal rate
  once multi-puzzle overlap is accounted for).

Every non-empty match is passed through a pre-registered Bonferroni-style
filter before being treated as alarming:

```
expected_spurious_count(matched_puzzle_set) =
    total_candidates_this_category * prod(2^-(n-1) for n in matched_puzzle_set)
```

A match set is only escalated to the CRITICAL SAFETY STOP protocol if
`expected_spurious_count < 0.001` — matching the task's own framing that a
real hit means "matching a specific 20+-bit number by chance" or "a match
across two or more puzzles simultaneously". No match in this run came close:
the largest observed `expected_spurious_count` values were 96.0 (classic)
and 36.0 (Electrum) — both many orders of magnitude above the 0.001 bar, and
both consisting of the single degenerate-adjacent `n=2` puzzle.

## Limitations / scope

- This covers 24 individually-documented real cracked-brainwallet phrases
  and the 8 formats already defined in `FORMATS`. It does not cover the full
  845-passphrase set behind Source B's Table 1 (only the top-10-by-value
  drains from Table 2 were individually named in the paper text; the full
  845-password list itself was not published, for the obvious reason that
  publishing it would just hand the remaining unswept balances to more
  attackers), nor the ~394K-word general "bitcoin-brainwallet.lst" dictionary
  found during sourcing (`duyet/bruteforce-database` — this is a generic
  English word list labelled "used for Bitcoin brainwallets", not a list of
  individually-confirmed finds, so it was set aside in favor of staying
  strictly within the task's "documented to have been used/cracked"
  category; it remains a candidate for a future, separate large-wordlist
  pass if warranted).
- These phrases were originally used in the wild as **direct single-address
  brainwallets** (`SHA256(passphrase) = privkey` with no sequence index).
  Here they are instead tested as **masterstring inputs to the puzzle's
  hypothesized sequential Type-1 scheme** (`SHA256(masterstring formatted
  with n)`), per this task's specific framing — a different, though related,
  hypothesis: not "did the puzzle creator reuse literally one of these exact
  drained addresses" (checkable directly against `data/solved_puzzles.json`
  addresses, and not the intended hypothesis here) but "did the puzzle
  creator pick one of these well-known memorable phrases as the seed for a
  from-scratch sequential deterministic wallet."
- As with every negative result in this repo: absence of a match here is not
  proof the seed isn't one of these phrases under some untested
  format/transform — only that it isn't one of the 288 concretely tested
  combinations.

## Safety-rule compliance

Per the task's CRITICAL SAFETY RULE: no candidate cleared the significance
threshold in this run (largest `expected_spurious_count` was 96.0, ~96,000×
above the 0.001 bar), so there is nothing to withhold. Harness controls were
re-confirmed passing before the run (not just assumed from the earlier
`common_passwords.md` run), so this negative result reflects the hypothesis
being false for these 288 combinations, not a broken test harness.
