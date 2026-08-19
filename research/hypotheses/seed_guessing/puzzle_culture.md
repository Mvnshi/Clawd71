# Seed-guessing dictionary attack — Bitcoin-puzzle-specific / creator-specific phrases

Research date: 2026-08-19. Part of the seed/passphrase-guessing extension to
Phase 2 (see `research/PHASE_2_6_SUMMARY.md` for why the bit-sequence itself
is statistically clean and this is a different, complementary attack: guess
the *seed*, not the bit pattern).

Module under test: `src/seed_attack.py` (validated — `tests/test_seed_attack.py`
passes: real Electrum test vector reproduced exactly, plus positive controls
confirming the harness detects a planted seed under both schemes and does not
spuriously match a wrong one).

## Result up front

**No match.** Across every candidate in this category, under both schemes,
zero statistically meaningful matches against the real 82-puzzle dataset.
Full methodology, the noise floor that had to be characterized before this
could be trusted, and the complete candidate list follow.

## Candidate sources (104 phrases)

Compiled from the exact creator quote and close variants, "bitcoin puzzle" /
"btc puzzle" phrasing, the puzzle #1 and #71 Bitcoin addresses, the
BitcoinTalk username `saatoshi_rising` and variants, "crude measuring
instrument", puzzle-number phrases, the 2015-01-15 creation date in several
formats, and the genesis funding transaction id — sourced from
`research/archaeology/creator_statements.md`, `research/BROAD_REPLICATION_FINDINGS.md`,
`data/raw_genesis_tx.json`, and `data/solved_puzzles.json` (for the puzzle #1
address; puzzle #71's address `1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU` is itself
*unsolved* so it is not in the solved-puzzle dataset, but is documented in
`research/BROAD_REPLICATION_FINDINGS.md` and `data/raw_p71_blockchain_info.json`).

| Category | Count |
|---|---:|
| Creator quote / close variant | 22 |
| "bitcoin puzzle" / "btc puzzle" phrasing | 15 |
| Puzzle #1 / #71 address | 2 |
| `saatoshi_rising` username variant | 15 |
| Puzzle-number phrase | 19 |
| Creation date (2015-01-15) format | 17 |
| Genesis tx / on-chain identifier | 8 |
| Tangential creator-post reference (LBC, Bulista, "satoshi", …) | 6 |
| **Total** | **104** |

The full creator quote used as the seed for the first category (per
`research/archaeology/creator_statements.md §3`, WebFetch-confirmed against
the BitcoinTalk profile of account `saatoshi_rising`, post dated 2017-04-27):

> "A few words about the puzzle. There is no pattern. It is just consecutive
> keys from a deterministic wallet (masked with leading 000...0001 to set
> difficulty). It is simply a crude measuring instrument, of the cracking
> strength of the community."

## Methodology

Every phrase was tested two ways:

1. **Classic Type-1** (`classic_type1_candidate`) — SHA256(masterstring
   formatted with n) — across **all 8 entries in `FORMATS`** (`plain`,
   `colon`, `dash`, `space`, `zero_indexed`, `colon_zero_indexed`,
   `n_then_m`, `sha256d`). Cheap: 832 (phrase, format) combinations ran in
   0.1s.
2. **Electrum Type-1**, via three cheap 16-byte hex-seed derivations of each
   phrase (`SHA256(phrase)[:16]`, `MD5(phrase)`, raw UTF-8 bytes
   zero-padded/truncated to 16 bytes), each fed through the **real, full
   100,000-round `electrum_stretch_key`** — not a placeholder. 312
   (phrase, derivation) combinations, 312 real stretches, 15.5s total
   (~50ms/stretch measured on this machine, matching the task's own
   estimate). Note on scope: the task brief suggested escalating only 5–10
   "most plausible" candidates to the full expensive Electrum path and
   treating the hex-seed derivation itself as the "cheap" part. Since 312
   stretches is still well inside the stated "hundreds to low thousands"
   Electrum budget (~15s, not the minutes/hours a "low thousands" count
   would suggest), every phrase × derivation combination got the real
   algorithm rather than a partial subset — more rigorous than a 5–10-item
   escalation, at negligible extra cost, so no further escalation step was
   needed for this category.
3. **Word-mnemonic path** (`hex_seed_from_words`): each phrase was also
   whitespace-tokenized and run through Electrum's literal old-mnemonic word
   decoder, in case any candidate happened to tokenize into words from
   Electrum's 1626-word list. 64 of the 104 phrases "succeeded" but every one
   of those was a **vacuous decode**: `mn_decode` only processes complete
   groups of 3 words (`len(wlist)//3`) and silently returns `''` for any
   input under 3 words or leftover words past the last group of 3 — most
   short candidate phrases hit this and decoded to an empty string, not a
   real 16-byte seed. Re-checked directly: **zero** non-empty/non-vacuous
   decodes among all 104 phrases. This path contributed nothing and is
   reported for completeness, not treated as a tested seed.

## A finding worth documenting: the mask makes small-n "matches" expected noise, not signal

Before trusting any negative result, per the task's own safety instructions,
the harness was sanity-checked against a degenerate/trivial input
(`classic_type1_candidate("", n, "plain")` — an empty masterstring). Result:
`matches = [1, 2]`.

This is **not a harness bug** — it is `apply_puzzle_mask`'s own definition:

```python
def apply_puzzle_mask(raw_key: int, n: int) -> int:
    if n <= 1:
        return 1                      # <-- constant, independent of raw_key
    forced_bit = 1 << (n - 1)
    return (raw_key & (forced_bit - 1)) | forced_bit
```

For `n=1` the masked output is **the literal constant 1 for every possible
`raw_key`**, and puzzle #1's real key is exactly 1 — so *every single
candidate function tested, valid or not, trivially "matches" puzzle #1*. For
`n=2` the mask keeps exactly 1 bit of the raw candidate (50% chance match by
pure luck); `n=3` keeps 2 bits (25%); and so on, `2^-(n-1)` per candidate.

With 104 phrases × (8 classic formats + 3 electrum derivations) = **1,144
independent candidate functions** tested in this run alone, the *expected
number of purely-by-chance small-n matches* is large — e.g. ~572 expected at
n=2, ~286 at n=3, ~143 at n=4, dropping below 1 only around n≈12 and below
0.01 only around n≈19–20. This is exactly the "20+-bit" bar the task brief
itself uses when it says a real match would be "an almost-impossible
coincidence (matching a specific 20+-bit number by chance)." A raw,
un-filtered non-empty result from `test_candidate_against_dataset` is
therefore *expected and uninformative* for small n — treating it naively as
a CRITICAL-SAFETY-RULE trigger would have halted on the very first candidate
tested, on a mathematical artifact, not a discovery.

**Resolution used throughout this run:** results were split into
`noise` (2 ≤ n < 20, expected by chance at this sample size, logged but not
alarmed on) and `notable` (n ≥ 20, the threshold at which chance coincidence
across the whole 1,144-candidate sweep is <0.3% even summed over every
puzzle at that bit length). Only a `notable` match would have triggered the
CRITICAL SAFETY RULE (stop immediately, do not print the candidate, report
only format/puzzle-numbers/that a match occurred). n=1 was excluded from
even the noise count since it is a certainty by construction, not
probabilistic — every single one of the 1,144 candidate functions "matched"
it, which by itself is proof it carries zero discriminating information.

## Results

- **Classic Type-1:** 832 (phrase, format) combinations tested against all 82
  solved puzzles. 0 notable (n≥20) matches. 585 combinations had small-n
  noise matches (expected; aggregate noise-n hit count across phrases: 334,
  consistent with the predicted chance rate above).
- **Electrum Type-1:** 312 (phrase, derivation) combinations, each with a
  real 100,000-round stretch, tested against all 82 solved puzzles. 0
  notable (n≥20) matches. 231 combinations had small-n noise matches
  (aggregate noise-n hit count: 228).
- **Word-mnemonic path:** 0 non-vacuous decodes (see methodology §3); not a
  contributing test.
- **CRITICAL SAFETY RULE status: never triggered.** No candidate, under
  either scheme, in any format/derivation, produced a match at n≥20 against
  any of the 82 real solved puzzles. This is the expected, honest result.

## Full candidate list

All 104 phrases, grouped by category. (Per-phrase small-n noise details and
raw match lists — including the full `noise_n` / `notable_n` breakdown per
phrase per scheme — are preserved in
`research/hypotheses/seed_guessing/puzzle_culture_results.json` for
reproducibility; omitted from the prose below since none are notable and the
noise counts are already summarized above — reproducing 1,144 individual
near-certain-to-be-noise rows would not add signal.)

### Creator quote / close variants (22)
1. `A few words about the puzzle. There is no pattern. It is just consecutive keys from a deterministic wallet (masked with leading 000...0001 to set difficulty). It is simply a crude measuring instrument, of the cracking strength of the community.` (full quote, verbatim)
2. `There is no pattern. It is just consecutive keys from a deterministic wallet (masked with leading 000...0001 to set difficulty).` (short quote, verbatim)
3. `There is no pattern. It is just consecutive keys from a deterministic wallet`
4. `There is no pattern`
5. `no pattern`
6. `It is just consecutive keys from a deterministic wallet`
7. `consecutive keys from a deterministic wallet`
8. `masked with leading 000...0001 to set difficulty`
9. `crude measuring instrument`
10. `crude measuring instrument of the cracking strength of the community`
11. `It is simply a crude measuring instrument, of the cracking strength of the community.`
12. `cracking strength of the community`
13. `consecutive keys`
14. `deterministic wallet`
15. `There Is No Pattern`
16. full quote, lowercased
17. short quote, lowercased
18. full quote, lowercased and stripped of all punctuation
19. short quote, lowercased and stripped of all punctuation
20. `a crude measuring instrument`
21. `It is simply a crude measuring instrument`
22. `measuring instrument`

### "bitcoin puzzle" / "btc puzzle" phrasing (15)
`bitcoin puzzle`, `Bitcoin Puzzle`, `BITCOIN PUZZLE`, `bitcoin puzzle transaction`,
`Bitcoin Puzzle Transaction`, `btc puzzle`, `BTC Puzzle`, `BTC puzzle`,
`bitcoinpuzzle`, `btcpuzzle`, `bitcoin-puzzle`, `bitcoin_puzzle`,
`Bitcoin puzzle transaction ~32 BTC`, `32 BTC puzzle`,
`bitcoin puzzle transaction ~32 BTC prize to who solves it`

### Puzzle #1 / #71 address (2)
`1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` (puzzle #1 address),
`1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU` (puzzle #71 address)

### `saatoshi_rising` username variants (15)
`saatoshi_rising`, `saatoshi rising`, `saatoshirising`, `SaatoshiRising`,
`saatoshi-rising`, `Saatoshi_Rising`, `Saatoshi_rising`, `saatoshi_Rising`,
`saatoshi`, `Saatoshi`, `saatoshi_rising, Bitcointalk`,
`saatoshi_rising bitcoin puzzle`, `bitcoin puzzle saatoshi_rising`,
`u=991321`, `991321` (BitcoinTalk profile id)

### Puzzle-number phrases (19)
`puzzle 71`, `puzzle71`, `puzzle-71`, `puzzle_71`, `Puzzle 71`, `Puzzle71`,
`71 bitcoin puzzle`, `bitcoin puzzle 71`, `bitcoin puzzle #71`, `#71`,
`Puzzle #71`, `71`, `puzzle 1`, `bitcoin puzzle 1`, `puzzle1`,
`Bitcoin Puzzle 71`, `BITCOIN PUZZLE 71`, `puzzle #71 private key`,
`1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU puzzle 71`

### Creation date formats (17)
`2015-01-15`, `01-15-2015`, `15-01-2015`, `01/15/2015`, `15/01/2015`,
`20150115`, `15012015`, `01152015`, `January 15, 2015`, `January 15 2015`,
`15 January 2015`, `Jan 15 2015`, `Jan 15, 2015`, `2015/01/15`, `15.01.2015`,
`01.15.2015`, `2015 01 15`

### Genesis tx / on-chain identifiers (8)
`08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15` (full genesis
txid), `08389f34c98c6063` (first 16 hex chars), `08389f34...cd15` (commonly
quoted truncated form), `08389f34cd15`, `339085` (genesis tx block height),
`1421345234` (genesis tx unix timestamp), `topic 1306983`, `1306983`
(BitcoinTalk thread id where the creator's post appears)

### Tangential creator-post references (6)
`Large Bitcoin Collider`, `LBC`, `satoshi`, `Satoshi Nakamoto`, `Bulista`,
`amaclin`

## Honest bottom line

None of the 104 culturally/historically plausible phrases — under classic
Type-1 (8 formats each) or Electrum Type-1 (3 cheap-hex-seed derivations
each, run through the real 100k-round stretch) — reproduce any real solved
puzzle key at a bit-length where that would mean anything. Consistent with
`research/PHASE_2_6_SUMMARY.md` and `research/BROAD_REPLICATION_FINDINGS.md
§7`: no tested hypothesis in this program beats randomness, and this
dictionary attack on the most narratively obvious seed candidates is no
exception. This does not rule out some *other* seed/passphrase (the space of
possible short strings is unbounded), only these specific, well-reasoned 104.
