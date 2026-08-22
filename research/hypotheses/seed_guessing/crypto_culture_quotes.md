# Seed-guessing dictionary attack — famous cryptography / Bitcoin-culture phrases

Research date: 2026-08-19. Part of the seed/passphrase-guessing extension to
Phase 2 (see `research/PHASE_2_6_SUMMARY.md` for why the bit sequence itself
is statistically clean and this is a different, complementary attack: guess
the *seed*, not the bit pattern). Sibling categories in this same effort:
`puzzle_culture.md` (puzzle/creator-specific phrases) and
`common_passwords.md` (SecLists top-10k passwords).

Module under test: `src/seed_attack.py`, script: `crypto_culture_quotes.py`
in this directory. Both use the already-validated crypto — `coincurve`
(libsecp256k1) for EC operations, and the exact `electrum/old_mnemonic.py` /
`electrum/keystore.py` `Old_KeyStore` derivation reproduced and checked
against a real published Electrum test vector before any of this ran (see
`tests/test_seed_attack.py`, all 3 controls pass, re-confirmed this run).

## Result up front

**No match.** 72 candidate phrases, tested classic Type-1 broadly (576
combinations across all 8 `FORMATS`) and Electrum Type-1 on a 39-phrase
curated "best/most plausible" subset (117 real 100,000-round-stretch
derivations) plus a word-mnemonic tokenization check on all 72. **Zero
statistically significant matches against the real 82-puzzle dataset, under
either scheme, in any format or derivation.** Full methodology, candidate
list, and the noise floor that had to be characterized before any result
here could be trusted, follow.

## Candidate sources (72 phrases)

Every phrase is a real, citable phrase or term from documented Bitcoin or
cypherpunk history — none invented for this run. Compiled from:

| Category | Count | Source |
|---|---:|---|
| Community slogan / in-joke | 19 | HODL, "vires in numeris", "in math we trust", "be your own bank", "21 million", "genesis block", "to the moon", "not your keys not your coins" (+ variants) |
| Precursor concept | 11 | b-money (Wei Dai), bit gold (Nick Szabo), Hashcash (Adam Back), "proof of work", "double-spending problem" |
| Satoshi's own quotes | 9 | documented bitcointalk.org / Cryptography mailing-list posts, 2008-2011 |
| Whitepaper | 6 | title, byline email, abstract opening line, `www.bitcoin.org` |
| Cypherpunk manifesto | 5 | Eric Hughes, 1993 — "Cypherpunks write code" etc. |
| Generic crypto-culture phrase | 5 | XKCD 936 "correct horse battery staple" (2011), "Alice and Bob", classic pangram |
| Genesis block coinbase text | 4 | block 0's real scriptSig text |
| Satoshi identity | 4 | "Satoshi Nakamoto", "Nakamoto", Dorian Nakamoto denial |
| Pizza day | 4 | May 2010, Laszlo Hanyecz |
| Crypto Anarchist Manifesto | 3 | Timothy May, 1988 |
| PGP / Zimmermann | 2 | "If privacy is outlawed, only outlaws will have privacy" |
| **Total** | **72** | |

**Era tagging (per task instruction to flag and deprioritize post-2015
in-jokes):** 67 of 72 phrases are **contemporary** — documented as existing
at or before the puzzle series' January 2015 creation date. 5 are flagged
**`likely_postdates_2015`**: "to the moon" (meme-ified later, though the
phrase existed informally earlier), "not your keys not your coins" / "not
your keys, not your coins" / "not your keys, not your bitcoin" (Andreas
Antonopoulos-era popularization, ~2017+), and "I am not Dorian Nakamoto"
(the Newsweek doxx was March 2014, but this exact denial-meme phrasing is
retrospective). These 5 were still tested (a script could in principle have
been reused/extended after 2015) but were **excluded from the curated
Electrum "best candidates" subset** as the task instructed for
deprioritization. HODL and "I AM HODLING" are correctly tagged
**contemporary** — the GameKyuubi post is dated December 2013, genuinely
before puzzle creation.

Full list (all 72, with category and era tag) is in
`crypto_culture_quotes_results.json` → `full_candidate_list`, and
reproduced in full at the bottom of this file.

## Methodology

1. **Classic Type-1** (`classic_type1_candidate`) — all 72 phrases × all 8
   `FORMATS` entries (`plain`, `colon`, `dash`, `space`, `zero_indexed`,
   `colon_zero_indexed`, `n_then_m`, `sha256d`). Cheap pure-SHA256: 576
   combinations, 0.07s.
2. **Word-mnemonic path** (`hex_seed_from_words`): every phrase
   whitespace-tokenized and run through Electrum's real `old_mnemonic.
   mn_decode`, in case a phrase happens to tokenize into complete groups of
   3 words from the real 1626-word Electrum old-seed wordlist. 0 of 72
   produced a non-empty decode (as expected — `mn_decode` only processes
   complete 3-word groups and returns `''` otherwise; none of these English
   phrases coincidentally consist of only Electrum wordlist tokens in
   multiples of 3).
3. **Electrum Type-1**, real 100,000-round `electrum_stretch_key`, on a
   **curated 39-phrase "best/most plausible" subset** (short, era-appropriate
   phrases/terms a real person would plausibly type as a seed — not entire
   paragraphs), × 3 cheap 16-byte hex-seed derivations each
   (`SHA256(phrase)[:16]`, `MD5(phrase)`, raw UTF-8 bytes
   zero-padded/truncated to 16 bytes). 117 real stretches, 5.91s
   (~50ms/stretch, matching the task's own estimate). This follows the
   task's explicit instruction: spend the expensive path on best candidates,
   not the entire list — the 39-phrase subset deliberately excludes long
   paragraph-length quotes (e.g. the full abstract opening line, full
   Satoshi quotes) since those are implausible as a literally-typed seed,
   and excludes the 5 `likely_postdates_2015` phrases.

## A note on expected small-`n` noise (read before judging any raw match count)

Per this research thread's now-established methodology (see
`common_passwords.py`/`.md`), `apply_puzzle_mask(raw, n)` keeps only the low
`(n-1)` bits and forces bit `(n-1)` high, so puzzle `n` has exactly `(n-1)`
"free" bits and matches an arbitrary candidate by pure chance with
probability `2^-(n-1)`. `n=1` is degenerate — masked is unconditionally `1`
for *any* raw input (confirmed by direct computation on 5 probe values
including `0`, `1`, and `2^200`) — and is excluded from the 82-puzzle
dataset entirely before matching (81 puzzles, `n=2..130`, used).

Rather than treat every raw non-empty match as alarming, each is passed
through a pre-registered Bonferroni-style filter:

```
expected_spurious_count(matched_ns) =
    total_candidates_this_run * prod(2^-(n-1) for n in matched_ns)
```

Only `expected_spurious_count < 0.001` would escalate to the CRITICAL SAFETY
STOP protocol — matching the task's own framing that a real hit means
"matching a specific 20+-bit number by chance" or "a match across two or
more puzzles simultaneously."

**Observed noise this run**, all sub-threshold and expected:
- Classic Type-1: 406 chance-level coincidences across 576 candidates, top
  patterns `(n=2,)`: 152, `(n=2,3)`: 67, `(n=3,)`: 59 — matching the
  theoretical ~50%/~25% base rates for `n=2`/`n=3` closely.
- Electrum Type-1 (best-candidates subset): 88 chance-level coincidences
  across 117 candidates, top patterns `(n=2,)`: 33, `(n=2,3)`: 11,
  `(n=3,)`: 10 — same expected shape, smaller sample.

No pattern in either tally involves `n≥8` at any meaningful frequency, and
none approached the `<0.001`-expected-count threshold at any point.

## Results

- **Classic Type-1:** 576 (phrase, format) combinations tested against all
  81 usable solved puzzles (n≥2). **0 significant matches.** 406 sub-threshold
  chance coincidences (all small-`n`, as predicted).
- **Word-mnemonic path:** 0 of 72 phrases produced a non-empty Electrum
  old-mnemonic decode. Not a contributing test.
- **Electrum Type-1 (39-phrase best-candidates subset × 3 derivations):**
  117 real 100,000-round-stretch derivations tested against all 81 usable
  solved puzzles. **0 significant matches.** 88 sub-threshold chance
  coincidences (all small-`n`, as predicted).
- **CRITICAL SAFETY RULE status: never triggered.** No candidate, under
  either scheme, in any format/derivation, produced an `expected_spurious_
  count < 0.001` match against any of the 82 real solved puzzles. This is
  the expected, honest result — consistent with every other category tested
  in this research thread and with the Phase 2-6 finding that no accessible
  shortcut has been found for Puzzle #71.

Full machine-readable output (candidate list, per-category counts,
chance-tally breakdowns, sample hex seeds): `crypto_culture_quotes_results.json`.

## Full candidate list (72 phrases)

| # | Phrase | Category | Era | In Electrum best-subset? |
|---|---|---|---|---|
| 1 | The Times 03/Jan/2009 Chancellor on brink of second bailout for banks | genesis_coinbase | contemporary | yes |
| 2 | Chancellor on brink of second bailout for banks | genesis_coinbase | contemporary | yes |
| 3 | The Times 03/Jan/2009 | genesis_coinbase | contemporary | no |
| 4 | 03/Jan/2009 Chancellor on brink of second bailout for banks | genesis_coinbase | contemporary | no |
| 5 | Bitcoin: A Peer-to-Peer Electronic Cash System | whitepaper | contemporary | yes |
| 6 | A Peer-to-Peer Electronic Cash System | whitepaper | contemporary | yes |
| 7 | Bitcoin A Peer to Peer Electronic Cash System | whitepaper | contemporary | no |
| 8 | A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution. | whitepaper | contemporary | no |
| 9 | satoshin@gmx.com | whitepaper | contemporary | yes |
| 10 | www.bitcoin.org | whitepaper | contemporary | yes |
| 11 | Satoshi Nakamoto | satoshi_identity | contemporary | yes |
| 12 | satoshi nakamoto | satoshi_identity | contemporary | yes |
| 13 | Nakamoto | satoshi_identity | contemporary | yes |
| 14 | I am not Dorian Nakamoto | satoshi_identity | likely_postdates_2015 | no |
| 15 | I've been working on a new electronic cash system that's fully peer-to-peer, with no trusted third party. | satoshi_quote | contemporary | no |
| 16 | The root problem with conventional currency is all the trust that's required to make it work. | satoshi_quote | contemporary | no |
| 17 | Lost coins only make everyone else's coins worth slightly more. Think of it as a donation to everyone. | satoshi_quote | contemporary | no |
| 18 | If you don't believe me or don't get it, I don't have time to try to convince you, sorry. | satoshi_quote | contemporary | no |
| 19 | It might make sense just to get some in case it catches on. | satoshi_quote | contemporary | no |
| 20 | I've developed a new open source P2P e-cash system called Bitcoin | satoshi_quote | contemporary | no |
| 21 | Announcing the first release of Bitcoin | satoshi_quote | contemporary | no |
| 22 | Bitcoin v0.1 released | satoshi_quote | contemporary | no |
| 23 | Running bitcoin | satoshi_quote | contemporary | yes |
| 24 | Privacy is necessary for an open society in the electronic age | cypherpunk_manifesto | contemporary | no |
| 25 | Cypherpunks write code | cypherpunk_manifesto | contemporary | yes |
| 26 | cypherpunks write code | cypherpunk_manifesto | contemporary | yes |
| 27 | We the Cypherpunks are dedicated to building anonymous systems | cypherpunk_manifesto | contemporary | no |
| 28 | Cypherpunks deplore regulations on cryptography | cypherpunk_manifesto | contemporary | no |
| 29 | Arise, you have nothing to lose but your barbed wire fences | crypto_anarchist_manifesto | contemporary | no |
| 30 | A specter is haunting the modern world, the specter of crypto anarchy | crypto_anarchist_manifesto | contemporary | no |
| 31 | The Crypto Anarchist Manifesto | crypto_anarchist_manifesto | contemporary | no |
| 32 | If privacy is outlawed, only outlaws will have privacy | pgp_zimmermann | contemporary | no |
| 33 | Pretty Good Privacy | pgp_zimmermann | contemporary | no |
| 34 | b-money | precursor_concept | contemporary | yes |
| 35 | bit gold | precursor_concept | contemporary | yes |
| 36 | hashcash | precursor_concept | contemporary | yes |
| 37 | Hashcash | precursor_concept | contemporary | yes |
| 38 | Wei Dai | precursor_concept | contemporary | no |
| 39 | Nick Szabo | precursor_concept | contemporary | no |
| 40 | Adam Back | precursor_concept | contemporary | no |
| 41 | proof of work | precursor_concept | contemporary | yes |
| 42 | proof-of-work | precursor_concept | contemporary | yes |
| 43 | double-spending problem | precursor_concept | contemporary | yes |
| 44 | the double-spending problem | precursor_concept | contemporary | no |
| 45 | HODL | community_slogan | contemporary | yes |
| 46 | hodl | community_slogan | contemporary | yes |
| 47 | I AM HODLING | community_slogan | contemporary | yes |
| 48 | vires in numeris | community_slogan | contemporary | yes |
| 49 | Vires in Numeris | community_slogan | contemporary | yes |
| 50 | in math we trust | community_slogan | contemporary | yes |
| 51 | Bitcoin: In Math We Trust | community_slogan | contemporary | yes |
| 52 | be your own bank | community_slogan | contemporary | yes |
| 53 | Be your own bank | community_slogan | contemporary | yes |
| 54 | digital gold | community_slogan | contemporary | yes |
| 55 | trustless | community_slogan | contemporary | yes |
| 56 | 21 million | community_slogan | contemporary | yes |
| 57 | 21000000 | community_slogan | contemporary | yes |
| 58 | genesis block | community_slogan | contemporary | yes |
| 59 | the genesis block | community_slogan | contemporary | yes |
| 60 | to the moon | community_slogan | likely_postdates_2015 | no |
| 61 | not your keys not your coins | community_slogan | likely_postdates_2015 | no |
| 62 | not your keys, not your coins | community_slogan | likely_postdates_2015 | no |
| 63 | not your keys, not your bitcoin | community_slogan | likely_postdates_2015 | no |
| 64 | 10000 bitcoins for a pizza | pizza_day | contemporary | no |
| 65 | 10000 BTC for two pizzas | pizza_day | contemporary | no |
| 66 | Laszlo Hanyecz | pizza_day | contemporary | yes |
| 67 | bitcoin pizza day | pizza_day | contemporary | yes |
| 68 | correct horse battery staple | generic_crypto_culture | contemporary | yes |
| 69 | Correct Horse Battery Staple | generic_crypto_culture | contemporary | yes |
| 70 | Alice and Bob | generic_crypto_culture | contemporary | yes |
| 71 | alice and bob | generic_crypto_culture | contemporary | no |
| 72 | the quick brown fox jumps over the lazy dog | generic_crypto_culture | contemporary | no |

## Bottom line

Consistent with every other seed-guessing category run so far in this
research thread (`puzzle_culture.md`, `common_passwords.md`) and with the
Phase 2-6 headline finding: **no accessible dictionary/guessing shortcut
found.** This does not prove no such seed exists — it is a finite, disclosed
candidate list against one honest test, not an exhaustive search — but it
rules out the specific 72 phrases tested here, under both deterministic-
wallet schemes, in every plausible formatting/derivation variant checked.
