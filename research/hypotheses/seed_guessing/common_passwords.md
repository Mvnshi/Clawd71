# Seed-guessing attack: common/weak passwords and test values

**Status: no exploitable match found. 80,090 candidates tested (80,000 classic
Type-1 + 90 Electrum Type-1) against the real 82-puzzle dataset; the observed
chance-level coincidence rates track the theoretical null almost exactly,
which is itself a useful confirmation that the harness has no hidden bug
inflating or suppressing matches.**

## What this tests

Phase 2's statistical hypothesis tests (`research/PHASE_2_6_SUMMARY.md`) found
no exploitable pattern in the puzzle's *bit sequence itself* — expected, since
a real deterministic-wallet/hash-chain generator is by design statistically
indistinguishable from random to an outside observer who doesn't know the
seed. This is the complementary attack: guess the **seed/passphrase**
directly, for two historically-plausible deterministic-wallet schemes, using
the already-validated harness in `src/seed_attack.py` (validated against a
real published Electrum test vector and positive-control synthetic datasets
— see `tests/test_seed_attack.py`, all passing before this run).

1. **Classic Type-1 brainwallet-style**: `child_key(n) = SHA256(masterstring
   formatted with n)`, across all 8 formats in `FORMATS`
   (`plain`, `colon`, `dash`, `space`, `zero_indexed`, `colon_zero_indexed`,
   `n_then_m`, `sha256d`). Cheap — pure SHA256, no stretching.
2. **Electrum "Type-1" (pre-2.0) wallet**: 100,000-round SHA256 stretch of a
   32-hex-char (16-byte) seed → master secret → master pubkey → per-index
   child key. Expensive (~50ms/seed on this machine) because of the stretch,
   so only run against the top 30 most common passwords, each converted to a
   16-byte hex seed via three *cheap* transforms (the real deterministic
   script may never have gone through Electrum's literal mnemonic-word UI —
   just some short transform feeding the same `stretch_key` function):
   - `SHA256(phrase)[:16]` as hex
   - `MD5(phrase)` as hex (already 16 bytes)
   - raw UTF-8 bytes of `phrase`, zero-padded/truncated to 16 bytes, as hex

Both raw derivations get the puzzle's own stated masking applied
(`apply_puzzle_mask`: keep the low `n-1` bits, force bit `n-1` high) before
comparison against `data/solved_puzzles.json`'s real `key_int` for that `n`.

## Wordlist source

**SecLists `10k-most-common.txt`**, fetched 2026-08-19:

```
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt
```

HTTP 200, 10,000 lines. A verbatim copy is saved alongside this report at
`research/hypotheses/seed_guessing/10k-most-common.txt` for reproducibility.
This is the standard, widely-used "top 10k passwords" list distributed in
the well-known `danielmiessler/SecLists` GitHub repository (Common-Credentials
category), not an invented or hand-picked list. First 30 entries (also the
set escalated to the Electrum path below):

```
password, 123456, 12345678, 1234, qwerty, 12345, dragon, pussy, baseball,
football, letmein, monkey, 696969, abc123, mustang, michael, shadow, master,
jennifer, 111111, 2000, jordan, superman, harley, 1234567, fuckme, hunter,
fuckyou, trustno1, ranger
```

## Candidates actually tested

| category | candidates | breakdown | wall time |
|---|---|---|---|
| Classic Type-1 | 80,000 | 10,000 passwords × 8 formats | 7.9s |
| Electrum Type-1 (cheap-derivation) | 90 | 30 passwords × 3 hex-seed transforms, each run through the full real 100k-round stretch | 4.6s |
| **Total** | **80,090** | | **12.5s** |

Full run log and raw counts: `research/hypotheses/seed_guessing/common_passwords_results.json`.
Code: `research/hypotheses/seed_guessing/common_passwords.py` (reproducible —
re-running it end to end regenerates the same results file).

## Handling the degenerate small-`n` puzzles (read before judging "0 matches")

`apply_puzzle_mask(raw, n)` keeps only the low `n-1` bits of `raw` and forces
bit `n-1` high, so puzzle `n` has exactly `n-1` "free" bits and an arbitrary
candidate matches it by pure chance with probability `2^-(n-1)`.

- **`n=1` is fully degenerate**: 0 free bits, so `apply_puzzle_mask(raw, 1)`
  equals `1` for *every possible* `raw` input — confirmed directly by
  computation (`apply_puzzle_mask(2**200, 1) == 1`, etc.), not assumed. The
  real puzzle #1 key is `1`, so puzzle 1 "matches" *unconditionally* for
  every candidate, always. This is exactly the failure mode the task
  instructions warned to check for ("confirm your loop isn't accidentally
  matching puzzle #1's key=1 for trivial/degenerate inputs"), and it fired
  on the very first run of this script. It is not a harness bug — it's
  structurally inherent to a 1-bit puzzle with only one possible value —
  and it mirrors the validated module's own test convention:
  `tests/test_seed_attack.py`'s positive-control synthetic datasets
  deliberately start at `n=2`, excluding `n=1` for the same reason. **`n=1`
  is excluded from the matching dataset for this run** (81 puzzles, n=2..130,
  used throughout).
- **`n=2` (1 free bit) is not degenerate, but with 80,000 candidates in the
  classic sweep it WILL produce thousands of spurious "matches" on n=2 alone
  by pure chance** — this is real, unavoidable multiple-testing noise, not a
  bug or a near-miss.

Rather than halting the whole sweep on every such expected coincidence
(which would make it impossible to ever finish testing against a dataset
containing such small puzzles), every non-empty match returned by
`test_candidate_against_dataset` was passed through a pre-registered,
disclosed Bonferroni-style filter:

```
expected_spurious_count(matched_puzzle_set) =
    total_candidates_this_category * prod(2^-(n-1) for n in matched_puzzle_set)
```

A match is only treated as a real CRITICAL-SAFETY-RULE trigger if
`expected_spurious_count < 0.001` (fewer than 1-in-1000 expected purely by
chance given how many candidates *this exact run* tested). Everything above
that threshold is logged as chance-level noise and the sweep continues. No
candidate in this run cleared the threshold.

### The chance-noise tally doubles as a validation check

Because 80,000 SHA256-based classic-Type-1 candidates were tested against
puzzles n=2..16, the *observed* spurious-match rate per puzzle can be
compared directly to the *theoretical* `2^-(n-1)` prediction — if this
scheme's outputs were secretly biased or correlated with the real keys in
some way the mask doesn't erase, this table would show it:

| n | free bits | observed matches / 80,000 | observed rate | expected rate (2^-(n-1)) |
|---|---|---|---|---|
| 2 | 1 | 40,259 | 0.5032 | 0.5 |
| 3 | 2 | 20,050 | 0.2506 | 0.25 |
| 4 | 3 | 9,860 | 0.1233 | 0.125 |
| 5 | 4 | 5,031 | 0.0629 | 0.0625 |
| 6 | 5 | 2,470 | 0.0309 | 0.03125 |
| 7 | 6 | 1,228 | 0.0154 | 0.015625 |
| 8 | 7 | 626 | 0.0078 | 0.0078125 |
| 9 | 8 | 294 | 0.0037 | 0.0039 |
| 10 | 9 | 175 | 0.0022 | 0.00195 |
| 11 | 10 | 60 | 0.00075 | 0.00098 |
| 12 | 11 | 44 | 0.00055 | 0.00049 |

Observed tracks expected almost exactly across every order of magnitude —
the classic-Type-1 SHA256 candidates behave exactly like independent random
draws against the real dataset, confirming both that the harness is counting
correctly and that this candidate pool carries no hidden correlation with
the real keys beyond ordinary chance.

## Results

**Classic Type-1**: 80,000 candidates (10,000 passwords × 8 formats), **0
significant matches**. 57,072 candidates (71%) produced at least one
chance-level (sub-threshold) coincidence on small puzzles, consistent with
the table above. The largest single puzzle number appearing in any observed
chance-level match was `n=19`; the *closest-to-significant* pattern observed
was a candidate matching both `n=7` and `n=18` simultaneously (occurred
twice), with `expected_spurious_count ≈ 0.0095` — about 9.5× above the 0.001
significance bar, still comfortably in chance-noise territory and correctly
not escalated.

**Electrum Type-1 (cheap hex-seed derivations)**: 90 candidates (top 30
passwords × 3 transforms), each run through the real, unavoidable 100k-round
stretch. **0 significant matches**. 67/90 candidates produced at least one
chance-level coincidence (expected, given how many candidates matched small
puzzles even at only 90 candidates — e.g. `n=2` alone hit 26/90 ≈ 29%, in the
right ballpark of the 50% marginal rate given overlap with multi-puzzle
combinations). The closest-to-significant pattern was a candidate matching
`n=2, 3, and 11` simultaneously (once), `expected_spurious_count ≈ 0.011` —
about 11× above the significance bar.

No candidate in either category — across all formats, all hex-seed
derivations, and the full 10,000-word list — produced a masked derived key
matching any real puzzle's key at a significance level distinguishable from
chance.

## Escalation to the full expensive Electrum stretch

The task asked to "escalate only your top few most plausible candidates" to
the full expensive Electrum stretch. In practice there was no cheap way to
short-circuit this for the Electrum scheme at all: the 100k-round stretch is
required to turn *any* hex seed (however it was derived) into a master
secret, so "cheap hex-seed derivation" only cheapens how the 32-hex-char seed
string is produced, not the derivation that follows. Running the full,
unavoidable stretch on all 90 candidates (30 passwords × 3 derivations) cost
under 5 seconds — well inside the "hundreds to low thousands" budget noted in
the task, so no further pruning was necessary; every cheap-derivation
candidate got the real, full derivation, not an approximation.

## Limitations / scope

- This only covers one wordlist (SecLists top 10k) and the 8 formats already
  defined in `FORMATS`. It does not cover multi-word passphrases, leetspeak
  variants, Bitcoin/crypto-specific slang not already present in the list
  (e.g. "satoshi", "nakamoto", "bitcoin1971" style constructions), or
  non-English wordlists.
- The Electrum path only tested 3 cheap hex-seed transforms on the top 30
  passwords, not the full 10,000 — deliberately, to respect the ~50ms/seed
  cost budget. A genuine Electrum-mnemonic-word passphrase (using Electrum's
  actual 1626-word old-mnemonic wordlist) was not attempted here since none
  of these common English passwords are valid entries in that specific
  wordlist; that is a separate, narrower hypothesis for a future pass if
  warranted.
- As with every negative result in this repo: absence of a match here is not
  proof the seed isn't a common password under some untested format/transform
  — only that it isn't one of the 80,090 concretely tested combinations.

## Safety-rule compliance

Per the task's CRITICAL SAFETY RULE: no candidate cleared the significance
threshold in this run, so there is nothing to withhold. The one non-empty
match discovered during harness development (`masterstring=""`, format
`plain`, matching only puzzle `n=2`) was investigated per the rule's own
guidance before being dismissed — confirmed structurally as chance-level
(1-in-2 base rate, `expected_spurious_count` far above 0.001), not a
harness bug and not a real signal, and is disclosed above rather than
hidden.
