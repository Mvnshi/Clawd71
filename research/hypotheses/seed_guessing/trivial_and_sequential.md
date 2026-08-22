# Seed-guessing attack: trivial, degenerate, and sequential hex seeds

**Status: no exploitable match found. 82,824 classic Type-1 candidates +
10,348 Electrum Type-1 candidates (the latter run through the REAL, full
100,000-round stretch — no cheap approximation) tested against the real
82-puzzle dataset. Zero statistically significant matches under either
scheme.**

## What this tests

Phase 2's statistical hypothesis tests (`research/PHASE_2_6_SUMMARY.md`) found
no exploitable pattern in the puzzle's *bit sequence itself* — expected, since
a real deterministic-wallet/hash-chain generator is by design statistically
indistinguishable from random to an outside observer who doesn't know the
seed. This is the complementary attack: guess the **seed/passphrase**
directly, using the already-validated harness in `src/seed_attack.py`
(validated against a real published Electrum test vector and positive-control
synthetic datasets — see `tests/test_seed_attack.py`, all passing before this
run).

This category tests the **"did the creator just not bother" hypothesis**:
that instead of picking a memorable phrase, the deterministic-wallet seed was
some trivial, degenerate, or sequential value — the kind of placeholder a
developer types while testing code and occasionally forgets to replace.
Candidates are constructed as raw 32-hex-char (16-byte) seeds directly,
bypassing any phrase/mnemonic-word layer entirely.

1. **Classic Type-1 brainwallet-style**: `child_key(n) = SHA256(masterstring
   formatted with n)`, across all 8 formats in `FORMATS` (`plain`, `colon`,
   `dash`, `space`, `zero_indexed`, `colon_zero_indexed`, `n_then_m`,
   `sha256d`). Cheap — pure SHA256, no stretching — so every candidate's hex
   text (or decimal string, for integers) was used as the masterstring.
2. **Electrum "Type-1" (pre-2.0) wallet**: 100,000-round SHA256 stretch of a
   32-hex-char (16-byte) seed → master secret → master pubkey → per-index
   child key. Normally expensive (~50-58ms/seed on this machine), but this
   category is conceptually cheap enough (a bounded, enumerable set of
   trivial/degenerate patterns) that the task instructions explicitly called
   for running the **real, full stretch on every candidate**, not a cheap
   approximation. See "Candidate count vs. the 'few hundred' framing" below
   for how the literal `0-10000` integer instruction was reconciled with
   that framing.

Both raw derivations get the puzzle's own stated masking applied
(`apply_puzzle_mask`: keep the low `n-1` bits, force bit `n-1` high) before
comparison against `data/solved_puzzles.json`'s real `key_int` for that `n`.

## Candidate buckets (10,353 labeled candidates → 10,348 unique hex seeds)

| bucket | count | construction |
|---|---:|---|
| Trivial / degenerate / sequential patterns | 9 | all-zeros, all-`f`s, `0000...0001`, ascending/descending hex-digit text (`0123456789abcdef` ×2, reverse), ascending/descending raw byte-value ramps (`00..0f`, `01..10`, `10..1f`, `ff..f0`) |
| "Magic number" hex constants, tiled to 16 bytes | 8 | `deadbeef`, `cafebabe`, `baadf00d`, `feedface`, `8badf00d`, `0defaced`, `deadc0de`, `b16b00b5` |
| Target puzzle number, zero-padded | 1 | `71` as a 32-hex-char big-endian integer |
| Repeating single-byte patterns, all 256 byte values | 256 | `0x00*16` .. `0xff*16` (includes duplicates of all-zeros/all-`f` — deduped) |
| **Trivial/degenerate/byte-repeat subtotal** | **274** | matches the task's "a few hundred truly trivial candidates" framing |
| Small integers, zero-padded to 32 hex chars | 10,001 | `0..10000` as big-endian 16-byte integers (literal task instruction) |
| Simple English/crypto-culture words, raw UTF-8, zero-padded/truncated to 16 bytes | 49 | `bitcoin`, `satoshi`, `nakamoto`, `puzzle71`, `brainwallet`, `hunter2`, `correcthorsebatterystaple`, etc. — see full list in code |
| Short number strings, raw UTF-8, zero-padded/truncated to 16 bytes | 29 | `"0".."20"`, `"71"`, `"82"`, `"130"`, `"160"`, `"1971"`, `"2009"`, `"2011"`, `"2015"` |
| **Total labeled** | **10,353** | |
| **Unique hex seeds after dedup** (Electrum path) | **10,348** | 5 label collisions, e.g. `int_0` / `all_zeros` / `byte_repeat_0x00` are the same 16 zero bytes; `int_71` collides with the explicit `puzzle_number_71` entry |

Full candidate construction code: `research/hypotheses/seed_guessing/trivial_and_sequential.py`
(reproducible — re-running it regenerates the same results file). Representative
samples of every bucket are saved in
`research/hypotheses/seed_guessing/trivial_and_sequential_results.json`.

### Candidate count vs. the "few hundred" framing

The task's category description simultaneously (a) lists `small integers
0-10000` as an example construction and (b) frames the category as
containing "only on the order of a few hundred truly 'trivial' candidates."
These are in tension — `0-10000` alone is 10,001 candidates. This script
resolves it transparently rather than silently picking one reading: the
truly trivial/degenerate/byte-repeat patterns really do total **274**,
matching the "few hundred" framing exactly, and the literal `0-10000`
integer instruction is honored as a **separate, explicitly-labeled bucket**
on top of that (10,001 more). The combined total (10,348 unique Electrum
candidates) stays within the task's overall stated Electrum budget
("hundreds to low thousands, not millions") and completed in under 5 minutes
via 4-way process parallelism (the 100k-round stretch is independent per
candidate — embarrassingly parallel, no change to the validated algorithm
or its inputs/outputs).

## Handling the degenerate small-`n` puzzles (read before judging "0 matches")

Identical approach to the sibling reports in this directory
(`common_passwords.md`, `puzzle_culture.md`, `crypto_culture_quotes.md`):

`apply_puzzle_mask(raw, n)` keeps only the low `n-1` bits of `raw` and forces
bit `n-1` high, so puzzle `n` has exactly `n-1` "free" bits and an arbitrary
candidate matches it by pure chance with probability `2^-(n-1)`.

- **`n=1` is fully degenerate**: 0 free bits, so `apply_puzzle_mask(raw, 1)`
  equals `1` for *every possible* `raw` input — confirmed directly by
  computation (`apply_puzzle_mask(2**200, 1) == 1`, etc.), not assumed. The
  real puzzle #1 key is `1`, so puzzle 1 "matches" *unconditionally* for
  every candidate, always — exactly the failure mode the task instructions
  warned to check for. **`n=1` is excluded from the matching dataset for
  this run** (81 puzzles, n=2..130, used throughout).
- **`n=2` (1 free bit) is not degenerate, but with tens of thousands of
  candidates in the classic sweep it WILL produce thousands of spurious
  "matches" on n=2 alone by pure chance** — real, unavoidable
  multiple-testing noise, not a bug or a near-miss.

Every non-empty match returned by `test_candidate_against_dataset` is passed
through the same pre-registered, disclosed Bonferroni-style filter used
throughout this research effort:

```
expected_spurious_count(matched_puzzle_set) =
    total_candidates_this_category * prod(2^-(n-1) for n in matched_puzzle_set)
```

A match is only treated as a real CRITICAL-SAFETY-RULE trigger if
`expected_spurious_count < 0.001`. Everything above that threshold is logged
as chance-level noise and the sweep continues.

## Results

### Part 1 — Classic Type-1 (82,824 candidates: 10,353 masterstrings × 8 formats)

**0 significant matches.** 82,824 candidates tested in 7.9s. 58,887
candidate-format combinations (71%) produced at least one chance-level
(sub-threshold) coincidence — the top observed patterns (`n=2` alone:
24,068; `n=2,3` together: 8,014; `n=3` alone: 7,798) track the theoretical
`2^-(n-1)` per-puzzle chance rate closely, consistent with this SHA256-based
scheme behaving like independent random draws against the real dataset (the
same sanity check performed in `common_passwords.md`). The single
closest-to-significant coincidence observed was a candidate matching
`n = 3, 6, 7, 13` simultaneously (occurred once), `expected_spurious_count ≈
0.00247` — about 2.5× above the 0.001 significance bar, correctly not
escalated.

### Part 2 — Electrum Type-1, full 100,000-round stretch (10,348 unique hex seeds)

**0 significant matches.** 10,348 candidates tested in 275.0s (4.6 minutes)
using 4-way process parallelism (~26.6ms/candidate effective throughput —
close to the ~4× speedup expected from `NPROC=4` over the raw ~58ms/candidate
serial cost measured on this machine). Every single trivial/degenerate/
sequential pattern, every integer 0-10000, and every word/number-string was
run through the real, unmodified, validated `electrum_stretch_key` →
`electrum_child_privkey` derivation — no shortcuts, no cheap approximation.
7,404 candidates (72%) produced at least one chance-level coincidence,
tracking the same theoretical rate (`n=2` alone: 3,048; `n=3` alone: 1,027;
`n=2,3` together: 993). The closest-to-significant coincidence was a
candidate matching `n = 2, 3, 4, 6, 10` simultaneously (once),
`expected_spurious_count ≈ 0.00987` — about 9.9× above the significance bar.

No candidate in either category — across all formats, all 274
trivial/degenerate/byte-repeat patterns, all 10,001 integers 0-10000, and
all 78 words/number-strings — produced a masked derived key matching any
real puzzle's key at a significance level distinguishable from chance.

Full run log and raw counts (including chance-tally breakdowns and sample
candidate hex seeds per bucket):
`research/hypotheses/seed_guessing/trivial_and_sequential_results.json`.

## Limitations / scope

- This covers the specific trivial/degenerate/sequential constructions named
  in the task plus a bounded word/number-string extension — it does not
  cover multi-word passphrases, leetspeak, non-English trivial strings, or
  integers beyond 10,000 (e.g. it does not test `2^70`, `2^71`, or other
  puzzle-bit-boundary-relevant large integers as raw seed material — a
  narrower follow-up hypothesis if warranted).
- The `puzzle_number` bucket only explicitly targeted `71`; other
  puzzle-relevant numbers (the current dataset size 82, or historical puzzle
  counts like 160) are implicitly covered only via the general `0-10000`
  integer sweep, not called out with their own dedicated label.
- As with every negative result in this repo: absence of a match here is not
  proof the seed isn't some trivial/degenerate value — only that it isn't
  one of the 10,348 concretely tested Electrum hex seeds or 82,824 concretely
  tested classic Type-1 combinations.

## Safety-rule compliance

Per the task's CRITICAL SAFETY RULE: no candidate cleared the significance
threshold in this run, so there is nothing to withhold. Before trusting this
negative result, the harness itself was re-verified (this run, live) against
the known n=1 degenerate case — `apply_puzzle_mask(raw, 1) == 1` for
`raw ∈ {0, 1, 12345, 2**200, 999999999999}`, confirming the loop's exclusion
of n=1 is deliberate and correct, not an accidental non-match masking a real
one. `tests/test_seed_attack.py`'s three controls (real Electrum test vector,
Electrum positive control, classic Type-1 positive control) all pass.
