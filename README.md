# Bitcoin Puzzle #71 -- cryptanalytic research program

Target: `1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU`, private key in
`[0x400000000000000000, 0x7FFFFFFFFFFFFFFFFF]` (2^70 keys). Unsolved as of
2026-08-18; current reward ~7.10 BTC.

This is **not** a brute-force script. The goal is to find genuine,
out-of-sample-validated structure in how the puzzle's private keys were
generated that would shrink the effective search space below 2^70 --
and to say so explicitly if no such structure survives scrutiny.

## Status

| Phase | Description | Status |
|---|---|---|
| 0 | Cryptographic verification (secp256k1/HASH160/Base58Check, known-answer tests) | done -- `tests/test_btcaddr.py` |
| 1 | Solved-puzzle dataset (#1-70), cryptographically re-derived and verified, not just scraped | done -- `data/solved_puzzles.{json,csv}`, 70/70 pass `tests/validate_solved_puzzles.py` |
| 2 | Generator-hypothesis reconstruction | done -- **all 6 hypotheses rejected/unfalsifiable**, `research/generator_hypotheses.md` |
| 3 | Statistical cryptanalysis (randomness battery, null models) | done -- clean nulls, `research/stats/` |
| 4 | Walk-forward validation (train on <=N, predict N+1..M) | done -- nothing retained to validate, `research/walk_forward_validation.md` |
| 5 | Historical archaeology (creator statements, period code) | done -- `research/archaeology/` |
| 6 | On-chain forensics (funding tx fingerprints) | done -- `research/onchain/` |
| 7 | Search-space reduction / tiered candidate ranking | **0 bits of reduction found** -- see `research/PHASE_2_6_SUMMARY.md` §(d); no tiering is justified by the evidence |
| 8 | High-performance search engine | running (see below) -- correct, checkpointed, resumable, but negligible on this hardware |
| 9 | Distributed search coordination | single-container only for now (`src/search_coordinator.py`); real multi-machine coordination not built |
| 10 | Continuous research loop | not applicable -- Phase 2-6 exhausted the tested hypothesis space without finding a lead to iterate on |

## Phase 2-6 headline finding

**No hypothesis, statistic, or model beat random guessing on out-of-sample
puzzle data.** The candidate interval for Puzzle #71 remains the full
`[2^70, 2^71)`, uniformly weighted by all evidence gathered. This
replicates a decade of community findings. Full writeup:
`research/PHASE_2_6_SUMMARY.md`.

## Phase 8: the search engine is running, but read this first

`src/search_coordinator.py` is running now, spawning one worker per CPU
core. Each worker steps the EC point by adding G once per candidate
(instead of a full scalar multiplication), checkpoints every 5s to
`data/search_state/` (gitignored -- runtime state, not source), and
resumes automatically if restarted. Check live progress any time:

```
python3 src/search_status.py
```

**Honest numbers, measured on this container** (4 vCPU, no GPU):
~280,000 keys/sec aggregate. The interval is `2^70 ≈ 1.18e21` keys.
At this speed, exhausting the assigned range takes **~130 million
years**. This is not a rounding error -- it is what "no GPU, no
cryptanalytic shortcut" actually means at this scale. The community's
combined pool hashrate (many GPUs, running for years) estimates ~421
years for the same interval; this container's CPU-only contribution is
a vanishingly small fraction of that.

**This container is also ephemeral** -- it's reclaimed after a period of
inactivity, which will stop the search regardless of the above. Nothing
here should be read as "this will find the key" or even "this meaningfully
improves the odds." It's built correct and resumable because that's the
honest way to ship a search engine, not because 4 CPU cores stand a real
chance against 2^70.

**If you want this to matter:** the only ways forward are (a) real GPU
hardware running an optimized, audited implementation -- e.g.
[VanitySearch](https://github.com/JeanLucPons/VanitySearch) or
[KeyHunt-Cuda](https://github.com/albertobsd/keyhunt), both open-source
and worth reading before running, not this Python engine -- pointed at
this same interval, ideally coordinated with the wider puzzle-hunting
community to avoid duplicated work; or (b) a genuine cryptanalytic lead
this program didn't find. Two untested leads remain open in
`research/archaeology/period_wallets.md` (Electrum Type-1 and classic
`SHA256(master+n)` derivation) -- both need a seed/passphrase-guessing
attack, not statistical pattern-mining, and neither was run to completion.

## Layout

- `src/btcaddr.py` -- verified secp256k1 -> P2PKH address pipeline (uses `coincurve`/libsecp256k1, not a from-scratch EC implementation)
- `src/build_dataset.py` -- builds `data/solved_puzzles.{json,csv}` from the raw scraped table, after cryptographic verification
- `src/search_engine.py` -- Phase 8 worker: incremental EC-point search, checkpoint/resume, found-key handling (independent double-verification, restrictive local file, never logged/printed)
- `src/search_coordinator.py` -- spawns one worker per CPU core over non-overlapping chunks from a random anchor offset
- `src/search_status.py` -- aggregate progress/ETA report across all worker checkpoints
- `tests/test_btcaddr.py` -- Phase 0 known-answer tests
- `tests/validate_solved_puzzles.py` -- cross-checks every solved-puzzle entry against the crypto pipeline
- `tests/test_search_engine.py` -- Phase 8 correctness tests against a synthetic target (checkpoint/resume, found-detection, stop-signal)
- `data/solved_puzzles_raw.json` -- scraped table (provenance noted, not trusted until verified)
- `data/solved_puzzles.{json,csv}` -- verified dataset with derived fields (normalized position in interval, EC point, etc.)
- `research/generator_hypotheses.md` -- ledger of all 6 generator hypotheses tested and why each was rejected/unfalsifiable
- `research/PHASE_2_6_SUMMARY.md` -- the honest synthesis of Phases 2-6 (read this first)
- `research/walk_forward_validation.md`, `research/stats/`, `research/archaeology/`, `research/onchain/` -- supporting analysis and evidence
