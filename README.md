# Bitcoin Puzzle #71 -- cryptanalytic research program

Target: `1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU`, private key in
`[0x400000000000000000, 0x7FFFFFFFFFFFFFFFFF]` (2^70 keys). Unsolved as of
2026-08-19; current reward ~7.10 BTC.

**This repository is a merge of two independently-conducted research
lines** on this repo's two feature branches, consolidated here after each
was checked against the other and, where they overlapped, cross-verified
rather than assumed to agree. Where they used genuinely different methods
and reached the same conclusion, that's noted explicitly -- it's stronger
evidence than either alone.

This is **not** a brute-force script. The primary goal was to find
genuine, out-of-sample-validated structure in how the puzzle's private
keys were generated that would shrink the effective search space below
2^70 -- and to say so explicitly if no such structure survives scrutiny
(it didn't, on either research line). A correct, checkpointed search
engine is included and running, but read the feasibility numbers below
before expecting anything from it.

## Headline result

**No hypothesis, statistic, or model beats random guessing on
out-of-sample puzzle data, across two independent implementations.**

- Line A (this branch's original work): 6 generator hypotheses,
  3 statistical batteries, Monte Carlo null models on a 70-puzzle
  dataset. All rejected or ruled unfalsifiable. See
  `research/PHASE_2_6_SUMMARY.md`.
- Line B (merged in from `claude/bitcoin-puzzle-71-797pkr`): 87 generator
  hypotheses (with positive/negative controls proving the test harness
  can detect a real pattern when one exists), 76 statistical tests with
  Holm/Benjamini-Hochberg correction, a 6-fold walk-forward validation
  with a permutation null, on an 82-puzzle dataset. Same conclusion. See
  `research/BROAD_REPLICATION_FINDINGS.md`.
- The two lines' 70 overlapping dataset entries (puzzles #1-70) were
  cross-checked programmatically and are **byte-identical** -- same
  private keys, same addresses, independently sourced and derived.

**Effective search-space reduction for Puzzle #71: 0 bits / 1.0x.** The
candidate interval remains the full `[2^70, 2^71)`, uniformly weighted.

## Why #71 specifically can't use kangaroo/BSGS

Puzzle #71's coin has never moved, so its public key has never been
exposed on-chain -- confirmed directly against blockstream.info
(`funded_txo_count=56, spent_txo_count=0`). Pollard's kangaroo and BSGS
both require a known discrete-log target point; without one, only a
generic 2^70 HASH160 preimage scan applies.

This also explains the puzzle's odd solve history. On 2019-06-01 the
creator spent 1000 sat from **exactly** the 20 multiples of 5 from #65 to
#160 (tx `17e4e323…b3d3`), which **publishes the spending address's
public key** -- collapsing those 20 puzzles' attack cost from O(2^n) to
O(2^(n/2)) via kangaroo. That's why #135 fell on 2026-07-28 while #71,
#72, #73, #74 (none multiples of 5, none ever spent) remain open. The
consecutive brute-force frontier runs 64 → 66 → 67 → 68 → 69, leaving
**#71 as the next brute-force target**, open since 2025-04-30.

## Status

| Phase | Description | Status |
|---|---|---|
| 0 | Cryptographic verification | done, **twice, independently** -- `tests/test_btcaddr.py` (coincurve-based) and `tests/test_crypto.py` (dependency-free implementation, 1464 assertions, cross-checked against coincurve) both pass |
| 1 | Solved-puzzle dataset | done -- 82 puzzles (1-70 consecutive + every 5th to 130), cryptographically re-derived and verified from two independent sources that agree byte-for-byte on the 70-puzzle overlap. `data/solved_puzzles.{json,csv}` (this branch's schema) and `data/solved_puzzles_broad.{json,csv}` (richer schema: WIF, Hamming weight, exposed-pubkey flag, solve method) |
| 2 | Generator-hypothesis reconstruction | done -- 6 + 87 hypotheses tested across both lines, **all rejected/unfalsifiable** |
| 3 | Statistical cryptanalysis | done -- clean nulls in both lines (3 batteries here, 76 tests with multiplicity correction in the broad line) |
| 4 | Walk-forward validation | done -- nothing retained to validate here; the broad line ran a full 6-fold/59-prediction walk-forward with a permutation null, also negative |
| 5 | Historical archaeology | done -- `research/archaeology/` traced the creator's quote to a specific 2017 BitcoinTalk post (medium-high corroboration, not signed) |
| 6 | On-chain forensics | done -- `research/onchain/` (funding/spending patterns, solver clustering) plus `research/BROAD_REPLICATION_FINDINGS.md` §3 (the 2019 pubkey-exposure transaction and its consequences) |
| 7 | Search-space reduction / tiered ranking | **0 bits found** -- no Tier A-D ranking is published in either line, because publishing one on this evidence would be a uniform prior dressed up as a finding |
| 8 | High-performance search engine | **running now** -- `src/engine.c` (incremental EC addition, batched modular inversion), ~4.2 Mkeys/s measured on this container, independently verified (see below) |
| 9 | Distributed search coordination | `src/coordinator.py` -- SQLite-backed, non-overlapping leases with expiry/reclaim, short-unit rejection, auditable coverage. Currently running single-machine; ready to add real workers |
| 10 | Continuous research loop | not applicable -- both lines exhausted their hypothesis space without finding a lead to iterate on |

## Phase 8/9: the search engine is running, but read this first

```
python3 src/coordinator.py status
```

`src/engine.c` steps the EC point by one addition of G per candidate
(never a fresh scalar multiplication), batches 1024 additions per shared
modular inversion, and specializes SHA256/RIPEMD160 to their single fixed
input block. **Measured ~4.2 Mkeys/s on this container's 4 vCPU (no
GPU)** -- about 15x faster than a straightforward Python+libsecp256k1
implementation (also in this repo, `src/search_engine.py`/
`src/search_status.py`, kept as a slower but simpler reference
implementation used to cross-check the C engine's target-hash160
computation during integration).

I independently verified this engine before trusting it: compiled it
fresh, cross-checked its `selftest` output against this repo's own
already-verified crypto pipeline, confirmed it finds a known key placed
at an arbitrary offset *and* at the exact last index of a thread's range
(the specific edge case its own commit history says was once a bug), and
reproduced the ~4.2 Mkeys/s throughput myself rather than taking the
number on trust.

**Honest numbers.** The interval is `2^70 ≈ 1.18e21` keys. At ~4.2
Mkeys/s, exhausting it takes **~8.9 million years**. Community pool
throughput, inferred from actual on-chain solve-date gaps (not spec
sheets) in `research/BROAD_REPLICATION_FINDINGS.md` §5, has grown from
~10^7 keys/s (2015) to ~10^13 keys/s (2025) -- about **seven orders of
magnitude** ahead of this container. This machine's contribution to
solving #71 is not "slow," it is not a path to the answer on any human
timescale. It runs anyway, correctly and resumably, because that's the
honest way to ship a search engine -- not because it stands a real
chance. **This container is also ephemeral** and will stop the search
regardless of the above when it's reclaimed for inactivity.

**If you want this to matter:** point real GPU hardware at an audited
tool -- [VanitySearch](https://github.com/JeanLucPons/VanitySearch) or
[KeyHunt-Cuda](https://github.com/albertobsd/keyhunt) -- ideally
coordinated with `src/coordinator.py`'s lease scheme so multiple machines
don't overlap. Or chase one of the two untested archaeology leads in
`research/archaeology/period_wallets.md` (Electrum Type-1, classic
`SHA256(master+n)`) -- both need a seed/passphrase-guessing attack, a
different kind of project than statistical pattern-mining.

**Safety.** A recovered key for an unsolved puzzle is written only to a
chmod-600 local file (`work/FOUND` via `src/coordinator.py`, or
`data/search_state/FOUND_SECRET.txt` via `src/search_engine.py`) --
never printed, logged, or committed; both paths are gitignored. Any hit
must be verified with two independent implementations before being
trusted (this repo has three: `src/btcaddr.py`/coincurve,
`src/crypto.py`/dependency-free, and the pure-Python `ecdsa` library) and
all search workers must be stopped immediately.

## Running it

```bash
pip install -r requirements.txt
cc -O3 -march=native -pthread -o engine src/engine.c -lm

# Phase 0 verification (both independent implementations)
python3 tests/test_btcaddr.py
PYTHONPATH=src python3 tests/test_crypto.py
python3 tests/validate_solved_puzzles.py

# Phase 8/9 search (primary path)
python3 src/coordinator.py init
python3 src/coordinator.py run <worker-id> --units 999999999 --threads 4
python3 src/coordinator.py status
```

## Layout

**Verification & dataset**
- `src/btcaddr.py`, `src/crypto.py` -- two independent secp256k1 -> P2PKH pipelines (coincurve-based and dependency-free respectively), cross-checked against each other
- `src/build_dataset.py`, `src/fetch_chain.py`, `src/solve_dates.py` -- dataset construction from raw/chain sources
- `tests/test_btcaddr.py`, `tests/test_crypto.py`, `tests/validate_solved_puzzles.py` -- Phase 0/1 verification suites
- `data/solved_puzzles.{json,csv}` / `data/solved_puzzles_broad.{json,csv}` -- the verified 82-puzzle dataset in two schemas (this branch's + the merged-in broad schema with WIF/Hamming-weight/exposed-pubkey/solve-method fields)
- `data/solved_puzzles_raw.json`, `data/candidate_keys.json` -- raw scraped inputs, provenance-noted, not trusted until verified
- `data/exposed_pubkeys.json`, `data/solve_dates.json`, `data/raw_*.json` -- on-chain forensic source data

**Research**
- `research/PHASE_2_6_SUMMARY.md` -- this branch's original Phase 2-6 synthesis (6 hypotheses, detailed methodology per test)
- `research/generator_hypotheses.md` -- this branch's 6-hypothesis ledger with full Monte Carlo writeups
- `research/hypotheses/`, `research/stats/` -- per-hypothesis/per-test code and results
- `research/BROAD_REPLICATION_FINDINGS.md` -- the merged-in independent replication (87 hypotheses, positive/negative controls, 76 statistical tests, on-chain forensics explaining the solve order, empirical community-throughput analysis)
- `research/generator_hypotheses_broad.md` -- the merged-in 87-hypothesis ledger
- `research/archaeology/`, `research/onchain/`, `research/walk_forward_validation.md` -- supporting evidence
- `results/*.json` -- machine-readable outputs backing `BROAD_REPLICATION_FINDINGS.md`

**Search engine**
- `src/engine.c` -- the fast (C, incremental EC addition, batched inversion) Phase 8 search engine, primary
- `src/coordinator.py` -- SQLite-backed Phase 9 distributed work allocator, primary
- `src/feasibility.py` -- feasibility accounting (expected work, hardware comparison, community-throughput inference)
- `src/generators.py`, `src/analysis.py`, `src/walkforward.py`, `src/null_calibration.py` -- the broad line's Phase 2-4 implementation
- `src/search_engine.py`, `src/search_coordinator.py`, `src/search_status.py` -- this branch's original Python search engine, kept as a slower reference implementation for cross-checking (not the primary search path anymore)
- `tests/test_search_engine.py` -- correctness tests for the Python reference engine
