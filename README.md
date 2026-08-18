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
| 2 | Generator-hypothesis reconstruction | in progress -- `research/generator_hypotheses.md` |
| 3 | Statistical cryptanalysis (randomness battery, null models) | in progress |
| 4 | Walk-forward validation (train on <=N, predict N+1..M) | in progress |
| 5 | Historical archaeology (creator statements, period code) | in progress |
| 6 | On-chain forensics (funding tx fingerprints) | in progress |
| 7 | Search-space reduction / tiered candidate ranking | pending phases 2-6 |
| 8 | High-performance search engine | pending -- see hardware note below |
| 9 | Distributed search coordination | pending |
| 10 | Continuous research loop | ongoing |

## Hardware note

This container has 4 CPU cores, no GPU, and is ephemeral. Exhaustive
search over 2^70 keys is not feasible here (or anywhere, without either a
large GPU/FPGA cluster or a genuine cryptanalytic reduction) -- see
`research/feasibility.md`. Puzzle #71's coin has never moved, so its
public key is **not** exposed on-chain, which rules out Pollard's
kangaroo / BSGS (those need a known discrete-log target point); any
speedup must come from either (a) a real reduction in the candidate key
distribution, or (b) raw hashrate this environment does not have.

## Layout

- `src/btcaddr.py` -- verified secp256k1 -> P2PKH address pipeline (uses `coincurve`/libsecp256k1, not a from-scratch EC implementation)
- `src/build_dataset.py` -- builds `data/solved_puzzles.{json,csv}` from the raw scraped table, after cryptographic verification
- `tests/test_btcaddr.py` -- Phase 0 known-answer tests
- `tests/validate_solved_puzzles.py` -- cross-checks every solved-puzzle entry against the crypto pipeline
- `data/solved_puzzles_raw.json` -- scraped table (provenance noted, not trusted until verified)
- `data/solved_puzzles.{json,csv}` -- verified dataset with derived fields (normalized position in interval, EC point, etc.)
- `research/generator_hypotheses.md` -- ledger of generator hypotheses tested and why each was retained/rejected
