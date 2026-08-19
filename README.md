# Puzzle 71 — Cryptanalytic Research Program

Scoped research program targeting **Bitcoin Puzzle #71**
(`1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU`, key interval `[2^70, 2^71-1]`),
an intentionally published challenge with a public reward.

This repository is scoped to Puzzle #71 and the historical public Bitcoin
Puzzle dataset. It is not a general wallet-attack tool.

## Layout

| path | contents |
|---|---|
| `src/crypto.py` | dependency-free secp256k1 + Bitcoin address pipeline |
| `src/fetch_chain.py` | canonical puzzle addresses + spend status, from chain |
| `src/build_dataset.py` | assembles and verifies the solved-key dataset |
| `src/analysis.py` | Phase 3 statistical battery with multiplicity correction |
| `src/generators.py` | Phase 2 generator hypotheses, with positive/negative controls |
| `src/walkforward.py` | Phase 4 out-of-sample validation |
| `src/null_calibration.py` | permutation null for the walk-forward result |
| `src/solve_dates.py` | solve dates from chain -> empirical community throughput |
| `src/feasibility.py` | Phase 7 feasibility accounting |
| `src/engine.c` | Phase 8 HASH160 search engine (incremental EC, batched inversion) |
| `src/coordinator.py` | Phase 9 distributed work allocation |
| `tests/test_crypto.py` | Phase 0 verification suite (must pass before anything else) |
| `data/` | verified datasets and raw chain snapshots |
| `research/` | hypothesis ledger and findings |
| `results/` | machine-readable outputs of each phase |

## Headline result

Puzzle #71's public key has **never been exposed** (the address has zero
outgoing value), so Pollard kangaroo and BSGS do not apply and the only generic
attack is a 2^70 HASH160 scan. Across 87 generator hypotheses, 76 statistical
tests, and 59 out-of-sample predictions, **no method beats uniform random**;
measured search-space reduction is 1.0x. See `research/findings.md`.

## Running it

```
cc -O3 -march=native -pthread -o engine src/engine.c
PYTHONPATH=src python3 tests/test_crypto.py      # 1464 assertions
PYTHONPATH=src python3 src/feasibility.py
python3 src/coordinator.py init && python3 src/coordinator.py status
```

A recovered key for an unsolved puzzle is written by the coordinator to
`work/FOUND` with mode 0600 and is never echoed, logged, or committed.
Note that invoking `engine` directly prints a hit to stdout for interactive
use -- do not redirect a direct engine run into a shared log.

## Verification posture

Nothing is trusted because a website said it. Every private key in
`data/solved_puzzles.csv` is accepted only if it reproduces the canonical
on-chain address, and — where a public key was exposed on-chain — the
matching public key too.

```
PYTHONPATH=src python3 tests/test_crypto.py
```
