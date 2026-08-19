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
| `tests/test_crypto.py` | Phase 0 verification suite (must pass before anything else) |
| `data/` | verified datasets and raw chain snapshots |
| `research/` | hypothesis ledger and findings |

## Verification posture

Nothing is trusted because a website said it. Every private key in
`data/solved_puzzles.csv` is accepted only if it reproduces the canonical
on-chain address, and — where a public key was exposed on-chain — the
matching public key too.

```
PYTHONPATH=src python3 tests/test_crypto.py
```
