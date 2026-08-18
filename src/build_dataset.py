"""
Phase 1: build data/solved_puzzles.json and data/solved_puzzles.csv from the
cryptographically-verified raw table (see tests/validate_solved_puzzles.py --
must pass 70/70 before this is run).

Fields per solved puzzle:
  n                  puzzle number
  key_int            private key as integer
  key_hex            private key as hex (no leading zero padding)
  key_hex64          private key as 64-hex-char (256-bit) zero-padded hex
  lower_bits_hex     key with the forced leading bit (bit n-1) removed,
                     i.e. key - 2**(n-1), which is the "free" part of the
                     key the generator actually had to choose (0 for n=1)
  bit_length         n (by construction; sanity field)
  binary             key_int in binary, zero-padded to n bits
  normalized         (key_int - 2**(n-1)) / (2**(n-1)) in [0, 1) -- the
                     key's position within its permitted interval
  address            base58check P2PKH address (compressed pubkey)
  compressed_pubkey  33-byte compressed secp256k1 pubkey, hex
  pubkey_x, pubkey_y EC point coordinates, decimal
  solve_date         null (not yet gathered -- Phase 6 on-chain forensics)
  funding_tx         null (not yet gathered -- Phase 6 on-chain forensics)
  provenance         source of the (address, key_hex) pair
"""
import csv
import json
import sys

sys.path.insert(0, "/home/user/Clawd71/src")
from btcaddr import privkey_int_to_addresses
from coincurve import PrivateKey

with open("/home/user/Clawd71/data/solved_puzzles_raw.json") as f:
    raw = json.load(f)

PROVENANCE = (
    "https://btcpuzzle.info/puzzle (fetched 2026-08-18), independently "
    "re-derived and verified against secp256k1/HASH160/Base58Check "
    "(coincurve/libsecp256k1) -- see tests/validate_solved_puzzles.py, 70/70 pass"
)

rows = []
for entry in raw["puzzles"]:
    n, addr, key_hex = entry["n"], entry["address"], entry["key_hex"]
    k = int(key_hex, 16)
    forced_bit = 1 << (n - 1)
    lower_bits = k - forced_bit
    addrs = privkey_int_to_addresses(k)
    sk = PrivateKey(k.to_bytes(32, "big"))
    pt = sk.public_key.point()  # (x, y) ints
    rows.append(
        {
            "n": n,
            "key_int": k,
            "key_hex": format(k, "x"),
            "key_hex64": format(k, "064x"),
            "lower_bits_hex": format(lower_bits, "x"),
            "bit_length": n,
            "binary": format(k, f"0{n}b"),
            "normalized": lower_bits / forced_bit if n > 1 else 0.0,
            "address": addr,
            "compressed_pubkey": addrs["compressed_pubkey"],
            "pubkey_x": pt[0],
            "pubkey_y": pt[1],
            "solve_date": None,
            "funding_tx": None,
            "provenance": PROVENANCE,
        }
    )

with open("/home/user/Clawd71/data/solved_puzzles.json", "w") as f:
    json.dump(rows, f, indent=2)

fieldnames = list(rows[0].keys())
with open("/home/user/Clawd71/data/solved_puzzles.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print(f"Wrote {len(rows)} verified rows to data/solved_puzzles.json and data/solved_puzzles.csv")
