"""
Cryptographically validate the scraped solved-puzzle table (Phase 0 + Phase 1).

For each (n, address, key_hex) entry:
  1. key must satisfy 2^(n-1) <= key < 2^n (the puzzle's stated interval)
  2. compressed-pubkey P2PKH(key) must equal the published address

Any entry failing either check is untrustworthy and must not be used in
downstream statistical analysis until corrected from a second source.
"""
import json
import sys

sys.path.insert(0, "/home/user/Clawd71/src")
from btcaddr import which_encoding_matches

with open("/home/user/Clawd71/data/solved_puzzles_raw.json") as f:
    data = json.load(f)

ok, bad = [], []
for entry in data["puzzles"]:
    n, addr, key_hex = entry["n"], entry["address"], entry["key_hex"]
    k = int(key_hex, 16)
    lo, hi = 2 ** (n - 1), 2**n
    in_range = lo <= k < hi
    match = which_encoding_matches(k, addr)
    row = {**entry, "key_int": k, "in_range": in_range, "encoding_match": match}
    if in_range and match == "compressed":
        ok.append(row)
    else:
        bad.append(row)

print(f"OK: {len(ok)}/{len(data['puzzles'])}")
if bad:
    print(f"FAILED ({len(bad)}):")
    for row in bad:
        print(f"  n={row['n']} addr={row['address']} key_hex={row['key_hex']} "
              f"in_range={row['in_range']} encoding_match={row['encoding_match']}")
else:
    print("All entries passed cryptographic verification (key in-range AND "
          "compressed-pubkey HASH160/Base58Check reproduces the published address).")
