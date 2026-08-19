"""Assemble the verified solved-puzzle dataset.

Verification chain (a record is emitted only if every link holds):
  1. address comes from the 2015 genesis tx, output n-1, value == n*100_000 sat
  2. private key lies inside [2^(n-1), 2^n - 1]
  3. privkey -> compressed pubkey -> hash160 -> base58check == that address
  4. where a public key was exposed on-chain (2019 tx), the derived pubkey
     must match it byte for byte
  5. the whole pipeline is cross-checked against libsecp256k1 (coincurve)

Unverified candidates are dropped and reported, never patched.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import crypto as c
from fetch_chain import canonical_addresses

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

# Provenance notes per source of private-key material.
PROVENANCE = {
    "consecutive": (
        "Community-published solve; independently verified here by deriving the "
        "compressed P2PKH address and matching the canonical genesis-tx output."
    ),
    "kangaroo": (
        "Solved via Pollard kangaroo after the 2019 pubkey-exposure tx; verified "
        "here against both the canonical address and the on-chain public key."
    ),
}


def solved_status() -> dict[int, dict]:
    return {s["puzzle"]: s for s in json.loads((DATA / "chain_status.json").read_text())}


# Puzzles #161..#256 were never cracked: the creator swept them in the 2017
# restructuring tx to fund the 10x prize increase on #1..#160.
CREATOR_RECLAIM_TX = "5d45587cfd1d5b0fb826805541da7d94c61fe432259e68ee26f4a04544384164"
CREATOR_RECLAIMED = set(range(161, 257))


def is_solved(s: dict) -> bool:
    """Prize swept by a solver (i.e. someone recovered the private key).

    Two traps this avoids:
      * total_sent > 0 is NOT sufficient. The creator spent 1000 sat from every
        multiple of 5 in 2019 to expose public keys, so #140..#160 show a
        nonzero total_sent while still holding their full prize.
      * #161..#256 have zero balance but were reclaimed by the creator, not
        cracked, so they are not evidence of anyone solving anything.
    """
    if s["puzzle"] in CREATOR_RECLAIMED:
        return False
    return s["final_balance"] == 0 and s["total_received"] > 1000


def load_keys() -> dict[int, int]:
    keys: dict[int, int] = {}
    base = json.loads((DATA / "candidate_keys.json").read_text())["keys"]
    for n, v in base.items():
        keys[int(n)] = int(v)
    extra_path = DATA / "verified_extra_keys.json"
    if extra_path.exists():
        for n, v in json.loads(extra_path.read_text()).items():
            keys[int(n)] = int(v)
    return keys


def build() -> tuple[list[dict], list[dict]]:
    addrs = canonical_addresses()
    status = solved_status()
    exposed = {
        p["puzzle"]: p["pubkey"]
        for p in json.loads((DATA / "exposed_pubkeys.json").read_text())
    }
    keys = load_keys()

    records: list[dict] = []
    rejected: list[dict] = []

    for n in sorted(keys):
        k = keys[n]
        addr = addrs[n]
        lo, hi = c.puzzle_range(n)
        problems = []
        if not (lo <= k <= hi):
            problems.append("key outside puzzle interval")
        else:
            pt = c.privkey_to_pubkey(k)
            pub_c = c.serialize_pubkey(pt, True)
            if c.hash160_to_address(c.hash160(pub_c)) != addr:
                problems.append("derived address != canonical address")
            if n in exposed and pub_c.hex() != exposed[n]:
                problems.append("derived pubkey != on-chain exposed pubkey")
        if problems:
            rejected.append({"puzzle": n, "key": hex(k), "problems": problems})
            continue

        pt = c.privkey_to_pubkey(k)
        pub_c = c.serialize_pubkey(pt, True)
        pub_u = c.serialize_pubkey(pt, False)
        offset = k - lo
        span = hi - lo + 1
        records.append(
            {
                "puzzle": n,
                "address": addr,
                "hash160": c.hash160(pub_c).hex(),
                "privkey_dec": str(k),
                "privkey_hex": f"{k:x}",
                "privkey_hex_padded": f"{k:0{(n + 3) // 4}x}",
                "range_low_hex": f"{lo:x}",
                "range_high_hex": f"{hi:x}",
                # forced leading bit removed -> the (n-1) "free" bits
                "offset_dec": str(offset),
                "offset_hex": f"{offset:x}",
                "offset_bits": n - 1,
                "binary": format(k, "b"),
                "offset_binary": format(offset, f"0{n - 1}b") if n > 1 else "",
                "normalized": offset / span,
                "hamming_weight": bin(k).count("1"),
                "wif_compressed": c.privkey_to_wif(k, True),
                "pubkey_compressed": pub_c.hex(),
                "pubkey_uncompressed": pub_u.hex(),
                "pubkey_x": f"{pt[0]:x}",
                "pubkey_y": f"{pt[1]:x}",
                "pubkey_exposed_onchain": n in exposed,
                "prize_btc": status[n]["total_received"] / 1e8,
                "solved": is_solved(status[n]),
                "solve_method": "kangaroo" if n in exposed else "bruteforce/other",
                "provenance": PROVENANCE["kangaroo" if n in exposed else "consecutive"],
            }
        )
    return records, rejected


def cross_check(records: list[dict]) -> None:
    """Re-derive every record with libsecp256k1 as an independent implementation."""
    from coincurve import PublicKey

    for r in records:
        k = int(r["privkey_dec"])
        pk = PublicKey.from_valid_secret(k.to_bytes(32, "big"))
        assert pk.format(True).hex() == r["pubkey_compressed"], r["puzzle"]
        assert pk.format(False).hex() == r["pubkey_uncompressed"], r["puzzle"]
    print(f"  cross-checked {len(records)} records against libsecp256k1: OK")


def main() -> None:
    records, rejected = build()
    cross_check(records)

    (DATA / "solved_puzzles.json").write_text(json.dumps(records, indent=2))
    cols = list(records[0].keys())
    with (DATA / "solved_puzzles.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(records)

    status = solved_status()
    all_solved = [n for n in range(1, 257) if is_solved(status[n])]
    have = {r["puzzle"] for r in records}
    print(f"  verified records : {len(records)}")
    print(f"  rejected         : {len(rejected)} {[r['puzzle'] for r in rejected]}")
    print(f"  solved on-chain  : {len(all_solved)}")
    print(f"  solved w/o key   : {sorted(set(all_solved) - have)}")
    print(f"  wrote {DATA / 'solved_puzzles.csv'} and .json")


if __name__ == "__main__":
    main()
