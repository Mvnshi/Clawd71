"""Fetch canonical puzzle addresses and their on-chain spend status.

Everything is derived from the 2015 genesis funding transaction, which paid
256 outputs in ascending value order: output index n-1 corresponds to puzzle #n
and carries exactly n * 100_000 satoshi. That value acts as a built-in checksum
on the ordering, so the address list needs no external source of truth.
"""

from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path

GENESIS_TXID = "08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15"
ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
UA = {"User-Agent": "puzzle71-research/1.0"}


def _get_json(url: str, retries: int = 5, timeout: int = 90):
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as fh:
                return json.loads(fh.read().decode())
        except Exception as exc:  # network flakiness / rate limits
            last = exc
            time.sleep(2 ** attempt)
    raise RuntimeError(f"GET failed after {retries} tries: {url}") from last


def load_genesis() -> dict:
    path = DATA / "raw_genesis_tx.json"
    if not path.exists():
        data = _get_json(f"https://blockchain.info/rawtx/{GENESIS_TXID}")
        path.write_text(json.dumps(data))
    return json.loads(path.read_text())


def canonical_addresses() -> dict[int, str]:
    """puzzle number -> address, validated against the value checksum."""
    tx = load_genesis()
    assert tx["hash"] == GENESIS_TXID, "genesis txid mismatch"
    assert len(tx["out"]) == 256, "genesis tx must have 256 outputs"
    out: dict[int, str] = {}
    for o in tx["out"]:
        n = o["n"] + 1
        if o["value"] != n * 100_000:
            raise AssertionError(
                f"output {o['n']} value {o['value']} != {n * 100_000}; ordering assumption broken"
            )
        out[n] = o["addr"]
    return out


def fetch_status(addresses: dict[int, str], chunk: int = 40) -> dict[int, dict]:
    """Bulk spend status via blockchain.info multiaddr."""
    by_addr = {a: n for n, a in addresses.items()}
    result: dict[int, dict] = {}
    items = list(addresses.items())
    for i in range(0, len(items), chunk):
        part = items[i : i + chunk]
        url = "https://blockchain.info/multiaddr?active=" + "|".join(a for _, a in part)
        data = _get_json(url)
        for entry in data["addresses"]:
            n = by_addr[entry["address"]]
            result[n] = {
                "puzzle": n,
                "address": entry["address"],
                "n_tx": entry["n_tx"],
                "total_received": entry["total_received"],
                "total_sent": entry["total_sent"],
                "final_balance": entry["final_balance"],
                # A puzzle is "solved" once its funds have been swept, which
                # requires knowledge of the private key.
                "spent": entry["total_sent"] > 0,
            }
        print(f"  fetched {min(i + chunk, len(items))}/{len(items)}", flush=True)
        time.sleep(1.0)
    return result


def main() -> None:
    DATA.mkdir(exist_ok=True)
    addrs = canonical_addresses()
    print(f"canonical addresses: {len(addrs)} (checksum on value verified)")
    status = fetch_status(addrs)
    (DATA / "chain_status.json").write_text(
        json.dumps([status[n] for n in sorted(status)], indent=2)
    )
    solved = sorted(n for n, s in status.items() if s["spent"])
    unsolved = sorted(n for n, s in status.items() if not s["spent"])
    print(f"\nspent(solved):   {len(solved)}")
    print(f"unspent:         {len(unsolved)}")
    print(f"lowest unspent:  {unsolved[:12]}")
    print(f"highest spent:   {solved[-12:]}")


if __name__ == "__main__":
    main()
