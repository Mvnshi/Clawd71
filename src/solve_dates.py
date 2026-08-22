"""Recover each puzzle's solve date from chain and infer community throughput.

For a solved puzzle the sweep transaction is the first tx that spends the
prize output. Its timestamp is the solve date (within hours). Comparing solve
dates across the consecutively-brute-forced puzzles gives an empirical estimate
of the whole community's aggregate search rate -- a far better feasibility
anchor than any single GPU's spec sheet.
"""

from __future__ import annotations

import datetime as dt
import json
import time
from pathlib import Path

from fetch_chain import _get_json, canonical_addresses

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

# 1000 sat spends from the 2019 pubkey-exposure tx are not solves.
EXPOSURE_TX = "17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3"


def sweep_info(addr: str) -> dict | None:
    d = _get_json(f"https://blockchain.info/rawaddr/{addr}?limit=50")
    spends = []
    for t in d["txs"]:
        for i in t["inputs"]:
            if i["prev_out"].get("addr") == addr and t["hash"] != EXPOSURE_TX:
                spends.append((t["time"], t["hash"], i["prev_out"]["value"]))
    if not spends:
        return None
    # the sweep is the earliest spend of a large (prize-sized) output
    big = [s for s in spends if s[2] > 100_000]
    chosen = min(big or spends)
    return {
        "sweep_time": chosen[0],
        "sweep_date": dt.datetime.utcfromtimestamp(chosen[0]).strftime("%Y-%m-%d"),
        "sweep_tx": chosen[1],
        "swept_value": chosen[2],
    }


def main() -> None:
    addrs = canonical_addresses()
    status = {s["puzzle"]: s for s in json.loads((DATA / "chain_status.json").read_text())}
    exposed = {p["puzzle"] for p in json.loads((DATA / "exposed_pubkeys.json").read_text())}

    targets = [n for n in range(50, 136) if status[n]["final_balance"] == 0
               and status[n]["total_received"] > 1000]
    out = {}
    for n in targets:
        info = sweep_info(addrs[n])
        if info:
            info["puzzle"] = n
            info["method"] = "kangaroo (pubkey exposed 2019)" if n in exposed else "brute force"
            out[n] = info
            print(f"#{n:3d} {info['sweep_date']}  {info['method']}")
        time.sleep(0.6)

    (DATA / "solve_dates.json").write_text(json.dumps([out[n] for n in sorted(out)], indent=2))
    print(f"\nwrote {DATA / 'solve_dates.json'}")


if __name__ == "__main__":
    main()
