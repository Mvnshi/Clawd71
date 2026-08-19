"""
Check src/stretch_bench.c's output (seed -> secexp pairs) against the real
puzzle dataset. Reads whatever has been computed so far -- safe to run on a
partial file while stretch_bench is still running, or after it finishes.

Two-pass, same discipline as the classic-scheme attack: fast filter against
FILTER_N first (chance rate <2e-6 per candidate at n=20), full 82-puzzle
check only on filter survivors.
"""
import json
import sys

sys.path.insert(0, "/home/user/Clawd71/src")
from seed_attack import apply_puzzle_mask, electrum_child_privkey

DATASET_PATH = "/home/user/Clawd71/data/solved_puzzles.json"
SECEXP_PATH = "/tmp/claude-0/-home-user-Clawd71/ad6103c2-6292-5da4-b74f-f5d157a4e883/scratchpad/electrum_secexp_out.txt"
RESULTS_PATH = "/home/user/Clawd71/research/hypotheses/seed_guessing/electrum_scaled_results.json"

FILTER_N = [20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130]


def main():
    data = json.load(open(DATASET_PATH))
    by_n = {d["n"]: d["key_int"] for d in data}
    filter_targets = {n: by_n[n] for n in FILTER_N if n in by_n}

    survivors = []
    total = 0
    with open(SECEXP_PATH) as f:
        for line in f:
            parts = line.split()
            if len(parts) != 2:
                continue
            seed_hex, secexp_hex = parts
            secexp = int(secexp_hex, 16)
            total += 1
            hit_ns = []
            for n, actual in filter_targets.items():
                raw = electrum_child_privkey(seed_hex, n, secexp=secexp)
                if apply_puzzle_mask(raw, n) == actual:
                    hit_ns.append(n)
            if hit_ns:
                survivors.append({"seed": seed_hex, "secexp_hex": secexp_hex, "filter_hits": hit_ns})

    confirmed = []
    for s in survivors:
        secexp = int(s["secexp_hex"], 16)
        full_hits = []
        for n, actual in by_n.items():
            raw = electrum_child_privkey(s["seed"], n, secexp=secexp)
            if apply_puzzle_mask(raw, n) == actual:
                full_hits.append(n)
        s["full_hits"] = full_hits
        if len(full_hits) >= 2:
            confirmed.append(s)

    result = {
        "total_secexp_checked": total,
        "filter_survivors": survivors,
        "confirmed_multi_hit": confirmed,
        "filter_n_used": FILTER_N,
    }
    with open(RESULTS_PATH, "w") as f:
        json.dump(result, f, indent=2)
    print(f"checked {total:,} secexp values. {len(survivors)} filter survivors, "
          f"{len(confirmed)} confirmed with >=2 full-dataset hits.")
    if confirmed:
        print("\n*** CONFIRMED MULTI-HIT CANDIDATE(S) FOUND -- see", RESULTS_PATH, "***")
        print("*** DO NOT print seed/secexp material beyond what's already in that local file. ***")


if __name__ == "__main__":
    main()
