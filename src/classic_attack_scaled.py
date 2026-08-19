"""
Scaled-up classic Type-1 (SHA256(masterstring+n)) dictionary attack.

Two-pass strategy to make a huge candidate list tractable:
  1. Fast filter: check each candidate against a spread of ~12 "high
     information" puzzle indices only (n=20,30,...,130). At n>=20 a chance
     match has probability <2^-19 per check, so this is cheap and safe.
  2. Full check: any candidate that survives the filter gets checked
     against the complete 82-puzzle dataset before being trusted.

Candidates: the full real rockyou.txt wordlist (14.3M entries, not
committed to the repo -- 140MB exceeds GitHub's 100MB push limit; source
documented below, re-fetch to reproduce) plus mutation-rule derivatives
(src/mutate.py) of its most common ~150,000 entries, run through every
format in FORMATS (src/seed_attack.py).
"""
import hashlib
import json
import sys
import time

sys.path.insert(0, "/home/user/Clawd71/src")
from mutate import mutations_of
from seed_attack import FORMATS, apply_puzzle_mask

ROCKYOU_PATH = "/tmp/claude-0/-home-user-Clawd71/ad6103c2-6292-5da4-b74f-f5d157a4e883/scratchpad/rockyou.txt"
DATASET_PATH = "/home/user/Clawd71/data/solved_puzzles.json"
RESULTS_PATH = "/home/user/Clawd71/research/hypotheses/seed_guessing/classic_scaled_results.json"

FILTER_N = [20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130]
MUTATE_TOP_N = 150_000


def load_dataset():
    data = json.load(open(DATASET_PATH))
    by_n = {d["n"]: d["key_int"] for d in data}
    return by_n


def candidate_stream():
    seen_count = 0
    with open(ROCKYOU_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            w = line.rstrip("\n")
            if not w:
                continue
            yield w
            seen_count += 1
            if i < MUTATE_TOP_N:
                for m in mutations_of(w):
                    if m != w:
                        yield m
                        seen_count += 1


def main():
    by_n = load_dataset()
    filter_targets = {n: by_n[n] for n in FILTER_N if n in by_n}

    survivors = []
    total_tested = 0
    t0 = time.time()
    last_report = t0

    for cand in candidate_stream():
        for fmt_name, fmt in FORMATS.items():
            total_tested += 1
            hit_ns = []
            for n, actual in filter_targets.items():
                s = fmt(cand, n)
                raw = int.from_bytes(hashlib.sha256(s.encode("utf-8")).digest(), "big")
                if apply_puzzle_mask(raw, n) == actual:
                    hit_ns.append(n)
            if hit_ns:
                survivors.append({"candidate": cand, "format": fmt_name, "filter_hits": hit_ns})
                print(f"FILTER SURVIVOR: {cand!r} fmt={fmt_name} hits={hit_ns}", flush=True)

        now = time.time()
        if now - last_report >= 30:
            rate = total_tested / (now - t0)
            print(f"[{now-t0:.0f}s] tested={total_tested:,} rate={rate:,.0f}/s survivors={len(survivors)}", flush=True)
            last_report = now

    # full check on survivors
    confirmed = []
    for s in survivors:
        fmt = FORMATS[s["format"]]
        full_hits = []
        for n, actual in by_n.items():
            raw = int.from_bytes(hashlib.sha256(fmt(s["candidate"], n).encode("utf-8")).digest(), "big")
            if apply_puzzle_mask(raw, n) == actual:
                full_hits.append(n)
        s["full_hits"] = full_hits
        if len(full_hits) >= 2:
            confirmed.append(s)

    elapsed = time.time() - t0
    result = {
        "total_candidates_tested": total_tested,
        "elapsed_sec": elapsed,
        "rate_per_sec": total_tested / elapsed if elapsed else None,
        "filter_survivors": survivors,
        "confirmed_multi_hit": confirmed,
        "filter_n_used": FILTER_N,
        "mutate_top_n": MUTATE_TOP_N,
        "rockyou_source": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
    }
    with open(RESULTS_PATH, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nDONE. {total_tested:,} candidates in {elapsed:.0f}s "
          f"({total_tested/elapsed:,.0f}/s). {len(survivors)} filter survivors, "
          f"{len(confirmed)} confirmed with >=2 full-dataset hits.")


if __name__ == "__main__":
    main()
