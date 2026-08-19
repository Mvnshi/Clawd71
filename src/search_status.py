"""Aggregate progress/ETA report across all worker checkpoints. Run any time with:
    python3 src/search_status.py
"""
import json
from pathlib import Path

from search_engine import RANGE_END, RANGE_START

STATE_DIR = Path("/home/user/Clawd71/data/search_state")
TOTAL = RANGE_END - RANGE_START + 1


def main():
    ckpts = sorted(STATE_DIR.glob("worker_*.json"))
    if not ckpts:
        print("No checkpoints yet -- coordinator hasn't run or state dir was cleared.")
        return

    total_tested = 0
    total_speed = 0.0
    statuses = []
    for p in ckpts:
        c = json.loads(p.read_text())
        total_tested += c["keys_tested"]
        total_speed += c["speed"] or 0
        statuses.append(c["status"])

    print(f"Workers: {len(ckpts)}  statuses: {statuses}")
    print(f"Keys tested so far (this run/resume lineage): {total_tested:,}")
    print(f"Aggregate speed: {total_speed:,.0f} keys/sec")
    frac = total_tested / TOTAL
    print(f"Fraction of full 2^70 interval covered so far: {frac:.3e}")
    if total_speed > 0:
        remaining = TOTAL - total_tested
        eta_seconds = remaining / total_speed
        eta_years = eta_seconds / (365.25 * 86400)
        print(f"ETA to exhaust the full assigned range at current speed: {eta_years:,.0f} years")
    found = STATE_DIR / "FOUND_SECRET.txt"
    if found.exists():
        print("\n*** FOUND_SECRET.txt EXISTS -- a candidate match was recorded. ***")
        print("Do not print its contents into chat/logs. Inspect it directly and locally:")
        print(f"    cat {found}")


if __name__ == "__main__":
    main()
