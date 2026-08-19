"""
Phase 8/9: spawns one search_worker per CPU core, each covering a
contiguous, non-overlapping chunk of [RANGE_START, RANGE_END], starting
from a single uniformly-random anchor offset (recorded once and reused
across restarts) rather than sequentially from the bottom -- Phase 2-6
found no informative prior over the interval, so there is no principled
reason to prefer the bottom of the range over anywhere else, and a
random anchor avoids any risk of duplicating whatever prefix other,
much larger, external search pools may have already swept.

Honest framing (see README.md): this container has 4 CPU cores and no
GPU. Measured throughput here (~100k keys/sec/core via incremental EC
point addition) covers a negligible fraction of the 2^70 interval on any
human timescale. This is built correct and checkpointed so it can be
resumed, inspected, or pointed at real (GPU) hardware later -- not
because it is expected to solve the puzzle from this container.
"""
import json
import multiprocessing as mp
import os
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, "/home/user/Clawd71/src")
from search_engine import RANGE_END, RANGE_START, STATE_DIR, search_worker


def get_or_create_anchor(n_workers: int, chunk_size: int) -> int:
    anchor_path = STATE_DIR / "anchor.json"
    total = RANGE_END - RANGE_START + 1
    if anchor_path.exists():
        return json.loads(anchor_path.read_text())["anchor_offset"]
    max_anchor = total - n_workers * chunk_size
    # chunk_size = total // n_workers can consume the entire range exactly
    # (e.g. 2^70 / 4 = 2^68 with no remainder), leaving no room for a
    # nonzero random offset -- that's fine, just start at the range floor.
    anchor_offset = secrets.randbelow(max_anchor) if max_anchor > 0 else 0
    anchor_path.write_text(json.dumps({
        "anchor_offset": anchor_offset,
        "chosen_at": time.time(),
        "note": ("uniformly random start offset within [RANGE_START, RANGE_END]; "
                 "Phase 2-6 research found no informative prior over the interval, "
                 "so this is an arbitrary, unbiased starting point, not a claim "
                 "about where the key is more likely to be"),
    }, indent=2))
    return anchor_offset


def main():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    stop_path = STATE_DIR / "STOP"
    if stop_path.exists():
        stop_path.unlink()

    n_workers = os.cpu_count() or 4
    total = RANGE_END - RANGE_START + 1
    # Reserve ~1% of the range as slack so there's room for a genuinely
    # random anchor offset (an exact even split leaves zero slack, e.g.
    # 2^70 / 4 has no remainder at all).
    chunk = (total - total // 100) // n_workers

    anchor_offset = get_or_create_anchor(n_workers, chunk)
    print(f"[coordinator] {n_workers} workers, chunk size {chunk:#x} keys each, "
          f"anchor offset {anchor_offset:#x} into the {total:#x}-key range")

    procs = []
    for i in range(n_workers):
        w_start = RANGE_START + anchor_offset + i * chunk
        w_end = w_start + chunk - 1
        p = mp.Process(target=search_worker, args=(i, w_start, w_end), name=f"puzzle71-worker-{i}")
        p.start()
        procs.append(p)
        print(f"[coordinator] worker {i}: range [{w_start:#x}, {w_end:#x}] pid={p.pid}")

    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        print("[coordinator] KeyboardInterrupt -- signalling STOP to all workers")
        stop_path.write_text("coordinator_shutdown")
        for p in procs:
            p.join()

    print("[coordinator] all workers exited")


if __name__ == "__main__":
    main()
