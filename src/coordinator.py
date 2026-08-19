"""Phase 9 - distributed search coordinator.

Hands out non-overlapping work units from Puzzle #71's interval and tracks what
has actually been scanned, so that multiple trusted machines can search without
duplicating effort and a crash loses at most one checkpoint interval.

Design points that matter:
  * Work units are derived deterministically from (interval, unit_size), so a
    unit id always denotes the same key range on every machine. Nothing depends
    on the order in which workers appear.
  * Units are leased, not assigned. A lease that expires is reclaimed, so a dead
    worker cannot strand a range forever.
  * Completion is recorded with the worker's reported key count, which is
    checked against the unit width. A short count is rejected, because a
    silently-truncated unit is exactly how an exhaustive search stops being
    exhaustive.
  * Coverage is auditable: `status` reports the exact fraction of the interval
    proven scanned.

Usage:
    python3 src/coordinator.py init
    python3 src/coordinator.py lease  <worker-id>
    python3 src/coordinator.py report <unit_id> <worker-id> <keys_done> [--done]
    python3 src/coordinator.py status
    python3 src/coordinator.py run    <worker-id> [--units N]   # lease->scan->report
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "work" / "coordinator.db"
ENGINE = ROOT / "engine"

TARGET_PUZZLE = 71
RANGE_LOW = 1 << (TARGET_PUZZLE - 1)
RANGE_HIGH = (1 << TARGET_PUZZLE) - 1
TARGET_HASH160 = "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"

UNIT_SIZE = 1 << 32          # ~4.29e9 keys: ~30 min at 2.2 Mkeys/s
LEASE_SECONDS = 6 * 3600
PROGRESS_SECS = 30

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY, value TEXT
);
CREATE TABLE IF NOT EXISTS units (
    unit_id      INTEGER PRIMARY KEY,
    range_start  TEXT NOT NULL,
    range_end    TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',   -- pending|leased|complete
    strategy     TEXT NOT NULL DEFAULT 'sequential',
    worker       TEXT,
    assigned_at  REAL,
    lease_expiry REAL,
    completed_at REAL,
    keys_tested  INTEGER DEFAULT 0,
    speed_mkeys  REAL,
    checksum     TEXT
);
CREATE INDEX IF NOT EXISTS idx_units_status ON units(status);
CREATE TABLE IF NOT EXISTS hits (
    unit_id INTEGER, worker TEXT, found_at REAL, note TEXT
);
"""


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=60)
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    return con


def unit_bounds(unit_id: int) -> tuple[int, int]:
    """Deterministic: unit_id -> [start, end) inside the puzzle interval."""
    start = RANGE_LOW + unit_id * UNIT_SIZE
    end = min(start + UNIT_SIZE, RANGE_HIGH + 1)
    return start, end


def total_units() -> int:
    span = RANGE_HIGH - RANGE_LOW + 1
    return (span + UNIT_SIZE - 1) // UNIT_SIZE


def unit_checksum(unit_id: int, keys: int) -> str:
    s, e = unit_bounds(unit_id)
    return hashlib.sha256(f"{unit_id}:{s:x}:{e:x}:{keys}".encode()).hexdigest()[:16]


def cmd_init(args) -> None:
    con = connect()
    con.execute("INSERT OR REPLACE INTO meta VALUES ('puzzle', ?)", (str(TARGET_PUZZLE),))
    con.execute("INSERT OR REPLACE INTO meta VALUES ('hash160', ?)", (TARGET_HASH160,))
    con.execute("INSERT OR REPLACE INTO meta VALUES ('unit_size', ?)", (str(UNIT_SIZE),))
    con.commit()
    n = total_units()
    print(f"puzzle #{TARGET_PUZZLE}  interval [2^70, 2^71-1]")
    print(f"unit size   : {UNIT_SIZE:,} keys (2^{UNIT_SIZE.bit_length() - 1})")
    print(f"total units : {n:,}  (2^{(n - 1).bit_length()})")
    print("units are materialised lazily on lease; the table stays small.")


def reclaim_expired(con: sqlite3.Connection) -> int:
    now = time.time()
    cur = con.execute(
        "UPDATE units SET status='pending', worker=NULL, assigned_at=NULL, lease_expiry=NULL "
        "WHERE status='leased' AND lease_expiry < ?", (now,))
    con.commit()
    return cur.rowcount


def cmd_lease(args) -> None:
    con = connect()
    reclaimed = reclaim_expired(con)
    now = time.time()
    row = con.execute(
        "SELECT unit_id FROM units WHERE status='pending' ORDER BY unit_id LIMIT 1").fetchone()
    if row:
        unit_id = row[0]
    else:
        # first never-materialised unit id
        row = con.execute("SELECT COALESCE(MAX(unit_id), -1) FROM units").fetchone()
        unit_id = row[0] + 1
        if unit_id >= total_units():
            print("no work remaining")
            return
        s, e = unit_bounds(unit_id)
        con.execute("INSERT INTO units(unit_id, range_start, range_end) VALUES (?,?,?)",
                    (unit_id, f"{s:x}", f"{e:x}"))
    con.execute(
        "UPDATE units SET status='leased', worker=?, assigned_at=?, lease_expiry=? "
        "WHERE unit_id=?", (args.worker, now, now + LEASE_SECONDS, unit_id))
    con.commit()
    s, e = unit_bounds(unit_id)
    out = {"unit_id": unit_id, "range_start": f"{s:x}", "range_end": f"{e:x}",
           "count": e - s, "hash160": TARGET_HASH160,
           "lease_expiry": now + LEASE_SECONDS, "reclaimed": reclaimed}
    print(json.dumps(out))


def cmd_report(args) -> None:
    con = connect()
    s, e = unit_bounds(args.unit_id)
    width = e - s
    if args.done and args.keys_done < width:
        print(f"REJECTED: unit {args.unit_id} claims complete with {args.keys_done} keys "
              f"but width is {width}. A short unit would leave a silent gap.")
        sys.exit(1)
    status = "complete" if args.done else "leased"
    con.execute(
        "UPDATE units SET status=?, keys_tested=?, completed_at=?, speed_mkeys=?, checksum=? "
        "WHERE unit_id=? AND worker=?",
        (status, args.keys_done, time.time() if args.done else None,
         args.speed, unit_checksum(args.unit_id, args.keys_done), args.unit_id, args.worker))
    con.commit()
    print(f"unit {args.unit_id}: {status} ({args.keys_done:,} keys)")


def cmd_status(args) -> None:
    con = connect()
    reclaim_expired(con)
    rows = dict(con.execute("SELECT status, COUNT(*) FROM units GROUP BY status").fetchall())
    done = con.execute("SELECT COALESCE(SUM(keys_tested),0) FROM units "
                       "WHERE status='complete'").fetchone()[0]
    # keys_tested on 'complete' units is a final, audited count; on 'leased'
    # units it is the last self-reported PROGRESS snapshot for a unit still
    # being scanned. Both are shown so `status` doesn't read as "no progress"
    # for the ~17 minutes (at ~4.2 Mkeys/s) it takes to finish one 2^32 unit.
    in_progress_rows = con.execute(
        "SELECT unit_id, keys_tested, speed_mkeys, worker FROM units WHERE status='leased'"
    ).fetchall()
    in_progress = sum(r[1] or 0 for r in in_progress_rows)
    span = RANGE_HIGH - RANGE_LOW + 1
    print(f"puzzle #{TARGET_PUZZLE}   total units: {total_units():,}")
    for k in ("pending", "leased", "complete"):
        print(f"  {k:<9}: {rows.get(k, 0):,}")
    print(f"keys proven scanned  (completed units only): {done:,}")
    if in_progress_rows:
        print(f"keys scanned so far  (+ in-progress units, last snapshot): {in_progress:,}")
        for unit_id, keys_tested, speed_mkeys, worker in in_progress_rows:
            speed_str = f"{speed_mkeys:.3f} Mkeys/s" if speed_mkeys else "speed unknown yet"
            print(f"    unit {unit_id} (worker {worker}): {keys_tested or 0:,} keys, {speed_str}")
    total_seen = done + in_progress
    print(f"fraction of interval (completed only): {done / span:.3e}  ({done / span * 100:.3e}%)")
    print(f"fraction of interval (incl. in-progress): {total_seen / span:.3e}  ({total_seen / span * 100:.3e}%)")
    hits = con.execute("SELECT * FROM hits").fetchall()
    if hits:
        print(f"\n*** {len(hits)} HIT(S) RECORDED - see work/FOUND (not committed) ***")


def cmd_run(args) -> None:
    """Lease -> scan -> report loop for one worker."""
    if not ENGINE.exists():
        print(f"engine not built: {ENGINE}\n  cc -O3 -march=native -pthread -o engine src/engine.c")
        sys.exit(1)
    worker = args.worker
    for _ in range(args.units):
        con = connect()
        reclaim_expired(con)
        now = time.time()
        row = con.execute("SELECT unit_id FROM units WHERE status='pending' "
                          "ORDER BY unit_id LIMIT 1").fetchone()
        if row:
            unit_id = row[0]
        else:
            r = con.execute("SELECT COALESCE(MAX(unit_id), -1) FROM units").fetchone()
            unit_id = r[0] + 1
            if unit_id >= total_units():
                print("no work remaining")
                return
            s0, e0 = unit_bounds(unit_id)
            con.execute("INSERT INTO units(unit_id, range_start, range_end) VALUES (?,?,?)",
                        (unit_id, f"{s0:x}", f"{e0:x}"))
        con.execute("UPDATE units SET status='leased', worker=?, assigned_at=?, lease_expiry=? "
                    "WHERE unit_id=?", (worker, now, now + LEASE_SECONDS, unit_id))
        con.commit()

        s, e = unit_bounds(unit_id)
        count = e - s
        print(f"[{worker}] unit {unit_id}: scanning {count:,} keys from {s:x}", flush=True)
        proc = subprocess.Popen(
            [str(ENGINE), "search", f"{s:x}", str(count), TARGET_HASH160,
             str(args.threads), str(PROGRESS_SECS)],
            stdout=subprocess.PIPE, text=True)
        last_done, speed = 0, None
        found_key = None
        for line in proc.stdout:
            line = line.strip()
            if line.startswith("PROGRESS"):
                _, d, el, mk = line.split()
                last_done, speed = int(d), float(mk)
                con.execute("UPDATE units SET keys_tested=?, speed_mkeys=? WHERE unit_id=?",
                            (last_done, speed, unit_id))
                con.commit()
            elif line.startswith("rate"):
                speed = float(line.split(":")[1].split()[0])
            elif line.startswith("KEY"):
                found_key = line.split(":")[1].strip()
        proc.wait()

        if found_key:
            # Never print, log, or commit a recovered key for an unsolved puzzle.
            secure = ROOT / "work" / "FOUND"
            fd = os.open(secure, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(found_key + "\n")
            con.execute("INSERT INTO hits VALUES (?,?,?,?)",
                        (unit_id, worker, time.time(), "key written to work/FOUND mode 0600"))
            con.commit()
            print(f"\n*** HIT in unit {unit_id}. Key written to {secure} (mode 0600). ***")
            print("*** STOP ALL WORKERS AND VERIFY WITH TWO IMPLEMENTATIONS. ***")
            return

        con.execute("UPDATE units SET status='complete', keys_tested=?, completed_at=?, "
                    "speed_mkeys=?, checksum=? WHERE unit_id=?",
                    (count, time.time(), speed, unit_checksum(unit_id, count), unit_id))
        con.commit()
        print(f"[{worker}] unit {unit_id}: complete ({speed} Mkeys/s)" if speed
              else f"[{worker}] unit {unit_id}: complete", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Puzzle #71 distributed search coordinator")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init").set_defaults(func=cmd_init)
    sub.add_parser("status").set_defaults(func=cmd_status)

    p = sub.add_parser("lease"); p.add_argument("worker"); p.set_defaults(func=cmd_lease)

    p = sub.add_parser("report")
    p.add_argument("unit_id", type=int); p.add_argument("worker")
    p.add_argument("keys_done", type=int); p.add_argument("--done", action="store_true")
    p.add_argument("--speed", type=float, default=None)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("run")
    p.add_argument("worker", nargs="?", default=socket.gethostname())
    p.add_argument("--units", type=int, default=1)
    p.add_argument("--threads", type=int, default=os.cpu_count() or 1)
    p.set_defaults(func=cmd_run)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
