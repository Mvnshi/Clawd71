"""
Phase 8: incremental-EC-point search engine for Bitcoin Puzzle #71.

No generator-hypothesis or statistical shortcut survived Phase 2-6 (see
research/PHASE_2_6_SUMMARY.md) -- effective search-space reduction was
0 bits. This engine therefore searches the full uniform [RANGE_START,
RANGE_END] interval. On this container's hardware (4 CPU cores, no GPU)
that is not a realistic path to a solve -- see the throughput/ETA note
printed by search_coordinator.py and README.md. It is built correct,
checkpointed, and resumable so it can also be pointed at real hardware.

Speed technique: instead of a full EC scalar multiplication per
candidate key (~18k keys/sec/core measured here), step the EC point by
a single point ADDITION of G per candidate (~100k keys/sec/core
measured here, ~5.8x faster) -- this is the standard "incremental EC
point generation" approach used by tools like VanitySearch/KeyHunt.

SUCCESS HANDLING: a match is independently re-verified via TWO separate
secp256k1 implementations (coincurve/libsecp256k1, and the pure-Python
`ecdsa` library, which shares no code with the first) before being
trusted. The private key is written ONLY to a chmod-600 local file
(data/search_state/FOUND_SECRET.txt, gitignored) -- never to the
regular checkpoint/log files, stdout beyond a redacted confirmation, or
any file that could end up in git history.
"""
import hashlib
import json
import os
import secrets
import time
from pathlib import Path

import base58
from coincurve import PrivateKey, PublicKey
from ecdsa import SECP256k1, SigningKey

TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
RANGE_START = 0x400000000000000000
RANGE_END = 0x7FFFFFFFFFFFFFFFFF  # inclusive
STATE_DIR = Path("/home/user/Clawd71/data/search_state")


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def target_hash160() -> bytes:
    payload = base58.b58decode_check(TARGET_ADDRESS)
    return payload[1:]  # strip version byte


def verify_with_ecdsa(key_int: int, expected_h160: bytes) -> bool:
    """Second, independent secp256k1 implementation (pure-Python `ecdsa`,
    no shared code with coincurve/libsecp256k1) for cross-checking a hit."""
    sk = SigningKey.from_secret_exponent(key_int, curve=SECP256k1)
    point = sk.verifying_key.pubkey.point
    prefix = b"\x02" if point.y() % 2 == 0 else b"\x03"
    compressed = prefix + point.x().to_bytes(32, "big")
    return hash160(compressed) == expected_h160


def _checksum(obj: dict) -> str:
    payload = json.dumps(obj, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


def save_checkpoint(path: Path, **fields):
    fields = dict(fields)
    fields["checksum"] = _checksum(fields)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(fields, indent=2))
    tmp.replace(path)  # atomic on POSIX


def append_log(path: Path, event: dict):
    with open(path, "a") as f:
        f.write(json.dumps(event) + "\n")


def handle_found(key_int: int, worker_id: int, expected_h160: bytes):
    (STATE_DIR / "STOP").write_text(f"found_by_worker_{worker_id}")

    import sys

    sys.path.insert(0, "/home/user/Clawd71/src")
    from btcaddr import which_encoding_matches

    verified_1 = which_encoding_matches(key_int, TARGET_ADDRESS) == "compressed"
    verified_2 = verify_with_ecdsa(key_int, expected_h160)
    verified = verified_1 and verified_2

    secret_path = STATE_DIR / "FOUND_SECRET.txt"
    with open(secret_path, "w") as f:
        f.write(
            f"puzzle=71\naddress={TARGET_ADDRESS}\nkey_hex={key_int:x}\n"
            f"verified_coincurve_pipeline={verified_1}\n"
            f"verified_independent_ecdsa_pipeline={verified_2}\n"
            f"verified={verified}\nfound_by_worker={worker_id}\n"
            f"found_at_unix={time.time()}\n"
        )
    os.chmod(secret_path, 0o600)
    print(
        f"[worker {worker_id}] *** CANDIDATE MATCH FOUND *** "
        f"verified={verified}. Details written to a chmod-600 local file "
        f"({secret_path}). Key material is NOT printed here or logged elsewhere. "
        f"STOP signal issued to all workers."
    )


def search_worker(worker_id: int, start: int, end: int, report_every_sec: float = 5.0):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    checkpoint_path = STATE_DIR / f"worker_{worker_id}.json"
    log_path = STATE_DIR / f"worker_{worker_id}.log.jsonl"
    stop_path = STATE_DIR / "STOP"
    expected_h160 = target_hash160()

    if checkpoint_path.exists():
        ckpt = json.loads(checkpoint_path.read_text())
        current = ckpt["current_position"]
        keys_tested = ckpt["keys_tested"]
    else:
        current = start
        keys_tested = 0

    if current > end:
        save_checkpoint(
            checkpoint_path, range_start=start, range_end=end, worker=worker_id,
            current_position=current, keys_tested=keys_tested, speed=0,
            status="completed_range_exhausted", assigned_at=None, completed_at=time.time(),
        )
        return

    g_pub = PrivateKey((1).to_bytes(32, "big")).public_key
    cur_pub = PrivateKey(current.to_bytes(32, "big")).public_key

    t_start = time.time()
    last_report = t_start
    keys_since_report = 0

    while current <= end:
        if stop_path.exists():
            save_checkpoint(
                checkpoint_path, range_start=start, range_end=end, worker=worker_id,
                current_position=current, keys_tested=keys_tested, speed=0,
                status="stopped_external", assigned_at=t_start, completed_at=time.time(),
            )
            return

        h = hash160(cur_pub.format(compressed=True))
        if h == expected_h160:
            handle_found(current, worker_id, expected_h160)
            save_checkpoint(
                checkpoint_path, range_start=start, range_end=end, worker=worker_id,
                current_position=current, keys_tested=keys_tested + 1, speed=0,
                status="found", assigned_at=t_start, completed_at=time.time(),
            )
            return

        current += 1
        keys_tested += 1
        keys_since_report += 1
        cur_pub.combine([g_pub], update=True)

        now = time.time()
        if now - last_report >= report_every_sec:
            speed = keys_since_report / (now - last_report)
            save_checkpoint(
                checkpoint_path, range_start=start, range_end=end, worker=worker_id,
                current_position=current, keys_tested=keys_tested, speed=round(speed, 1),
                status="running", assigned_at=t_start, completed_at=None,
            )
            append_log(log_path, {
                "t": now, "worker": worker_id, "current_position_hex": format(current, "x"),
                "keys_tested": keys_tested, "speed_keys_per_sec": round(speed, 1),
            })
            last_report = now
            keys_since_report = 0

    save_checkpoint(
        checkpoint_path, range_start=start, range_end=end, worker=worker_id,
        current_position=current, keys_tested=keys_tested, speed=0,
        status="completed_range_exhausted", assigned_at=t_start, completed_at=time.time(),
    )
