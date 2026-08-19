"""
Correctness test for the incremental-EC search engine (Phase 8), against a
synthetic small target -- NOT the real puzzle -- so this runs in well
under a second and proves the incremental-stepping + checkpoint/resume +
found-handling logic is correct before trusting it against the real
puzzle #71 target.
"""
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, "/home/user/Clawd71/src")
import search_engine as se
from btcaddr import privkey_int_to_addresses

TEST_STATE_DIR = Path("/tmp/claude-0/-home-user-Clawd71/ad6103c2-6292-5da4-b74f-f5d157a4e883/scratchpad/test_search_state")


def setup():
    if TEST_STATE_DIR.exists():
        shutil.rmtree(TEST_STATE_DIR)
    TEST_STATE_DIR.mkdir(parents=True)
    se.STATE_DIR = TEST_STATE_DIR


def test_finds_known_key_in_small_range():
    setup()
    known_key = 123456789
    synthetic_address = privkey_int_to_addresses(known_key)["address_from_compressed"]
    se.TARGET_ADDRESS = synthetic_address

    se.search_worker(worker_id=0, start=known_key - 1000, end=known_key + 1000, report_every_sec=9999)

    secret_path = TEST_STATE_DIR / "FOUND_SECRET.txt"
    assert secret_path.exists(), "engine did not find a key that is in-range"
    content = secret_path.read_text()
    assert f"key_hex={known_key:x}" in content
    assert "verified=True" in content
    assert oct(secret_path.stat().st_mode)[-3:] == "600", "found-key file must be chmod 600"


def test_misses_when_key_out_of_range():
    setup()
    known_key = 123456789
    synthetic_address = privkey_int_to_addresses(known_key)["address_from_compressed"]
    se.TARGET_ADDRESS = synthetic_address

    se.search_worker(worker_id=0, start=known_key + 1, end=known_key + 500, report_every_sec=9999)

    assert not (TEST_STATE_DIR / "FOUND_SECRET.txt").exists()
    ckpt = json.loads((TEST_STATE_DIR / "worker_0.json").read_text())
    assert ckpt["status"] == "completed_range_exhausted"
    assert ckpt["keys_tested"] == 500


def test_checkpoint_resume():
    setup()
    known_key = 123456789
    synthetic_address = privkey_int_to_addresses(known_key)["address_from_compressed"]
    se.TARGET_ADDRESS = synthetic_address

    # simulate a crash partway through by writing a checkpoint stopped short of the key
    ckpt_path = TEST_STATE_DIR / "worker_0.json"
    se.save_checkpoint(
        ckpt_path, range_start=known_key - 1000, range_end=known_key + 1000, worker=0,
        current_position=known_key - 5, keys_tested=995, speed=0, status="stopped_external",
        assigned_at=None, completed_at=None,
    )
    se.search_worker(worker_id=0, start=known_key - 1000, end=known_key + 1000, report_every_sec=9999)

    secret_path = TEST_STATE_DIR / "FOUND_SECRET.txt"
    assert secret_path.exists()
    ckpt = json.loads(ckpt_path.read_text())
    # resumed at current_position=known_key-5 with keys_tested=995 already counted;
    # the loop then tests known_key-5..known_key inclusive (6 more) before matching
    assert ckpt["keys_tested"] == 1001


def test_stop_signal_halts_worker():
    setup()
    known_key = 123456789
    synthetic_address = privkey_int_to_addresses(known_key)["address_from_compressed"]
    se.TARGET_ADDRESS = synthetic_address
    (TEST_STATE_DIR / "STOP").write_text("test")

    se.search_worker(worker_id=0, start=known_key - 1000, end=known_key + 1000, report_every_sec=9999)

    assert not (TEST_STATE_DIR / "FOUND_SECRET.txt").exists()
    ckpt = json.loads((TEST_STATE_DIR / "worker_0.json").read_text())
    assert ckpt["status"] == "stopped_external"


if __name__ == "__main__":
    test_finds_known_key_in_small_range()
    print("PASS: test_finds_known_key_in_small_range")
    test_misses_when_key_out_of_range()
    print("PASS: test_misses_when_key_out_of_range")
    test_checkpoint_resume()
    print("PASS: test_checkpoint_resume")
    test_stop_signal_halts_worker()
    print("PASS: test_stop_signal_halts_worker")
    shutil.rmtree(TEST_STATE_DIR, ignore_errors=True)
    print("All Phase 8 search-engine correctness tests passed.")
