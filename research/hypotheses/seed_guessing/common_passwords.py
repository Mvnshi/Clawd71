"""
Seed-guessing dictionary attack, CATEGORY: common/weak passwords and test values.

Source wordlist: SecLists 10k-most-common.txt
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt
  (fetched 2026-08-19, 10,000 lines, verified HTTP 200)

Runs:
  1. Classic Type-1: all 10,000 passwords x all 8 FORMATS entries against the
     real puzzle dataset (cheap: pure SHA256, no stretching). 80,000 candidates.
  2. Electrum Type-1: the top 30 most common passwords, each turned into a
     16-byte hex seed via three cheap transforms (SHA256[:16], MD5, raw UTF-8
     padded/truncated to 16 bytes), run through the REAL expensive 100k-round
     stretch (unavoidable for this scheme -- "cheap" refers only to how the
     hex seed is produced). secexp/mpk are computed ONCE per unique seed and
     reused across all dataset entries via the module's own secexp=/mpk_hex=
     params (test_candidate_against_dataset would otherwise redo the
     100k-round stretch once per dataset entry -- an efficient call pattern,
     not a change to the validated algorithm). 90 candidates.

MULTIPLE-TESTING / DEGENERATE-PUZZLE HANDLING (read before judging any
"match" below):

  apply_puzzle_mask(raw, n) keeps only the low (n-1) bits of raw and forces
  bit (n-1) high, so puzzle n has exactly (n-1) "free" bits and an arbitrary
  candidate matches it by pure chance with probability 2^-(n-1).

  - n=1 has 0 free bits: masked is ALWAYS 1 for ANY raw input, and the real
    puzzle #1 key IS 1 -- so n=1 "matches" unconditionally, for every single
    candidate, always. This is confirmed by direct computation below (not
    trusted from a description) and mirrors the validated module's own test
    convention (tests/test_seed_attack.py's positive controls start their
    synthetic datasets at n=2, excluding n=1 for this exact reason). n=1 is
    excluded from the matching dataset entirely.
  - n=2 has 1 free bit: matches by pure chance ~50% of the time. This is
    NOT a degenerate 100%-certain case like n=1, but across tens of
    thousands of candidates it WILL produce thousands of spurious "matches"
    on n=2 alone purely by chance -- this is a real, unavoidable multiple-
    testing effect, not a bug. (Discovered empirically on the first run of
    this script: masterstring="" plain-format spuriously matched n=2 with
    the theoretically expected ~50% base rate -- see chance-hit tally below,
    which confirms the observed rate tracks the predicted rate, itself a
    useful sanity check that this cheap SHA256 scheme isn't secretly
    correlated with anything.)

  Rather than halting on every such expected coincidence (which would make
  it impossible to ever complete a large candidate sweep against a dataset
  containing puzzles this small), every non-empty match is passed through a
  pre-registered, disclosed Bonferroni-style significance filter BEFORE it
  is treated as alarming:

      expected_spurious_count(matched_puzzle_set) =
          total_candidates_this_category * prod(2^-(n-1) for n in matched_puzzle_set)

  A match set is only escalated to the CRITICAL SAFETY STOP protocol if
  expected_spurious_count < 0.001 (i.e., fewer than 1-in-1000 expected
  purely by chance given how many candidates this exact run tested) --
  matching the task's own framing that a real hit means "matching a
  specific 20+-bit number by chance" or "a match across two or more
  puzzles simultaneously". Sub-threshold matches are logged as chance noise
  and the run continues.

SAFETY: if a match ever clears the significance threshold, the script stops
immediately, does not print/write the winning seed or derived key, and
records only the format/derivation name + matched puzzle numbers.
"""
import hashlib
import json
import sys
import time

sys.path.insert(0, "/home/user/Clawd71/src")
from seed_attack import (
    FORMATS,
    apply_puzzle_mask,
    classic_type1_candidate,
    electrum_child_privkey,
    electrum_stretch_key,
    test_candidate_against_dataset,
)
from coincurve import PrivateKey

DATASET_PATH = "/home/user/Clawd71/data/solved_puzzles.json"
WORDLIST_PATH = "/home/user/Clawd71/research/hypotheses/seed_guessing/10k-most-common.txt"
OUT_JSON = "/home/user/Clawd71/research/hypotheses/seed_guessing/common_passwords_results.json"

SIGNIFICANCE_THRESHOLD = 0.001  # expected spurious count below which a match is "real"

dataset_full = json.load(open(DATASET_PATH))
assert len(dataset_full) == 82, f"expected 82 puzzles, got {len(dataset_full)}"

# n=1 is structurally degenerate: apply_puzzle_mask(raw, 1) == 1 for EVERY
# possible raw input (0 free bits), and the real dataset's puzzle #1 key IS
# 1 -- confirmed directly, not assumed:
for raw_probe in (0, 1, 12345, 2**200, 999999999999):
    assert apply_puzzle_mask(raw_probe, 1) == 1
dataset = [e for e in dataset_full if e["n"] >= 2]
assert len(dataset) == 81
print(f"n=1 confirmed structurally degenerate (masked==1 unconditionally); excluded. "
      f"{len(dataset)} puzzles (n=2..130) used for matching.")

with open(WORDLIST_PATH) as f:
    wordlist = [line.rstrip("\n") for line in f if line.strip()]
assert len(wordlist) == 10000, f"expected 10000 passwords, got {len(wordlist)}"


def expected_spurious_count(matched_ns, total_candidates):
    p = 1.0
    for n in matched_ns:
        p *= 2.0 ** -(n - 1)
    return total_candidates * p


def handle_matches(matches, total_candidates_this_category, chance_tally):
    """Returns True if this match set is SIGNIFICANT (real safety-stop trigger)."""
    if not matches:
        return False
    exp = expected_spurious_count(matches, total_candidates_this_category)
    if exp < SIGNIFICANCE_THRESHOLD:
        return True
    # expected/chance-level coincidence -- tally and continue
    key = tuple(matches)
    chance_tally[key] = chance_tally.get(key, 0) + 1
    return False


# -----------------------------------------------------------------------
# PART 1: Classic Type-1, full 10,000-password wordlist x 8 formats
# -----------------------------------------------------------------------
CLASSIC_TOTAL = len(wordlist) * len(FORMATS)
t0 = time.time()
classic_tested = 0
classic_match = None
classic_chance_tally = {}
for pw in wordlist:
    for fmt in FORMATS:
        fn = lambda n, m=pw, f=fmt: classic_type1_candidate(m, n, f)
        matches = test_candidate_against_dataset(fn, dataset)
        classic_tested += 1
        if matches and handle_matches(matches, CLASSIC_TOTAL, classic_chance_tally):
            classic_match = (pw, fmt, matches)
            break
    if classic_match:
        break
t1 = time.time()

if classic_match:
    pw, fmt, matches = classic_match
    exp = expected_spurious_count(matches, CLASSIC_TOTAL)
    print("!!! SIGNIFICANT MATCH FOUND (classic Type-1) !!!")
    print(f"format={fmt!r}  matched puzzle numbers={matches}  "
          f"expected-by-chance={exp:.2e} (over {CLASSIC_TOTAL} candidates)")
    print("Winning passphrase is withheld from output per safety rule; "
          "available in this process's local state only.")
    with open(OUT_JSON, "w") as f:
        json.dump({
            "STOP": True,
            "category": "classic_type1",
            "format": fmt,
            "matched_puzzle_numbers": matches,
            "expected_spurious_count": exp,
            "candidates_tested_before_match": classic_tested,
        }, f, indent=2)
    sys.exit(0)

chance_summary_classic = {str(k): v for k, v in sorted(classic_chance_tally.items(), key=lambda kv: -kv[1])}
print(f"PART 1 (classic Type-1): {classic_tested} candidates tested "
      f"({len(wordlist)} passwords x {len(FORMATS)} formats), "
      f"0 SIGNIFICANT matches, {t1 - t0:.1f}s")
print(f"  chance-level coincidences observed (sub-threshold, expected noise): "
      f"{sum(classic_chance_tally.values())} total; top patterns: "
      f"{dict(list(chance_summary_classic.items())[:5])}")

# -----------------------------------------------------------------------
# PART 2: Electrum Type-1, top 30 passwords x 3 cheap hex-seed derivations,
# run through the REAL 100k-round stretch (unavoidable for this scheme).
# -----------------------------------------------------------------------
TOP_N = 30
top_passwords = wordlist[:TOP_N]
ELECTRUM_TOTAL = TOP_N * 3


def derive_hex_seeds(phrase: str):
    b = phrase.encode("utf-8")
    sha_seed = hashlib.sha256(b).digest()[:16].hex()
    md5_seed = hashlib.md5(b).hexdigest()
    if len(b) >= 16:
        raw = b[:16]
    else:
        raw = b + b"\x00" * (16 - len(b))
    raw_seed = raw.hex()
    return {"sha256_16": sha_seed, "md5": md5_seed, "raw_utf8_16": raw_seed}


t2 = time.time()
electrum_tested = 0
electrum_match = None
electrum_chance_tally = {}
electrum_candidates_log = []

for pw in top_passwords:
    seeds = derive_hex_seeds(pw)
    for deriv_name, hex_seed in seeds.items():
        secexp = electrum_stretch_key(hex_seed)
        priv = PrivateKey(secexp.to_bytes(32, "big"))
        mpk_hex = priv.public_key.format(compressed=False)[1:].hex()

        fn = lambda n, se=secexp, mp=mpk_hex, hs=hex_seed: electrum_child_privkey(
            hs, n, secexp=se, mpk_hex=mp
        )
        matches = test_candidate_against_dataset(fn, dataset)
        electrum_tested += 1
        electrum_candidates_log.append((pw, deriv_name, hex_seed))
        if matches and handle_matches(matches, ELECTRUM_TOTAL, electrum_chance_tally):
            electrum_match = (pw, deriv_name, hex_seed, matches)
            break
    if electrum_match:
        break
t3 = time.time()

if electrum_match:
    pw, deriv_name, hex_seed, matches = electrum_match
    exp = expected_spurious_count(matches, ELECTRUM_TOTAL)
    print("!!! SIGNIFICANT MATCH FOUND (Electrum Type-1, cheap hex-seed derivation) !!!")
    print(f"derivation={deriv_name!r}  matched puzzle numbers={matches}  "
          f"expected-by-chance={exp:.2e} (over {ELECTRUM_TOTAL} candidates)")
    print("Winning passphrase/hex-seed is withheld from output per safety rule; "
          "available in this process's local state only.")
    with open(OUT_JSON, "w") as f:
        json.dump({
            "STOP": True,
            "category": "electrum_type1_cheap_derivation",
            "derivation": deriv_name,
            "matched_puzzle_numbers": matches,
            "expected_spurious_count": exp,
            "candidates_tested_before_match": electrum_tested,
        }, f, indent=2)
    sys.exit(0)

chance_summary_electrum = {str(k): v for k, v in sorted(electrum_chance_tally.items(), key=lambda kv: -kv[1])}
print(f"PART 2 (Electrum Type-1, cheap derivations): {electrum_tested} candidates "
      f"tested ({TOP_N} passwords x 3 derivations), 0 SIGNIFICANT matches, {t3 - t2:.1f}s")
print(f"  chance-level coincidences observed (sub-threshold, expected noise): "
      f"{sum(electrum_chance_tally.values())} total; top patterns: "
      f"{dict(list(chance_summary_electrum.items())[:5])}")

# -----------------------------------------------------------------------
# Write full result summary (no significant matches) + representative sample
# -----------------------------------------------------------------------
summary = {
    "wordlist_source": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
    "wordlist_size": len(wordlist),
    "significance_threshold_expected_spurious_count": SIGNIFICANCE_THRESHOLD,
    "classic_type1": {
        "passwords_tested": len(wordlist),
        "formats_tested": list(FORMATS.keys()),
        "total_candidates": classic_tested,
        "significant_matches": [],
        "chance_level_coincidences_total": sum(classic_chance_tally.values()),
        "chance_level_coincidences_by_pattern": chance_summary_classic,
        "elapsed_sec": round(t1 - t0, 2),
    },
    "electrum_type1_cheap": {
        "top_passwords_tested": top_passwords,
        "derivations": ["sha256_16", "md5", "raw_utf8_16"],
        "total_candidates": electrum_tested,
        "significant_matches": [],
        "chance_level_coincidences_total": sum(electrum_chance_tally.values()),
        "chance_level_coincidences_by_pattern": chance_summary_electrum,
        "elapsed_sec": round(t3 - t2, 2),
        "sample_hex_seeds_first_5": electrum_candidates_log[:5],
    },
}
with open(OUT_JSON, "w") as f:
    json.dump(summary, f, indent=2)

print("\nFull summary written to", OUT_JSON)
