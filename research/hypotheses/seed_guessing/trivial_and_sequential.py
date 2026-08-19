"""
Seed-guessing dictionary attack, CATEGORY: trivial, degenerate, and
sequential hex seeds -- the "did the creator just not bother" hypothesis.

Directly constructs 32-hex-char (16-byte) seed candidates, bypassing any
phrase/mnemonic-word layer entirely, covering:

  - all-zeros, all-'f's, 0000...0001
  - sequential ascending/descending hex-digit text and raw byte-value ramps
  - well-known "magic number" hex constants (deadbeef, cafebabe, ...) tiled
    to 16 bytes
  - repeating single-byte patterns for ALL 256 byte values (0x00*16 .. 0xff*16)
  - the target puzzle number (71) zero-padded
  - small integers 0..10000, zero-padded to 32 hex chars
  - ~50 simple English/crypto-culture words and ~28 short number strings, as
    raw UTF-8 bytes zero-padded/truncated to exactly 16 bytes

Per task instructions, this category is treated as cheap enough *in kind*
(a few hundred genuinely "trivial" patterns) to justify running the REAL,
expensive 100,000-round Electrum stretch on every candidate rather than a
cheap approximation -- no shortcutting. The literal task instructions also
named "small integers 0-10000" explicitly, which is a strictly larger set
than "a few hundred"; this script honors that literal instruction (10,001
integers) in addition to the ~274 truly trivial/degenerate patterns and the
~78 word/number-string candidates, for 10,351 unique hex seeds total run
through the full expensive stretch. This is disclosed explicitly (see
trivial_and_sequential.md) as a deliberate, bounded extension beyond the "few
hundred" framing, not a silent scope change -- it stays within the task's
overall "hundreds to low thousands, not millions" Electrum budget and
completes in a few minutes via 4-way process parallelism (each candidate's
100k-round stretch is independent / embarrassingly parallel; no crypto
algorithm change).

Each hex-seed candidate's own hex text (or decimal string, for integers) is
ALSO used as a classic Type-1 "masterstring" across all 8 FORMATS, per the
task's "also test them all against classic Type-1" instruction -- this part
is pure SHA256, cheap, run single-threaded, no approximation needed.

MULTIPLE-TESTING / DEGENERATE-PUZZLE HANDLING: identical Bonferroni-style
disclosed-threshold approach as research/hypotheses/seed_guessing/
common_passwords.py -- see that script's docstring and
research/hypotheses/seed_guessing/common_passwords.md for the full
rationale (n=1 is structurally degenerate and excluded; a pre-registered
expected_spurious_count < 0.001 significance filter is applied to every
non-empty match before it is treated as alarming).

SAFETY: if a match ever clears the significance threshold, the script stops
immediately (best-effort cancellation of in-flight parallel work), does not
print/write the winning seed/passphrase/derived key, and records only the
label/format + matched puzzle numbers.
"""
import concurrent.futures as cf
import json
import sys
import time
from collections import defaultdict

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
OUT_JSON = "/home/user/Clawd71/research/hypotheses/seed_guessing/trivial_and_sequential_results.json"
SIGNIFICANCE_THRESHOLD = 0.001
NPROC = 4

dataset_full = json.load(open(DATASET_PATH))
assert len(dataset_full) == 82, f"expected 82 puzzles, got {len(dataset_full)}"

# n=1 is structurally degenerate: apply_puzzle_mask(raw, 1) == 1 for EVERY
# possible raw input (0 free bits), and the real dataset's puzzle #1 key IS
# 1 -- confirmed directly, not assumed (same check as common_passwords.py):
for raw_probe in (0, 1, 12345, 2**200, 999999999999):
    assert apply_puzzle_mask(raw_probe, 1) == 1
dataset = [e for e in dataset_full if e["n"] >= 2]
assert len(dataset) == 81
print(f"n=1 confirmed structurally degenerate (masked==1 unconditionally); excluded. "
      f"{len(dataset)} puzzles (n=2..130) used for matching.")


def expected_spurious_count(matched_ns, total_candidates):
    p = 1.0
    for n in matched_ns:
        p *= 2.0 ** -(n - 1)
    return total_candidates * p


def handle_matches(matches, total_candidates_this_category, chance_tally):
    if not matches:
        return False
    exp = expected_spurious_count(matches, total_candidates_this_category)
    if exp < SIGNIFICANCE_THRESHOLD:
        return True
    key = tuple(matches)
    chance_tally[key] = chance_tally.get(key, 0) + 1
    return False


# ===========================================================================
# Candidate construction
# ===========================================================================

def utf8_16(s: str) -> str:
    b = s.encode("utf-8")
    b = b[:16] if len(b) >= 16 else b + b"\x00" * (16 - len(b))
    return b.hex()


# --- Bucket A: truly trivial / degenerate / sequential hex patterns -------
TRIVIAL_PATTERNS = {}
TRIVIAL_PATTERNS["all_zeros"] = "0" * 32
TRIVIAL_PATTERNS["all_f"] = "f" * 32
TRIVIAL_PATTERNS["low_bit_one_0000...0001"] = "0" * 31 + "1"
TRIVIAL_PATTERNS["ascending_hex_digits_0123456789abcdef_x2"] = "0123456789abcdef" * 2
TRIVIAL_PATTERNS["descending_hex_digits_fedcba9876543210_x2"] = "fedcba9876543210" * 2
TRIVIAL_PATTERNS["ascending_bytes_00_to_0f"] = bytes(range(0, 16)).hex()
TRIVIAL_PATTERNS["ascending_bytes_01_to_10"] = bytes(range(1, 17)).hex()
TRIVIAL_PATTERNS["ascending_bytes_10_to_1f"] = bytes(range(16, 32)).hex()
TRIVIAL_PATTERNS["descending_bytes_ff_to_f0"] = bytes(range(255, 239, -1)).hex()

MAGIC_HEX_WORDS = ["deadbeef", "cafebabe", "baadf00d", "feedface", "8badf00d", "0defaced", "deadc0de", "b16b00b5"]
for mw in MAGIC_HEX_WORDS:
    TRIVIAL_PATTERNS[f"magic_{mw}_tiled"] = (mw * (32 // len(mw) + 1))[:32]

# the target puzzle number, zero-padded (explicit, on top of the 0-10000 sweep below)
TRIVIAL_PATTERNS["puzzle_number_71_zero_padded_hex"] = f"{71:032x}"

# repeating single-byte patterns, ALL 256 byte values (includes 0x00*16 and
# 0xff*16, which duplicate all_zeros / all_f above -- harmless, deduped below)
for b in range(256):
    TRIVIAL_PATTERNS[f"byte_repeat_0x{b:02x}_x16"] = bytes([b] * 16).hex()

TRIVIAL_COUNT = len(TRIVIAL_PATTERNS)

# --- Bucket B: small integers 0..10000, zero-padded to 32 hex chars -------
INT_RANGE = range(0, 10001)
INT_HEX_PATTERNS = {f"int_{i}_zero_padded_hex": f"{i:032x}" for i in INT_RANGE}
INT_DECIMAL_STRINGS = {f"int_decimal:{i}": str(i) for i in INT_RANGE}

# --- Bucket C: simple English/crypto-culture words + short number strings -
WORDS = [
    "bitcoin", "satoshi", "nakamoto", "genesis", "puzzle", "puzzle71",
    "secret", "secretkey", "privatekey", "password", "seed", "wallet",
    "private", "key", "electrum", "brainwallet", "brainwallet71", "brain",
    "hello", "helloworld", "world", "test", "testing", "admin", "root",
    "master", "masterkey", "money", "crypto", "cryptocurrency",
    "blockchain", "hash", "hunter2", "letmein", "qwerty", "freedom",
    "liberty", "trustno1", "correcthorsebatterystaple", "abc", "abc123",
    "satoshinakamoto", "btcpuzzle", "onepuzzle", "hiddenmessage",
    "thisisthepuzzle", "thisisasecret", "iamsatoshi", "toshi",
]
NUMSTRS = [str(i) for i in range(0, 21)] + ["71", "82", "130", "160", "1971", "2009", "2011", "2015"]

WORD_PATTERNS = {f"word_utf8_16:{w}": utf8_16(w) for w in WORDS}
NUMSTR_PATTERNS = {f"numstr_utf8_16:{s}": utf8_16(s) for s in NUMSTRS}

# ===========================================================================
# PART 1: Classic Type-1 (cheap), single-threaded
#   masterstring = the hex text itself (buckets A) / decimal string
#   (bucket B) / the word or number-string itself (bucket C), x 8 FORMATS
# ===========================================================================
CLASSIC_MASTERSTRINGS = {}
for label, hexseed in TRIVIAL_PATTERNS.items():
    CLASSIC_MASTERSTRINGS[f"hexpattern:{label}"] = hexseed
CLASSIC_MASTERSTRINGS.update(INT_DECIMAL_STRINGS)
for w in WORDS:
    CLASSIC_MASTERSTRINGS[f"word:{w}"] = w
for s in NUMSTRS:
    CLASSIC_MASTERSTRINGS[f"numstr:{s}"] = s

CLASSIC_TOTAL = len(CLASSIC_MASTERSTRINGS) * len(FORMATS)
print(f"PART 1 (classic Type-1): {len(CLASSIC_MASTERSTRINGS)} masterstrings x "
      f"{len(FORMATS)} formats = {CLASSIC_TOTAL} candidates")

t0 = time.time()
classic_tested = 0
classic_match = None
classic_chance_tally = {}
for label, m in CLASSIC_MASTERSTRINGS.items():
    for fmt in FORMATS:
        fn = lambda n, mm=m, f=fmt: classic_type1_candidate(mm, n, f)
        matches = test_candidate_against_dataset(fn, dataset)
        classic_tested += 1
        if matches and handle_matches(matches, CLASSIC_TOTAL, classic_chance_tally):
            classic_match = (label, fmt, matches)
            break
    if classic_match:
        break
t1 = time.time()

if classic_match:
    label, fmt, matches = classic_match
    exp = expected_spurious_count(matches, CLASSIC_TOTAL)
    print("!!! SIGNIFICANT MATCH FOUND (classic Type-1) !!!")
    print(f"candidate_label={label!r}  format={fmt!r}  matched puzzle numbers={matches}  "
          f"expected-by-chance={exp:.2e} (over {CLASSIC_TOTAL} candidates)")
    print("Winning masterstring is withheld from output per safety rule; "
          "available in this process's local state only.")
    with open(OUT_JSON, "w") as f:
        json.dump({
            "STOP": True,
            "category": "classic_type1",
            "candidate_label": label,
            "format": fmt,
            "matched_puzzle_numbers": matches,
            "expected_spurious_count": exp,
            "candidates_tested_before_match": classic_tested,
        }, f, indent=2)
    sys.exit(0)

chance_summary_classic = {str(k): v for k, v in sorted(classic_chance_tally.items(), key=lambda kv: -kv[1])}
print(f"  {classic_tested} candidates tested, 0 SIGNIFICANT matches, {t1 - t0:.1f}s")
print(f"  chance-level coincidences (sub-threshold, expected noise): "
      f"{sum(classic_chance_tally.values())} total; top patterns: "
      f"{dict(list(chance_summary_classic.items())[:5])}")

# ===========================================================================
# PART 2: Electrum Type-1, FULL expensive 100k-round stretch on every
# unique direct hex-seed candidate (buckets A, B-as-hex, C), parallelized
# across NPROC processes. No cheap approximation -- every candidate gets
# the real, validated derivation.
# ===========================================================================
ALL_HEX_LABELED = {}
ALL_HEX_LABELED.update(TRIVIAL_PATTERNS)
ALL_HEX_LABELED.update(INT_HEX_PATTERNS)
ALL_HEX_LABELED.update(WORD_PATTERNS)
ALL_HEX_LABELED.update(NUMSTR_PATTERNS)

seed_to_labels = defaultdict(list)
for label, hexseed in ALL_HEX_LABELED.items():
    assert len(hexseed) == 32 and all(c in "0123456789abcdef" for c in hexseed), (label, hexseed)
    seed_to_labels[hexseed].append(label)

ELECTRUM_ITEMS = list(seed_to_labels.items())  # (hex_seed, [labels...])
ELECTRUM_TOTAL = len(ELECTRUM_ITEMS)
print(f"\nPART 2 (Electrum Type-1, FULL 100k-round stretch): "
      f"{len(ALL_HEX_LABELED)} labeled candidates -> {ELECTRUM_TOTAL} unique hex seeds "
      f"(buckets: {TRIVIAL_COUNT} trivial/degenerate/byte-repeat, {len(INT_HEX_PATTERNS)} "
      f"integers 0-10000, {len(WORD_PATTERNS)} words, {len(NUMSTR_PATTERNS)} number-strings)")


def electrum_worker(hexseed):
    secexp = electrum_stretch_key(hexseed)
    priv = PrivateKey(secexp.to_bytes(32, "big"))
    mpk_hex = priv.public_key.format(compressed=False)[1:].hex()
    fn = lambda n, se=secexp, mp=mpk_hex, hs=hexseed: electrum_child_privkey(hs, n, secexp=se, mpk_hex=mp)
    matches = test_candidate_against_dataset(fn, dataset)
    return hexseed, matches


t2 = time.time()
electrum_tested = 0
electrum_match = None
electrum_chance_tally = {}
progress_step = max(1, ELECTRUM_TOTAL // 20)

with cf.ProcessPoolExecutor(max_workers=NPROC) as ex:
    future_to_seed = {ex.submit(electrum_worker, hexseed): hexseed for hexseed, _ in ELECTRUM_ITEMS}
    for fut in cf.as_completed(future_to_seed):
        hexseed = future_to_seed[fut]
        try:
            _, matches = fut.result()
        except Exception as e:
            print(f"  [worker error, skipping] {hexseed[:8]}...: {e}")
            continue
        electrum_tested += 1
        if electrum_tested % progress_step == 0:
            print(f"  ... {electrum_tested}/{ELECTRUM_TOTAL} tested "
                  f"({time.time() - t2:.0f}s elapsed)")
        if matches and handle_matches(matches, ELECTRUM_TOTAL, electrum_chance_tally):
            electrum_match = (hexseed, seed_to_labels[hexseed], matches)
            print("!!! SIGNIFICANT MATCH -- cancelling remaining work !!!")
            for f2 in future_to_seed:
                f2.cancel()
            break
    if electrum_match:
        ex.shutdown(wait=False, cancel_futures=True)
t3 = time.time()

if electrum_match:
    hexseed, labels, matches = electrum_match
    exp = expected_spurious_count(matches, ELECTRUM_TOTAL)
    print("!!! SIGNIFICANT MATCH FOUND (Electrum Type-1, full stretch) !!!")
    print(f"candidate_labels={labels}  matched puzzle numbers={matches}  "
          f"expected-by-chance={exp:.2e} (over {ELECTRUM_TOTAL} candidates)")
    print("Winning hex seed is withheld from output per safety rule; "
          "available in this process's local state only.")
    with open(OUT_JSON, "w") as f:
        json.dump({
            "STOP": True,
            "category": "electrum_type1_full_stretch",
            "candidate_labels": labels,
            "matched_puzzle_numbers": matches,
            "expected_spurious_count": exp,
            "candidates_tested_before_match": electrum_tested,
        }, f, indent=2)
    sys.exit(0)

chance_summary_electrum = {str(k): v for k, v in sorted(electrum_chance_tally.items(), key=lambda kv: -kv[1])}
print(f"  {electrum_tested} candidates tested, 0 SIGNIFICANT matches, {t3 - t2:.1f}s "
      f"({NPROC} processes)")
print(f"  chance-level coincidences (sub-threshold, expected noise): "
      f"{sum(electrum_chance_tally.values())} total; top patterns: "
      f"{dict(list(chance_summary_electrum.items())[:5])}")

# ===========================================================================
# Write full result summary (no significant matches) + representative sample
# ===========================================================================
summary = {
    "buckets": {
        "trivial_degenerate_sequential_and_byte_repeat": TRIVIAL_COUNT,
        "small_integers_0_to_10000": len(INT_HEX_PATTERNS),
        "words": len(WORDS),
        "number_strings": len(NUMSTRS),
    },
    "significance_threshold_expected_spurious_count": SIGNIFICANCE_THRESHOLD,
    "classic_type1": {
        "masterstrings_tested": len(CLASSIC_MASTERSTRINGS),
        "formats_tested": list(FORMATS.keys()),
        "total_candidates": classic_tested,
        "significant_matches": [],
        "chance_level_coincidences_total": sum(classic_chance_tally.values()),
        "chance_level_coincidences_by_pattern": chance_summary_classic,
        "elapsed_sec": round(t1 - t0, 2),
    },
    "electrum_type1_full_stretch": {
        "unique_hex_seeds_tested": ELECTRUM_TOTAL,
        "total_candidates": electrum_tested,
        "significant_matches": [],
        "chance_level_coincidences_total": sum(electrum_chance_tally.values()),
        "chance_level_coincidences_by_pattern": chance_summary_electrum,
        "elapsed_sec": round(t3 - t2, 2),
        "nproc": NPROC,
        "sample_trivial_hex_seeds": {k: TRIVIAL_PATTERNS[k] for k in list(TRIVIAL_PATTERNS)[:15]},
        "sample_int_hex_seeds_first_5": {k: INT_HEX_PATTERNS[k] for k in list(INT_HEX_PATTERNS)[:5]},
        "sample_word_hex_seeds_first_10": {k: WORD_PATTERNS[k] for k in list(WORD_PATTERNS)[:10]},
    },
}
with open(OUT_JSON, "w") as f:
    json.dump(summary, f, indent=2)

print("\nFull summary written to", OUT_JSON)
print(f"\nTOTAL wall time: {t3 - t0:.1f}s")
