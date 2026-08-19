"""
Seed-guessing dictionary attack, CATEGORY: known historically-cracked Bitcoin
brainwallet passphrases.

Rationale (per task): a puzzle creator picking a "memorable" deterministic-
wallet seed around 2013-2015 plausibly drew from the same cultural pool of
phrases early Bitcoin users actually used (and lost funds with) for brain-
wallets. Unlike the common_passwords.py run (generic weak-password lists),
every candidate here is a REAL, individually documented brainwallet
passphrase that funds were sent to and then drained, sourced from two
primary accounts of large-scale brainwallet cracking:

SOURCE A: Ryan Castellucci, "Cracking Cryptocurrency Brainwallets",
  DEF CON 23, August 2015.
  https://rya.nc/files/cracking_cryptocurrency_brainwallets.pdf
  (mirror: https://media.defcon.org/DEF%20CON%2023/DEF%20CON%2023%20presentations/DEF%20CON%2023%20-%20Ryan-Castellucci-Cracking-Cryptocurrency-Brainwalletsll.pdf)
  Fetched 2026-08-19, saved verbatim at
  research/hypotheses/seed_guessing/defcon23_castellucci.pdf (268KB, HTTP 200).
  Slides explicitly titled "Some results" / "Some more results" / "A few more
  results" list passphrases Castellucci's own cracker (and later Brainflayer)
  found funded brainwallets for, several with BTC/USD amounts and dates
  quoted directly from the slide text (see per-candidate "source" field
  below for the exact slide).

SOURCE B: Vasek, Bonneau, Castellucci, Keith, Moore, "The Bitcoin Brain
  Drain: Examining the Use and Abuse of Bitcoin Brain Wallets", Financial
  Cryptography and Data Security 2016 (peer-reviewed).
  https://jbonneau.com/doc/VBCKM16-FC-bitcoin_brain_wallets.pdf
  Fetched 2026-08-19, saved verbatim at
  research/hypotheses/seed_guessing/bitcoin_brain_drain_paper.pdf (243KB,
  HTTP 200). Table 2 ("Top 10 drain addresses from brain wallets") gives
  the exact passphrase-derived description for several of the largest
  confirmed drains, with USD/BTC amounts and number of drain events.

Every candidate below is a PRIMARY-SOURCE, dollar/BTC-amount-documented real
brainwallet passphrase (not an invented or estimated guess) EXCEPT one
explicitly flagged lower-confidence item (see CANDIDATES list, "xkcd_demo"
tag) included for completeness because Vasek et al. Table 1 documents the
broader xkcd-style category (90 wallets, $29K, "drained repeatedly the
most") even though this exact phrase's individual crack status isn't
confirmed by name.

Runs (same methodology/significance-filter as common_passwords.py, reused
deliberately for a consistent, pre-registered decision rule across this
seed-guessing research line):

  1. Classic Type-1: all 24 candidate phrases x all 8 FORMATS entries
     against the real puzzle dataset. 192 candidates. Cheap (pure SHA256).
  2. Electrum Type-1: ALL 24 candidate phrases (not just a subset -- the
     list is short enough that the "escalate only your best candidates"
     budget is trivially satisfied by escalating all of them), each turned
     into a 16-byte hex seed via three cheap transforms (SHA256[:16] as hex,
     MD5 as hex, raw UTF-8 bytes zero-padded/truncated to 16 bytes as hex),
     run through the REAL unavoidable 100k-round stretch. 72 candidates.
  3. Bonus: for each phrase, attempt Electrum's actual literal mnemonic-word
     path (hex_seed_from_words) in case the phrase happens to parse as a
     valid 12-word entry in Electrum's old-mnemonic wordlist. This is a
     free/cheap parse-and-reject check (returns None instantly for any
     phrase that isn't exactly 12 words drawn from that specific 1626-word
     list) -- expected to reject every candidate here but run anyway since
     it costs nothing extra.

Multiple-testing / degenerate-puzzle handling: IDENTICAL methodology to
common_passwords.py -- n=1 excluded (masked key is unconditionally 1 for
any input, confirmed directly below, not assumed), and any non-empty match
is passed through a pre-registered Bonferroni-style filter
(expected_spurious_count = total_candidates_this_category *
prod(2^-(n-1) for n in matched_ns)) before being treated as alarming, at
the SAME threshold (< 0.001) used throughout this research line.

SAFETY: if a match ever clears the significance threshold, the script stops
immediately, does not print/write the winning phrase or derived key, and
records only the source/format/derivation name + matched puzzle numbers.
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
    hex_seed_from_words,
    test_candidate_against_dataset,
)
from coincurve import PrivateKey

DATASET_PATH = "/home/user/Clawd71/data/solved_puzzles.json"
OUT_JSON = "/home/user/Clawd71/research/hypotheses/seed_guessing/brainwallet_cracked_results.json"

SIGNIFICANCE_THRESHOLD = 0.001  # expected spurious count below which a match is "real"

# ---------------------------------------------------------------------------
# Candidate list: real, documented, individually-cracked brainwallet
# passphrases. "source" cites the exact slide/table this was pulled from.
# ---------------------------------------------------------------------------
CANDIDATES = [
    # --- Source A: DEF CON 23 slides (Castellucci) ---
    {"phrase": "", "source": "A slide 7 ('Things you should remember') -- $14K sent to empty-string passphrase, stolen in seconds"},
    {"phrase": "how much wood could a woodchuck chuck if a woodchuck could chuck wood",
     "source": "A slides 24-31 ('WTF!?'/'The Plan'/'What actually happened') -- 250 BTC (~$20K at the time), the 'woodchuck' drain also independently confirmed in Source B Table 2 rank #1-2 (unintentional + owner drain, $22,466 + $15,267)"},
    {"phrase": "Down the Rabbit-Hole", "source": "A slide 43 ('Some results') -- held ~85 BTC, July 2012"},
    {"phrase": "The Quick Brown Fox Jumped Over The Lazy Dot", "source": "A slide 43 ('Some results') -- held ~85 BTC, December 2011 (note: 'Dot' not 'Dog' as literally shown on the slide)"},
    {"phrase": "gate gate paragate parasamgate bodhi svaha", "source": "A slide 44 ('Some more results')"},
    {"phrase": "The Persistence Of Memory", "source": "A slide 44 ('Some more results')"},
    {"phrase": "QTC", "source": "A slide 44 ('Some more results')"},
    {"phrase": "644122178", "source": "A slide 44 ('Some more results')"},
    {"phrase": "8964009", "source": "A slide 44 ('Some more results')"},
    {"phrase": "que me lleve la muerte", "source": "A slide 44 ('Some more results')"},
    {"phrase": "one two three four five six seven",
     "source": "A slide 44 ('Some more results'); independently confirmed in Source B section 3 as the FIRST brain wallet observed, September 2011, pre-dating compressed-key support"},
    {"phrase": "it's a secret to everybody", "source": "A slide 44 ('Some more results')"},
    {"phrase": "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn", "source": "A slide 44 ('Some more results')"},
    {"phrase": "my hovercraft is full of eels", "source": "A slide 45 ('A few more results (for the lulz)')"},
    {"phrase": "Interior Crocodile Alligator", "source": "A slide 45 ('A few more results (for the lulz)')"},
    {"phrase": "No need to worry, my accountant handles that", "source": "A slide 45 ('A few more results (for the lulz)')"},
    {"phrase": "tomb-of-the-unknown-soldier-identification-badge", "source": "A slide 45 ('A few more results (for the lulz)')"},
    {"phrase": "permit me to issue and control the money of a nation and i care not who makes its laws", "source": "A slide 45 ('A few more results (for the lulz)')"},
    {"phrase": "who is john galt", "source": "A slide 45 ('A few more results (for the lulz)')"},
    {"phrase": "Live as if you were to die tomorrow. Learn as if you were to live forever.", "source": "A slide 45 ('A few more results (for the lulz)')"},
    # --- Source B: FC'16 paper Table 2 (top-10 drains by USD) ---
    {"phrase": "bitcoin is awesome", "source": "B Table 2 rank #6 -- $5,800 / 500.00 BTC, 1 drain, labelled 'bitcoin is awesome' drain"},
    {"phrase": "deadsheep", "source": "B Table 2 rank #9 -- $1,429 / 14.29 BTC, 1 drain, labelled 'deadsheep' drain"},
    {"phrase": "thequickbrownfoxjumpedoverthelazydog", "source": "B Table 2 rank #10 -- $1,322 / 97.66 BTC, 59 drains (all-lowercase, no-space variant -- distinct string from the spaced/capitalized 'Lazy Dot' entry above)"},
    # --- Lower-confidence bonus (flagged, not individually confirmed) ---
    {"phrase": "correct horse battery staple",
     "source": "LOWER CONFIDENCE / included for completeness only: this is Castellucci's own canonical xkcd-derived running-demo phrase (A slides 8-13), not stated by him to be an individually confirmed find. Included because Source B Table 1 documents the broader 'xkcd' word-list category (90 wallets, $29,140, and 'passwords derived from xkcd are drained repeatedly the most') as a real cracked category even though this exact string's crack status isn't separately confirmed."},
]

print(f"Candidate phrase list: {len(CANDIDATES)} phrases "
      f"({sum(1 for c in CANDIDATES if 'LOWER CONFIDENCE' not in c['source'])} confirmed-cracked + "
      f"{sum(1 for c in CANDIDATES if 'LOWER CONFIDENCE' in c['source'])} flagged lower-confidence)")

dataset_full = json.load(open(DATASET_PATH))
assert len(dataset_full) == 82, f"expected 82 puzzles, got {len(dataset_full)}"

# n=1 is structurally degenerate (0 free bits): masked==1 unconditionally for
# ANY raw input, and the real dataset's puzzle #1 key IS 1 -- confirmed
# directly, not assumed, matching the convention set in common_passwords.py
# and the module's own positive-control tests.
for raw_probe in (0, 1, 12345, 2**200, 999999999999):
    assert apply_puzzle_mask(raw_probe, 1) == 1
dataset = [e for e in dataset_full if e["n"] >= 2]
assert len(dataset) == 81
print(f"n=1 confirmed structurally degenerate; excluded. {len(dataset)} puzzles (n=2..130) used for matching.")


def expected_spurious_count(matched_ns, total_candidates):
    p = 1.0
    for n in matched_ns:
        p *= 2.0 ** -(n - 1)
    return total_candidates * p


def handle_matches(matches, total_candidates_this_category, chance_tally, tag_info):
    """Returns True if this match set is SIGNIFICANT (real safety-stop trigger)."""
    if not matches:
        return False
    exp = expected_spurious_count(matches, total_candidates_this_category)
    if exp < SIGNIFICANCE_THRESHOLD:
        return True
    key = tuple(matches)
    chance_tally[key] = chance_tally.get(key, 0) + 1
    return False


# -----------------------------------------------------------------------
# PART 1: Classic Type-1, all candidate phrases x all 8 formats
# -----------------------------------------------------------------------
CLASSIC_TOTAL = len(CANDIDATES) * len(FORMATS)
t0 = time.time()
classic_tested = 0
classic_match = None
classic_chance_tally = {}
classic_log = []
for cand in CANDIDATES:
    pw = cand["phrase"]
    for fmt in FORMATS:
        fn = lambda n, m=pw, f=fmt: classic_type1_candidate(m, n, f)
        matches = test_candidate_against_dataset(fn, dataset)
        classic_tested += 1
        classic_log.append({"phrase_index": CANDIDATES.index(cand), "format": fmt, "matches": matches})
        if matches and handle_matches(matches, CLASSIC_TOTAL, classic_chance_tally, cand):
            classic_match = (cand, fmt, matches)
            break
    if classic_match:
        break
t1 = time.time()

if classic_match:
    cand, fmt, matches = classic_match
    exp = expected_spurious_count(matches, CLASSIC_TOTAL)
    print("!!! SIGNIFICANT MATCH FOUND (classic Type-1) !!!")
    print(f"source={cand['source']!r}  format={fmt!r}  matched puzzle numbers={matches}  "
          f"expected-by-chance={exp:.2e} (over {CLASSIC_TOTAL} candidates)")
    print("Winning passphrase is withheld from output per safety rule; "
          "available in this process's local state only.")
    with open(OUT_JSON, "w") as f:
        json.dump({
            "STOP": True,
            "category": "classic_type1",
            "candidate_source": cand["source"],
            "format": fmt,
            "matched_puzzle_numbers": matches,
            "expected_spurious_count": exp,
            "candidates_tested_before_match": classic_tested,
        }, f, indent=2)
    sys.exit(0)

chance_summary_classic = {str(k): v for k, v in sorted(classic_chance_tally.items(), key=lambda kv: -kv[1])}
print(f"PART 1 (classic Type-1): {classic_tested} candidates tested "
      f"({len(CANDIDATES)} phrases x {len(FORMATS)} formats), "
      f"0 SIGNIFICANT matches, {t1 - t0:.2f}s")
print(f"  chance-level coincidences observed (sub-threshold, expected noise): "
      f"{sum(classic_chance_tally.values())} total; patterns: {dict(chance_summary_classic)}")

# -----------------------------------------------------------------------
# PART 2: Electrum Type-1, ALL candidate phrases x 3 cheap hex-seed
# derivations, run through the REAL 100k-round stretch (unavoidable).
# -----------------------------------------------------------------------
ELECTRUM_TOTAL = len(CANDIDATES) * 3


def derive_hex_seeds(phrase: str):
    b = phrase.encode("utf-8")
    sha_seed = hashlib.sha256(b).digest()[:16].hex()
    md5_seed = hashlib.md5(b).hexdigest()
    raw = b[:16] if len(b) >= 16 else b + b"\x00" * (16 - len(b))
    raw_seed = raw.hex()
    return {"sha256_16": sha_seed, "md5": md5_seed, "raw_utf8_16": raw_seed}


t2 = time.time()
electrum_tested = 0
electrum_match = None
electrum_chance_tally = {}
electrum_candidates_log = []

for cand in CANDIDATES:
    pw = cand["phrase"]
    seeds = derive_hex_seeds(pw)
    for deriv_name, hex_seed in seeds.items():
        secexp = electrum_stretch_key(hex_seed)
        priv = PrivateKey(secexp.to_bytes(32, "big"))
        mpk_hex = priv.public_key.format(compressed=False)[1:].hex()

        fn = lambda n, se=secexp, mp=mpk_hex: electrum_child_privkey(hex_seed, n, secexp=se, mpk_hex=mp)
        matches = test_candidate_against_dataset(fn, dataset)
        electrum_tested += 1
        electrum_candidates_log.append({"phrase_index": CANDIDATES.index(cand), "derivation": deriv_name, "hex_seed": hex_seed, "matches": matches})
        if matches and handle_matches(matches, ELECTRUM_TOTAL, electrum_chance_tally, cand):
            electrum_match = (cand, deriv_name, hex_seed, matches)
            break
    if electrum_match:
        break
t3 = time.time()

if electrum_match:
    cand, deriv_name, hex_seed, matches = electrum_match
    exp = expected_spurious_count(matches, ELECTRUM_TOTAL)
    print("!!! SIGNIFICANT MATCH FOUND (Electrum Type-1, cheap hex-seed derivation) !!!")
    print(f"source={cand['source']!r}  derivation={deriv_name!r}  matched puzzle numbers={matches}  "
          f"expected-by-chance={exp:.2e} (over {ELECTRUM_TOTAL} candidates)")
    print("Winning passphrase/hex-seed is withheld from output per safety rule; "
          "available in this process's local state only.")
    with open(OUT_JSON, "w") as f:
        json.dump({
            "STOP": True,
            "category": "electrum_type1_cheap_derivation",
            "candidate_source": cand["source"],
            "derivation": deriv_name,
            "matched_puzzle_numbers": matches,
            "expected_spurious_count": exp,
            "candidates_tested_before_match": electrum_tested,
        }, f, indent=2)
    sys.exit(0)

chance_summary_electrum = {str(k): v for k, v in sorted(electrum_chance_tally.items(), key=lambda kv: -kv[1])}
print(f"PART 2 (Electrum Type-1, cheap derivations): {electrum_tested} candidates "
      f"tested ({len(CANDIDATES)} phrases x 3 derivations, REAL 100k-round stretch each), "
      f"0 SIGNIFICANT matches, {t3 - t2:.2f}s")
print(f"  chance-level coincidences observed (sub-threshold, expected noise): "
      f"{sum(electrum_chance_tally.values())} total; patterns: {dict(chance_summary_electrum)}")

# -----------------------------------------------------------------------
# PART 3 (bonus, free): attempt each phrase as a literal Electrum
# old-mnemonic word sequence (requires exactly 12 words, all drawn from
# Electrum's specific 1626-word list). Expected to reject everything here.
# -----------------------------------------------------------------------
t4 = time.time()
mnemonic_attempts = []
mnemonic_match = None
for cand in CANDIDATES:
    words = cand["phrase"].split()
    hex_seed = hex_seed_from_words(words) if len(words) == 12 else None
    mnemonic_attempts.append({"phrase_index": CANDIDATES.index(cand), "word_count": len(words), "parsed": hex_seed is not None})
    if hex_seed is not None:
        fn = lambda n, hs=hex_seed: electrum_child_privkey(hs, n)
        matches = test_candidate_against_dataset(fn, dataset)
        if matches:
            exp = expected_spurious_count(matches, len(CANDIDATES))
            if exp < SIGNIFICANCE_THRESHOLD:
                mnemonic_match = (cand, matches)
                break
t5 = time.time()

if mnemonic_match:
    cand, matches = mnemonic_match
    print("!!! SIGNIFICANT MATCH FOUND (Electrum literal mnemonic-word path) !!!")
    print(f"source={cand['source']!r}  matched puzzle numbers={matches}")
    print("Winning phrase withheld from output per safety rule.")
    with open(OUT_JSON, "w") as f:
        json.dump({"STOP": True, "category": "electrum_literal_mnemonic",
                    "candidate_source": cand["source"], "matched_puzzle_numbers": matches}, f, indent=2)
    sys.exit(0)

parseable = sum(1 for a in mnemonic_attempts if a["parsed"])
print(f"PART 3 (bonus, literal Electrum mnemonic-word path): {len(mnemonic_attempts)} phrases checked "
      f"for 12-word Electrum-wordlist parse, {parseable} parsed successfully (expected: 0 or near-0), {t5 - t4:.2f}s")

# -----------------------------------------------------------------------
# Write full result summary (no significant matches) + full candidate log
# -----------------------------------------------------------------------
summary = {
    "sources": {
        "A": "Ryan Castellucci, 'Cracking Cryptocurrency Brainwallets', DEF CON 23, Aug 2015. "
             "https://rya.nc/files/cracking_cryptocurrency_brainwallets.pdf "
             "(saved: research/hypotheses/seed_guessing/defcon23_castellucci.pdf, fetched 2026-08-19, HTTP 200)",
        "B": "Vasek, Bonneau, Castellucci, Keith, Moore, 'The Bitcoin Brain Drain: Examining the Use and "
             "Abuse of Bitcoin Brain Wallets', Financial Cryptography 2016. "
             "https://jbonneau.com/doc/VBCKM16-FC-bitcoin_brain_wallets.pdf "
             "(saved: research/hypotheses/seed_guessing/bitcoin_brain_drain_paper.pdf, fetched 2026-08-19, HTTP 200)",
    },
    "candidates": CANDIDATES,
    "significance_threshold_expected_spurious_count": SIGNIFICANCE_THRESHOLD,
    "classic_type1": {
        "phrases_tested": len(CANDIDATES),
        "formats_tested": list(FORMATS.keys()),
        "total_candidates": classic_tested,
        "significant_matches": [],
        "chance_level_coincidences_total": sum(classic_chance_tally.values()),
        "chance_level_coincidences_by_pattern": chance_summary_classic,
        "elapsed_sec": round(t1 - t0, 2),
        "full_log": classic_log,
    },
    "electrum_type1_cheap": {
        "phrases_tested": len(CANDIDATES),
        "derivations": ["sha256_16", "md5", "raw_utf8_16"],
        "total_candidates": electrum_tested,
        "significant_matches": [],
        "chance_level_coincidences_total": sum(electrum_chance_tally.values()),
        "chance_level_coincidences_by_pattern": chance_summary_electrum,
        "elapsed_sec": round(t3 - t2, 2),
        "full_log": electrum_candidates_log,
    },
    "electrum_literal_mnemonic_bonus": {
        "phrases_checked": len(mnemonic_attempts),
        "parsed_as_valid_12word_mnemonic": parseable,
        "significant_matches": [],
        "elapsed_sec": round(t5 - t4, 2),
    },
}
with open(OUT_JSON, "w") as f:
    json.dump(summary, f, indent=2)

print("\nFull summary written to", OUT_JSON)
print(f"\nGRAND TOTAL candidates tested: {classic_tested + electrum_tested + len(mnemonic_attempts)}")
print("0 SIGNIFICANT matches across all three parts.")
