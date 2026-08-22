"""
Seed-guessing dictionary attack, CATEGORY: famous cryptography / Bitcoin-culture
phrases and quotes -- a plausible 2013-2015-era Bitcoin enthusiast's pick for a
memorable deterministic-wallet seed/passphrase.

Candidate sources (all independently well-known, not invented for this run):
  - Genesis block coinbase text (verified against the real block 0 coinbase
    scriptSig, widely published: "The Times 03/Jan/2009 Chancellor on brink
    of second bailout for banks").
  - Bitcoin whitepaper title, author byline/email, and abstract opening line.
  - Eric Hughes' "A Cypherpunk's Manifesto" (1993) and Timothy May's "The
    Crypto Anarchist Manifesto" (1988) -- well-known foundational texts of
    the culture that produced Bitcoin.
  - Satoshi Nakamoto's own documented forum/mailing-list quotes (bitcointalk.org
    and the Cryptography mailing list, 2008-2011; all pre-2015).
  - Foundational precursor concepts every early Bitcoiner would recognize:
    b-money (Wei Dai), bit gold (Nick Szabo), Hashcash (Adam Back).
  - Era-appropriate crypto/Bitcoin-community slogans and in-jokes, each
    explicitly tagged with an era-plausibility flag -- HODL (Dec 2013,
    genuinely contemporary to the puzzle's Jan 2015 creation) is tagged
    "contemporary"; "not your keys, not your coins" and "to the moon" as a
    meme postdate 2015 (popularized ~2017+) and are tagged
    "likely_postdates_2015" per the task's instruction to flag and
    deprioritize those, not exclude them outright.
  - XKCD 936 "correct horse battery staple" (2011) -- extremely well-known
    in security/crypto circles specifically, a very plausible "memorable
    passphrase" pick for a crypto-literate person of this era.
  - Bitcoin pizza day (May 2010), the 21,000,000 supply cap, "genesis block".

No phrase here was invented as a guess at what the creator "might" have
picked beyond documented cultural fame -- every entry is a real, citable
phrase/term from Bitcoin or cypherpunk history.

Methodology matches this research thread's established pattern
(research/hypotheses/seed_guessing/common_passwords.py):
  1. Classic Type-1: every candidate phrase x all 8 FORMATS entries
     (cheap, pure SHA256) against the full 82-puzzle dataset.
  2. Electrum Type-1: a curated "best/most plausible" subset (short,
     era-appropriate, high cultural salience -- the kind of thing an actual
     person would type as a seed, not an entire paragraph) x 3 cheap
     16-byte hex-seed derivations (SHA256[:16], MD5, raw UTF-8
     padded/truncated), each run through the REAL 100,000-round
     electrum_stretch_key. Per the task brief: spend the expensive path on
     best candidates only, not the entire list.
  3. Word-mnemonic path (hex_seed_from_words) on every phrase, in case any
     candidate happens to tokenize into Electrum's actual 1626-word list.

MULTIPLE-TESTING / DEGENERATE-PUZZLE HANDLING (same pre-registered rule used
throughout this research thread -- read before judging any "match" below):

  apply_puzzle_mask(raw, n) keeps only the low (n-1) bits of raw and forces
  bit (n-1) high, so puzzle n has exactly (n-1) "free" bits and an arbitrary
  candidate matches it by pure chance with probability 2^-(n-1). n=1 is
  degenerate (masked is unconditionally 1 for ANY raw input, confirmed by
  direct computation below) and is excluded from the matching dataset
  entirely -- not evidence of anything, just 0 free bits.

  Every non-empty match is passed through a pre-registered Bonferroni-style
  filter BEFORE being treated as alarming:

      expected_spurious_count(matched_ns) =
          total_candidates_this_run * prod(2^-(n-1) for n in matched_ns)

  Only expected_spurious_count < 0.001 escalates to the CRITICAL SAFETY STOP
  protocol (matching the task's own framing: a real hit means "matching a
  specific 20+-bit number by chance" or "a match across two or more puzzles
  simultaneously"). Sub-threshold matches are logged as chance noise and the
  run continues -- halting on every expected small-n coincidence would make
  it impossible to ever finish a real sweep.

SAFETY: if a match ever clears the significance threshold, the script stops
immediately, does not print/write the winning seed/passphrase/derived key,
and records only the format/derivation + matched puzzle numbers.
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
OUT_JSON = "/home/user/Clawd71/research/hypotheses/seed_guessing/crypto_culture_quotes_results.json"

SIGNIFICANCE_THRESHOLD = 0.001  # expected spurious count below which a match is "real"

dataset_full = json.load(open(DATASET_PATH))
assert len(dataset_full) == 82, f"expected 82 puzzles, got {len(dataset_full)}"

# n=1 structural degeneracy, confirmed directly (not assumed):
for raw_probe in (0, 1, 12345, 2**200, 999999999999):
    assert apply_puzzle_mask(raw_probe, 1) == 1
dataset = [e for e in dataset_full if e["n"] >= 2]
assert len(dataset) == 81
print(f"n=1 confirmed structurally degenerate (masked==1 unconditionally); excluded. "
      f"{len(dataset)} puzzles (n=2..130) used for matching.")

# ---------------------------------------------------------------------------
# Candidate list: (phrase, category, era_flag)
#   era_flag: "contemporary" (documented pre- or circa-2015), or
#             "likely_postdates_2015" (culturally later; flagged/deprioritized
#             per task instruction, still tested since a script could in
#             principle have been extended/reused, but excluded from the
#             curated Electrum "best candidates" subset).
# ---------------------------------------------------------------------------
CANDIDATES = [
    # --- Genesis block coinbase text (block 0, verified) ---
    ("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks", "genesis_coinbase", "contemporary"),
    ("Chancellor on brink of second bailout for banks", "genesis_coinbase", "contemporary"),
    ("The Times 03/Jan/2009", "genesis_coinbase", "contemporary"),
    ("03/Jan/2009 Chancellor on brink of second bailout for banks", "genesis_coinbase", "contemporary"),

    # --- Whitepaper title / byline / abstract opening ---
    ("Bitcoin: A Peer-to-Peer Electronic Cash System", "whitepaper", "contemporary"),
    ("A Peer-to-Peer Electronic Cash System", "whitepaper", "contemporary"),
    ("Bitcoin A Peer to Peer Electronic Cash System", "whitepaper", "contemporary"),
    ("A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution.",
     "whitepaper", "contemporary"),
    ("satoshin@gmx.com", "whitepaper", "contemporary"),
    ("www.bitcoin.org", "whitepaper", "contemporary"),

    # --- Satoshi Nakamoto name / identity ---
    ("Satoshi Nakamoto", "satoshi_identity", "contemporary"),
    ("satoshi nakamoto", "satoshi_identity", "contemporary"),
    ("Nakamoto", "satoshi_identity", "contemporary"),
    ("I am not Dorian Nakamoto", "satoshi_identity", "likely_postdates_2015"),  # Newsweek doxx was Mar 2014, but "I am..." denial framing is retrospective meme phrasing

    # --- Satoshi's own documented quotes (forum/mailing-list, 2008-2011) ---
    ("I've been working on a new electronic cash system that's fully peer-to-peer, with no trusted third party.",
     "satoshi_quote", "contemporary"),
    ("The root problem with conventional currency is all the trust that's required to make it work.",
     "satoshi_quote", "contemporary"),
    ("Lost coins only make everyone else's coins worth slightly more. Think of it as a donation to everyone.",
     "satoshi_quote", "contemporary"),
    ("If you don't believe me or don't get it, I don't have time to try to convince you, sorry.",
     "satoshi_quote", "contemporary"),
    ("It might make sense just to get some in case it catches on.", "satoshi_quote", "contemporary"),
    ("I've developed a new open source P2P e-cash system called Bitcoin", "satoshi_quote", "contemporary"),
    ("Announcing the first release of Bitcoin", "satoshi_quote", "contemporary"),
    ("Bitcoin v0.1 released", "satoshi_quote", "contemporary"),
    ("Running bitcoin", "satoshi_quote", "contemporary"),  # Hal Finney's first Bitcoin tweet, 11 Jan 2009

    # --- Cypherpunk manifesto (Eric Hughes, 1993) ---
    ("Privacy is necessary for an open society in the electronic age", "cypherpunk_manifesto", "contemporary"),
    ("Cypherpunks write code", "cypherpunk_manifesto", "contemporary"),
    ("cypherpunks write code", "cypherpunk_manifesto", "contemporary"),
    ("We the Cypherpunks are dedicated to building anonymous systems", "cypherpunk_manifesto", "contemporary"),
    ("Cypherpunks deplore regulations on cryptography", "cypherpunk_manifesto", "contemporary"),

    # --- Crypto Anarchist Manifesto (Timothy May, 1988) ---
    ("Arise, you have nothing to lose but your barbed wire fences", "crypto_anarchist_manifesto", "contemporary"),
    ("A specter is haunting the modern world, the specter of crypto anarchy", "crypto_anarchist_manifesto", "contemporary"),
    ("The Crypto Anarchist Manifesto", "crypto_anarchist_manifesto", "contemporary"),

    # --- Zimmermann / PGP ---
    ("If privacy is outlawed, only outlaws will have privacy", "pgp_zimmermann", "contemporary"),
    ("Pretty Good Privacy", "pgp_zimmermann", "contemporary"),

    # --- Precursor concepts every early Bitcoiner would know ---
    ("b-money", "precursor_concept", "contemporary"),
    ("bit gold", "precursor_concept", "contemporary"),
    ("hashcash", "precursor_concept", "contemporary"),
    ("Hashcash", "precursor_concept", "contemporary"),
    ("Wei Dai", "precursor_concept", "contemporary"),
    ("Nick Szabo", "precursor_concept", "contemporary"),
    ("Adam Back", "precursor_concept", "contemporary"),
    ("proof of work", "precursor_concept", "contemporary"),
    ("proof-of-work", "precursor_concept", "contemporary"),
    ("double-spending problem", "precursor_concept", "contemporary"),
    ("the double-spending problem", "precursor_concept", "contemporary"),

    # --- Bitcoin-community slogans / in-jokes ---
    ("HODL", "community_slogan", "contemporary"),          # GameKyuubi "I AM HODLING", Dec 2013
    ("hodl", "community_slogan", "contemporary"),
    ("I AM HODLING", "community_slogan", "contemporary"),
    ("vires in numeris", "community_slogan", "contemporary"),   # Casascius / Trezor motto, "strength in numbers"
    ("Vires in Numeris", "community_slogan", "contemporary"),
    ("in math we trust", "community_slogan", "contemporary"),   # popularized by Forbes 2013 cover
    ("Bitcoin: In Math We Trust", "community_slogan", "contemporary"),
    ("be your own bank", "community_slogan", "contemporary"),
    ("Be your own bank", "community_slogan", "contemporary"),
    ("digital gold", "community_slogan", "contemporary"),
    ("trustless", "community_slogan", "contemporary"),
    ("21 million", "community_slogan", "contemporary"),
    ("21000000", "community_slogan", "contemporary"),
    ("genesis block", "community_slogan", "contemporary"),
    ("the genesis block", "community_slogan", "contemporary"),
    ("to the moon", "community_slogan", "likely_postdates_2015"),
    ("not your keys not your coins", "community_slogan", "likely_postdates_2015"),
    ("not your keys, not your coins", "community_slogan", "likely_postdates_2015"),
    ("not your keys, not your bitcoin", "community_slogan", "likely_postdates_2015"),

    # --- Bitcoin pizza day (May 2010) ---
    ("10000 bitcoins for a pizza", "pizza_day", "contemporary"),
    ("10000 BTC for two pizzas", "pizza_day", "contemporary"),
    ("Laszlo Hanyecz", "pizza_day", "contemporary"),
    ("bitcoin pizza day", "pizza_day", "contemporary"),

    # --- Generic well-known cryptography-culture phrases ---
    ("correct horse battery staple", "generic_crypto_culture", "contemporary"),  # XKCD 936, 2011
    ("Correct Horse Battery Staple", "generic_crypto_culture", "contemporary"),
    ("Alice and Bob", "generic_crypto_culture", "contemporary"),
    ("alice and bob", "generic_crypto_culture", "contemporary"),
    ("the quick brown fox jumps over the lazy dog", "generic_crypto_culture", "contemporary"),
]

assert len({p for p, _, _ in CANDIDATES}) == len(CANDIDATES), "duplicate phrase in CANDIDATES"
print(f"{len(CANDIDATES)} candidate phrases compiled "
      f"({sum(1 for _, _, e in CANDIDATES if e == 'contemporary')} contemporary, "
      f"{sum(1 for _, _, e in CANDIDATES if e == 'likely_postdates_2015')} likely_postdates_2015).")


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
    key = tuple(matches)
    chance_tally[key] = chance_tally.get(key, 0) + 1
    return False


# -----------------------------------------------------------------------
# PART 1: Classic Type-1, every candidate phrase x all 8 FORMATS
# -----------------------------------------------------------------------
CLASSIC_TOTAL = len(CANDIDATES) * len(FORMATS)
t0 = time.time()
classic_tested = 0
classic_match = None
classic_chance_tally = {}
for phrase, cat, era in CANDIDATES:
    for fmt in FORMATS:
        fn = lambda n, m=phrase, f=fmt: classic_type1_candidate(m, n, f)
        matches = test_candidate_against_dataset(fn, dataset)
        classic_tested += 1
        if matches and handle_matches(matches, CLASSIC_TOTAL, classic_chance_tally):
            classic_match = (phrase, fmt, matches)
            break
    if classic_match:
        break
t1 = time.time()

if classic_match:
    phrase, fmt, matches = classic_match
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
      f"({len(CANDIDATES)} phrases x {len(FORMATS)} formats), "
      f"0 SIGNIFICANT matches, {t1 - t0:.2f}s")
print(f"  chance-level coincidences observed (sub-threshold, expected noise): "
      f"{sum(classic_chance_tally.values())} total; top patterns: "
      f"{dict(list(chance_summary_classic.items())[:5])}")

# -----------------------------------------------------------------------
# PART 1b: word-mnemonic path -- does any phrase tokenize into Electrum's
# real 1626-word list?
# -----------------------------------------------------------------------
word_mnemonic_hits = []
for phrase, cat, era in CANDIDATES:
    words = phrase.split()
    hexseed = hex_seed_from_words(words)
    if hexseed:  # non-None AND non-empty (mn_decode returns '' for <3 or leftover words)
        word_mnemonic_hits.append((phrase, hexseed))
print(f"PART 1b (word-mnemonic path): {len(CANDIDATES)} phrases tokenized and run through "
      f"Electrum's real old_mnemonic.mn_decode; {len(word_mnemonic_hits)} produced a "
      f"non-empty hex seed.")

word_mnemonic_match = None
word_mnemonic_chance_tally = {}
WORD_MNEMONIC_TOTAL = max(len(word_mnemonic_hits), 1)
if word_mnemonic_hits:
    for phrase, hexseed in word_mnemonic_hits:
        fn = lambda n, hs=hexseed: electrum_child_privkey(hs, n)
        matches = test_candidate_against_dataset(fn, dataset)
        if matches and handle_matches(matches, WORD_MNEMONIC_TOTAL, word_mnemonic_chance_tally):
            word_mnemonic_match = (phrase, hexseed, matches)
            break

if word_mnemonic_match:
    phrase, hexseed, matches = word_mnemonic_match
    exp = expected_spurious_count(matches, WORD_MNEMONIC_TOTAL)
    print("!!! SIGNIFICANT MATCH FOUND (Electrum word-mnemonic path) !!!")
    print(f"matched puzzle numbers={matches}  expected-by-chance={exp:.2e}")
    print("Winning passphrase/hex-seed is withheld from output per safety rule.")
    with open(OUT_JSON, "w") as f:
        json.dump({
            "STOP": True,
            "category": "electrum_word_mnemonic",
            "matched_puzzle_numbers": matches,
            "expected_spurious_count": exp,
        }, f, indent=2)
    sys.exit(0)

# -----------------------------------------------------------------------
# PART 2: Electrum Type-1, curated "best candidates" subset x 3 cheap
# hex-seed derivations, run through the REAL 100k-round stretch.
# -----------------------------------------------------------------------
BEST_CANDIDATES = [
    "Satoshi Nakamoto", "satoshi nakamoto", "Nakamoto",
    "Cypherpunks write code", "cypherpunks write code",
    "vires in numeris", "Vires in Numeris",
    "HODL", "hodl", "I AM HODLING",
    "genesis block", "the genesis block",
    "correct horse battery staple", "Correct Horse Battery Staple",
    "in math we trust", "Bitcoin: In Math We Trust",
    "be your own bank", "Be your own bank",
    "double-spending problem", "proof of work", "proof-of-work",
    "21 million", "21000000",
    "b-money", "bit gold", "hashcash", "Hashcash",
    "Running bitcoin",
    "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
    "Chancellor on brink of second bailout for banks",
    "Bitcoin: A Peer-to-Peer Electronic Cash System",
    "A Peer-to-Peer Electronic Cash System",
    "www.bitcoin.org", "satoshin@gmx.com",
    "digital gold", "trustless",
    "Laszlo Hanyecz", "bitcoin pizza day",
    "Alice and Bob",
]
assert set(BEST_CANDIDATES) <= {p for p, _, _ in CANDIDATES}, "BEST_CANDIDATES must be a subset of CANDIDATES"
assert len(set(BEST_CANDIDATES)) == len(BEST_CANDIDATES)

ELECTRUM_TOTAL = len(BEST_CANDIDATES) * 3


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
for phrase in BEST_CANDIDATES:
    seeds = derive_hex_seeds(phrase)
    for deriv_name, hex_seed in seeds.items():
        secexp = electrum_stretch_key(hex_seed)
        priv = PrivateKey(secexp.to_bytes(32, "big"))
        mpk_hex = priv.public_key.format(compressed=False)[1:].hex()

        fn = lambda n, se=secexp, mp=mpk_hex, hs=hex_seed: electrum_child_privkey(
            hs, n, secexp=se, mpk_hex=mp
        )
        matches = test_candidate_against_dataset(fn, dataset)
        electrum_tested += 1
        electrum_candidates_log.append((phrase, deriv_name, hex_seed))
        if matches and handle_matches(matches, ELECTRUM_TOTAL, electrum_chance_tally):
            electrum_match = (phrase, deriv_name, hex_seed, matches)
            break
    if electrum_match:
        break
t3 = time.time()

if electrum_match:
    phrase, deriv_name, hex_seed, matches = electrum_match
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
      f"tested ({len(BEST_CANDIDATES)} phrases x 3 derivations), 0 SIGNIFICANT matches, {t3 - t2:.2f}s")
print(f"  chance-level coincidences observed (sub-threshold, expected noise): "
      f"{sum(electrum_chance_tally.values())} total; top patterns: "
      f"{dict(list(chance_summary_electrum.items())[:5])}")

# -----------------------------------------------------------------------
# Write full result summary (no significant matches) + full candidate list
# -----------------------------------------------------------------------
summary = {
    "candidates_total": len(CANDIDATES),
    "candidates_by_category": {
        cat: sum(1 for _, c, _ in CANDIDATES if c == cat)
        for cat in sorted({c for _, c, _ in CANDIDATES})
    },
    "candidates_by_era": {
        era: sum(1 for _, _, e in CANDIDATES if e == era)
        for era in sorted({e for _, _, e in CANDIDATES})
    },
    "full_candidate_list": [{"phrase": p, "category": c, "era": e} for p, c, e in CANDIDATES],
    "significance_threshold_expected_spurious_count": SIGNIFICANCE_THRESHOLD,
    "classic_type1": {
        "phrases_tested": len(CANDIDATES),
        "formats_tested": list(FORMATS.keys()),
        "total_candidates": classic_tested,
        "significant_matches": [],
        "chance_level_coincidences_total": sum(classic_chance_tally.values()),
        "chance_level_coincidences_by_pattern": chance_summary_classic,
        "elapsed_sec": round(t1 - t0, 2),
    },
    "word_mnemonic_path": {
        "phrases_tested": len(CANDIDATES),
        "non_empty_decodes": len(word_mnemonic_hits),
        "non_empty_decode_phrases": [p for p, _ in word_mnemonic_hits],
        "significant_matches": [],
    },
    "electrum_type1_cheap": {
        "best_candidates_tested": BEST_CANDIDATES,
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
