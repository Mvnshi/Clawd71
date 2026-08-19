"""
Phase 2 (seed-guessing extension): validate the Electrum Type-1 and classic
Type-1 implementations before trusting any negative result from them.

1. Electrum derivation reproduced against a REAL, externally-sourced test
   vector (from spesmilo/electrum's own keystore, not invented here).
2. Positive control: construct a synthetic 20-puzzle dataset FROM a known
   seed via each scheme, then confirm the attack harness actually finds the
   match. If this fails, a negative result against the real puzzle dataset
   would mean nothing (the harness could just be broken, not the hypothesis
   being false) -- this is the same control discipline the merged-in broad
   research line used for its 87 hypotheses.
"""
import sys

sys.path.insert(0, "/home/user/Clawd71/src")
from seed_attack import (
    apply_puzzle_mask,
    classic_type1_candidate,
    electrum_child_privkey,
    electrum_mpk_from_seed,
    hex_seed_from_words,
    test_candidate_against_dataset,
)

KNOWN_ELECTRUM_MNEMONIC = (
    "powerful random nobody notice nothing important anyway "
    "look away hidden message over"
).split()
KNOWN_ELECTRUM_MPK = (
    "e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968d"
    "f9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3"
)


def test_electrum_known_answer_vector():
    hex_seed = hex_seed_from_words(KNOWN_ELECTRUM_MNEMONIC)
    assert hex_seed is not None
    mpk = electrum_mpk_from_seed(hex_seed)
    assert mpk == KNOWN_ELECTRUM_MPK, f"got {mpk}"


def test_electrum_positive_control():
    seed = "acb740e454c3134901d7c8f16497cc1c"  # from the known-answer vector above
    synthetic = []
    for n in range(2, 22):  # bit-lengths 2..21
        raw = electrum_child_privkey(seed, n)
        synthetic.append({"n": n, "key_int": apply_puzzle_mask(raw, n)})

    matches = test_candidate_against_dataset(
        lambda n: electrum_child_privkey(seed, n), synthetic
    )
    assert matches == list(range(2, 22)), f"harness failed to detect its own planted seed: {matches}"

    # and a WRONG seed must not match (sanity: the check isn't vacuously true)
    wrong_matches = test_candidate_against_dataset(
        lambda n: electrum_child_privkey("00000000000000000000000000000000", n), synthetic
    )
    assert wrong_matches == [], f"wrong seed should not match, got {wrong_matches}"


def test_classic_type1_positive_control():
    masterstring = "correct horse battery staple"
    synthetic = []
    for n in range(2, 22):
        raw = classic_type1_candidate(masterstring, n, "colon")
        synthetic.append({"n": n, "key_int": apply_puzzle_mask(raw, n)})

    matches = test_candidate_against_dataset(
        lambda n: classic_type1_candidate(masterstring, n, "colon"), synthetic
    )
    assert matches == list(range(2, 22))

    # a different format on the SAME masterstring must not spuriously match
    wrong_fmt_matches = test_candidate_against_dataset(
        lambda n: classic_type1_candidate(masterstring, n, "dash"), synthetic
    )
    assert wrong_fmt_matches == [], f"wrong format should not match, got {wrong_fmt_matches}"


if __name__ == "__main__":
    test_electrum_known_answer_vector()
    print("PASS: test_electrum_known_answer_vector (matches real spesmilo/electrum test vector)")
    test_electrum_positive_control()
    print("PASS: test_electrum_positive_control (harness detects a planted Electrum-derived seed)")
    test_classic_type1_positive_control()
    print("PASS: test_classic_type1_positive_control (harness detects a planted SHA256(m+n) seed)")
    print("\nAll seed-attack harness controls pass -- cleared to run against the real dataset.")
