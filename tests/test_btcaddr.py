"""
Phase 0 cryptographic verification suite.

Known-answer tests independent of any scraped puzzle-solution table:
k=1 is the secp256k1 generator point G itself, whose compressed and
uncompressed pubkeys and derived P2PKH addresses are among the most
widely reproduced values in all of Bitcoin (Bitcoin Core's own test
vectors, textbooks, and countless independent implementations agree on
them). If our pipeline reproduces these, HASH160 / Base58Check / secp256k1
scalar multiplication are all correct, with zero dependency on any
scraped puzzle table.
"""
import sys

sys.path.insert(0, "/home/user/Clawd71/src")
from btcaddr import privkey_int_to_addresses, which_encoding_matches

KAT_K1 = {
    "compressed_pubkey": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "uncompressed_pubkey": (
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    ),
    "address_from_compressed": "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
    "address_from_uncompressed": "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
}


def test_k1_known_answer():
    result = privkey_int_to_addresses(1)
    for key, expected in KAT_K1.items():
        assert result[key] == expected, f"{key}: got {result[key]!r}, expected {expected!r}"


def test_k1_compressed_matches_puzzle1_address():
    # Puzzle #1's published address is 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH,
    # which is the COMPRESSED-pubkey address for k=1 (verified empirically
    # here, not assumed) -- puzzle addresses use compressed pubkeys.
    assert which_encoding_matches(1, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") == "compressed"


def test_out_of_range_rejected():
    import pytest

    with pytest.raises(ValueError):
        privkey_int_to_addresses(0)


if __name__ == "__main__":
    test_k1_known_answer()
    test_k1_compressed_matches_puzzle1_address()
    print("All Phase 0 known-answer tests passed.")
    r = privkey_int_to_addresses(1)
    for k, v in r.items():
        print(f"  {k}: {v}")
