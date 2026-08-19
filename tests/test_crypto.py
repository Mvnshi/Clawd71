"""Phase 0 verification suite.

Run with:  PYTHONPATH=src python3 tests/test_crypto.py

Nothing downstream is permitted to run until every check here passes.
"""

from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import crypto as c  # noqa: E402
from fetch_chain import canonical_addresses  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data"

TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
TARGET_HASH160 = "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"
TARGET_LOW = 0x400000000000000000
TARGET_HIGH = 0x7FFFFFFFFFFFFFFFFF

_passed = 0
_failed: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed
    if cond:
        _passed += 1
    else:
        _failed.append(f"{name}: {detail}")
        print(f"  FAIL  {name}  {detail}")


def section(title: str) -> None:
    print(f"\n[{title}]")


# ---------------------------------------------------------------------------
def test_curve_parameters() -> None:
    section("secp256k1 domain parameters")
    check("p is the documented prime", c.P == 2**256 - 2**32 - 977)
    check("p % 4 == 3 (sqrt shortcut valid)", c.P % 4 == 3)
    check(
        "n is the documented order",
        c.N == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    )
    check("a == 0, b == 7", c.A == 0 and c.B == 7)
    check("G on curve", c.is_on_curve(c.G))
    check("n*G == infinity", c.scalar_mult(c.N, c.G) is None)
    check("(n-1)*G == -G", c.scalar_mult(c.N - 1, c.G) == c.point_neg(c.G))
    check("(n+1)*G == G", c.scalar_mult(c.N + 1, c.G) == c.G)
    check("cofactor is 1", c.H == 1)


def test_point_arithmetic() -> None:
    section("EC group law")
    rng = random.Random(20260819)
    for _ in range(12):
        a = rng.randrange(1, c.N)
        b = rng.randrange(1, c.N)
        A, B = c.scalar_mult(a), c.scalar_mult(b)
        check("A on curve", c.is_on_curve(A))
        check("commutative add", c.point_add(A, B) == c.point_add(B, A))
        check(
            "additive homomorphism aG+bG == (a+b)G",
            c.point_add(A, B) == c.scalar_mult((a + b) % c.N),
        )
        check("A + (-A) == infinity", c.point_add(A, c.point_neg(A)) is None)
        check("2A == A + A", c.point_double(A) == c.point_add(A, A))
    # associativity
    A, B, C = c.scalar_mult(3), c.scalar_mult(5), c.scalar_mult(7)
    check(
        "associative",
        c.point_add(c.point_add(A, B), C) == c.point_add(A, c.point_add(B, C)),
    )


def test_pubkey_serialization() -> None:
    section("SEC1 public key encoding")
    rng = random.Random(7)
    for _ in range(20):
        k = rng.randrange(1, c.N)
        pt = c.scalar_mult(k)
        for comp in (True, False):
            ser = c.serialize_pubkey(pt, comp)
            check(f"len {'33' if comp else '65'}", len(ser) == (33 if comp else 65))
            check("round-trip", c.deserialize_pubkey(ser) == pt)
    check(
        "G compressed encoding",
        c.serialize_pubkey(c.G, True).hex()
        == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )


def test_hashes() -> None:
    section("hash primitives (RFC / published vectors)")
    check(
        "sha256('abc')",
        c.sha256(b"abc").hex()
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    check("ripemd160('')", c.ripemd160(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31")
    check("ripemd160('abc')", c.ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
    check(
        "ripemd160('message digest')",
        c.ripemd160(b"message digest").hex() == "5d0689ef49d2fae572b881b123a85ffa21595f36",
    )


def test_base58() -> None:
    section("Base58Check")
    # Bitcoin Core base58 test vectors
    check("b58encode(00)", c.b58encode(b"\x00") == "1")
    check("b58encode(61)", c.b58encode(b"\x61") == "2g")
    check("b58encode(626262)", c.b58encode(bytes.fromhex("626262")) == "a3gV")
    check("b58encode(516b6fcd0f)", c.b58encode(bytes.fromhex("516b6fcd0f")) == "ABnLTmg")
    rng = random.Random(11)
    for _ in range(50):
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40)))
        check("b58 round-trip", c.b58decode(c.b58encode(raw)) == raw)
        check("b58check round-trip", c.b58check_decode(c.b58check_encode(raw)) == raw)
    try:
        c.b58check_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMX")  # corrupted last char
        check("bad checksum rejected", False, "no exception raised")
    except ValueError:
        check("bad checksum rejected", True)


def test_wif() -> None:
    section("WIF encoding")
    # Well-known vector: privkey 0x01
    check(
        "priv=1 uncompressed WIF",
        c.privkey_to_wif(1, False) == "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
    )
    check(
        "priv=1 compressed WIF",
        c.privkey_to_wif(1, True) == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
    )
    rng = random.Random(3)
    for _ in range(20):
        k = rng.randrange(1, c.N)
        for comp in (True, False):
            back, cb = c.wif_to_privkey(c.privkey_to_wif(k, comp))
            check("WIF round-trip", back == k and cb == comp)


def test_address_vectors() -> None:
    section("address pipeline (published vectors)")
    # privkey 1 -> canonical addresses
    check(
        "priv=1 uncompressed addr",
        c.privkey_to_address(1, False) == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
    )
    check(
        "priv=1 compressed addr",
        c.privkey_to_address(1, True) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
    )
    check(
        "hash160(priv=1 compressed)",
        c.privkey_to_hash160(1, True).hex() == "751e76e8199196d454941c45d1b3a323f1433bd6",
    )
    check(
        "address <-> hash160 round-trip",
        c.hash160_to_address(c.address_to_hash160(TARGET_ADDRESS)) == TARGET_ADDRESS,
    )


def test_cross_implementation() -> None:
    section("cross-check vs libsecp256k1 (coincurve)")
    try:
        from coincurve import PublicKey
    except ImportError:
        check("coincurve available", False, "not installed")
        return
    rng = random.Random(1234)
    n = 300
    for _ in range(n):
        k = rng.randrange(1, c.N)
        mine = c.scalar_mult(k)
        theirs = PublicKey.from_valid_secret(k.to_bytes(32, "big"))
        ok = (
            c.serialize_pubkey(mine, True) == theirs.format(True)
            and c.serialize_pubkey(mine, False) == theirs.format(False)
        )
        check("pubkey agrees", ok, f"k={k:x}")
    # edge scalars
    for k in (1, 2, 3, c.N - 1, c.N - 2, 2**70, 2**71 - 1, TARGET_LOW, TARGET_HIGH):
        mine = c.scalar_mult(k)
        theirs = PublicKey.from_valid_secret(k.to_bytes(32, "big"))
        check(f"edge k={hex(k)}", c.serialize_pubkey(mine, True) == theirs.format(True))
    print(f"  ({n} random + 9 edge scalars compared)")


def test_puzzle_ranges() -> None:
    section("puzzle interval algebra")
    check("range(1)", c.puzzle_range(1) == (1, 1))
    check("range(2)", c.puzzle_range(2) == (2, 3))
    check("range(71)", c.puzzle_range(71) == (TARGET_LOW, TARGET_HIGH))
    check("range(71) low  == 2^70", TARGET_LOW == 2**70)
    check("range(71) high == 2^71-1", TARGET_HIGH == 2**71 - 1)
    check("interval size == 2^70", TARGET_HIGH - TARGET_LOW + 1 == 2**70)
    for n in range(1, 161):
        lo, hi = c.puzzle_range(n)
        check(f"range({n}) width", hi - lo + 1 == 2 ** (n - 1))
        check(f"range({n}) bit length", lo.bit_length() == n and hi.bit_length() == n)


def test_target_facts() -> None:
    section("Puzzle #71 target facts (independently derived)")
    addrs = canonical_addresses()
    check("genesis output 70 == target address", addrs[71] == TARGET_ADDRESS)
    check(
        "target hash160 matches address",
        c.address_to_hash160(TARGET_ADDRESS).hex() == TARGET_HASH160,
    )
    status = {s["puzzle"]: s for s in json.loads((DATA / "chain_status.json").read_text())}
    check("target unspent (no pubkey exposed)", status[71]["total_sent"] == 0)
    check("target still funded", status[71]["final_balance"] > 0)
    exposed = {p["puzzle"] for p in json.loads((DATA / "exposed_pubkeys.json").read_text())}
    check("71 not in the 2019 pubkey-exposure set", 71 not in exposed)


def test_reproduce_solved_puzzles() -> None:
    section("reproduce every verified solved puzzle end-to-end")
    records = json.loads((DATA / "solved_puzzles.json").read_text())
    addrs = canonical_addresses()
    check("dataset non-empty", len(records) > 0)
    for r in records:
        n = r["puzzle"]
        k = int(r["privkey_dec"])
        lo, hi = c.puzzle_range(n)
        check(f"#{n} key in interval", lo <= k <= hi)
        check(f"#{n} addr reproduces", c.privkey_to_address(k, True) == addrs[n])
        check(f"#{n} addr matches record", c.privkey_to_address(k, True) == r["address"])
        check(f"#{n} hash160 matches", c.privkey_to_hash160(k, True).hex() == r["hash160"])
        check(f"#{n} WIF round-trips", c.wif_to_privkey(r["wif_compressed"])[0] == k)
        check(f"#{n} offset consistent", int(r["offset_dec"]) == k - lo)
    exposed = {p["puzzle"]: p["pubkey"] for p in json.loads((DATA / "exposed_pubkeys.json").read_text())}
    for r in records:
        if r["puzzle"] in exposed:
            check(
                f"#{r['puzzle']} pubkey == on-chain exposed pubkey",
                r["pubkey_compressed"] == exposed[r["puzzle"]],
            )
    print(f"  ({len(records)} solved puzzles reproduced from private key)")


def test_negative_controls() -> None:
    section("negative controls (pipeline must reject wrong input)")
    addrs = canonical_addresses()
    # off-by-one keys must NOT produce the right address
    for n, k in ((5, 21), (30, 1033162084), (64, 17799667357578236628)):
        check(f"#{n} key+1 fails", c.privkey_to_address(k + 1, True) != addrs[n])
        check(f"#{n} key-1 fails", c.privkey_to_address(k - 1, True) != addrs[n])
        check(f"#{n} uncompressed fails", c.privkey_to_address(k, False) != addrs[n])
    try:
        c.privkey_to_pubkey(0)
        check("privkey 0 rejected", False, "no exception")
    except ValueError:
        check("privkey 0 rejected", True)
    try:
        c.privkey_to_pubkey(c.N)
        check("privkey n rejected", False, "no exception")
    except ValueError:
        check("privkey n rejected", True)


def main() -> int:
    test_curve_parameters()
    test_point_arithmetic()
    test_pubkey_serialization()
    test_hashes()
    test_base58()
    test_wif()
    test_address_vectors()
    test_cross_implementation()
    test_puzzle_ranges()
    test_target_facts()
    test_reproduce_solved_puzzles()
    test_negative_controls()

    print("\n" + "=" * 60)
    print(f"PASSED: {_passed}   FAILED: {len(_failed)}")
    if _failed:
        print("\nFailures:")
        for f in _failed[:40]:
            print("  -", f)
        return 1
    print("Phase 0 verification COMPLETE - downstream research is cleared to run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
