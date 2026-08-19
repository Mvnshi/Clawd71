"""
secp256k1 + Bitcoin address primitives, implemented from scratch.

This module is deliberately dependency-free (stdlib only) so that it forms an
*independent* implementation which can be cross-checked against libsecp256k1
(via the `coincurve` package) in the test suite. Nothing in the research
pipeline is trusted until both implementations agree.

Scope: Bitcoin Puzzle research only.
"""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# secp256k1 domain parameters (SEC 2, v2.0, section 2.4.1)
# ---------------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
H = 1  # cofactor

Point = Optional[Tuple[int, int]]  # None == point at infinity
G: Point = (GX, GY)


# ---------------------------------------------------------------------------
# Affine EC arithmetic over F_p
# ---------------------------------------------------------------------------
def is_on_curve(pt: Point) -> bool:
    if pt is None:
        return True
    x, y = pt
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None  # p2 == -p1
        return point_double(p1)
    lam = ((y2 - y1) * pow(x2 - x1, P - 2, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_double(p1: Point) -> Point:
    if p1 is None:
        return None
    x1, y1 = p1
    if y1 == 0:
        return None
    lam = ((3 * x1 * x1 + A) * pow(2 * y1, P - 2, P)) % P
    x3 = (lam * lam - 2 * x1) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_neg(p1: Point) -> Point:
    if p1 is None:
        return None
    x1, y1 = p1
    return (x1, (-y1) % P)


def scalar_mult(k: int, pt: Point = G) -> Point:
    """Double-and-add. Constant-timeness is irrelevant here (public research)."""
    if pt is None:
        return None
    k %= N
    if k == 0:
        return None
    result: Point = None
    addend: Point = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1
    return result


# ---------------------------------------------------------------------------
# Public key serialization (SEC1)
# ---------------------------------------------------------------------------
def serialize_pubkey(pt: Point, compressed: bool = True) -> bytes:
    if pt is None:
        raise ValueError("cannot serialize point at infinity")
    x, y = pt
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def deserialize_pubkey(data: bytes) -> Point:
    if len(data) == 65 and data[0] == 0x04:
        return (int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:65], "big"))
    if len(data) == 33 and data[0] in (0x02, 0x03):
        x = int.from_bytes(data[1:33], "big")
        alpha = (pow(x, 3, P) + A * x + B) % P
        beta = pow(alpha, (P + 1) // 4, P)  # p % 4 == 3, so this is the sqrt
        if beta * beta % P != alpha:
            raise ValueError("x is not on the curve")
        y = beta if (beta & 1) == (data[0] & 1) else P - beta
        return (x, y)
    raise ValueError(f"bad pubkey encoding (len={len(data)}, prefix={data[:1].hex()})")


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def ripemd160(b: bytes) -> bytes:
    try:
        h = hashlib.new("ripemd160")
    except ValueError:  # pragma: no cover - OpenSSL without legacy provider
        from . import _ripemd160_pure  # type: ignore

        return _ripemd160_pure.ripemd160(b)
    h.update(b)
    return h.digest()


def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))


def double_sha256(b: bytes) -> bytes:
    return sha256(sha256(b))


# ---------------------------------------------------------------------------
# Base58Check
# ---------------------------------------------------------------------------
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    # leading zero bytes -> '1'
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        idx = B58_ALPHABET.find(ch)
        if idx < 0:
            raise ValueError(f"invalid base58 character {ch!r}")
        n = n * 58 + idx
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body


def b58check_encode(payload: bytes) -> str:
    return b58encode(payload + double_sha256(payload)[:4])


def b58check_decode(s: str) -> bytes:
    raw = b58decode(s)
    payload, checksum = raw[:-4], raw[-4:]
    if double_sha256(payload)[:4] != checksum:
        raise ValueError("bad base58check checksum")
    return payload


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------
P2PKH_VERSION = 0x00


def hash160_to_address(h160: bytes, version: int = P2PKH_VERSION) -> str:
    return b58check_encode(bytes([version]) + h160)


def address_to_hash160(addr: str) -> bytes:
    payload = b58check_decode(addr)
    if len(payload) != 21:
        raise ValueError("not a P2PKH/P2SH address payload")
    return payload[1:]


def pubkey_to_hash160(pt: Point, compressed: bool = True) -> bytes:
    return hash160(serialize_pubkey(pt, compressed))


def pubkey_to_address(pt: Point, compressed: bool = True) -> str:
    return hash160_to_address(pubkey_to_hash160(pt, compressed))


def privkey_to_pubkey(k: int) -> Point:
    if not (1 <= k < N):
        raise ValueError("private key out of range [1, n-1]")
    return scalar_mult(k, G)


def privkey_to_address(k: int, compressed: bool = True) -> str:
    return pubkey_to_address(privkey_to_pubkey(k), compressed)


def privkey_to_hash160(k: int, compressed: bool = True) -> bytes:
    return pubkey_to_hash160(privkey_to_pubkey(k), compressed)


def privkey_to_wif(k: int, compressed: bool = True, testnet: bool = False) -> str:
    if not (1 <= k < N):
        raise ValueError("private key out of range [1, n-1]")
    version = b"\xef" if testnet else b"\x80"
    payload = version + k.to_bytes(32, "big") + (b"\x01" if compressed else b"")
    return b58check_encode(payload)


def wif_to_privkey(wif: str) -> Tuple[int, bool]:
    payload = b58check_decode(wif)
    compressed = len(payload) == 34 and payload[-1] == 0x01
    body = payload[1:33]
    return int.from_bytes(body, "big"), compressed


# ---------------------------------------------------------------------------
# Puzzle-specific helpers
# ---------------------------------------------------------------------------
def puzzle_range(n: int) -> Tuple[int, int]:
    """Inclusive [low, high] private-key interval for puzzle #n.

    Puzzle #n's key has exactly n bits, i.e. bit (n-1) is set.
    #1 -> [1, 1]; #71 -> [2^70, 2^71 - 1].
    """
    if n < 1:
        raise ValueError("puzzle number must be >= 1")
    return (1 << (n - 1), (1 << n) - 1)


def puzzle_offset(n: int, key: int) -> int:
    """Key with the forced leading bit removed: key - 2^(n-1), in [0, 2^(n-1))."""
    lo, hi = puzzle_range(n)
    if not (lo <= key <= hi):
        raise ValueError(f"key {key:x} outside puzzle #{n} range")
    return key - lo


def puzzle_normalized(n: int, key: int) -> float:
    """Position within the interval, in [0, 1)."""
    lo, hi = puzzle_range(n)
    span = hi - lo + 1
    return (key - lo) / span
