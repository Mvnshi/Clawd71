"""
Minimal, verified secp256k1 -> Bitcoin P2PKH address pipeline.

Uses coincurve (a binding to libsecp256k1, the same library Bitcoin Core
uses) for EC scalar multiplication rather than a from-scratch EC
implementation, so we are not trusting our own modular-arithmetic code for
the cryptographically load-bearing step.
"""
import hashlib

import base58
from coincurve import PrivateKey

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def privkey_int_to_pubkeys(k: int) -> tuple[bytes, bytes]:
    """Return (compressed_pubkey, uncompressed_pubkey) for integer private key k."""
    if not (1 <= k < SECP256K1_N):
        raise ValueError(f"private key out of range: {k:x}")
    sk = PrivateKey(k.to_bytes(32, "big"))
    return sk.public_key.format(compressed=True), sk.public_key.format(compressed=False)


def hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    rip = hashlib.new("ripemd160")
    rip.update(sha)
    return rip.digest()


def hash160_to_p2pkh_address(h160: bytes, version_byte: bytes = b"\x00") -> str:
    payload = version_byte + h160
    return base58.b58encode_check(payload).decode("ascii")


def privkey_int_to_addresses(k: int) -> dict:
    """Return both compressed- and uncompressed-pubkey P2PKH addresses for k."""
    compressed_pub, uncompressed_pub = privkey_int_to_pubkeys(k)
    return {
        "compressed_pubkey": compressed_pub.hex(),
        "uncompressed_pubkey": uncompressed_pub.hex(),
        "address_from_compressed": hash160_to_p2pkh_address(hash160(compressed_pub)),
        "address_from_uncompressed": hash160_to_p2pkh_address(hash160(uncompressed_pub)),
    }


def which_encoding_matches(k: int, expected_address: str) -> str | None:
    """Return 'compressed', 'uncompressed', 'both', or None."""
    r = privkey_int_to_addresses(k)
    c = r["address_from_compressed"] == expected_address
    u = r["address_from_uncompressed"] == expected_address
    if c and u:
        return "both"
    if c:
        return "compressed"
    if u:
        return "uncompressed"
    return None
