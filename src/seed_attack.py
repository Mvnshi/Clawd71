"""
Seed/passphrase-guessing attack against two deterministic-wallet hypotheses
that Phase 2's statistical tests could not resolve (a real seed-derived
sequence is, by design, statistically indistinguishable from random -- see
research/hypotheses/hash_chain.md). This is a different kind of attack:
guess the SEED, not the bit pattern.

Scheme 1: Electrum "Type-1" (pre-2.0) deterministic wallet.
  Algorithm reproduced exactly from the current spesmilo/electrum source
  (electrum/keystore.py Old_KeyStore, electrum/old_mnemonic.py), fetched
  2026-08-19. Validated against a real published test vector before use --
  see tests/test_seed_attack.py -- not trusted from memory.

Scheme 2: classic "Type-1" SHA256(masterstring + n) brainwallet-style
  sequential derivation, in several historically-plausible formats.

Both raw derivations produce a full ~256-bit number; the puzzle creator's
own description ("masked with leading 000...0001 to set difficulty") is
applied identically to both: keep the low (n-1) bits, force bit (n-1) high.
"""
import hashlib
import sys

sys.path.insert(0, "/home/user/Clawd71/src")
import electrum_old_mnemonic as old_mnemonic
from coincurve import PrivateKey, PublicKey

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G_PUBKEY = PrivateKey((1).to_bytes(32, "big")).public_key


def apply_puzzle_mask(raw_key: int, n: int) -> int:
    """raw_key -> low (n-1) bits kept, bit (n-1) forced high (n>=1)."""
    if n <= 1:
        return 1
    forced_bit = 1 << (n - 1)
    return (raw_key & (forced_bit - 1)) | forced_bit


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# ---------------------------------------------------------------------------
# Scheme 1: Electrum Type-1
# ---------------------------------------------------------------------------

def electrum_stretch_key(hex_seed: str) -> int:
    encoded = hex_seed.encode("ascii")
    x = encoded
    for _ in range(100_000):
        x = hashlib.sha256(x + encoded).digest()
    return int.from_bytes(x, "big")


def electrum_mpk_from_seed(hex_seed: str) -> str:
    secexp = electrum_stretch_key(hex_seed)
    priv = PrivateKey(secexp.to_bytes(32, "big"))
    uncompressed = priv.public_key.format(compressed=False)
    return uncompressed[1:].hex()


def electrum_get_sequence(mpk_hex: str, for_change: int, n: int) -> int:
    return int.from_bytes(sha256d(f"{n}:{for_change}:".encode("ascii") + bytes.fromhex(mpk_hex)), "big")


def electrum_child_privkey(hex_seed: str, n: int, for_change: int = 0, secexp=None, mpk_hex=None) -> int:
    """Precompute-friendly: pass secexp/mpk_hex if already known for this seed."""
    if secexp is None:
        secexp = electrum_stretch_key(hex_seed)
    if mpk_hex is None:
        priv = PrivateKey(secexp.to_bytes(32, "big"))
        mpk_hex = priv.public_key.format(compressed=False)[1:].hex()
    z = electrum_get_sequence(mpk_hex, for_change, n)
    return (secexp + z) % SECP256K1_N


def hex_seed_from_words(words: list[str]) -> str | None:
    try:
        return old_mnemonic.mn_decode(words)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Scheme 2: classic SHA256(masterstring + n) Type-1
# ---------------------------------------------------------------------------

def classic_type1_candidate(masterstring: str, n: int, fmt: str) -> int:
    """fmt selects a formatting convention; see FORMATS below."""
    s = FORMATS[fmt](masterstring, n)
    return int.from_bytes(hashlib.sha256(s.encode("utf-8")).digest(), "big")


FORMATS = {
    "plain": lambda m, n: f"{m}{n}",
    "colon": lambda m, n: f"{m}:{n}",
    "dash": lambda m, n: f"{m}-{n}",
    "space": lambda m, n: f"{m} {n}",
    "zero_indexed": lambda m, n: f"{m}{n - 1}",
    "colon_zero_indexed": lambda m, n: f"{m}:{n - 1}",
    "n_then_m": lambda m, n: f"{n}{m}",
    "sha256d": lambda m, n: f"{m}{n}",  # handled specially below if ever needed
}


# ---------------------------------------------------------------------------
# Dataset matching
# ---------------------------------------------------------------------------

def test_candidate_against_dataset(candidate_key_fn, dataset, max_n=None):
    """candidate_key_fn(n) -> raw int. Returns (matches, total_tested)."""
    matches = []
    for entry in dataset:
        n = entry["n"] if "n" in entry else entry.get("puzzle")
        if max_n and n > max_n:
            continue
        try:
            raw = candidate_key_fn(n)
        except Exception:
            continue
        masked = apply_puzzle_mask(raw, n)
        actual = entry["key_int"] if "key_int" in entry else int(entry["privkey_hex"], 16)
        if masked == actual:
            matches.append(n)
    return matches
