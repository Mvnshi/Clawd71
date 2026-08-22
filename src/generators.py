"""Phase 2 - implement candidate generators and try to falsify them.

The creator's (widely quoted, weakly attributed) statement is:

    "A few words about the puzzle. There is no pattern. It is just consecutive
     keys from a deterministic wallet (masked with leading 000...0001 to set
     difficulty). It is simply a crude measuring instrument, of the cracking
     strength of the community."
                                        -- saatoshi_rising, Bitcointalk

Taken literally that describes:  puzzle_key(n) = mask(wallet_key(i0 + n), n)
with mask(v, n) = (v mod 2^(n-1)) | 2^(n-1).

That is a *strong, falsifiable* claim, and it is what this module tests. A
candidate generator is accepted only if it reproduces known keys; matching even
two mid-sized puzzles by chance has probability ~2^-(n1+n2-2), so a single
genuine hit would be decisive. Everything else is rejected and recorded.

Screening note: rather than compare full keys, we compare the low `SCREEN_BITS`
of each masked candidate. That is what makes large seed sweeps affordable while
keeping the false-positive rate at 2^-SCREEN_BITS per (seed, puzzle) pair.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RESULTS = ROOT / "results"

SCREEN_BITS = 24


# ---------------------------------------------------------------------------
# Masking conventions
# ---------------------------------------------------------------------------
def mask_low(v: int, n: int) -> int:
    """Keep low n-1 bits, force bit n-1. Matches 'masked with leading 000...0001'."""
    return (v & ((1 << (n - 1)) - 1)) | (1 << (n - 1))


def mask_top(v: int, n: int, width: int = 256) -> int:
    """Keep the top n-1 bits of a width-bit value, force bit n-1."""
    if width <= n - 1:
        return mask_low(v, n)
    return ((v >> (width - (n - 1))) & ((1 << (n - 1)) - 1)) | (1 << (n - 1))


def mask_mod(v: int, n: int) -> int:
    """Reduce into the interval [2^(n-1), 2^n) by modular folding."""
    span = 1 << (n - 1)
    return (v % span) + span


MASKS: dict[str, Callable[[int, int], int]] = {
    "low_bits": mask_low,
    "top_bits": mask_top,
    "mod_fold": mask_mod,
}


# ---------------------------------------------------------------------------
# Candidate generators: n -> 256-bit integer (before masking)
# ---------------------------------------------------------------------------
def gen_counter(n: int) -> int:
    return n


def gen_sha_counter_be(n: int) -> int:
    return int.from_bytes(hashlib.sha256(n.to_bytes(4, "big")).digest(), "big")


def gen_sha_counter_le(n: int) -> int:
    return int.from_bytes(hashlib.sha256(n.to_bytes(4, "little")).digest(), "big")


def gen_sha_counter_str(n: int) -> int:
    return int.from_bytes(hashlib.sha256(str(n).encode()).digest(), "big")


def gen_sha_counter_str0(n: int) -> int:
    return int.from_bytes(hashlib.sha256(str(n - 1).encode()).digest(), "big")


def gen_double_sha_counter(n: int) -> int:
    h = hashlib.sha256(hashlib.sha256(str(n).encode()).digest()).digest()
    return int.from_bytes(h, "big")


def make_sha_seed_counter(seed: bytes, order: str = "seed_first") -> Callable[[int], int]:
    def f(n: int) -> int:
        payload = seed + str(n).encode() if order == "seed_first" else str(n).encode() + seed
        return int.from_bytes(hashlib.sha256(payload).digest(), "big")

    return f


def make_hash_chain(seed: bytes) -> Callable[[int], int]:
    """k_n = SHA256^n(seed) - a classic 'chained hashing' wallet."""
    cache: dict[int, bytes] = {0: seed}

    def f(n: int) -> int:
        cur = max(k for k in cache if k <= n)
        h = cache[cur]
        for i in range(cur, n):
            h = hashlib.sha256(h).digest()
            cache[i + 1] = h
        return int.from_bytes(cache[n], "big")

    return f


def make_electrum_v1(seed_hex: str) -> Callable[[int], int]:
    """Electrum 1.x deterministic derivation (historically period-appropriate).

    master = stretch(seed); k_i = master + sha256d(str(i) + ':0:' + mpk)
    We only need the additive structure, not the curve, for a low-bit screen.
    """
    seed = seed_hex.encode()
    oldseed = seed
    for _ in range(100_000):
        seed = hashlib.sha256(seed + oldseed).digest()
    master = int.from_bytes(seed, "big")

    def f(n: int) -> int:
        msg = f"{n}:0:".encode()
        off = int.from_bytes(
            hashlib.sha256(hashlib.sha256(msg + seed).digest()).digest(), "big"
        )
        return master + off

    return f


SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def make_bip32_hardened(seed: bytes) -> Callable[[int], int]:
    """BIP32 master key then hardened children m/i' - consecutive indices."""
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k_par, c_par = int.from_bytes(I[:32], "big"), I[32:]

    def f(n: int) -> int:
        idx = 0x80000000 + n
        data = b"\x00" + k_par.to_bytes(32, "big") + idx.to_bytes(4, "big")
        Ii = hmac.new(c_par, data, hashlib.sha512).digest()
        return (int.from_bytes(Ii[:32], "big") + k_par) % SECP_N

    return f


def make_lcg(a: int, c: int, m: int, seed: int, shift: int = 0) -> Callable[[int], int]:
    state = {"x": seed, "i": 0, "vals": {}}

    def f(n: int) -> int:
        if n in state["vals"]:
            return state["vals"][n]
        while state["i"] < n:
            state["x"] = (a * state["x"] + c) % m
            state["i"] += 1
            state["vals"][state["i"]] = state["x"] >> shift
        return state["vals"][n]

    return f


def make_mt19937(seed: int, words: int = 8) -> Callable[[int], int]:
    """Python's random.Random(seed) - MT19937, packing `words` 32-bit draws."""
    import random as _r

    rng = _r.Random(seed)
    cache: dict[int, int] = {}
    produced = 0

    def f(n: int) -> int:
        nonlocal produced
        while produced < n:
            v = 0
            for _ in range(words):
                v = (v << 32) | rng.getrandbits(32)
            produced += 1
            cache[produced] = v
        return cache[n]

    return f


def make_brainwallet(template: str) -> Callable[[int], int]:
    def f(n: int) -> int:
        return int.from_bytes(hashlib.sha256(template.format(n=n).encode()).digest(), "big")

    return f


# ---------------------------------------------------------------------------
# Hypothesis harness
# ---------------------------------------------------------------------------
@dataclass
class Hypothesis:
    name: str
    evidence: str
    generator: Callable[[int], int]
    masks: Iterable[str] = ("low_bits", "top_bits", "mod_fold")
    index_offsets: Iterable[int] = (0, -1, 1)
    params: str = ""


@dataclass
class Outcome:
    name: str
    params: str
    evidence: str
    best_mask: str
    best_offset: int
    matched: int
    tested: int
    retained: bool
    note: str = ""
    hits: list = field(default_factory=list)


def load_keys() -> dict[int, int]:
    recs = json.loads((DATA / "solved_puzzles_broad.json").read_text())
    return {r["puzzle"]: int(r["privkey_dec"]) for r in recs}


def evaluate(h: Hypothesis, keys: dict[int, int], min_puzzle: int = 12) -> Outcome:
    """Score a hypothesis over every (mask, index-offset) variant."""
    targets = {n: k for n, k in keys.items() if n >= min_puzzle}
    best = (0, "low_bits", 0, [])
    for mname in h.masks:
        mfn = MASKS[mname]
        for off in h.index_offsets:
            hits = []
            for n, k in targets.items():
                try:
                    v = h.generator(n + off)
                except Exception:
                    continue
                cand = mfn(v, n)
                # low-bit screen: cheap and keeps the FP rate at 2^-SCREEN_BITS
                sb = min(SCREEN_BITS, n - 1)
                if (cand ^ k) & ((1 << sb) - 1) == 0:
                    hits.append(n)
            if len(hits) > best[0]:
                best = (len(hits), mname, off, hits)
    matched, mname, off, hits = best
    tested = len(targets)
    # Expected chance hits. The screen is min(SCREEN_BITS, n-1) bits wide, so
    # small puzzles are screened far more weakly and dominate this sum.
    n_variants = len(list(h.masks)) * len(list(h.index_offsets))
    expected = n_variants * sum(2.0 ** (-min(SCREEN_BITS, n - 1)) for n in targets)
    retained = matched >= 2
    note = (
        f"{matched} low-{SCREEN_BITS}-bit hits over {tested} puzzles "
        f"({n_variants} variants; chance expectation {expected:.3g}; "
        f"hits at puzzles {hits})"
    )
    return Outcome(h.name, h.params, h.evidence, mname, off, matched, tested, retained, note, hits)


def build_hypotheses() -> list[Hypothesis]:
    hs: list[Hypothesis] = []

    hs.append(Hypothesis(
        "counter / arithmetic progression",
        "Simplest possible generator; trivially falsifiable and worth excluding first.",
        gen_counter))
    hs.append(Hypothesis(
        "SHA256(counter) big-endian u32",
        "Counter-based hashing was the most common amateur key-gen idiom in 2013-2015.",
        gen_sha_counter_be))
    hs.append(Hypothesis(
        "SHA256(counter) little-endian u32", "Endianness variant of the above.",
        gen_sha_counter_le))
    hs.append(Hypothesis(
        "SHA256(ascii counter)",
        "Brainwallet-style: hash the decimal string of the index.", gen_sha_counter_str))
    hs.append(Hypothesis(
        "SHA256(ascii counter-1)", "0-based variant.", gen_sha_counter_str0))
    hs.append(Hypothesis(
        "double SHA256(ascii counter)", "Bitcoin's hash256 applied to the index.",
        gen_double_sha_counter))

    for tmpl in ("{n}", "puzzle {n}", "bitcoin puzzle {n}", "key{n}", "satoshi{n}",
                 "address{n}", "test{n}", "{n} bitcoin"):
        hs.append(Hypothesis(
            f"brainwallet SHA256({tmpl!r})",
            "Brainwallets were widespread pre-2015; passphrase+index is a natural scheme.",
            make_brainwallet(tmpl), params=tmpl))

    for seed_txt in (b"", b"0", b"seed", b"bitcoin", b"satoshi", b"puzzle",
                     b"correct horse battery staple"):
        hs.append(Hypothesis(
            "SHA256(seed || counter)",
            "Chained/salted counter hashing with a guessable salt.",
            make_sha_seed_counter(seed_txt, "seed_first"), params=repr(seed_txt)))
        hs.append(Hypothesis(
            "SHA256(counter || seed)", "Salt-after variant.",
            make_sha_seed_counter(seed_txt, "seed_last"), params=repr(seed_txt)))
        hs.append(Hypothesis(
            "hash chain SHA256^n(seed)",
            "Chained hashing: the classic pre-BIP32 'deterministic wallet'.",
            make_hash_chain(seed_txt), params=repr(seed_txt)))

    # Classic LCGs, seeded with small values
    lcgs = {
        "glibc rand (a=1103515245,c=12345,m=2^31)": (1103515245, 12345, 2**31, 0),
        "MSVC rand (a=214013,c=2531011,m=2^31)": (214013, 2531011, 2**31, 16),
        "Numerical Recipes (a=1664525,c=1013904223,m=2^32)": (1664525, 1013904223, 2**32, 0),
        "MINSTD (a=16807,c=0,m=2^31-1)": (16807, 0, 2**31 - 1, 0),
        "java.util.Random (a=25214903917,c=11,m=2^48)": (25214903917, 11, 2**48, 16),
    }
    for label, (a, c, m, sh) in lcgs.items():
        for seed in (0, 1, 42, 1337, 2015):
            hs.append(Hypothesis(
                f"LCG {label}",
                "Period-appropriate language RNGs an amateur may have used directly.",
                make_lcg(a, c, m, seed, sh), params=f"seed={seed}"))

    for seed in (0, 1, 42, 1337, 2015, 12345):
        for words in (1, 3, 8):
            hs.append(Hypothesis(
                "MT19937 (Python random.Random)",
                "MT19937 backs Python/PHP/Ruby RNGs; small integer seeds are common.",
                make_mt19937(seed, words), params=f"seed={seed},words={words}"))

    for seed_txt in (b"", b"seed", b"bitcoin", b"satoshi", b"puzzle", b"00" * 16):
        hs.append(Hypothesis(
            "BIP32 hardened children m/i'",
            "BIP32 (2012) is the canonical 'deterministic wallet' of the era.",
            make_bip32_hardened(seed_txt), params=repr(seed_txt)))

    for seed_hex in ("00" * 16, "0" * 32, "deadbeef" * 4):
        hs.append(Hypothesis(
            "Electrum 1.x deterministic derivation",
            "Electrum 1.x was the dominant deterministic wallet in 2013-2015.",
            make_electrum_v1(seed_hex), params=seed_hex))

    return hs


def positive_control(keys: dict[int, int]) -> Hypothesis:
    """A generator that IS the answer, to prove the harness can detect one.

    If this is not retained, every rejection above is meaningless.
    """
    def f(n: int) -> int:
        return keys.get(n, 0)

    return Hypothesis(
        "POSITIVE CONTROL (true keys by construction)",
        "Harness self-test: a deliberately correct generator must be retained.",
        f, masks=("low_bits",), index_offsets=(0,), params="n/a")


def negative_control(keys: dict[int, int]) -> Hypothesis:
    """Fresh cryptographic randomness: must be rejected."""
    import secrets

    fixed = {n: secrets.randbits(256) for n in keys}
    return Hypothesis(
        "NEGATIVE CONTROL (fresh random values)",
        "Harness self-test: unrelated randomness must be rejected.",
        lambda n: fixed.get(n, 0), params="n/a")


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    keys = load_keys()
    outcomes = []
    hs = build_hypotheses()
    hs = [positive_control(keys), negative_control(keys)] + hs
    print(f"evaluating {len(hs)} generator hypotheses against {len(keys)} verified keys")
    print(f"screen: low {SCREEN_BITS} bits; retention threshold: >=2 hits\n")
    for h in hs:
        o = evaluate(h, keys)
        outcomes.append(o)
        flag = "RETAIN" if o.retained else "reject"
        print(f"  [{flag}] {o.name:<46} {o.params:<24} hits={o.matched}/{o.tested}")

    retained = [o for o in outcomes if o.retained]
    print(f"\nretained: {len(retained)}   rejected: {len(outcomes) - len(retained)}")
    (RESULTS / "phase2_generators.json").write_text(
        json.dumps([o.__dict__ for o in outcomes], indent=2)
    )
    print(f"wrote {RESULTS / 'phase2_generators.json'}")


if __name__ == "__main__":
    main()
