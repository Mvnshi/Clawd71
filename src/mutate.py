"""
Password-mutation rules for the classic Type-1 seed-guessing attack, in the
same spirit as real cracking rule sets (hashcat's best64.rule, John the
Ripper's default rules) -- the point being: if a deterministic-wallet
seed was a "memorable" phrase, it's exactly as likely to be a mutated
form of a common word/password as the raw word itself, and any serious
prior attempt at this ("everyone else prob tried them also") would have
covered this ground too, so it's the right next expansion, not padding.
"""
import re

LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"})
YEARS = [str(y) for y in range(1990, 2027)]
COMMON_SUFFIXES = ["1", "12", "123", "1234", "!", "!!", "01", "007", "69", "420"]
COMMON_PREFIXES = ["the", "my", "i", "bitcoin", "btc"]


def mutations_of(word: str):
    """Yield a bounded, disclosed set of mutations for one base word."""
    seen = set()

    def emit(w):
        if w and w not in seen:
            seen.add(w)
            yield w

    yield from emit(word)
    yield from emit(word.lower())
    yield from emit(word.upper())
    yield from emit(word.capitalize())
    yield from emit(word.translate(LEET))
    yield from emit(word.translate(LEET).capitalize())
    yield from emit(word[::-1])  # reversed
    for suf in COMMON_SUFFIXES:
        yield from emit(word + suf)
        yield from emit(word.capitalize() + suf)
    for year in YEARS:
        yield from emit(word + year)
    for pre in COMMON_PREFIXES:
        yield from emit(pre + word)
        yield from emit(pre + "_" + word)


def count_mutations_of(word: str) -> int:
    return len(list(mutations_of(word)))


if __name__ == "__main__":
    import sys

    for m in mutations_of(sys.argv[1] if len(sys.argv) > 1 else "bitcoin"):
        print(m)
