"""
Build the candidate seed list for the scaled-up Electrum Type-1 attack:
top 2,000,000 rockyou.txt entries, each turned into a 32-hex-char seed via
SHA256(phrase)[:16] (the single most standard way to turn an arbitrary
phrase into a fixed-length seed -- the earlier, smaller round tried 3
derivation methods per phrase; at this scale one well-chosen method times
2M phrases covers more real ground than 3 methods times far fewer).

Output: one 32-hex-char seed per line, for src/stretch_bench.c's
`batch` mode to consume directly.
"""
import hashlib

ROCKYOU_PATH = "/tmp/claude-0/-home-user-Clawd71/ad6103c2-6292-5da4-b74f-f5d157a4e883/scratchpad/rockyou.txt"
OUT_PATH = "/tmp/claude-0/-home-user-Clawd71/ad6103c2-6292-5da4-b74f-f5d157a4e883/scratchpad/electrum_seeds_2M.txt"
TOP_N = 2_000_000


def main():
    seen = set()
    with open(ROCKYOU_PATH, "r", encoding="utf-8", errors="ignore") as f, open(OUT_PATH, "w") as out:
        for i, line in enumerate(f):
            if i >= TOP_N:
                break
            w = line.rstrip("\n")
            if not w:
                continue
            seed = hashlib.sha256(w.encode("utf-8")).hexdigest()[:32]
            if seed in seen:
                continue
            seen.add(seed)
            out.write(seed + "\n")
    print(f"wrote {len(seen):,} unique seeds to {OUT_PATH}")


if __name__ == "__main__":
    main()
