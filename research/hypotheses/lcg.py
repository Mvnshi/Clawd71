"""
Hypothesis: LCG (Linear Congruential Generator) origin of puzzle keys.

x_{i+1} = (a * x_i + c) mod m

and puzzle n's key relates to LCG output n via the masking transform
key(n) = 2^(n-1) + (raw_lcg_output(n) mod 2^(n-1)).

Working sequence: normalized(n) = lower_bits(n) / 2^(n-1), for n = 1..70,
read directly from data/solved_puzzles.json (verified, 70/70 keys).

Three independent lines of attack, each with an explicit Monte Carlo null
(never "does it fit" -- always "does it fit MORE than chance produces"):

  A. Direct search over small-to-moderate power-of-two moduli m: convert
     normalized(n) -> integer state X_n = round(normalized(n)*m) mod m,
     solve for (a,c) from a consecutive triple via modular inverse, then
     count how many of the OTHER 66+ transitions that (a,c,m) also
     predicts correctly. Best-match count compared to a Monte Carlo null
     of random sequences put through the identical search.

  B. Determinant/GCD modulus-recovery method (Plumstead/Boyar): for a true
     LCG, differences d_i = X_{i+1}-X_i satisfy d_{i+1}*d_{i-1} - d_i^2 = 0
     (mod m) for EVERY i, so m divides gcd of all such determinants. If the
     data really came from an LCG with modulus <= our working precision K,
     gcd(z_i) over the real sequence will be a huge, obviously-structured
     number (near K). We compute gcd(z_i) for the real sequence and compare
     against the same statistic on Monte Carlo random-float control
     sequences.

  C. Lattice / spectral-test structure: classic LCGs, plotted as consecutive
     pairs (x_n, x_{n+1}), fall on a small family of parallel lines
     p*x + q*y = k/m for small integer (p,q) -- the "spectral test" defect.
     We project the real (normalized(n), normalized(n+1)) pairs onto many
     candidate small-integer directions (p,q), bin each projection mod 1,
     and take the worst (largest) chi-square deviation from uniform over
     all directions tested. That "max chi-square over many directions"
     statistic is compared to the same statistic computed on Monte Carlo
     random point sets (correcting for the multiple-comparisons search
     automatically, since the null undergoes the identical search). We also
     run a simple minimum-nearest-neighbour-distance clustering statistic
     as a second, more literal "lattice spacing" test.

  D. Walk-forward test: using only 3 consecutive known values (a literal
     LCG output-prediction attack -- if it really is an LCG with a
     candidate modulus m, 3 consecutive outputs are enough to solve for
     (a,c) exactly and predict all future outputs), predict normalized(n+1)
     from normalized(n-2..n) for n = 4..69 and multiple candidate moduli.
     Compare mean squared error of these LCG-based predictions against the
     trivial baseline "always guess the interval midpoint, 0.5" -- exactly
     the walk-forward criterion requested.

Run: python3 lcg.py
Deterministic given random.seed / np.random.seed(20260819).
"""

import json
import math
import random as pyrandom
import time
import numpy as np

SEED = 20260819
random_state = np.random.default_rng(SEED)
py_rng = pyrandom.Random(SEED)  # for arbitrary-precision (>64-bit) random ints

DATA_PATH = "/home/user/Clawd71/data/solved_puzzles.json"


# --------------------------------------------------------------------------
# Data loading
# --------------------------------------------------------------------------

def load_normalized():
    data = json.load(open(DATA_PATH))
    data.sort(key=lambda d: d["n"])
    assert [d["n"] for d in data] == list(range(1, 71)), "expected puzzles #1-70"
    norm = np.array([d["normalized"] for d in data], dtype=np.float64)
    return norm


def load_exact_fullscale(scale_bits=69):
    """Exact-integer representation of normalized(n) at a COMMON denominator
    2**scale_bits, computed directly from key_int/n with pure Python bigints
    (no float, no precision loss). normalized(n) = lower_bits(n) / 2**(n-1);
    to express every n's value on the same integer scale we left-shift by
    (scale_bits - (n-1)):  Y_n = lower_bits(n) * 2**(scale_bits-(n-1))
                               = normalized(n) * 2**scale_bits   (exactly).
    scale_bits=69 matches the maximum precision actually present in the
    data (puzzle #70 has 69 free/lower bits), so this is the natural upper
    bound on how fine a fixed-point LCG-state scale can meaningfully be for
    this dataset -- using a larger K would just be padding with zero bits
    that carry no information from the source data."""
    data = json.load(open(DATA_PATH))
    data.sort(key=lambda d: d["n"])
    assert [d["n"] for d in data] == list(range(1, 71))
    Y = []
    for d in data:
        n = d["n"]
        lower_bits = d["key_int"] - 2 ** (n - 1)
        assert 0 <= lower_bits < 2 ** (n - 1) or n == 1
        shift = scale_bits - (n - 1)
        assert shift >= 0, "scale_bits must be >= max(n-1)"
        Y.append(lower_bits << shift)  # exact big int, no rounding
    return Y  # list of Python ints (arbitrary precision), length 70


def random_exact_fullscale(scale_bits, rng):
    """Generate ONE random control sequence matching the REAL data's exact
    structure: position n draws lower_bits uniformly from [0, 2**(n-1))
    -- i.e. the same varying per-position precision/denominator the real
    puzzles have (n=1 is forced to 0, n=2 has 1 free bit, etc.) -- then
    embeds on the common 2**scale_bits scale exactly like load_exact_fullscale.
    This is critical: a naive null that draws full scale_bits-precision
    integers at EVERY position does not reproduce the real data's forced
    trailing-zero structure (small n necessarily contributes huge powers of
    2 to any difference/determinant statistic purely by construction, with
    zero relation to any LCG), and so is not a fair control."""
    Y = []
    for n in range(1, 71):
        lower_bits = rng.getrandbits(n - 1) if n > 1 else 0  # matches [0, 2**(n-1))
        shift = scale_bits - (n - 1)
        Y.append(lower_bits << shift)
    return Y


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def modinv(a, m):
    a %= m
    if a == 0:
        return None
    g = math.gcd(a, m)
    if g != 1:
        return None
    return pow(a, -1, m)


# --------------------------------------------------------------------------
# Test A: direct search over small-to-moderate power-of-two moduli
# --------------------------------------------------------------------------

def search_moduli(norm, moduli):
    """For each modulus m, try every consecutive triple as an (a,c) solver,
    then score that (a,c,m) by how many of ALL 69 transitions it predicts
    correctly. Returns {m: (best_match_count, a, c, total_transitions)}."""
    L = len(norm)
    out = {}
    for m in moduli:
        X = [int(v) for v in np.round(norm * m).astype(np.int64) % m]
        best = (0, None, None)
        for i in range(L - 2):
            d1 = (X[i + 1] - X[i]) % m
            inv = modinv(d1, m)
            if inv is None:
                continue
            a = ((X[i + 2] - X[i + 1]) * inv) % m
            c = (X[i + 1] - a * X[i]) % m
            matches = 0
            for j in range(L - 1):
                if (a * X[j] + c) % m == X[j + 1]:
                    matches += 1
            if matches > best[0]:
                best = (matches, a, c)
        out[m] = (best[0], best[1], best[2], L - 1)
    return out


def best_match_fraction(norm, moduli):
    res = search_moduli(norm, moduli)
    frac = {m: v[0] / v[3] for m, v in res.items()}
    return res, frac


def monte_carlo_test_A(real_norm, moduli, n_trials=300):
    real_res, real_frac = best_match_fraction(real_norm, moduli)
    real_stat = max(real_frac.values())  # worst-case (best-fitting) modulus
    real_best_m = max(real_frac, key=real_frac.get)

    null_stats = np.empty(n_trials)
    L = len(real_norm)
    for t in range(n_trials):
        trial = random_state.random(L)
        _, frac = best_match_fraction(trial, moduli)
        null_stats[t] = max(frac.values())

    p_value = (np.sum(null_stats >= real_stat) + 1) / (n_trials + 1)
    return {
        "real_res": real_res,
        "real_frac": real_frac,
        "real_stat": real_stat,
        "real_best_modulus": real_best_m,
        "null_stats": null_stats,
        "null_mean": float(null_stats.mean()),
        "null_max": float(null_stats.max()),
        "p_value": p_value,
    }


# --------------------------------------------------------------------------
# Test B: determinant/GCD modulus-recovery method
# --------------------------------------------------------------------------

def determinant_gcd_stat_exact(X):
    """X: list/sequence of exact Python ints (arbitrary precision, no float
    involved anywhere). Compute z_i = d_{i+1}*d_{i-1} - d_i^2 for consecutive
    difference triples (pure bigint arithmetic, cannot overflow), and return
    gcd of all z_i. For a true LCG mod m, every z_i is an exact multiple of
    m, so gcd(z_i) >= m (often == m or a small multiple)."""
    d = [X[i + 1] - X[i] for i in range(len(X) - 1)]
    z = [d[i + 1] * d[i - 1] - d[i] ** 2 for i in range(1, len(d) - 1)]
    g = 0
    for zi in z:
        g = math.gcd(g, int(zi))
    return g, z


def monte_carlo_test_B(real_Y, scale_bits, n_trials=2000):
    real_g, real_z = determinant_gcd_stat_exact(real_Y)
    null_g = []
    for _ in range(n_trials):
        # Random control sequence matching the REAL data's exact per-position
        # structure (see random_exact_fullscale docstring) -- NOT a naive
        # full-precision-everywhere draw, which would not reproduce the
        # forced trailing-zero pattern that small n contributes mechanically.
        trial = random_exact_fullscale(scale_bits, py_rng)
        g, _ = determinant_gcd_stat_exact(trial)
        null_g.append(g)
    null_g = np.array([float(g) for g in null_g])
    real_log = math.log2(real_g) if real_g > 0 else 0.0
    null_log = np.log2(np.maximum(null_g, 1))
    p_value = (np.sum(null_g >= real_g) + 1) / (n_trials + 1)
    return {
        "real_g": real_g,
        "real_log2_g": real_log,
        "null_log2_mean": float(null_log.mean()),
        "null_log2_max": float(null_log.max()),
        "null_g_max": float(null_g.max()),
        "p_value": p_value,
        "scale_bits": scale_bits,
    }


# --------------------------------------------------------------------------
# Test C: lattice / spectral test via directional chi-square + NN distance
# --------------------------------------------------------------------------

def build_directions(cmax):
    dirs = []
    for p in range(-cmax, cmax + 1):
        for q in range(-cmax, cmax + 1):
            if p == 0 and q == 0:
                continue
            if p < 0 or (p == 0 and q < 0):
                continue  # canonicalize sign (direction == -direction for this test)
            if math.gcd(abs(p), abs(q)) != 1:
                continue  # skip redundant collinear multiples
            dirs.append((p, q))
    return np.array(dirs, dtype=np.float64)


def max_chi2_over_directions(x, y, P, Q, bins=20):
    L = len(x)
    W = (P[:, None] * x[None, :] + Q[:, None] * y[None, :]) % 1.0  # (D, L)
    bin_idx = np.minimum((W * bins).astype(np.int64), bins - 1)  # (D, L)
    D = P.shape[0]
    counts = np.zeros((D, bins), dtype=np.float64)
    rows = np.repeat(np.arange(D), L)
    np.add.at(counts, (rows, bin_idx.ravel()), 1.0)
    expected = L / bins
    chi2 = ((counts - expected) ** 2 / expected).sum(axis=1)
    return chi2.max(), chi2


def min_nn_distance(x, y):
    pts = np.stack([x, y], axis=1)
    diff = pts[:, None, :] - pts[None, :, :]
    dist = np.sqrt((diff ** 2).sum(axis=-1))
    np.fill_diagonal(dist, np.inf)
    return dist.min()


def monte_carlo_test_C(real_norm, cmax=12, bins=20, n_trials=3000):
    x = real_norm[:-1]
    y = real_norm[1:]
    L = len(x)
    P_Q = build_directions(cmax)
    P, Q = P_Q[:, 0], P_Q[:, 1]

    real_chi2_max, real_chi2_all = max_chi2_over_directions(x, y, P, Q, bins)
    real_nn = min_nn_distance(x, y)

    null_chi2 = np.empty(n_trials)
    null_nn = np.empty(n_trials)
    for t in range(n_trials):
        trial = random_state.random(L + 1)
        tx, ty = trial[:-1], trial[1:]
        c2, _ = max_chi2_over_directions(tx, ty, P, Q, bins)
        null_chi2[t] = c2
        null_nn[t] = min_nn_distance(tx, ty)

    p_chi2 = (np.sum(null_chi2 >= real_chi2_max) + 1) / (n_trials + 1)
    p_nn = (np.sum(null_nn <= real_nn) + 1) / (n_trials + 1)  # small NN dist = clustering

    best_dir_idx = int(np.argmax(real_chi2_all))
    best_dir = (int(P[best_dir_idx]), int(Q[best_dir_idx]))

    return {
        "n_directions": len(P),
        "real_chi2_max": float(real_chi2_max),
        "real_best_direction": best_dir,
        "null_chi2_mean": float(null_chi2.mean()),
        "null_chi2_p95": float(np.percentile(null_chi2, 95)),
        "p_value_chi2": p_chi2,
        "real_nn_dist": float(real_nn),
        "null_nn_mean": float(null_nn.mean()),
        "null_nn_p05": float(np.percentile(null_nn, 5)),
        "p_value_nn": p_nn,
    }


# --------------------------------------------------------------------------
# Test D: walk-forward prediction using 3-consecutive-output LCG attack
# --------------------------------------------------------------------------

def walk_forward_lcg(norm, m):
    """For each n with 3 known predecessors, solve (a,c) mod m from the
    consecutive triple (n-3,n-2,n-1)->(n-2,n-1,n) style window and predict
    the next value. Returns arrays of squared errors (LCG) and baseline
    (guess-0.5) squared errors, in normalized [0,1) space."""
    L = len(norm)
    X = np.round(norm * m).astype(np.int64) % m
    lcg_sq_err = []
    baseline_sq_err = []
    exact_hits = 0
    attempts = 0
    for i in range(2, L - 1):
        x0, x1, x2 = int(X[i - 2]), int(X[i - 1]), int(X[i])
        d1 = (x1 - x0) % m
        inv = modinv(d1, m)
        if inv is None:
            continue
        a = ((x2 - x1) * inv) % m
        c = (x1 - a * x0) % m
        pred = (a * x2 + c) % m
        actual = int(X[i + 1])
        attempts += 1
        if pred == actual:
            exact_hits += 1
        pred_norm = pred / m
        actual_norm = actual / m
        # circular distance on [0,1)
        d = abs(pred_norm - actual_norm)
        d = min(d, 1 - d)
        lcg_sq_err.append(d ** 2)
        baseline_sq_err.append((0.5 - actual_norm) ** 2)
    return {
        "m": m,
        "attempts": attempts,
        "exact_hits": exact_hits,
        "expected_chance_hits": attempts / m,
        "lcg_mse": float(np.mean(lcg_sq_err)) if lcg_sq_err else None,
        "baseline_mse": float(np.mean(baseline_sq_err)) if baseline_sq_err else None,
    }


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    t0 = time.time()
    norm = load_normalized()
    print(f"Loaded {len(norm)} normalized values (puzzles #1-70).")
    print(f"normalized[1..10] = {norm[:10]}")

    print("\n" + "=" * 78)
    print("TEST A: direct search over small-to-moderate power-of-two moduli")
    print("=" * 78)
    moduli_A = [2 ** k for k in range(4, 25)]  # 2^4 .. 2^24
    resA = monte_carlo_test_A(norm, moduli_A, n_trials=300)
    print(f"Moduli searched: 2^4 .. 2^24 ({len(moduli_A)} values)")
    print("Per-modulus best match fraction (real data), matches/69 transitions:")
    for m in moduli_A:
        cnt, a, c, tot = resA["real_res"][m]
        print(f"  m=2^{int(math.log2(m)):>2d} ({m:>9d}): best={cnt:2d}/{tot} "
              f"(a={a}, c={c})" if a is not None else f"  m=2^{int(math.log2(m))}: no candidate found")
    print(f"\nBest-fitting modulus overall: 2^{int(math.log2(resA['real_best_modulus']))}"
          f"  match fraction = {resA['real_stat']:.4f}")
    print(f"Monte Carlo null (n=300 random control sequences, same search): "
          f"mean={resA['null_mean']:.4f}  max={resA['null_max']:.4f}")
    print(f"P-value (real max-match-fraction >= null): {resA['p_value']:.4f}")

    print("\n" + "=" * 78)
    print("TEST B: determinant/GCD modulus-recovery method")
    print("=" * 78)
    SCALE_BITS = 69  # matches max free-bit precision actually in the data (puzzle #70)
    Y = load_exact_fullscale(scale_bits=SCALE_BITS)
    resB = monte_carlo_test_B(Y, SCALE_BITS, n_trials=2000)
    print(f"Working precision: EXACT arbitrary-precision integers, common scale 2^{SCALE_BITS}")
    print(f"  (computed directly from key_int/n, no float rounding anywhere in this test)")
    print(f"Real data: gcd(z_i) = {resB['real_g']}  (log2 = {resB['real_log2_g']:.2f})")
    print(f"Monte Carlo null (n=2000 random control sequences on the identical exact scale): "
          f"mean(log2 gcd) = {resB['null_log2_mean']:.2f}, "
          f"max(log2 gcd) seen = {resB['null_log2_max']:.2f} "
          f"(max raw gcd = {resB['null_g_max']:.0f})")
    print(f"P-value (real gcd >= null gcd): {resB['p_value']:.4f}")
    print(f"Interpretation: a true power-of-two-modulus LCG with m<=2^{SCALE_BITS} would give "
          f"gcd(z_i) close to 2^{SCALE_BITS} (or a large divisor thereof) -- i.e. log2(gcd) near "
          f"{SCALE_BITS}. Real data's log2(gcd) should be compared to that, not to 0.")

    # Diagnostic: 2-adic valuation profile of z_i (catches the trailing-zero
    # artifact from small-n coarse precision before it gets mistaken for
    # genuine structure).
    _, real_z = determinant_gcd_stat_exact(Y)
    def val2(x):
        if x == 0:
            return None
        x = abs(x)
        v = 0
        while x % 2 == 0:
            x //= 2
            v += 1
        return v
    vals = [val2(z) for z in real_z]
    print(f"\nDiagnostic -- 2-adic valuation of each z_i (index 0 = earliest n-triple):")
    print(f"  {vals}")
    print("  (monotonic decrease from ~130+ down to a few bits is the EXPECTED signature")
    print("   of the small-n trailing-zero-padding artifact, not LCG structure -- the")
    print("   overall gcd is set by whichever triple has the fewest forced trailing zeros,")
    print("   i.e. the highest-n triple, so this test is essentially only informative")
    print("   about the last few n's once corrected this way.)")

    # Robustness check: restrict to only the high-n tail (n >= 20), where per-
    # position precision is already >=19 bits and the small-n artifact cannot
    # dominate the gcd.
    print("\nRobustness check: repeat Test B using only puzzles n=20..70 (49 points),")
    print("so no position contributes fewer than 19 bits of real precision:")
    data_full = json.load(open(DATA_PATH))
    data_full.sort(key=lambda d: d["n"])
    sub = [d for d in data_full if d["n"] >= 20]
    Y_sub = []
    base_shift = 69 - 19  # align n=20 (19 free bits) to top of its own local scale
    local_scale = sub[-1]["n"] - 1  # = 69, denom of n=70
    for d in sub:
        n = d["n"]
        lb = d["key_int"] - 2 ** (n - 1)
        Y_sub.append(lb << (local_scale - (n - 1)))
    real_g_sub, _ = determinant_gcd_stat_exact(Y_sub)
    null_g_sub = []
    for _ in range(500):
        trial = []
        for d in sub:
            n = d["n"]
            lb = py_rng.getrandbits(n - 1)
            trial.append(lb << (local_scale - (n - 1)))
        g, _ = determinant_gcd_stat_exact(trial)
        null_g_sub.append(g)
    null_g_sub = np.array([float(g) for g in null_g_sub])
    p_sub = (np.sum(null_g_sub >= real_g_sub) + 1) / (501)
    print(f"  Real gcd(z_i), n=20..70 only: {real_g_sub}  (log2={math.log2(real_g_sub) if real_g_sub>0 else 0:.2f})")
    print(f"  Monte Carlo null (500 trials, matched structure): "
          f"mean(log2)={np.log2(np.maximum(null_g_sub,1)).mean():.2f}  "
          f"max raw gcd seen={null_g_sub.max():.0f}")
    print(f"  P-value: {p_sub:.4f}")

    print("\n" + "=" * 78)
    print("TEST C: lattice / spectral-test structure (2D scatter statistic)")
    print("=" * 78)
    resC = monte_carlo_test_C(norm, cmax=12, bins=20, n_trials=3000)
    print(f"Directions tested (small coprime integer p,q, |p|,|q|<=12): {resC['n_directions']}")
    print(f"Real data: max chi-square over all directions = {resC['real_chi2_max']:.2f} "
          f"(worst/best-fitting direction p,q = {resC['real_best_direction']})")
    print(f"Monte Carlo null (n=3000 random 2D point sets, same search): "
          f"mean={resC['null_chi2_mean']:.2f}  95th pct={resC['null_chi2_p95']:.2f}")
    print(f"P-value (real max-chi2 >= null): {resC['p_value_chi2']:.4f}")
    print(f"\nMinimum nearest-neighbour distance (2D, 69 points):")
    print(f"Real = {resC['real_nn_dist']:.6f}")
    print(f"Monte Carlo null: mean={resC['null_nn_mean']:.6f}  5th pct={resC['null_nn_p05']:.6f}")
    print(f"P-value (real nn-dist <= null, i.e. anomalous clustering): {resC['p_value_nn']:.4f}")

    print("\n" + "=" * 78)
    print("TEST D: walk-forward prediction (3-consecutive-output LCG attack)")
    print("=" * 78)
    moduli_D = [2 ** k for k in (8, 12, 16, 20, 24)]
    resD_list = []
    for m in moduli_D:
        d = walk_forward_lcg(norm, m)
        resD_list.append(d)
        print(f"m=2^{int(math.log2(m)):>2d}: attempts={d['attempts']:2d}  "
              f"exact_hits={d['exact_hits']} (chance-expected={d['expected_chance_hits']:.4f})  "
              f"LCG walk-forward MSE={d['lcg_mse']:.5f}  "
              f"baseline(midpoint=0.5) MSE={d['baseline_mse']:.5f}")
    beats_baseline = [d for d in resD_list if d["lcg_mse"] is not None and d["lcg_mse"] < d["baseline_mse"]]
    print(f"\nModuli where LCG walk-forward MSE < baseline MSE: {len(beats_baseline)}/{len(resD_list)}")

    print(f"\nTotal runtime: {time.time()-t0:.1f}s")

    return {
        "norm": norm,
        "A": resA,
        "B": resB,
        "C": resC,
        "D": resD_list,
    }


if __name__ == "__main__":
    main()
