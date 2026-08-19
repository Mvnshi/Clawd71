#!/bin/bash
# Correctness AND performance regression test for src/stretch_bench.c.
#
# This file exists because of a real, confirmed bug hunt: a working,
# SHA-NI-accelerated stretch_key implementation silently became ~100x
# slower (1.03s/candidate instead of ~10ms) purely because GCC -O3 chose
# not to inline it once it had two call sites (run_selftest + worker) in
# the same translation unit -- correctness was completely unaffected (every
# version still passed the known-answer test), only speed. Nothing short
# of an actual timing check would have caught that. Fixed with
# `__attribute__((always_inline)) static inline`; this test keeps it fixed.
set -euo pipefail
cd "$(dirname "$0")/.."

cc -O3 -march=native -msse4.1 -msha -pthread -o /tmp/stretch_bench_test src/stretch_bench.c

echo "=== correctness: known-answer vector ==="
/tmp/stretch_bench_test selftest

echo "=== performance regression guard ==="
SEED="acb740e454c3134901d7c8f16497cc1c"
T0=$(date +%s.%N)
echo "$SEED" | /tmp/stretch_bench_test batch 1 > /tmp/stretch_bench_test_out.txt
T1=$(date +%s.%N)
ELAPSED=$(python3 -c "print(f'{$T1 - $T0:.4f}')")
echo "1 candidate in ${ELAPSED}s"

python3 -c "
elapsed = $ELAPSED
# ~10-15ms expected on SHA-NI hardware; 200ms is a generous margin that
# still catches the ~1000ms-per-candidate regression this test exists for.
if elapsed > 0.2:
    print(f'FAIL: {elapsed}s for one candidate -- expected ~0.01-0.02s. '
          f'This is the exact symptom of the inlining regression documented '
          f'above (or a new one just like it). Do not ship this binary.')
    raise SystemExit(1)
print(f'PASS: {elapsed}s is within the expected fast range')
"

grep -q "^$SEED " /tmp/stretch_bench_test_out.txt || { echo "FAIL: output missing/malformed"; exit 1; }
echo "=== all stretch_bench checks passed ==="
rm -f /tmp/stretch_bench_test /tmp/stretch_bench_test_out.txt
