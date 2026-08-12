#!/usr/bin/env python3
"""Extended measurements for the paper."""
import sys, os, time, random
import numpy as np

sys.path.insert(0, "../src")
sys.path.insert(0, "../src/utils")

from ecurve.secp256k1 import Secp256k1, TEST_PARAMS, LEGACY_PARAMS
from utils.class_forge import ECDSAClassGenerator

N = TEST_PARAMS.n
TOTAL = 100_000_000
CHUNK = 2_000_000
SEED = 20260812

# =====================================================================
# 1. EXACT combinatorial probability of the case-E condition
# =====================================================================
# Enumerate over the integer sum S0 = s_zk + s_rxk in [2, 2n): the split is
# integral iff S0 % 4 in {1,2}, and then the two parts are determined.
exact = 0
for s0 in range(2, 2 * N):
    if s0 % 4 not in (1, 2):
        continue
    larger = (s0 + s0 // 2 + 1) // 2
    smaller = s0 - larger
    if 1 <= smaller and larger < N:
        exact += 2 if larger != smaller else 1
p_e_exact = exact / (N - 1) ** 2
print(f"[E] exact favourable ordered pairs : {exact:,}")
print(f"[E] exact P(case E)                : {p_e_exact:.6e}")
print(f"[E] closed form 4/(3n)             : {4/(3*N):.6e}")
print(f"[E] ratio exact / closed form      : {p_e_exact/(4/(3*N)):.4f}")
print(f"[A] closed form 1/(4(n-1))         : {1/(4*(N-1)):.6e}", flush=True)

# =====================================================================
# 2. Full class census, real vs null, 1e8 each
# =====================================================================
t0 = time.time()
ec = Secp256k1(TEST_PARAMS)
r_of_k = np.zeros(N, dtype=np.int64)
point = None
for k in range(1, N):
    point = ec.point_add(point, TEST_PARAMS.g)
    r_of_k[k] = point[0] % N
inv = np.zeros(N, dtype=np.int64)
for k in range(1, N):
    inv[k] = pow(k, -1, N)
print(f"\ntables built in {time.time()-t0:.1f}s", flush=True)


def census(s, s_zk, s_rxk, s_zr):
    big_s = s_zk + s_rxk
    e_hit = (((big_s & 3) == 1) | ((big_s & 3) == 2))
    e_hit &= np.abs(s_zk - s_rxk) == (big_s >> 1) + 1

    va = s_zr > s
    d = np.where(va, s_zr - s, 1)
    a = np.where(va, s % d, 0)
    va &= (a > 0) & (a != s)

    a_safe = np.where(va, a, 1)
    m1_int = va & (s_zk % a_safe == 0)
    m1 = np.where(m1_int, s_zk // a_safe, 0)

    rxk_safe = np.where(s_rxk == 0, 1, s_rxk)
    m2_int = va & (s_rxk != 0) & ((s + s_zr) % rxk_safe == 0)
    m2 = np.where(m2_int, (s + s_zr) // rxk_safe, -1)

    a_hit = va & (m1 == 1) & m1_int          # s_zk == a
    b_hit = va & m1_int & m2_int & (m1 == m2) & (m1 != 1)
    c_hit = va & m1_int & (m1 > 1) & ~b_hit
    return (int(va.sum()), int(a_hit.sum()), int(b_hit.sum()),
            int(c_hit.sum()), int(e_hit.sum()))


def run(model, total, seed):
    rng = np.random.default_rng(seed)
    acc = np.zeros(5, dtype=np.int64)
    done = 0
    while done < total:
        m = min(CHUNK, total - done)
        if model == "real":
            k = rng.integers(1, N, size=m, dtype=np.int64)
            z = rng.integers(1, N, size=m, dtype=np.int64)
            dk = rng.integers(1, N, size=m, dtype=np.int64)
            r = r_of_k[k]; k_inv = inv[k]
            ok = r != 0
            s_zk = (z * k_inv) % N
            s_rxk = r % N * dk % N * k_inv % N
            s = (s_zk + s_rxk) % N
            s_zr = (z * r) % N
            if not ok.all():
                s, s_zk, s_rxk, s_zr = s[ok], s_zk[ok], s_rxk[ok], s_zr[ok]
                m = int(ok.sum())
        else:
            s_zk = rng.integers(1, N, size=m, dtype=np.int64)
            s_rxk = rng.integers(1, N, size=m, dtype=np.int64)
            P = rng.integers(1, N, size=m, dtype=np.int64)
            s = (s_zk + s_rxk) % N
            s_zr = (s_zk * P) % N
        acc += np.array(census(s, s_zk, s_rxk, s_zr), dtype=np.int64)
        done += m
    return done, acc


results = {}
for model in ("real", "null"):
    t0 = time.time()
    done, acc = run(model, TOTAL, SEED)
    results[model] = (done, acc)
    va, a, b, c, e = acc
    print(f"\n=== {model.upper()} ({done:,} tuples, {time.time()-t0:.0f}s) ===")
    print(f"  valid a : {va:>10,}  rate {va/done:.6f}")
    print(f"  case A  : {a:>10,}  rate {a/done:.4e}")
    print(f"  case B  : {b:>10,}  rate {b/done:.4e}")
    print(f"  case C  : {c:>10,}  rate {c/done:.4e}")
    print(f"  case E  : {e:>10,}  rate {e/done:.4e}", flush=True)

# two-sample Poisson comparison
print("\n=== REAL vs NULL (two-sample Poisson z) ===")
names = ["valid a", "case A", "case B", "case C", "case E"]
for i, nm in enumerate(names):
    x, y = int(results["real"][1][i]), int(results["null"][1][i])
    den = np.sqrt(x + y)
    z = (x - y) / den if den > 0 else 0.0
    print(f"  {nm:8}: real {x:>10,}  null {y:>10,}  z = {z:+.2f}")

# =====================================================================
# 3. Cost of CONSTRUCTING class A / E on real secp256k1
# =====================================================================
print("\n=== construction cost on real secp256k1 (100 signatures each) ===")
ecL = Secp256k1(LEGACY_PARAMS, rng=random.Random(31337))
gen = ECDSAClassGenerator(ecL)
for cls in ("A", "E"):
    t0 = time.time()
    for _ in range(100):
        fs = gen.generate(cls)
    dt = time.time() - t0
    print(f"  class {cls}: 100 signatures in {dt:.2f}s  "
          f"({1000*dt/100:.1f} ms each)")
