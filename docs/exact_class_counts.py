#!/usr/bin/env python3
"""Exact (exhaustive) class counts on the test curve secp17k1.

Reproduces the exact figures quoted in the README.  Requires numpy; the curve
arithmetic below is self-contained, so the counts do not depend on src/.

Configurations are the triples (s_zk, s_rxk, P) in [1, n-1]^3 -- equivalently
(s, s_zr, s_zk) with s = s_zk + s_rxk and s_zr = s_zk * P (mod n) -- i.e. the
uniform ("null") model of one signature.  Counts:

  * case E                      -- over pairs (s_zk, s_rxk); the S-even
                                   family (S % 4 == 2) in brackets, then the
                                   E1:E2 split;
  * case A label                -- s_zk == a: exactly one s_zk per (s, s_zr)
                                   pair with a valid a;
  * case-B formula event        -- s_zk * s_rxk == a * (s + s_zr)  (mod n),
                                   counted per (s, s_zr) from the discriminant
                                   of s_zk^2 - s*s_zk + a*(s + s_zr) == 0;
  * case-B label                -- m1 == m2 integral (m1 != 1);
  * case A under the REAL model -- P = k * (k*G).x mod n for every nonce k,
                                   instead of a uniform P (pass --skip-real-a
                                   to skip this ~5-minute pass).

Run time on one core: about 3 minutes, plus about 5 for the real-model pass.
"""
import argparse
import time

import numpy as np

P_FIELD, B_COEF, G, N = 100003, 2, (20002, 57568), 99667


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P_FIELD == 0:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], -1, P_FIELD) % P_FIELD
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, P_FIELD) % P_FIELD
    x = (lam * lam - p1[0] - p2[0]) % P_FIELD
    return x, (lam * (p1[0] - x) - p1[1]) % P_FIELD


def count_case_e(n):
    """Ordered pairs (s_zk, s_rxk) in [1, n-1]^2 that are case E."""
    total = even = e1 = 0
    for big_s in range(2, 2 * n):
        if big_s % 4 not in (1, 2):
            continue
        larger = (big_s + big_s // 2 + 1) // 2
        smaller = big_s - larger
        if 1 <= smaller and larger < n:
            pairs = 2 if larger != smaller else 1
            total += pairs
            even += pairs if big_s % 2 == 0 else 0
            e1 += pairs if big_s < n else 0
    return total, even, e1


def count_a_and_b(n):
    """Valid (s, s_zr) pairs (= case-A configurations), B formula, B label."""
    sqrt_of = np.full(n, -1, dtype=np.int64)
    for i in range(1, (n - 1) // 2 + 1):
        sqrt_of[i * i % n] = i
    sqrt_of[0] = 0
    inv2 = pow(2, -1, n)
    valid_pairs = formula = label_b = 0
    for s in range(1, n):
        hi = min(2 * s, n - 1)          # a = s mod (s_zr - s) != s needs s_zr <= 2s
        if hi <= s:
            continue
        s_zr = np.arange(s + 1, hi + 1, dtype=np.int64)
        a = s % (s_zr - s)
        keep = (a > 0) & (a != s)
        s_zr, a = s_zr[keep], a[keep]
        valid_pairs += s_zr.size
        keep = (s + s_zr) != n          # then the roots are {0, s}: not valid
        s_zr, a = s_zr[keep], a[keep]
        disc = (s * s - 4 * a * ((s + s_zr) % n)) % n
        root = sqrt_of[disc]
        keep = root >= 0
        s_zr, a, root = s_zr[keep], a[keep], root[keep]
        for sign in (1, -1):
            s_zk = (s + sign * root) % n * inv2 % n
            ok = (s_zk != 0) & (s_zk != s)
            if sign == -1:
                ok &= root != 0             # a double root counts once
            formula += int(ok.sum())
            s_rxk = (s - s_zk) % n
            rxk_safe = np.where(s_rxk == 0, 1, s_rxk)
            m1 = s_zk // a
            is_b = (ok & (s_zk % a == 0) & (s_rxk != 0)
                    & ((s + s_zr) % rxk_safe == 0)
                    & (m1 == (s + s_zr) // rxk_safe) & (m1 != 1))
            label_b += int(is_b.sum())
    return valid_pairs, formula, label_b


def count_a_real_model(n):
    """Case-A configurations summed over the real nonce map k -> P(k)."""
    r_of_k = np.zeros(n, dtype=np.int64)
    point = None
    for k in range(1, n):
        point = _add(point, G)
        r_of_k[k] = point[0] % n
    # divisors of every M < n as sorted keys M*n + d
    tau = np.zeros(n, dtype=np.int64)
    ms, ds = [], []
    for d in range(1, n):
        mult = np.arange(d, n, d, dtype=np.int64)
        ms.append(mult)
        ds.append(np.full(mult.size, d, dtype=np.int64))
    ms, ds = np.concatenate(ms), np.concatenate(ds)
    keys = np.sort(ms * n + ds)
    np.add.at(tau, ms, 1)
    start = np.searchsorted(keys, np.arange(n, dtype=np.int64) * n, side="left")
    s_zk = np.arange(1, n, dtype=np.int64)
    total = nonces = 0
    for k in range(1, n):
        r = int(r_of_k[k])
        if r == 0:
            continue
        nonces += 1
        m = s_zk * (k * r % n) % n - s_zk           # M = s_zr - s_zk
        v = m > 0
        mv, yv = m[v], s_zk[v]
        # case A <=> d | M with s_zk < d <= M/2  (one s per such divisor d)
        at_most_y = np.searchsorted(keys, mv * n + yv, side="right") - start[mv]
        total += int(np.clip(tau[mv] - 1 - at_most_y, 0, None).sum())
    return total, nonces


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--skip-real-a", action="store_true",
                        help="skip the ~5-minute real-model case-A pass")
    args = parser.parse_args()
    n = N
    cube, square = (n - 1) ** 3, (n - 1) ** 2

    t0 = time.time()
    e_all, e_even, e1 = count_case_e(n)
    print(f"case E          : {e_all:,} of (n-1)^2 pairs  ({e_all / square:.6e}; "
          f"4/(3n) = {4 / (3 * n):.6e})  [S even only: {e_even:,}]  "
          f"E1:E2 = {e1:,}:{e_all - e1:,}")

    valid, formula, label_b = count_a_and_b(n)
    print(f"case A (null)   : {valid:,} of (n-1)^3  ({valid / cube:.6e}; "
          f"1/(4(n-1)) = {1 / (4 * (n - 1)):.6e})")
    print(f"B formula event : {formula:,} of (n-1)^3  ({formula / cube:.6e})")
    print(f"B label         : {label_b:,} of (n-1)^3  ({label_b / cube:.6e}); "
          f"formula/label = {formula / label_b:,.0f}")
    print(f"[{time.time() - t0:.0f}s]", flush=True)

    if not args.skip_real_a:
        t0 = time.time()
        real, nonces = count_a_real_model(n)
        rate = real / (nonces * square)
        print(f"case A (real)   : {real:,} of {nonces:,}*(n-1)^2  ({rate:.6e}; "
              f"{rate * 1e8:.1f} per 1e8)  [{time.time() - t0:.0f}s]")


if __name__ == "__main__":
    main()
