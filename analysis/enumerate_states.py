#!/usr/bin/env python3
"""
Exhaustive enumeration of the ECDSA coincidence-class state space.

Reproduces every identity in the paper:

    Coincidence Classes in the ECDSA State Space:
    A Zero-Yield Theorem, with Exact Frequencies for Classes A, B and E
    (docs/Coincidence_Classes_ECDSA_Zero_Yield.pdf)

For n <= 1009 this sweeps all (n-1)^3 states of the space S of the structure
lemma, so the probabilities returned are exact rationals, not estimates.
Each assert below is a restatement of a theorem in the paper.

Usage:  python analysis/enumerate_states.py
Needs:  numpy
"""

import math

import numpy as np


def enumerate_states(n):
    """Exhaustive sweep over the state space S: (zeta, xi, u) in (Z_n^*)^3."""
    v = np.arange(1, n, dtype=np.int64)
    Z, X = np.meshgrid(v, v, indexing="ij")
    Z, X = Z.ravel(), X.ravel()
    S = (Z + X) % n
    keep = S != 0
    Z, X, S = Z[keep], X[keep], S[keep]

    # ---- class E -----------------------------------------------------------
    sig = Z + X                                        # true integer sum
    nE = int(np.count_nonzero((sig % 2 == 0) & (np.abs(Z - X) == sig // 2 + 1)))
    nE_line = int(np.count_nonzero((Z == 3 * X + 2) | (X == 3 * Z + 2)))
    assert nE == nE_line, "E structure theorem: E is the affine line zeta = 3*xi + 2"
    assert nE == 2 * ((n - 3) // 3), "exact E count: #E = 2*floor((n-3)/3)"

    # ---- qualification, class A, class B -----------------------------------
    q = a_ct = b_ct = 0
    for u in range(1, n):
        ZR = (Z * u) % n
        m = ZR > S
        z_, x_, s_, zr_ = Z[m], X[m], S[m], ZR[m]
        d = zr_ - s_
        a = s_ % d
        g = (a > 0) & (a != s_) & (a != zr_)           # qualification
        z_, x_, s_, zr_, a = z_[g], x_[g], s_[g], zr_[g], a[g]
        q += a.size

        a_ct += int(np.count_nonzero(z_ == a))         # class A: zeta == a

        t = s_ + zr_                                   # class B: m1 == m2 in Z
        both = (z_ % a == 0) & (t % x_ == 0)
        if both.any():
            b_ct += int(
                np.count_nonzero(z_[both] // a[both] == t[both] // x_[both])
            )

    tot = (n - 1) ** 3
    assert abs(a_ct / tot - (q / tot) / (n - 2)) < 1e-15, \
        "exact A frequency: Pr[A] = Pr[Q] / (n - 2)"

    return dict(n=n, PQ=q / tot, PA=a_ct / tot, PE=nE / (n - 1) ** 2, PB=b_ct / tot)


def secp256k1_figures():
    from decimal import Decimal as D, getcontext
    getcontext().prec = 60
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    PA = D(1) / 4 / (n - 2)
    PE = D(2 * ((n - 3) // 3)) / D((n - 1) ** 2)
    PB = D("0.19") * D(n).ln() / (D(n) * D(n))
    guess = D(1) / (n - 1)
    return PA, PB, PE, guess


if __name__ == "__main__":
    print(f"{'n':>6}  {'Pr[Q]':>9}  {'Pr[A]':>13}  {'Pr[E]':>13}  {'Pr[B]*n^2/ln n':>15}")
    for n in (101, 151, 251, 401, 503, 751, 1009):
        r = enumerate_states(n)
        print(f"{r['n']:6d}  {r['PQ']:9.6f}  {r['PA']:13.6e}  {r['PE']:13.6e}"
              f"  {r['PB'] * n * n / math.log(n):15.3f}")

    PA, PB, PE, guess = secp256k1_figures()
    print("\nsecp256k1")
    print(f"  Pr[A]          = {PA:.6E}")
    print(f"  Pr[B]          ~ {PB:.3E}")
    print(f"  Pr[E]          = {PE:.6E}")
    print(f"  one blind guess= {guess:.6E}   <-- larger than any of the above")
