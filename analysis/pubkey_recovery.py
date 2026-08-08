#!/usr/bin/env python3
"""
Empirical check of Remark 10 of the paper:

    "ECDSA offers no information-theoretic security ... The residual entropy of x
     given (z, r, s) is one or two bits, not 256 -- which is precisely why
     public-key recovery from a signature is a routine operation."

This is the counterexample that keeps the main theorem honest. If you are tempted
to read Theorem 7 as "ECDSA signatures leak nothing", run this first.

Method: build a small elliptic curve of prime order, sign, then recover candidate
public keys from (z, r, s) ALONE -- no private key, no public key given. Every
x-coordinate congruent to r mod n gives up to two curve points R'; for each,
Q = r^-1 (sR' - zG). The true public key is always among them.

Result on the curve below: exactly 2 candidates in 200/200 trials, i.e. 1 bit of
residual entropy -- against log2(n-2) = 10.06 bits if the signature really carried
no information about the key.

The obstruction to going from Q to x is ECDLP, and nothing else. That is the whole
point of Definition 6 (abscissa-oblivious rules) and Corollary 9.

Usage: python analysis/pubkey_recovery.py     (pure stdlib, a few seconds)
"""

import math
import random
from collections import Counter


# --------------------------------------------------------------------------
# find a small curve y^2 = x^3 + ax + b over F_p with PRIME group order
# --------------------------------------------------------------------------
def curve_order(p, a, b):
    qr = {}
    for y in range(p):
        qr.setdefault((y * y) % p, []).append(y)
    cnt = 1  # point at infinity
    for x in range(p):
        cnt += len(qr.get((x * x * x + a * x + b) % p, []))
    return cnt


def is_prime(m):
    if m < 2:
        return False
    i = 2
    while i * i <= m:
        if m % i == 0:
            return False
        i += 1
    return True


def find_curve():
    for p in (1009, 1013, 1019, 1021, 1031):
        for a in range(1, 12):
            for b in range(1, 12):
                if (4 * a**3 + 27 * b**2) % p == 0:
                    continue
                n = curve_order(p, a, b)
                if is_prime(n):
                    return p, a, b, n
    raise RuntimeError("no suitable curve found")


P, A, B, N = find_curve()
INF = None


# --------------------------------------------------------------------------
# group law
# --------------------------------------------------------------------------
def add(Pt, Qt):
    if Pt is INF:
        return Qt
    if Qt is INF:
        return Pt
    if Pt[0] == Qt[0] and (Pt[1] + Qt[1]) % P == 0:
        return INF
    if Pt == Qt:
        lam = (3 * Pt[0] * Pt[0] + A) * pow(2 * Pt[1], -1, P) % P
    else:
        lam = (Qt[1] - Pt[1]) * pow((Qt[0] - Pt[0]) % P, -1, P) % P
    xr = (lam * lam - Pt[0] - Qt[0]) % P
    return (xr, (lam * (Pt[0] - xr) - Pt[1]) % P)


def mul(k, Pt):
    R, Q, k = INF, Pt, k % N
    while k:
        if k & 1:
            R = add(R, Q)
        Q = add(Q, Q)
        k >>= 1
    return R


def find_generator():
    for x in range(P):
        rhs = (x * x * x + A * x + B) % P
        for y in range(P):
            if (y * y) % P == rhs:
                return (x, y)
    raise RuntimeError("no point found")


G = find_generator()
assert mul(N, G) is INF, "generator does not have order n"


def sqrts(v):
    return [y for y in range(P) if (y * y) % P == v % P]


# --------------------------------------------------------------------------
# sign, then recover the public key from (z, r, s) only
# --------------------------------------------------------------------------
def recover_candidates(z, r, s):
    """All public keys consistent with the signature. Uses no secret input."""
    out = []
    for xc in range(r, P, N):                     # x-coordinates == r (mod n)
        for yc in sqrts((xc**3 + A * xc + B) % P):
            Q = mul(pow(r, -1, N), add(mul(s, (xc, yc)), mul(N - z % N, G)))
            if Q is not INF:
                out.append(Q)
    return list(dict.fromkeys(out))


def main(trials=200, seed=7):
    rng = random.Random(seed)
    counts = []
    for t in range(trials):
        x_priv = rng.randrange(1, N)
        Q_true = mul(x_priv, G)
        z = rng.randrange(1, N)
        while True:
            k = rng.randrange(1, N)
            r = mul(k, G)[0] % N
            if r == 0:
                continue
            s = (z + r * x_priv) * pow(k, -1, N) % N
            if s:
                break

        cands = recover_candidates(z, r, s)
        assert Q_true in cands, f"true key not recovered at trial {t}"
        counts.append(len(cands))

    mean = sum(counts) / len(counts)
    print(f"curve      : y^2 = x^3 + {A}x + {B} over F_{P}, prime order n = {N}")
    print(f"generator  : {G}   ([n]G = infinity)")
    print(f"trials     : {trials}  -- true public key recovered in ALL of them")
    print(f"candidates : {dict(Counter(counts))}   mean = {mean:.3f}")
    print()
    print(f"residual entropy of x given (z, r, s)  ~ {math.log2(mean):.2f} bits")
    print(f"entropy if the signature leaked nothing = {math.log2(N - 2):.2f} bits")
    print()
    print("=> ECDSA has no information-theoretic security. The hardness is ECDLP.")


if __name__ == "__main__":
    main()
