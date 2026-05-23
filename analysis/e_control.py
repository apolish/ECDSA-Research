#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Control experiment for the class-E ("Goldbach-type") anomaly.

Claim under test
----------------
Class E recovers the key for signatures whose hidden pair (s_zk, s_rxk) satisfies
    |s_zk - s_rxk| = floor(s/2) + 1.
The "Goldbach" framing suggests the offset +1 is structurally meaningful.

This script shows it is NOT. For uniformly-random hidden components
(s_zk = z*k^-1, s_rxk = r*x*k^-1 are independent and ~uniform over [1, n-1]),
the class defined by target difference  delta = floor(s/2) + k  has essentially
the SAME size for every odd offset k. The Goldbach value k=1 is one slice of a
family of ~n equally-frequent classes, all of frequency ~c/n.

The enumeration is exact (full sweep over all pairs), not sampled.
"""
from __future__ import annotations
import argparse
import numpy as np


def analyze(n: int, offsets=(1, 3, 5, 7, 9, -1, -3, 101)) -> dict:
    """Exact sweep over all (s_zk, s_rxk) in [1, n-1]^2."""
    v = np.arange(1, n, dtype=np.int64)
    szk = v[:, None]
    srxk = v[None, :]
    total = szk + srxk            # true sum S (== s, or s+n after E2 adjustment)
    diff = np.abs(szk - srxk)
    even = (total % 2 == 0)
    half = total // 2

    pairs = (n - 1) ** 2
    out = {}
    for k in offsets:
        cnt = int(np.count_nonzero(even & (diff == half + k)))
        out[k] = (cnt, cnt / pairs)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="E-anomaly offset control experiment.")
    ap.add_argument("--n", type=int, nargs="+", default=[2003, 5003, 10007],
                    help="Curve orders to sweep (small primes for exact enumeration).")
    args = ap.parse_args()

    for n in args.n:
        res = analyze(n)
        print(f"\nn = {n}   (1/n = {1/n:.3e})")
        for k, (cnt, frac) in res.items():
            tag = "E  (Goldbach, k=+1)" if k == 1 else f"control k={k:+d}"
            print(f"  {tag:<22} count={cnt:>7d}  freq={frac:.3e}  (~{frac*n:.2f}/n)")
    print("\nConclusion: every odd offset k yields the same frequency. "
          "The Goldbach value k=+1 is not privileged.")


if __name__ == "__main__":
    main()
