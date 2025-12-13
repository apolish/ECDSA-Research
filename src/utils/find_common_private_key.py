#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import sys
import argparse
from dataclasses import dataclass
from decimal import Decimal, getcontext
from time import perf_counter
from typing import Iterable, List, Optional, Tuple, DefaultDict
from collections import defaultdict

try:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from ecurve.secp256k1 import Secp256k1, TEST_PARAMS_SMALL, TEST_PARAMS_LARGE, LEGACY_PARAMS
except Exception as exc:
    raise ImportError(
        "Failed to import local 'secp256k1.py'. "
        "Make sure the file is in the same directory."
    ) from exc


# ======================================================================
# DATA MODEL
# ======================================================================
@dataclass(frozen=True)
class ECDSATransaction:
    """
    Container for a single ECDSA transaction and its auxiliary invariants.

    NOTE:
    Only floor(f) is used in level computation.
    """
    mode: str
    s: int
    s_zk: int
    s_rxk: int
    s_zr: int
    z: int
    r: int
    x: int
    k_inv: int
    a: int
    f: float


# ======================================================================
# CORE MATH
# ======================================================================
def inverse_mod_safe(k: int, m: int) -> Optional[int]:
    """Safe modular inverse returning None if not invertible."""
    try:
        return pow(k, -1, m)
    except ValueError:
        return None


def recover_x(s_zk: int, s: int, z: int, r: int, n: int) -> Optional[int]:
    """
    Recover candidate x from a single s_zk.

    Derived ECDSA relation:
        x = z*(s - s_zk) * (r*s_zk)^(-1) mod n

    Returns None if denominator is non-invertible.
    """
    num = (z * (s - s_zk)) % n
    den = (r * s_zk) % n
    den_inv = inverse_mod_safe(den, n)
    if den_inv is None:
        return None
    return (num * den_inv) % n


def factor_window(f: float) -> Tuple[int, int]:
    """
    Compute integer factor window:
        N = floor(f)
        s_zk ∈ [a*N, a*(N+1)]
    """
    if f < 0:
        raise ValueError("f must be non-negative.")
    N = int(f)            # floor(f)
    return N, N + 1


# ======================================================================
# RANGE BUILDER (WITH ZERO-LEVEL FIX)
# ======================================================================
def s_zk_range(a: int, low: int, high: int) -> range:
    """
    Full s_zk range for levels [low, high].

    Normal case:
        s_zk ∈ [a*low, a*high]

    Zero-level case:
        low == 0 → formal window is [0, a]
        We modify it to:
            start = 1
            end   = a
    """
    if high < low:
        raise ValueError("Invalid factor window.")

    if low == 0:
        start = 1
        end = a
    else:
        start = a * low
        end = a * high

    return range(start, end + 1)


# ======================================================================
# BUILD LOCAL CANDIDATES:  x -> [list of s_zk]
# ======================================================================
def build_x_index(
    s: int, z: int, r: int, n: int, candidates: Iterable[int]
) -> DefaultDict[int, List[int]]:
    """
    For a single transaction, build:
        x_candidate -> [list of s_zk producing this x]
    """
    out: DefaultDict[int, List[int]] = defaultdict(list)
    for szk in candidates:
        x = recover_x(szk, s, z, r, n)
        if x is not None:
            out[x].append(szk)
    return out


# ======================================================================
# MAIN INTERSECTION ENGINE
# ======================================================================
def find_common_x_any(
    txs: List[ECDSATransaction],
    curve_mode: str,
) -> List[Tuple[int, List[int]]]:
    """
    Compute intersection of x-candidates across all transactions
    using full-width factor levels.

    Steps:
      1. Build s_zk ranges for each transaction.
      2. Sort by smallest window to largest.
      3. Build base x-index from narrowest.
      4. Iteratively intersect across remaining transactions.
    """
    if len(txs) < 2:
        raise ValueError("At least two transactions are required.")

    # Select curve mode
    if curve_mode == "test_small":
        ec = Secp256k1(TEST_PARAMS_SMALL)
    elif curve_mode == "test_large":
        ec = Secp256k1(TEST_PARAMS_LARGE)
    elif curve_mode == "legacy":
        ec = Secp256k1(LEGACY_PARAMS)
    n = ec.curve.n

    # Build full s_zk windows
    items: List[Tuple[int, ECDSATransaction, range]] = []
    for idx, t in enumerate(txs):
        low, high = factor_window(t.f)
        rng = s_zk_range(t.a, low, high)
        items.append((idx, t, rng))

    # Sort by ascending range size
    items_sorted = sorted(items, key=lambda x: len(x[2]))

    # Base transaction
    first_idx, first_tx, first_rng = items_sorted[0]
    idx_map: DefaultDict[int, List[List[Tuple[int, int]]]] = defaultdict(list)
    base_index = build_x_index(first_tx.s, first_tx.z, first_tx.r, n, first_rng)

    for x, s_list in base_index.items():
        for szk in s_list:
            idx_map[x].append([(first_idx, szk)])

    # Intersect across remaining transactions
    for pos in range(1, len(items_sorted)):
        cur_idx, cur_tx, cur_rng = items_sorted[pos]
        cur_index = build_x_index(cur_tx.s, cur_tx.z, cur_tx.r, n, cur_rng)

        new_map: DefaultDict[int, List[List[Tuple[int, int]]]] = defaultdict(list)

        for x, chains in idx_map.items():
            if x not in cur_index:
                continue
            for chain in chains:
                for szk_cur in cur_index[x]:
                    new_chain = list(chain)
                    new_chain.append((cur_idx, szk_cur))
                    new_map[x].append(new_chain)

        idx_map = new_map
        if not idx_map:
            return []

    # Restore original order
    results: List[Tuple[int, List[int]]] = []
    for x, chains in idx_map.items():
        for chain in chains:
            ordered = [None] * len(txs)
            for pos, szk_val in chain:
                ordered[pos] = szk_val
            if None not in ordered:
                results.append((x, ordered))

    return results


# ======================================================================
# CLI + DEMO
# ======================================================================
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Search for common private key x via full-level windows."
    )
    parser.add_argument(
        "--curve-mode",
        choices=["test_small", "test_large", "legacy"],
        default="test_small",
        help="Select EC curve mode: test_small, test_large or legacy."
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    tx1 = ECDSATransaction("test_small", 37056, 2688,  34368, 13361, 76123, 45968, 45809, 79957, 13361, 0.201182546216600553)
    tx2 = ECDSATransaction("test_small", 95040, 4142,  90898, 73553, 44223, 84492, 45809, 97952, 9092,  0.455565332160140783)
    tx3 = ECDSATransaction("test_small", 29017, 13518, 15499, 86566, 48595, 252,   45809, 28839, 29017, 0.465864837853671985)
    tx4 = ECDSATransaction("test_small", 81859, 5504,  76355, 60734, 2029,  10591, 45809, 24023, 18484, 0.297771045228305561)
    tx5 = ECDSATransaction("test_small", 35813, 478,   35335, 67033, 46356, 12706, 45809, 42962, 4593,  0.104071413019812758)
    tx6 = ECDSATransaction("test_small", 15169, 12403, 2766,  68187, 55468, 11837, 45809, 87066, 15169, 0.817654426791482629)

    txs = [tx1, tx2, tx3, tx4, tx5, tx6]

    t0 = perf_counter()
    matches = find_common_x_any(
        txs,
        curve_mode=args.curve_mode,
    )
    dt = perf_counter() - t0

    print("----------- Finding common x for all transactions (FULL RANGE) -----------")
    total_attempts = 1
    for i, t in enumerate(txs, 1):
        low, high = factor_window(t.f)
        rng = s_zk_range(t.a, low, high)
        total_attempts *= len(rng)
        print(f"tx{i}: N (levels) = [{low}, {high}], s_zk range = [{rng.start}, {rng.stop - 1}], attempts = {len(rng)}")
    print(f"Total attempts (theoretical Cartesian product): {total_attempts:.6e}")

    if matches:
        getcontext().prec = 20 if args.curve_mode in ("test_small", "test_large") else 80
        for x, chain in matches:
            print(f"\nFound common x = {x}")
            for i, (t, szk) in enumerate(zip(txs, chain), 1):
                fv = Decimal(szk) / Decimal(t.a)
                print(f"  tx{i}: s_zk = {szk}, f = {str(fv)[:20]}")
    else:
        print("\nNo common x found.")

    print(f"\nTime spent: {dt:.3f} sec.")


if __name__ == "__main__":
    main()
