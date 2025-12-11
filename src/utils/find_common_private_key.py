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
def s_zk_range(a: int, low: int, high: int, zero_level_factor: float) -> range:
    """
    Full s_zk range for levels [low, high].

    Normal case:
        s_zk ∈ [a*low, a*high]

    Zero-level case:
        low == 0 → formal window is [0, a]
        We modify it to:
            start = max(1, round(a * zero_level_factor))
            end   = a
    """
    if high < low:
        raise ValueError("Invalid factor window.")

    if low == 0:
        start = int(round(a * zero_level_factor))
        if start < 1:
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
    zero_level_factor: float,
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
        rng = s_zk_range(t.a, low, high, zero_level_factor)
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
    parser.add_argument(
        "--zero-level-factor",
        type=float,
        default=0.01,
        help="Lower bound shift for zero-level (floor(f) == 0): s_zk_low = round(a * zero_level_factor)."
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    tx1 = ECDSATransaction("test_small", 33436, 10126, 23310, 45940, 30951, 44533, 94770, 74914, 8428,  1.201471286188894162)
    tx2 = ECDSATransaction("test_small", 68667, 22866, 45801, 86129, 8546,  46858, 94770, 72263, 16281, 1.404459185553712916)
    tx3 = ECDSATransaction("test_small", 61461, 27709, 33752, 85240, 64289, 18439, 94770, 23120, 13903, 1.993023088542041286)
    tx4 = ECDSATransaction("test_small", 64098, 19551, 44547, 90719, 35708, 6051,  94770, 72222, 10856, 1.800939572586588061)
    tx5 = ECDSATransaction("test_small", 60980, 25877, 35103, 83541, 62174, 67885, 94770, 46179, 15858, 1.631794677765165846)
    tx6 = ECDSATransaction("test_small", 22322, 11140, 11182, 35402, 50888, 59106, 94770, 93345, 9242,  1.205366803722138065)
    tx7 = ECDSATransaction("test_small", 64830, 27086, 37744, 90460, 44881, 89838, 94770, 58869, 13570, 1.996020633750921149)

    txs = [tx1, tx2, tx3, tx4, tx5, tx6, tx7]

    t0 = perf_counter()
    matches = find_common_x_any(
        txs,
        curve_mode=args.curve_mode,
        zero_level_factor=args.zero_level_factor,
    )
    dt = perf_counter() - t0

    print("----------- Finding common x for all transactions (FULL RANGE) -----------")
    total_attempts = 1
    for i, t in enumerate(txs, 1):
        low, high = factor_window(t.f)
        rng = s_zk_range(t.a, low, high, args.zero_level_factor)
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
