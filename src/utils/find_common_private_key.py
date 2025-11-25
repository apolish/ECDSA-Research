#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from decimal import Decimal, ROUND_FLOOR, getcontext
from time import perf_counter
from typing import Iterable, List, Optional, Tuple, DefaultDict
from collections import defaultdict

try:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from ecurve.secp256k1 import Secp256k1, TEST_PARAMS_LARGE, LEGACY_PARAMS  # type: ignore
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "Failed to import local 'secp256k1.py'. "
        "Make sure the file is in the same directory."
    ) from exc

FACTOR_WIDTH = 0.09  # width of the factor window for searching

@dataclass(frozen=True)
class ECDSATransaction:
    mode: str
    s: int
    s_zk: int
    s_rxk: int
    s_zr: int
    z: int
    r: int
    x: int
    k_inv: int
    q: int
    a: int
    f: float  # base multiplier for forming the range s_zk


def inverse_mod_safe(k: int, m: int) -> Optional[int]:
    try:
        return pow(k, -1, m)
    except ValueError:
        return None


def recover_x(s_zk: int, s: int, z: int, r: int, n: int) -> Optional[int]:
    num = (z * (s - s_zk)) % n
    den = (r * s_zk) % n
    den_inv = inverse_mod_safe(den, n)
    if den_inv is None:
        return None
    return (num * den_inv) % n


def factor_window(f: float, width: float = FACTOR_WIDTH) -> Tuple[Decimal, Decimal]:
    df = Decimal(str(f))
    low = df.quantize(Decimal(str(width).replace("9", "1")), rounding=ROUND_FLOOR)
    high = low + Decimal(str(width))
    return low, high


def s_zk_range(a: int, low: Decimal, high: Decimal) -> range:
    start = int((Decimal(a) * low).to_integral_value(rounding=ROUND_FLOOR))
    end = int((Decimal(a) * high).to_integral_value(rounding=ROUND_FLOOR))
    return range(start, end + 1)


def build_x_index(
    s: int, z: int, r: int, n: int, candidates: Iterable[int]
) -> DefaultDict[int, List[int]]:
    """
    For one transaction, it builds an index x -> list of s_zk that give this x.
    """
    out: DefaultDict[int, List[int]] = defaultdict(list)
    for s_zk in candidates:
        x = recover_x(s_zk, s, z, r, n)
        if x is not None:
            out[x].append(s_zk)
    return out


def find_common_x_any(
    txs: List[ECDSATransaction],
    curve_mode: str = "test",
    factor_width: float = FACTOR_WIDTH,
) -> List[Tuple[int, List[int]]]:
    """
    Common x for any number of transactions (>=2).
    Returns a list (x, [s_zk_i in incoming order]).
    If there are multiple s_zk sets for x, returns all.
    """
    if len(txs) < 2:
        raise ValueError("At least two transactions are required.")

    modes = {t.mode for t in txs}
    if len(modes) != 1:
        raise ValueError("The same 'mode' is expected for all transactions.")

    getcontext().prec = 20 if curve_mode == "test" else 80
    ec = Secp256k1(TEST_PARAMS_LARGE if curve_mode == "test" else LEGACY_PARAMS)
    n = ec.curve.n

    # Generate candidates s_zk for each transaction
    items = []
    for idx, t in enumerate(txs):
        low, high = factor_window(t.f, width=factor_width)
        rng = s_zk_range(t.a, low, high)
        items.append((idx, t, rng))

    # Sort by range width
    items_sorted = sorted(items, key=lambda x: len(x[2]))

    # Base index for the narrowest range
    first_idx, first_tx, first_rng = items_sorted[0]
    idx_map: DefaultDict[int, List[List[Tuple[int, int]]]] = defaultdict(list)
    base_index = build_x_index(first_tx.s, first_tx.z, first_tx.r, n, first_rng)
    for x, s_list in base_index.items():
        for s in s_list:
            idx_map[x].append([(first_idx, s)])

    # Consecutive intersections in x
    for pos in range(1, len(items_sorted)):
        cur_idx, cur_tx, cur_rng = items_sorted[pos]
        cur_index = build_x_index(cur_tx.s, cur_tx.z, cur_tx.r, n, cur_rng)
        new_map: DefaultDict[int, List[List[Tuple[int, int]]]] = defaultdict(list)

        for x, chains in idx_map.items():
            if x not in cur_index:
                continue
            for chain in chains:
                for s_cur in cur_index[x]:
                    new_chain = list(chain)
                    new_chain.append((cur_idx, s_cur))
                    new_map[x].append(new_chain)

        idx_map = new_map
        if not idx_map:
            return []

    # Restoring the order of transactions
    results: List[Tuple[int, List[int]]] = []
    for x, chains in idx_map.items():
        for chain in chains:
            ordered = [None] * len(txs)
            for orig_pos, s in chain:
                ordered[orig_pos] = s
            if any(v is None for v in ordered):
                continue
            results.append((x, ordered))  # type: ignore

    return results


def main() -> None:
    # Demo data
    tx1 = ECDSATransaction(
        "test",
        459571451,
        348404429,
        111167022,
        826948871,
        739837011,
        1101966157,
        621753600,
        884694657,
        367377420,
        92194031,
        3.779034555935622339,
    )
    tx2 = ECDSATransaction(
        "test",
        877323445,
        194417748,
        682905697,
        1218100508,
        1168161469,
        698890601,
        621753600,
        1186182482,
        340777063,
        195769319,
        0.993096104093818705,
    )
    tx3 = ECDSATransaction(
        "test",
        368393195,
        805954802,
        804069136,
        509368551,
        630898708,
        800526239,
        621753600,
        1022889089,
        140975356,
        86442483,
        9.323596153525576075,
    )
    tx4 = ECDSATransaction(
        "test",
        303412819,
        408371557,
        1136672005,
        486043919,
        772845050,
        1139016727,
        621753600,
        7218970,
        182631100,
        120781719,
        3.381070913554393111
    )
    tx5 = ECDSATransaction(
        "test",
        261496431,
        255836041,
        5660390,
        458673444,
        516074317,
        439175992,
        621753600,
        897225613,
        197177013,
        64319418,
        3.977586379901634060
    )

    txs = [tx1, tx2, tx3, tx4, tx5]

    modes = {t.mode for t in txs}
    if modes != {"test"}:
        raise ValueError("Expected 'test' mode for all transactions in this demo.")

    t0 = perf_counter()
    matches_all = find_common_x_any(txs, curve_mode="test", factor_width=FACTOR_WIDTH)
    dt_all = perf_counter() - t0

    print("----------- Finding common x for all transactions -----------")
    total_attemts = 1
    for i, t in enumerate(txs, 1):
        low, high = factor_window(t.f)
        rng = s_zk_range(t.a, low, high)
        total_attemts *= len(rng)
        print(f"s_zk{i}: [{rng.start}, {rng.stop - 1}], {len(rng)} attempts")
    print(f"Total attempts (approx): {total_attemts:.6e}")

    if matches_all:
        for x, s_list in matches_all:
            print(f"Match for everyone tx: x = {x}")
            for i, (t, s_zk_val) in enumerate(zip(txs, s_list), 1):
                f_val = Decimal(s_zk_val) / Decimal(t.a)
                print(f"  tx{i}: s_zk = {s_zk_val}, f{i} = {str(f_val)[:20]}")
    else:
        print("No matches found for x for all transactions.")

    print(f"Spent: {dt_all:.3f} sec.")


if __name__ == "__main__":
    main()
