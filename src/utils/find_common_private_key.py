#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Search for a private key shared by several ECDSA transactions.

METHOD
======
For each transaction the unknown ``s_zk = z*k^-1 mod n`` is searched over the
level window

    s_zk in [a*N, a*(N+1) - 1],    N = floor(s_zk / a)

Each trial value yields a key candidate through the public relation

    x = z*(s - s_zk) * (r*s_zk)^-1  (mod n)

The candidate sets of the transactions are intersected, and every survivor is
then confirmed on the curve with ``Secp256k1.verify_x_candidate`` -- which uses
public data only: it recomputes ``k = (z + r*x)/s`` and tests ``(k*G).x == r``.

WHY THE VERIFICATION MATTERS
============================
Without it the intersection is not conclusive.  For k transactions the expected
number of coincidental survivors is roughly ``prod(|W_i|) / n^(k-1)``; at the
window sizes in the bundled demo that quantity is close to 1, so the search
returned the true key alongside, on average, one or two impostors and had no
way to tell them apart.  The verification step removes them.

SCOPE
=====
``N`` is derived from ``f = s_zk/a`` and is therefore an input, not something
the search discovers.  ``--max-window`` bounds the work; on secp256k1 a single
window is on the order of ``a`` itself, so the search is rejected rather than
started.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from time import perf_counter
from typing import DefaultDict, Dict, Iterable, List, Optional, Sequence, Tuple, Union

# ----------------------------------------------------------------------
# IMPORT SHIM -- see the note in generate_transactions.py
# ----------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
for _candidate in (os.path.abspath(os.path.join(_HERE, os.pardir)), _HERE):
    if _candidate not in sys.path:
        sys.path.insert(0, _candidate)

try:
    from ecurve.secp256k1 import (  # type: ignore[import-not-found]
        Secp256k1,
        TEST_PARAMS,
        LEGACY_PARAMS,
        CurveParams,
        recover_x_from_s_zk,
    )
except ImportError:
    try:
        from secp256k1 import (  # type: ignore[no-redef]
            Secp256k1,
            TEST_PARAMS,
            LEGACY_PARAMS,
            CurveParams,
            recover_x_from_s_zk,
        )
    except ImportError as exc:
        raise ImportError(
            "Cannot import secp256k1.py. Supported layouts:\n"
            "  <repo>/src/ecurve/secp256k1.py  (package layout)\n"
            "  ./secp256k1.py                  (flat layout, same folder)\n"
            f"searched: {sys.path[:2]}"
        ) from exc


CURVES: Dict[str, CurveParams] = {"test": TEST_PARAMS, "legacy": LEGACY_PARAMS}
PRECISION: Dict[str, int] = {"test": 20, "legacy": 80}

RatioLike = Union[str, int, Fraction, Decimal]


def exact_level(f: RatioLike) -> int:
    """Return ``floor(f)`` exactly.

    ``float`` is refused on purpose.  The reports carry f with 20 (test) or 80
    (legacy) significant digits; ``float`` keeps about 16.  Two concrete
    failures followed from feeding it in:

      * ``float("4.9999999999999999")`` is ``5.0``, so the window jumps to the
        level above the one that actually contains s_zk;
      * at secp256k1 scale ``int(float(f))`` misses the true floor by about
        4.3e38, so the window cannot contain s_zk at all.

    Pass a string, Fraction, Decimal or int.
    """
    if isinstance(f, bool):
        raise TypeError("f must be a number, not a bool")
    if isinstance(f, float):
        raise TypeError(
            "f must not be a float: 16 significant digits cannot hold the "
            "reported ratio. Pass the value as a string, e.g. f=\"11.2538860103626943\"."
        )
    if isinstance(f, int):
        value = Fraction(f)
    elif isinstance(f, Fraction):
        value = f
    elif isinstance(f, Decimal):
        value = Fraction(f)
    elif isinstance(f, str):
        value = Fraction(Decimal(f.strip()))
    else:
        raise TypeError(f"unsupported type for f: {type(f).__name__}")
    if value < 0:
        raise ValueError("f must be non-negative.")
    return value.numerator // value.denominator


# ======================================================================
# DATA MODEL
# ======================================================================
@dataclass(frozen=True)
class ECDSATransaction:
    """One transaction.

    The search reads ``s, z, r, a, level`` only.  ``s_zk_true`` and
    ``x_expected`` are ground truth kept for the self-check at the end of a
    demo run; the original dataclass carried the answer (``x``) in the same
    namespace as the inputs, which made it easy to lose track of what the
    search actually consumes.
    """

    s: int
    z: int
    r: int
    a: int
    level: int
    s_zk_true: Optional[int] = None
    x_expected: Optional[int] = None

    def __post_init__(self) -> None:
        if self.a < 1:
            raise ValueError("a must be >= 1")
        if self.level < 0:
            raise ValueError("level must be >= 0")

    @classmethod
    def from_ratio(
        cls,
        *,
        s: int,
        z: int,
        r: int,
        a: int,
        f: RatioLike,
        s_zk_true: Optional[int] = None,
        x_expected: Optional[int] = None,
    ) -> "ECDSATransaction":
        return cls(
            s=s, z=z, r=r, a=a, level=exact_level(f),
            s_zk_true=s_zk_true, x_expected=x_expected,
        )


# ======================================================================
# WINDOWS
# ======================================================================
def s_zk_window(a: int, level: int) -> range:
    """Half-open level window ``[a*level, a*(level+1) - 1]``, size ``a``.

    ``s_zk == a*(level+1)`` would have floor ``level+1``, so the original
    inclusive upper bound added a value that cannot belong to this level and
    made the window ``a+1`` wide for ``level > 0`` but ``a`` wide for
    ``level == 0``.  Zero is still skipped: ``s_zk == 0`` implies ``z == 0``.
    """
    if a < 1:
        raise ValueError("a must be >= 1")
    if level < 0:
        raise ValueError("level must be >= 0")
    return range(max(1, a * level), a * (level + 1))


def window_size(window: range) -> int:
    """Number of values in ``window``, computed arithmetically.

    ``len(range(...))`` raises ``OverflowError: Python int too large to convert
    to C ssize_t`` once the span exceeds 2**63, which is exactly the legacy
    case this module has to be able to describe before refusing it.
    """
    return max(0, window.stop - window.start)


def build_x_index(
    s: int, z: int, r: int, n: int, candidates: Iterable[int]
) -> DefaultDict[int, List[int]]:
    """Map each key candidate to the s_zk values that produce it."""
    out: DefaultDict[int, List[int]] = defaultdict(list)
    for s_zk in candidates:
        x = recover_x_from_s_zk(s_zk, s, z, r, n)
        if x is not None:
            out[x].append(s_zk)
    return out


# ======================================================================
# SEARCH
# ======================================================================
def find_common_x(
    txs: Sequence[ECDSATransaction],
    ec: Secp256k1,
    verify: bool = True,
    max_window: int = 50_000_000,
) -> List[Tuple[int, List[int]]]:
    """Intersect the per-transaction candidate sets and verify the survivors.

    Returns ``[(x, [s_zk per transaction in input order]), ...]``.
    """
    if len(txs) < 2:
        raise ValueError("At least two transactions are required.")
    n = ec.curve.n

    windows = [s_zk_window(t.a, t.level) for t in txs]
    widest = max(window_size(w) for w in windows)
    if widest > max_window:
        raise ValueError(
            f"window of {widest:,} values exceeds --max-window ({max_window:,}). "
            f"On {ec.curve.name} a level window is about as large as 'a' itself, "
            "so an exhaustive scan of it is not a viable search."
        )

    order = sorted(range(len(txs)), key=lambda i: window_size(windows[i]))

    base = order[0]
    chains: DefaultDict[int, List[Dict[int, int]]] = defaultdict(list)
    for x, s_zk_list in build_x_index(txs[base].s, txs[base].z, txs[base].r, n, windows[base]).items():
        for s_zk in s_zk_list:
            chains[x].append({base: s_zk})

    for idx in order[1:]:
        current = build_x_index(txs[idx].s, txs[idx].z, txs[idx].r, n, windows[idx])
        merged: DefaultDict[int, List[Dict[int, int]]] = defaultdict(list)
        for x, chain_list in chains.items():
            if x not in current:
                continue
            for chain in chain_list:
                for s_zk in current[x]:
                    extended = dict(chain)
                    extended[idx] = s_zk
                    merged[x].append(extended)
        chains = merged
        if not chains:
            return []

    results: List[Tuple[int, List[int]]] = []
    for x in sorted(chains):
        if verify and not all(ec.verify_x_candidate(x, t.z, t.r, t.s) for t in txs):
            continue
        for chain in chains[x]:
            if len(chain) != len(txs):
                continue
            results.append((x, [chain[i] for i in range(len(txs))]))
    return results


# ======================================================================
# CLI + DEMO
# ======================================================================
def demo_transactions() -> List[ECDSATransaction]:
    """Bundled demo bundle: four transactions sharing the key x = 32768.

    f is passed as a string so the level is computed exactly.
    """
    #                             s       z       r       a       f
    raw = [
        (31808, 62889, 32461, 3281,  "11.25388601036269430", 36924),
        (51963, 71144, 60685, 5725,  "0.741310043668122270", 4244),
        (44381, 49223, 1710,  4376,  "4.762111517367458866", 20839),
        (33155, 13718, 7807,  12242, "0.686815879758209442", 8408),
    ]
    return [
        ECDSATransaction.from_ratio(
            s=s, z=z, r=r, a=a, f=f, s_zk_true=s_zk, x_expected=32768
        )
        for s, z, r, a, f, s_zk in raw
    ]


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Search for a common private key over level windows."
    )
    p.add_argument("--curve-mode", choices=sorted(CURVES), default="test")
    p.add_argument("--max-window", type=int, default=50_000_000,
                   help="Refuse windows wider than this (default: 50,000,000)")
    p.add_argument("--no-verify", action="store_true",
                   help="Skip the on-curve check (shows the raw, ambiguous intersection)")
    return p.parse_args(argv)


def main() -> None:
    args = parse_args()
    curve = CURVES[args.curve_mode]          # KeyError is impossible: argparse
    precision = PRECISION[args.curve_mode]   # constrains the choice.
    ec = Secp256k1(curve)
    txs = demo_transactions()

    print("----------- Finding common x for all transactions -----------")
    windows = [s_zk_window(t.a, t.level) for t in txs]
    scanned = sum(window_size(w) for w in windows)
    naive_product = 1
    for i, (t, w) in enumerate(zip(txs, windows), 1):
        naive_product *= window_size(w)
        print(f"tx{i}: N = {t.level}, s_zk in [{w.start}, {w.stop - 1}], window = {window_size(w):,}")

    # The original printed only the Cartesian product and called it "total
    # attempts". The algorithm never enumerates that product -- it builds one
    # index per transaction and intersects -- so the figure overstated the work
    # by about eleven orders of magnitude on this very demo.
    print(f"\nCandidates actually evaluated: {scanned:,}")
    print(f"Naive Cartesian product (not performed): {naive_product:.6e}")
    expected_noise = naive_product / curve.n ** (len(txs) - 1)
    print(f"Expected coincidental survivors before verification: {expected_noise:.3f}")

    t0 = perf_counter()
    matches = find_common_x(txs, ec, verify=not args.no_verify, max_window=args.max_window)
    elapsed = perf_counter() - t0

    if matches:
        for x, chain in matches:
            print(f"\nFound common x = {x}"
                  f"{'' if args.no_verify else '  [verified on curve]'}")
            for i, (t, s_zk) in enumerate(zip(txs, chain), 1):
                print(f"  tx{i}: s_zk = {s_zk}, f = {_ratio_text(s_zk, t.a, precision)}")
    else:
        print("\nNo common x found.")

    expected = {t.x_expected for t in txs if t.x_expected is not None}
    if len(expected) == 1:
        target = expected.pop()
        got = {x for x, _ in matches}
        print(f"\nSelf-check: expected x = {target}; "
              f"returned {sorted(got)} -> {'OK' if got == {target} else 'MISMATCH'}")

    print(f"\nTime spent: {elapsed:.3f} sec.")


def _ratio_text(num: int, den: int, digits: int) -> str:
    """Exact decimal rendering of ``num/den`` -- no Decimal context, no
    string truncation, no exponent form."""
    whole, rem = divmod(num, den)
    return f"{whole}.{(rem * 10 ** digits) // den:0{digits}d}"


if __name__ == "__main__":
    main()
