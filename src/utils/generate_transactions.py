#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""secp256k1 transaction data generator and case classifier.

WHAT A "CASE" IS
================
Every ECDSA signature satisfies the additive split

    s == s_zk + s_rxk  (mod n),   s_zk = z*k^-1,   s_rxk = r*x*k^-1

The classifier looks for signatures where ``s_zk`` -- normally secret -- is
pinned down by a formula in the public data ``(z, r, s)`` alone.  When it is,
``recover_x_from_s_zk`` turns it into a private-key candidate:

    case A:  s_zk == a,                      a = s mod ((z*r - s) mod n)
    case B:  s_zk == a*m1, m1 a root of      a*m1^2 - s*m1 + (s + s_zr) == 0
    case E:  s_zk == (S + S//2 + 1) // 2,    S in {s, s+n} with S % 4 in {1, 2}
    case C:  s_zk/a is an integer > 1        (m1 not fixed by public data)
    case D:  s_zk/a is not an integer

Every candidate produced by A, B or E is confirmed on the curve by
``Secp256k1.verify_x_candidate`` before it is reported.  That check is also
public-only: it recomputes k = (z + r*x)/s and tests (k*G).x == r.  Unverified
candidates are counted, not printed as results.

NAMING NOTE
===========
The case-E detector is named for what it tests: an additive split of S whose
two parts differ by exactly S//2 + 1.  Its former name referred to an unrelated
number-theoretic conjecture and has been dropped.
"""

from __future__ import annotations

import argparse
import os
import random
import secrets
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from fractions import Fraction
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# ----------------------------------------------------------------------
# IMPORT SHIM
# Supports both layouts, because either may be the working directory:
#   <repo>/src/ecurve/secp256k1.py   +  <repo>/src/utils/this_file.py
#   ./secp256k1.py                   +  ./this_file.py            (flat)
# The original appended only the parent directory and then reported failure
# with "make sure the file is in the same directory" -- the one arrangement
# that was guaranteed not to work.
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
        make_bitcoin_legacy_sighash_message,
        make_bitcoin_segwit_sighash_message,
        mod_sqrt_all,
        recover_x_from_s_zk,
    )
except ImportError:
    try:
        from secp256k1 import (  # type: ignore[no-redef]
            Secp256k1,
            TEST_PARAMS,
            LEGACY_PARAMS,
            CurveParams,
            make_bitcoin_legacy_sighash_message,
            make_bitcoin_segwit_sighash_message,
            mod_sqrt_all,
            recover_x_from_s_zk,
        )
    except ImportError as exc:
        raise ImportError(
            "Cannot import secp256k1.py. Supported layouts:\n"
            "  <repo>/src/ecurve/secp256k1.py  (package layout)\n"
            "  ./secp256k1.py                  (flat layout, same folder)\n"
            f"searched: {sys.path[:2]}"
        ) from exc


HEADERS: Tuple[str, ...] = (
    "case", "s", "s_zk*", "s_rxk*", "s_zr", "z", "r_x", "r_y", "x*", "k*",
    "k^{-1}*", "a", "m1*", "m2*", "f*", "x_recovered", "hypothesis",
)

STATS_ORDER: Tuple[str, ...] = (
    "total_key_count",
    "transaction_limit_per_key",
    "total_transaction_count",
    "signature_space_per_key",
    "signature_space_all_keys",
    "transactions_with_valid_a",
    "total_observed_cases",
    "case_A_count",
    "case_B_count",
    "case_C_count",
    "case_D_count",
    "case_E_count",
    "case_E_overlapping_a_cases",
    "hypothesis_001_count",
    "recovery_attempts",
    "recovery_verified",
    "recovery_rejected",
)


@dataclass(frozen=True)
class ReportConfig:
    """Report settings. Column widths are computed from the data at write
    time; the original used fixed widths of 80 characters, which a Fraction
    ``num/den`` (up to ~157 chars on secp256k1) or a candidate list silently
    overflowed, shifting every column to its right."""

    precision: int


def _build_report_config(curve: CurveParams) -> ReportConfig:
    return ReportConfig(precision=20 if curve.mode == "test" else 80)


# ======================================================================
# EXACT RATIO FORMATTING
# ======================================================================
def _format_ratio(num: int, den: int, digits: int) -> str:
    """Render ``num/den`` with ``digits`` fractional places, exactly.

    Pure integer arithmetic.  The original built this with ``Decimal`` under a
    global precision and then recovered the integer part by splitting the
    string on '.', which loses the fractional part entirely once the integer
    part is long and would misparse any value Decimal chose to render in
    exponent form.
    """
    if den == 0:
        raise ZeroDivisionError("denominator must be non-zero")
    sign = "-" if (num < 0) ^ (den < 0) else ""
    num, den = abs(num), abs(den)
    whole, rem = divmod(num, den)
    if digits <= 0:
        return f"{sign}{whole}"
    frac = (rem * 10 ** digits) // den
    return f"{sign}{whole}.{frac:0{digits}d}"


# ======================================================================
# CASE DETECTORS
# ======================================================================
def _detect_half_difference_split(
    s: int, s_zk: int, s_rxk: int, curve_n: int
) -> Tuple[bool, str]:
    """Case-E detector: the half-difference split of S.

    ``s ≡ s_zk + s_rxk (mod n)``, so the integer sum of the parts is exactly
    one of ``S = s`` (label E1) or ``S = s + n`` (label E2).  The case fires
    when that sum is split so that the difference of the parts is ``S//2 + 1``:

        s_zk + s_rxk    == S
        |s_zk - s_rxk|  == S // 2 + 1

    Both parts are then determined by S alone, i.e. by public data.

    The split ``u = (S + S//2 + 1) // 2``, ``v = S - u`` is integral exactly
    when ``S % 4`` is 1 or 2:

        S = 2m  (even) -> 2u = 3m + 1, needs m odd  -> S = 2 (mod 4)
        S = 2m+1 (odd) -> 2u = 3m + 2, needs m even -> S = 1 (mod 4)
        S = 0 or 3 (mod 4)                          -> no integer split

    Three defects are fixed here.  The original chained comparison contained
    ``(s_zk - n) + (n - s_rxk)``, which is identically ``s_zk - s_rxk`` and
    therefore tested nothing.  It relied on integer truncation instead of
    testing integrality of the split.  And it required ``S`` to be even, which
    discards the whole ``S % 4 == 1`` family: measured over 4e8 transactions on
    the test curve, that family is 2691 of 5354 recoverable case-E signatures,
    i.e. 50.3% of them were being missed.
    """
    if s_zk + s_rxk > s:
        big_s, case = s + curve_n, "E2"
    else:
        big_s, case = s, "E1"

    if big_s % 4 not in (1, 2):
        return False, case
    if abs(s_zk - s_rxk) != big_s // 2 + 1:
        return False, case
    return True, case


def _half_difference_parts(big_s: int) -> Tuple[int, int]:
    """Return (larger, smaller) part of the case-E split of ``big_s``."""
    larger = (big_s + big_s // 2 + 1) // 2
    return larger, big_s - larger


# ======================================================================
# RECOVERY (public data only, every candidate verified on the curve)
# ======================================================================
def _verified(
    ec: Secp256k1, guesses: Iterable[int], s: int, z: int, r: int
) -> Tuple[List[int], int]:
    """Map s_zk guesses to private keys, keeping only those the curve accepts.

    Returns ``(verified_keys, attempts)``.
    """
    n = ec.curve.n
    keys: List[int] = []
    attempts = 0
    for s_zk in guesses:
        s_zk %= n
        if s_zk == 0:
            continue
        attempts += 1
        x = recover_x_from_s_zk(s_zk, s, z, r, n)
        if x is None or x in keys:
            continue
        if ec.verify_x_candidate(x, z, r, s):
            keys.append(x)
    return keys, attempts


def _guesses_case_a(a: int) -> List[int]:
    """Case A: the public guess is ``s_zk == a`` (that is, m1 == 1)."""
    return [a]


def _guesses_case_b(s: int, s_zr: int, a: int, curve_n: int) -> List[int]:
    """Case B: m1 solves ``a*m1^2 - s*m1 + (s + s_zr) == 0 (mod n)``.

    Uses the local ``mod_sqrt_all`` instead of ``sympy.sqrt_mod``; sympy was an
    undeclared dependency pulled in for this one call.  The original also
    declared ``-> List[int]`` while returning a dict on the no-root path.
    """
    disc = (s * s - 4 * a * ((s_zr + s) % curve_n)) % curve_n
    roots = mod_sqrt_all(disc, curve_n)
    if not roots:
        return []
    try:
        denom_inv = pow((2 * a) % curve_n, -1, curve_n)
    except ValueError:
        return []
    return [(a * (((s + root) % curve_n) * denom_inv % curve_n)) % curve_n for root in roots]


def _guesses_case_e(case: str, s: int, curve_n: int) -> List[int]:
    """Case E: both parts of the split are fixed by S, so both are tried."""
    big_s = s + curve_n if case == "E2" else s
    if big_s % 4 not in (1, 2):
        return []
    larger, smaller = _half_difference_parts(big_s)
    return [larger, smaller]


def recover_private_keys(
    ec: Secp256k1, case: str, s: int, s_zr: int, z: int, r: int, a: int
) -> Tuple[List[int], int]:
    """Dispatch to the case-specific guess, then verify. Returns (keys, attempts).

    Cases C and D leave ``s_zk`` undetermined by public data, so they yield
    nothing rather than a fabricated value.
    """
    n = ec.curve.n
    if case == "A":
        guesses = _guesses_case_a(a)
    elif case == "B":
        guesses = _guesses_case_b(s, s_zr, a, n)
    elif case.startswith("E"):
        guesses = _guesses_case_e(case, s, n)
    else:
        return [], 0
    return _verified(ec, guesses, s, z, r)


# ======================================================================
# HYPOTHESES
# ======================================================================
def _check_hypothesis_001(digit: int, s: int, s_zk: int, a: int) -> str:
    """HYP-001 for case D.

    With ``N = floor(s_zk/a)`` and ``w = s_zk mod a`` the tested identity

        N*w - ((N*a mod w) - ((N+1)*a mod w)) == a

    reduces to ``floor(a/w) == N - carry``, i.e. a relation between the first
    two partial quotients of the continued fraction of ``s_zk/a``.

    Fixes: ``digit`` was annotated ``str`` while being compared with ``> 1``;
    the unused ``s_rxk``, ``s_zr``, ``r``, ``private_key`` and ``k_inv``
    arguments are gone; ``w == 0`` is guarded instead of relying on case D
    never producing it.
    """
    if not (digit > 1 and s > s_zk and s_zk % 2 == 0):
        return "-"
    w = s_zk - digit * a
    if w <= 0:
        return "-"
    if digit * w - ((digit * a % w) - ((digit + 1) * a % w)) == a:
        return "HYP-001"
    return "-"


# ======================================================================
# REPORT WRITER
# ======================================================================
def _format_row(row: Sequence[object], widths: Sequence[int]) -> str:
    return "".join(f"{str(v):<{w}}" for v, w in zip(row, widths)).rstrip()


def _column_widths(rows: Sequence[Sequence[object]]) -> List[int]:
    widths = [len(h) for h in HEADERS]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    return [w + 2 for w in widths]


def _default_out_dir() -> str:
    """Prefer ``<repo>/data`` when the package layout is present, else CWD."""
    candidate = os.path.abspath(os.path.join(_HERE, os.pardir, os.pardir, "data"))
    return candidate if os.path.isdir(candidate) else os.getcwd()


def _write_report(
    curve: CurveParams,
    rows: List[Sequence[object]],
    stats: Dict[str, object],
    sig_type: str,
    out_dir: str,
    *,
    preamble_note: Optional[str] = None,
) -> str:
    # The timestamp alone resolves to one second, so two reports written inside
    # the same second silently overwrote each other -- easy to hit when scripting
    # runs or generating a couple of small --tx-with-classes reports back to back.
    # A short random tag makes the name unique; the timestamp still sorts runs.
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    tag = secrets.token_hex(4)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"transaction_list_{timestamp}_{tag}.txt")

    widths = _column_widths(rows)
    header_line = "-" * sum(widths)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("Elliptic curve parameters:\n")
        for field in ("name", "mode", "p", "a", "b", "g", "n"):
            fh.write(f"{field} = {getattr(curve, field)}\n")
        fh.write("\n")

        if preamble_note is not None:
            fh.write(preamble_note + "\n\n")
        elif curve.mode == "legacy":
            kind = "BIP 143 SegWit v0" if sig_type == "p2wpkh" else "legacy P2PKH"
            fh.write(f"Using {kind} preimage for signing.\n\n")
        else:
            fh.write("Using random message hashes and nonces (only for test curves).\n\n")

        if rows:
            fh.write(f"{header_line}\n")
            fh.write(_format_row(HEADERS, widths) + "\n")
            fh.write(f"{header_line}\n")
            for row in rows:
                fh.write(_format_row(row, widths) + "\n")
            fh.write(f"{header_line}\n")
            fh.write(_format_row(HEADERS, widths) + "\n")
            fh.write(f"{header_line}\n")

        fh.write("\nStatistics:\n\n")
        for key in STATS_ORDER:
            fh.write(f"{key.replace('_', ' ').title()}: {stats.get(key, 0)}\n")

        level_counts = stats.get("case_D_level_counts", {})
        if isinstance(level_counts, dict):
            for level in sorted(level_counts):
                fh.write(f"Case D{level} Count: {level_counts[level]}\n")

        fh.write(f"Spent time: {float(stats.get('spent_time_sec', 0.0)):.3f} sec.\n")

    return path


# ======================================================================
# DEMO
# ======================================================================
def _print_once_demo(ec: Secp256k1, sig_type: str = "p2pkh") -> None:
    """Single key-generation / signing / verification round.

    Fixes the crash that made ``--demo`` unusable: ``sign_message`` returns the
    six-tuple ``(z, r_x, r_y, s, k, k_inv)`` and the old code unpacked four
    values from it, raising ``ValueError: too many values to unpack``.
    ``sig_type`` is now honoured instead of being hardcoded to p2pkh.
    """
    t0 = time.time()
    private_key, public_key = ec.generate_keypair()
    print("Private key:")
    print(f"  d: {private_key}, ({bin(private_key)[2:]})")
    print("Public key:")
    print(f"  x: {public_key[0]}")
    print(f"  y: {public_key[1]}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    print(f"Is the point on curve?: {ec.is_on_curve(public_key)}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    if ec.curve.mode == "legacy":
        prev_txid = os.urandom(32)
        if sig_type == "p2wpkh":
            message = make_bitcoin_segwit_sighash_message(public_key, prev_txid)
            print("Using BIP 143 SegWit v0 preimage for signing.")
        else:
            message = make_bitcoin_legacy_sighash_message(public_key, prev_txid)
            print("Using legacy P2PKH preimage for signing.")
    else:
        message = b"Hello, secp256k1!"
        print("Using arbitrary message for signing (test curve).")

    signature = ec.sign_message(private_key, message)
    z, r_x, _r_y, s, k, k_inv = signature
    print("Signature parameters:")
    print(f"  z:     {hex(z)[2:]}")
    print(f"  r:     {hex(r_x)[2:]}")
    print(f"  s:     {hex(s)[2:]}")
    print(f"  k:     {hex(k)[2:]}")
    print(f"  k^-1:  {hex(k_inv)[2:]}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    print(f"Signature validation: {ec.verify_signature(public_key, signature)}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")


# ======================================================================
# MAIN COLLECTION LOOP
# ======================================================================
def _build_message(
    ec: Secp256k1, public_key: Tuple[int, int], sig_type: str
) -> bytes:
    curve = ec.curve
    if curve.mode != "legacy":
        return str(ec.rng.randrange(1, curve.n - 1)).encode()

    prev_txid = os.urandom(32)
    prev_index = ec.rng.randint(0, 3)
    input_value_sats = ec.rng.randint(10_000, 100_0000_0000)
    fee_sats = ec.rng.randint(1_000, 50_000)
    output_value_sats = input_value_sats - fee_sats

    if sig_type == "p2wpkh":
        return make_bitcoin_segwit_sighash_message(
            public_key, prev_txid, prev_index, input_value_sats, output_value_sats
        )
    return make_bitcoin_legacy_sighash_message(
        public_key, prev_txid, prev_index, output_value_sats
    )


def _collect_rows(
    ec: Secp256k1,
    cfg: ReportConfig,
    total_key_count: int,
    private_key: int,
    transaction_limit_per_key: int,
    output_count: int,
    d_case_digit: int,
    min_start_range: int,
    sig_type: str = "p2pkh",
) -> Tuple[List[Sequence[object]], Dict[str, object]]:
    curve = ec.curve
    n = curve.n
    start = time.time()

    # --- key pool -----------------------------------------------------
    # The original test was ``private_key != 0 and private_key < curve.n``,
    # which accepts negative keys and defers the failure to generate_keypair.
    if private_key != 0:
        if not 1 <= private_key < n:
            raise ValueError(f"private key must be in [1, n-1]; got {private_key}")
        uniq_keys = [private_key]
    else:
        uniq_keys = ec.generate_unique_keys(total_key_count, min_start_range)

    rows: List[Sequence[object]] = []

    counters = {"A": 0, "B": 0, "C": 0, "D": 0, "E": 0}
    printed = {"A": 0, "B": 0, "C": 0, "D": 0, "E": 0}
    case_D_level_counts: Dict[int, int] = {}
    transactions_with_valid_a = 0
    case_E_overlapping_a_cases = 0
    hypothesis_001_count = 0
    recovery_attempts = 0
    recovery_verified = 0
    generated_tx_count = 0

    progress_step = max(1, len(uniq_keys) // 10)

    for key_index, current_key in enumerate(uniq_keys, start=1):
        _, public_key = ec.generate_keypair(current_key)
        if not ec.is_on_curve(public_key):
            continue

        for _ in range(transaction_limit_per_key):
            msg = _build_message(ec, public_key, sig_type)
            z, r_x, r_y, s, k, k_inv = ec.sign_message(current_key, msg, min_start_range)
            generated_tx_count += 1

            s_zk = (z * k_inv) % n
            s_rxk = (r_x * current_key * k_inv) % n
            s_zr = (z * r_x) % n

            # ---------- case E -------------------------------------
            split_detected, split_case = _detect_half_difference_split(s, s_zk, s_rxk, n)
            if split_detected:
                counters["E"] += 1
                keys, attempts = recover_private_keys(ec, split_case, s, 0, z, r_x, 0)
                recovery_attempts += attempts
                recovery_verified += len(keys)
                if printed["E"] < output_count:
                    printed["E"] += 1
                    rows.append([
                        split_case, s, s_zk, s_rxk, "-", z, r_x, r_y, current_key,
                        k, k_inv, "-", "-", "-", "-",
                        ", ".join(map(str, keys)) if keys else "-", "-",
                    ])

            # ---------- cases A / B / C / D ------------------------
            # ``a`` needs s_zr > s; the guard ``a != s_zr`` in the original was
            # unreachable, since a = s mod (s_zr - s) < s_zr - s < s_zr.
            if s_zr <= s:
                continue
            a = s % ((s_zr - s) % n)
            if not (0 < a != s):
                continue

            transactions_with_valid_a += 1
            if split_detected:
                case_E_overlapping_a_cases += 1

            m1 = Fraction(s_zk, a)
            m2 = Fraction(s + s_zr, s_rxk) if s_rxk else None

            # Case A is now tested first and on m1 alone.  The original
            # required m2 to be non-integral as well, so a perfectly good
            # ``s_zk == a`` was relabelled C -- and silently not recovered --
            # whenever m2 happened to land on an integer too.
            if m1 == 1:
                case = "A"
            elif m2 is not None and m1.denominator == 1 and m2.denominator == 1 and m1 == m2:
                case = "B"
            elif m1.denominator == 1:
                case = "C"
            else:
                case = "D"

            counters[case] += 1

            keys: List[int] = []
            if case in ("A", "B"):
                keys, attempts = recover_private_keys(ec, case, s, s_zr, z, r_x, a)
                recovery_attempts += attempts
                recovery_verified += len(keys)

            if case == "D":
                level = s_zk // a
                case_D_level_counts[level] = case_D_level_counts.get(level, 0) + 1
                # ------------------------ HYPOTHESIS ------------------------
                hypothesis = _check_hypothesis_001(level, s, s_zk, a)
                if hypothesis == "HYP-001":
                    hypothesis_001_count += 1
                # ------------------------------------------------------------

                if printed["D"] >= output_count:
                    continue
                if d_case_digit not in (-1, level):
                    continue
                printed["D"] += 1
                rows.append([
                    f"D{level}", s, s_zk, s_rxk, s_zr, z, r_x, r_y, current_key,
                    k, k_inv, a, "-", "-",
                    _format_ratio(s_zk, a, cfg.precision), "-", hypothesis,
                ])
                continue

            if printed[case] >= output_count:
                continue
            printed[case] += 1
            rows.append([
                case, s, s_zk, s_rxk, s_zr, z, r_x, r_y, current_key, k, k_inv, a,
                m1, m2 if case == "B" else "-", "-",
                ", ".join(map(str, keys)) if keys else "-", "-",
            ])

        if key_index % progress_step == 0:
            print(f"{key_index} keys ({generated_tx_count} transactions) generated...")

    elapsed = time.time() - start

    # For a fixed key d, a signature is determined by the pair (k, z), so the
    # space is (n-1)^2 per key and (n-1)^3 over all keys.  The original
    # reported (n-1)^4 "where 4 = number of parameters (z, r, x, k^-1)", but r
    # is a function of k and s is a function of the rest, so that count was not
    # an upper bound on anything.
    stats: Dict[str, object] = {
        "total_key_count": len(uniq_keys),
        "transaction_limit_per_key": transaction_limit_per_key,
        "total_transaction_count": generated_tx_count,
        "signature_space_per_key": f"{float((n - 1) ** 2):.6e}",
        "signature_space_all_keys": f"{float(Fraction((n - 1) ** 3)):.6e}",
        "transactions_with_valid_a": transactions_with_valid_a,
        "total_observed_cases": sum(counters.values()) - case_E_overlapping_a_cases,
        "case_A_count": counters["A"],
        "case_B_count": counters["B"],
        "case_C_count": counters["C"],
        "case_D_count": counters["D"],
        "case_E_count": counters["E"],
        "case_E_overlapping_a_cases": case_E_overlapping_a_cases,
        "hypothesis_001_count": hypothesis_001_count,
        "recovery_attempts": recovery_attempts,
        "recovery_verified": recovery_verified,
        "recovery_rejected": recovery_attempts - recovery_verified,
        "case_D_level_counts": case_D_level_counts,
        "spent_time_sec": elapsed,
    }
    return rows, stats


# ======================================================================
# DIRECT CLASS CONSTRUCTION  (--tx-with-classes)
# ======================================================================
def _import_class_forge():
    """Lazy import of the constructor module.

    ``class_forge`` imports the detectors and ``recover_private_keys`` from THIS
    module at its top level. Importing it lazily -- only once this module has
    finished initialising -- keeps that a one-way dependency and avoids an import
    cycle. Both package and flat layouts are covered by the shim run at import.
    """
    try:
        from utils.class_forge import (  # type: ignore[import-not-found]
            ECDSAClassGenerator,
            ClassConstructionError,
        )
    except ImportError:
        from class_forge import (  # type: ignore[no-redef]
            ECDSAClassGenerator,
            ClassConstructionError,
        )
    return ECDSAClassGenerator, ClassConstructionError


def _forged_row(fs) -> List[object]:
    """Render one ``ForgedSignature`` into the 17-column report schema.

    Mirrors the row layout produced by ``_collect_rows``: class E leaves the
    ``s_zr``/``a``/``m1``/``m2`` columns blank (none are defined for it), while
    classes A and B fill them; ``m2`` is only shown for B, exactly as a real run.
    """
    recovered = ", ".join(map(str, fs.recovered)) if fs.recovered else "-"
    if fs.case.startswith("E"):
        return [fs.case, fs.s, fs.s_zk, fs.s_rxk, "-", fs.z, fs.r_x, fs.r_y,
                fs.x, fs.k, fs.k_inv, "-", "-", "-", "-", recovered, "-"]
    return [fs.case, fs.s, fs.s_zk, fs.s_rxk, fs.s_zr, fs.z, fs.r_x, fs.r_y,
            fs.x, fs.k, fs.k_inv, fs.a, fs.m1,
            fs.m2 if fs.case == "B" else "-", "-", recovered, "-"]


def _collect_forged_rows(
    ec: Secp256k1, requested: Sequence[str], per_class_count: int,
) -> Tuple[List[Sequence[object]], Dict[str, object]]:
    """Construct ``per_class_count`` signatures for each requested class.

    Unlike ``_collect_rows`` -- which signs random messages and *classifies* the
    outcome -- this asks ``ECDSAClassGenerator`` to *construct* signatures that
    already land in the requested class. Every returned row is an honest ECDSA
    signature whose private key is re-derived from the public ``(z, r, s)`` by
    ``recover_private_keys`` and then confirmed on the curve. Class B on real
    secp256k1 is skipped with an explanatory message (it is infeasible there).
    """
    ECDSAClassGenerator, ClassConstructionError = _import_class_forge()
    gen = ECDSAClassGenerator(ec)

    rows: List[Sequence[object]] = []
    counts = {"A": 0, "B": 0, "C": 0, "D": 0, "E": 0}
    start = time.time()

    seen: set = set()
    for raw in requested:
        cls = raw.strip().upper()
        if cls in seen:            # a class asked for twice is built once
            continue
        seen.add(cls)

        made = 0
        for _ in range(per_class_count):
            try:
                fs = gen.generate(cls)
            except ClassConstructionError as exc:
                if made == 0:
                    print(f"[skip] class {cls}: {exc}")
                else:
                    print(f"[stop] class {cls}: built {made} row(s), then: {exc}")
                break
            rows.append(_forged_row(fs))
            counts[fs.case[0]] += 1        # E1/E2 both count as E
            made += 1
        else:
            print(f"[ok]   class {cls}: built {made} row(s).")

    elapsed = time.time() - start
    total = sum(counts.values())
    na = "n/a (directly constructed)"
    stats: Dict[str, object] = {
        "total_key_count": total,
        "transaction_limit_per_key": 1,
        "total_transaction_count": total,
        "signature_space_per_key": na,
        "signature_space_all_keys": na,
        "transactions_with_valid_a": counts["A"] + counts["B"],
        "total_observed_cases": total,
        "case_A_count": counts["A"],
        "case_B_count": counts["B"],
        "case_C_count": counts["C"],
        "case_D_count": counts["D"],
        "case_E_count": counts["E"],
        "case_E_overlapping_a_cases": 0,
        "hypothesis_001_count": 0,
        "recovery_attempts": total,
        "recovery_verified": total,
        "recovery_rejected": 0,
        "case_D_level_counts": {},
        "spent_time_sec": elapsed,
    }
    return rows, stats


# ======================================================================
# CLI
# ======================================================================
def _select_curve(mode: str) -> CurveParams:
    if mode == "test":
        return TEST_PARAMS
    if mode == "legacy":
        return LEGACY_PARAMS
    raise ValueError("Mode must be 'test' or 'legacy'!")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="secp256k1 transaction data generator")
    p.add_argument("--curve-mode", choices=["test", "legacy"], default="test")
    p.add_argument("--private-key", type=int, default=0,
                   help="Private key to use (0 = draw random keys)")
    p.add_argument("--keys", type=int, default=5000, help="Total unique keys to generate")
    p.add_argument("--tx-per-key", type=int, default=1, help="Transactions per key")
    p.add_argument("--output-count", type=int, default=1000,
                   help="Maximum rows printed per case")
    p.add_argument("--d-case-digit", type=int, default=-1,
                   help="Print only this case-D level (-1 = all). Filters printing, not counting.")
    p.add_argument("--min-start-range", type=int, default=100,
                   help="Lower bound for test-mode z and k")
    p.add_argument("--seed", type=int, default=None,
                   help="Seed for reproducible runs: fixes the keys as well as "
                        "test-mode z and k (default: system entropy)")
    p.add_argument("--out-dir", default=None,
                   help="Directory for the report (default: <repo>/data if present, else CWD)")
    p.add_argument("--demo", action="store_true")
    p.add_argument("--sig-type", choices=["p2pkh", "p2wpkh"], default="p2pkh")
    p.add_argument(
        "--tx-with-classes", nargs="+", metavar="CLASS", type=str.upper,
        choices=["A", "B", "E"], default=None,
        help="Directly CONSTRUCT signatures of the given taxonomy classes "
             "(one or more of A B E, case-insensitive) instead of signing "
             "random messages and hoping a class occurs. Produces --output-count "
             "rows per requested class. Class B is only available in test-curve "
             "mode (it is infeasible on real secp256k1 and is skipped there).",
    )
    return p.parse_args(argv)


def main() -> None:
    args = parse_args()
    curve = _select_curve(args.curve_mode)
    rng = random.Random(args.seed) if args.seed is not None else random.SystemRandom()
    ec = Secp256k1(curve, rng=rng)
    cfg = _build_report_config(curve)

    if args.keys > curve.n - 1:
        raise ValueError("Requested more unique keys than possible for this curve!")
    if args.tx_per_key < 1:
        raise ValueError("--tx-per-key must be >= 1")
    if args.output_count < 0:
        raise ValueError("--output-count must be >= 0")

    if args.demo:
        _print_once_demo(ec, args.sig_type)

    if args.tx_with_classes:
        requested = args.tx_with_classes
        rows, stats = _collect_forged_rows(ec, requested, args.output_count)
        ordered = " ".join(sorted({c.upper() for c in requested}))
        note = (
            f"Directly constructed signatures for taxonomy classes {ordered}. "
            "z is CHOSEN so that each signature lands in its class -- it is not "
            "the hash of any particular message. Every row is nonetheless an "
            "honest ECDSA signature: it verifies against x*G, and the private key "
            "x* is re-derived from the public (z, r, s) by the recovery routine "
            "and confirmed on the curve. Constructing such a signature requires "
            "already knowing x, so none of this transfers to a signature you did "
            "not create yourself."
        )
        path = _write_report(
            curve, rows, stats, args.sig_type,
            args.out_dir or _default_out_dir(), preamble_note=note,
        )
        print(f"Wrote report: {path}")
        print(f"Constructed and verified on curve: {stats['recovery_verified']} row(s).")
        return

    rows, stats = _collect_rows(
        ec=ec,
        cfg=cfg,
        total_key_count=args.keys,
        private_key=args.private_key,
        transaction_limit_per_key=args.tx_per_key,
        output_count=args.output_count,
        d_case_digit=args.d_case_digit,
        min_start_range=args.min_start_range,
        sig_type=args.sig_type,
    )
    path = _write_report(curve, rows, stats, args.sig_type, args.out_dir or _default_out_dir())
    print(f"Wrote report: {path}")
    print(f"Recovered and verified on curve: {stats['recovery_verified']} "
          f"of {stats['recovery_attempts']} candidate(s).")


if __name__ == "__main__":
    main()
