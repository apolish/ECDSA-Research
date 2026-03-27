#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import os
import random
import time
import sys
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, getcontext
from fractions import Fraction
from math import gcd
from typing import Iterable, List, Sequence, Tuple
import re
from sympy import mod_inverse, sqrt_mod

try:
    # Add the path to the parent directory
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from ecurve.secp256k1 import (
        Secp256k1,
        TEST_PARAMS_TINY,
        TEST_PARAMS_SMALL,
        TEST_PARAMS_LARGE,
        LEGACY_PARAMS,
        CurveParams,
        make_bitcoin_legacy_sighash_message,
        make_bitcoin_segwit_sighash_message,
    )
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "Failed to import local 'secp256k1.py'. "
        "Make sure the file is in the same directory."
    ) from exc


@dataclass(frozen=True)
class ReportConfig:
    precision: int
    column_widths: Sequence[int]
    line_length: int
    headers: Sequence[str] = (
        "case", "s", "s_zk", "s_rxk", "s_zr", "z", "r", "x", "k^{-1}", "a", "m1", "m2", "f", "x_recovered", "hypothesis"
    )


def _build_report_config(curve: CurveParams) -> ReportConfig:
    if curve.mode == "test":
        precision = 20
        getcontext().prec = precision
        column_widths = [13, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, precision + 5, 28, 12]
        line_length = 145 + precision + 5 + 28 + 12
    else:
        precision = 80
        getcontext().prec = precision
        column_widths = [81, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, precision + 5, 80, 12]
        line_length = 961 + precision + 5 + 80 + 12
    return ReportConfig(precision=precision, column_widths=column_widths, line_length=line_length)


def _print_once_demo(ec: Secp256k1, sig_type: str = "p2pkh") -> None:
    import time
    pk: int
    pub: Tuple[int, int]

    t0 = time.time()
    pk, pub = ec.generate_keypair()
    print("Private key:")
    print(f"  d: {pk}, ({bin(pk)[2:]})")
    print("Public key:")
    print(f"  x: {pub[0]}")
    print(f"  y: {pub[1]}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    print(f"Is the point on curve?: {ec.is_on_curve(pub)}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    if ec.curve.mode == "legacy":
        prev_txid = os.urandom(32)
        if sig_type == "p2wpkh":
            # SegWit v0 (P2WPKH) — BIP 143 SIGHASH_ALL preimage
            message = make_bitcoin_segwit_sighash_message(pub, prev_txid)
            print("Using BIP 143 SegWit v0 preimage for signing.")
        else:
            # Legacy P2PKH — traditional SIGHASH_ALL preimage
            message = make_bitcoin_legacy_sighash_message(pub, prev_txid)
            print("Using legacy P2PKH preimage for signing.")
    else:
        # For test curves we keep an arbitrary message; z is randomized in hash_message
        message = b"Hello, secp256k1!"
    sig = ec.sign_message(pk, message)
    z, r, s, k_inv = sig
    print("Signature parameters:")
    print(f"  z:   {hex(z)[2:]}")
    print(f"  r:   {hex(r)[2:]}")
    print(f"  s:   {hex(s)[2:]}")
    print(f"  k-1: {hex(k_inv)[2:]}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    print(f"Signature validation: {ec.verify_signature(pub, sig)}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")


def _format_row(row: Sequence[object], widths: Sequence[int]) -> str:
    cells = []
    for val, w in zip(row, widths):
        cells.append(f"{str(val):<{w}}")
    return "".join(cells)


def _write_report(
    curve: CurveParams,
    cfg: ReportConfig,
    rows: List[Sequence[object]],
    stats: dict,
    sig_type: str = "p2pkh",
) -> str:
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    fname = f"transaction_list_{timestamp}.txt"
    header_line = "-" * cfg.line_length

    with open(fname, "w", encoding="utf-8") as f:
        # Elliptic curve parameters
        f.write("Elliptic curve parameters:\n")
        f.write(f"name = {curve.name}\n")
        f.write(f"mode = {curve.mode}\n")
        f.write(f"p = {curve.p}\n")
        f.write(f"a = {curve.a}\n")
        f.write(f"b = {curve.b}\n")
        f.write(f"g = {curve.g}\n")
        f.write(f"n = {curve.n}\n\n")
        if sig_type == "p2wpkh":
            # SegWit v0 (P2WPKH) — BIP 143 SIGHASH_ALL preimage
            f.write("Using BIP 143 SegWit v0 preimage for signing.\n\n")
        else:
            # Legacy P2PKH — traditional SIGHASH_ALL preimage
            f.write("Using legacy P2PKH preimage for signing.\n\n")

        # Rows table
        if rows:
            f.write(f"{header_line}\n")
            f.write(_format_row(cfg.headers, cfg.column_widths) + "\n")
            f.write(f"{header_line}\n")
            for row in rows:
                f.write(_format_row(row, cfg.column_widths) + "\n")
            f.write(f"{header_line}\n")
            f.write(_format_row(cfg.headers, cfg.column_widths) + "\n")
            f.write(f"{header_line}\n")

        # Statistics
        f.write("\nStatistics:\n\n")

        base_keys = [
            "total_key_count",
            "transaction_limit_per_key",
            "total_transaction_count",
            "maximum_transaction_count",
            "total_cases",
            "case_A_count",
            "case_B_count",
            "case_C_count",
            "case_D_count",
            "case_E_count",
        ]

        # Reliable collection and sorting case_D<number>_count
        dynamic_items: list[tuple[int, str]] = []
        for k in stats.keys():
            m = re.fullmatch(r"case_D(\d+)_count", k)
            if m:
                dynamic_items.append((int(m.group(1)), k))
        dynamic_items.sort(key=lambda t: t[0])

        # Output base keys
        for k in base_keys:
            v = stats.get(k, 0)
            f.write(f"{k.replace('_', ' ').title()}: {v}\n")

        # Output dynamic keys in ascending numerical order
        for _, k in dynamic_items:
            v = stats[k]
            f.write(f"{k.replace('_', ' ').title()}: {v}\n")

        # Spent time
        spent = stats.get("spent_time_sec", 0.0)
        f.write(f"Spent time: {spent:.3f} sec.\n")

    return fname


def _goldbach_condition(s: int, s_zk: int, s_rxk: int, curve_n: int) -> Tuple[bool, str]:
    """Check Goldbach condition for case E1 and E2."""
    result = False
    case = "E1"
    if s_zk + s_rxk > s:
        s += curve_n
        case = "E2"
    if s % 2 == 0:
        n = s // 2
        if ((s_zk > s_rxk) and (s_zk - s_rxk == (s_zk - n) + (n - s_rxk) == n + 1)) or \
           ((s_rxk > s_zk) and (s_rxk - s_zk == (s_rxk - n) + (n - s_zk) == n + 1)):
            result = True
    return result, case


def _recover_private_key_case_b(s: int, s_zr: int, z: int, r: int, a: int, curve_n: int) -> List[int]:
    """Recover private key for Goldbach case B."""
    # Step 1: compute discriminant
    D = (s * s - 4 * a * ((s_zr + s) % curve_n)) % curve_n

    # Step 2: solve for m1 using modular square root
    roots = sqrt_mod(D, curve_n, all_roots=True)
    if not roots:
        return {"error": "No modular sqrt exists for discriminant D."}

    results = []
    for root in roots:
        numerator = (s + root) % curve_n
        denominator = (2 * a) % curve_n
        try:
            denom_inv = mod_inverse(denominator, curve_n)
        except:
            continue  # skip if denominator not invertible
        m1 = (numerator * denom_inv) % curve_n

        s_zk = (a * m1) % curve_n
        z_inv = mod_inverse(z, curve_n)
        k = (s_zk * z_inv) % curve_n
        rk = (r * k) % curve_n
        rk_inv = mod_inverse(rk, curve_n)
        s_rxk = (s - s_zk) % curve_n
        x = (s_rxk * rk_inv) % curve_n

        results.append(x)

    return results


def _recover_private_key_case_a(s: int, z: int, r: int, a: int, curve_n: int, m: int = 1) -> int:
    """Recover private key for Goldbach case A."""
    z_inv = mod_inverse(z, curve_n)
    s_zk = a * m
    k = (s_zk * z_inv) % curve_n
    s_rxk = (s - s_zk) % curve_n
    rk = (r * k) % curve_n
    rk_inv = mod_inverse(rk, curve_n)

    return (s_rxk * rk_inv) % curve_n


def _recover_private_key_case_e(case: str, s: int, z: int, r: int, curve_n: int) -> Tuple[int, int]:
    """Recover private key for Goldbach cases E1 and E2."""
    if case == "E2":
        s += curve_n
    s_half = s // 2
    a = (s + s_half + 1) // 2
    b = s - a
    x1 = _recover_private_key_case_a(s, z, r, a, curve_n, m=1)
    x2 = _recover_private_key_case_a(s, z, r, b, curve_n, m=1)
    return x1, x2
    

def _recover_private_key(case: str, s: int, s_zr: int, z: int, r: int, a: int, curve_n: int) -> object:
    """Recover private key based on the identified case and public parameters."""
    if case == "A":
        return _recover_private_key_case_a(s, z, r, a, curve_n)
    elif case == "B":
        return _recover_private_key_case_b(s, s_zr, z, r, a, curve_n)
    elif case == "C":
        return "-"
    elif case == "D":
        return "-"
    elif case[0] == "E":
        return _recover_private_key_case_e(case, s, z, r, curve_n)
    else:
        return "-"

def _check_math_hypothesis_case_d(digit: str, s: int, s_zk: int, s_rxk: int, s_zr: int, z: int, r: int, private_key: int, k_inv: int, a: int) -> str:
    """Check the mathematical hypothesis for case D."""
    if digit > 0:
        # Hypothesis: HYP-005
        w = s_zk - digit * a
        a_found = 3 * w - ((digit * a % w) - ((digit + 1) * a % w))
        if a_found == a:
            return "HYP-005"
        # Hypothesis: HYP-006
        #return "HYP-006"
        #...
    return "-"

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
) -> Tuple[List[Sequence[object]], dict]:

    curve = ec.curve
    start = time.time()

    # key pool
    if private_key != 0 and private_key < curve.n:
        uniq_keys = [private_key]
    else:
        uniq_keys = ec.generate_unique_keys(total_key_count, min_start_range)

    rows: List[Sequence[object]] = []

    # counters
    total_cases = 0
    case_A_count = 0
    case_B_count = 0
    case_C_count = 0
    case_D_count = 0
    case_D_counts: dict[int, int] = {}
    case_E_count = 0

    # progress
    progress_step = max(1, total_key_count // 10)

    for i, private_key in enumerate(uniq_keys, start=1):
        _, public_key = ec.generate_keypair(private_key)
        if not ec.is_on_curve(public_key):
            continue

        for _ in range(transaction_limit_per_key):
            # message generation
            if curve.mode == "legacy":
                # Each transaction spends a different UTXO.
                # In real Bitcoin prev_txid = dSHA256(serialized_prev_tx),
                # which is effectively a unique 256-bit identifier per UTXO.
                prev_txid = os.urandom(32)
                prev_index = random.randint(0, 3)
                input_value_sats = random.randint(10_000, 100_0000_0000)
                fee_sats = random.randint(1_000, 50_000)
                output_value_sats = input_value_sats - fee_sats

                if sig_type == "p2wpkh":
                    # SegWit v0 (P2WPKH) — BIP 143 SIGHASH_ALL preimage
                    # BIP 143 commits to input value (anti-fee-manipulation)
                    msg = make_bitcoin_segwit_sighash_message(
                        public_key, prev_txid, prev_index,
                        input_value_sats, output_value_sats,
                    )
                else:
                    # Legacy P2PKH — traditional SIGHASH_ALL preimage
                    # Legacy sighash does NOT commit to input value
                    msg = make_bitcoin_legacy_sighash_message(
                        public_key, prev_txid, prev_index,
                        output_value_sats,
                    )
            else:
                rnd = random.randrange(1, curve.n - 1)
                msg = str(rnd).encode()

            z, r, s, k_inv = ec.sign_message(private_key, msg, min_start_range)

            # hidden data analysis ========================
            s_zk = (z * k_inv) % curve.n
            s_rxk = (r * private_key * k_inv) % curve.n
            # =============================================
            # E case
            goldbach_result, goldbach_case = _goldbach_condition(s, s_zk, s_rxk, curve.n)
            if goldbach_result:
                case_E_count += 1
                if case_E_count <= output_count:
                    x1, x2 = _recover_private_key(goldbach_case, s, 0, z, r, 0, curve.n)
                    rows.append(
                        [f"{goldbach_case}", s, s_zk, s_rxk, "-", z, r, private_key, k_inv, "-", "-", "-", "-", f"{x1}, {x2}", "-"]
                    )
            # A, B, C, D cases
            s_zr = (z * r) % curve.n
            if s_zr > s:
                a = s % ((s_zr - s) % curve.n)
                if a > 0 and a != s and a != s_zr:
                    total_cases += 1
                    # hidden data analysis ========================
                    m1 = Fraction(s_zk, a)
                    m2 = Fraction(s + s_zr, s_rxk)
                    # =============================================
                    # B, C cases
                    if m1.denominator == 1 and m2.denominator == 1:
                        if m1 == m2:
                            case_B_count += 1
                            if case_B_count <= output_count:
                                rows.append(
                                    ["B", s, s_zk, s_rxk, s_zr, z, r, private_key, k_inv, a, m1, m2, "-", _recover_private_key("B", s, s_zr, z, r, a, curve.n), "-"]
                                )
                        else:
                            case_C_count += 1
                            if case_C_count <= output_count:
                                rows.append(
                                    ["C", s, s_zk, s_rxk, s_zr, z, r, private_key, k_inv, a, m1, "-", "-", _recover_private_key("C", s, s_zr, z, r, a, curve.n), "-"]
                                )
                    # A, C cases
                    elif m1.denominator == 1 and m2.denominator != 1:
                        if m1 == 1:
                            case_A_count += 1
                            if case_A_count <= output_count:
                                rows.append(
                                    ["A", s, s_zk, s_rxk, s_zr, z, r, private_key, k_inv, a, m1, "-", "-", _recover_private_key("A", s, s_zr, z, r, a, curve.n), "-"]
                                )
                        elif m1 > 1:
                            case_C_count += 1
                            if case_C_count <= output_count:
                                rows.append(
                                    ["C", s, s_zk, s_rxk, s_zr, z, r, private_key, k_inv, a, m1, "-", "-", _recover_private_key("C", s, s_zr, z, r, a, curve.n), "-"]
                                )
                    else:
                        # D case
                        if m1.numerator * a == s_zk * m1.denominator:
                            f = Decimal(m1.numerator) / Decimal(m1.denominator)
                            case_D_count += 1
                            f_str = str(f)[: cfg.precision]
                            int_frac = f_str.split(".")
                            try:
                                digit = int(int_frac[0])
                            except ValueError:
                                continue
                            case_D_counts[digit] = case_D_counts.get(digit, 0) + 1
                            if case_D_count <= output_count:
                                if d_case_digit == -1 or digit == d_case_digit:
                                    rows.append(
                                        [f"D{digit}", s, s_zk, s_rxk, s_zr, z, r, private_key, k_inv, a, "-", "-", f_str, _recover_private_key("D", s, s_zr, z, r, a, curve.n), _check_math_hypothesis_case_d(digit, s, s_zk, s_rxk, s_zr, z, r, private_key, k_inv, a)]
                                    )

        if i % progress_step == 0:
            print(f"{i} keys ({i * transaction_limit_per_key} transactions) generated...")

    elapsed = time.time() - start

    # project dynamic case_D counts into flat stats
    dynamic_stats = {f"case_D{idx}_count": cnt for idx, cnt in sorted(case_D_counts.items())}

    # maximum transaction count, where 4 = number of parameters (z, r, x, k-1)
    maximum_transaction_count = Decimal(curve.n - 1) ** 4

    stats = {
        "total_key_count": total_key_count,
        "transaction_limit_per_key": transaction_limit_per_key,
        "total_transaction_count": total_key_count * transaction_limit_per_key,
        "maximum_transaction_count": f"{maximum_transaction_count:.6e}",
        "total_cases": total_cases + case_E_count,
        "case_A_count": case_A_count,
        "case_B_count": case_B_count,
        "case_C_count": case_C_count,
        "case_D_count": case_D_count,
        **dynamic_stats,
        "case_E_count": case_E_count,
        "spent_time_sec": elapsed,
    }

    return rows, stats


def _select_curve(mode: str) -> CurveParams:
    if mode == "test_tiny":
        return TEST_PARAMS_TINY
    if mode == "test_small":
        return TEST_PARAMS_SMALL
    if mode == "test_large":
        return TEST_PARAMS_LARGE
    if mode == "legacy":
        return LEGACY_PARAMS
    raise ValueError("Mode must be 'test_tiny' or 'test_small' or 'test_large' or 'legacy'!")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="secp256k1 transaction data generator")
    p.add_argument("--mode", choices=["test_tiny", "test_small", "test_large", "legacy"], default="test_small", help="Curve mode: test_tiny, test_small, test_large or legacy.")
    p.add_argument("--private_key", type=int, default=0, help="Private key to use (if '0' then random else specific key)")
    p.add_argument("--keys", type=int, default=9966, help="Total unique keys to generate")
    p.add_argument("--tx_per_key", type=int, default=10, help="Transactions per key")
    p.add_argument("--output_count", type=int, default=1000, help="Number of output transactions to generate")
    p.add_argument("--d_case_digit", type=int, default=-1, help="Digit for filtering case D (if -1 then all)")
    p.add_argument("--min_start_range", type=int, default=1, help="Minimum start range for private key and k-nonce generation")
    p.add_argument("--demo", action="store_true", help="Run demo of key generation, signing, and verification")
    p.add_argument("--sig_type", choices=["p2pkh", "p2wpkh"], default="p2pkh", help="Signature type: p2pkh (legacy) or p2wpkh (segwit)")
    return p.parse_args(argv)


def main() -> None:
    args = parse_args()
    curve = _select_curve(args.mode)
    ec = Secp256k1(curve)
    cfg = _build_report_config(curve)

    if args.keys > ec.curve.n - 1:
        raise ValueError("Requested more unique keys than possible for this curve!")

    if args.demo:
        _print_once_demo(ec)

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
    path = _write_report(curve, cfg, rows, stats, args.sig_type)
    print(f"Wrote report: {path}")


if __name__ == "__main__":
    main()
