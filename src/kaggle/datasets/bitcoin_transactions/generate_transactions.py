#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, getcontext
from fractions import Fraction
from typing import Iterable, List, Sequence, Tuple
import re
from secp256k1 import (
    Secp256k1,
    TEST_PARAMS_SMALL,
    TEST_PARAMS_LARGE,
    LEGACY_PARAMS,
    CurveParams,
    make_bitcoin_legacy_sighash_message,
)


@dataclass(frozen=True)
class ReportConfig:
    precision: int
    column_widths: Sequence[int]
    line_length: int
    headers: Sequence[str] = (
        "case", "s", "s_zk", "s_rxk", "s_zr", "z", "r", "x", "k-1", "a", "m1", "m2", "f"
    )


def _build_report_config(curve: CurveParams) -> ReportConfig:
    if curve.mode == "test":
        precision = 20
        getcontext().prec = precision
        column_widths = [13, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, precision + 5]
        line_length = 145 + precision + 5
    else:
        precision = 80
        getcontext().prec = precision
        column_widths = [81, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, precision + 5]
        line_length = 961 + precision + 5
    return ReportConfig(precision=precision, column_widths=column_widths, line_length=line_length)


def _print_once_demo(ec: Secp256k1) -> None:
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
        message = make_bitcoin_legacy_sighash_message(pub)
    else:
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
        if isinstance(val, Fraction):
            cells.append(f"{str(val):<{w}}")
        else:
            cells.append(f"{val:<{w}}")
    return "".join(cells)


def _write_report(
    curve: CurveParams,
    cfg: ReportConfig,
    rows: List[Sequence[object]],
    stats: dict,
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
            "total_cases",
            "case_A_count",
            "case_B_count",
            "case_C_count",
            "case_D_count",
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


def _collect_rows(
    ec: Secp256k1,
    cfg: ReportConfig,
    total_key_count: int,
    private_key: int,
    transaction_limit_per_key: int,
    output_count: int,
) -> Tuple[List[Sequence[object]], dict]:
    import random
    import time

    curve = ec.curve
    start = time.time()

    # key pool
    if private_key != 0 and private_key < curve.n:
        uniq_keys = [private_key]
    else:
        range_start = 1
        range_end = curve.n - 1
        uniq_keys = ec.generate_unique_keys(total_key_count, range_start, range_end)

    rows: List[Sequence[object]] = []

    # counters
    total_cases = 0
    case_A_count = 0
    case_B_count = 0
    case_C_count = 0
    case_D_count = 0
    case_D_counts: dict[int, int] = {}

    # progress
    progress_step = max(1, total_key_count // 10)

    for i, private_key in enumerate(uniq_keys, start=1):
        _, public_key = ec.generate_keypair(private_key)
        if not ec.is_on_curve(public_key):
            continue

        for _ in range(transaction_limit_per_key):
            # message generation
            if curve.mode == "legacy":
                msg = make_bitcoin_legacy_sighash_message(public_key)
            else:
                rnd = random.randrange(1, curve.n - 1)
                msg = str(rnd).encode()

            z, r, s, k_inv = ec.sign_message(private_key, msg)

            # public data analysis for case C
            s_zr = (z * r) % curve.n
            if s_zr > s:
                a = s % ((s_zr - s) % curve.n)
                if a != 0 and a != s:
                    total_cases += 1
                    # hidden data analysis
                    s_zk = (z * k_inv) % curve.n
                    s_rxk = (r * private_key * k_inv) % curve.n
                    m1 = Fraction(s_zk, a)
                    m2 = Fraction(s + s_zr, s_rxk)
                    # B, C cases
                    if m1.denominator == 1 and m2.denominator == 1:
                        if m1 == m2:
                            case_B_count += 1
                            if case_B_count <= output_count:
                                rows.append(
                                    ["B", s, s_zk, s_rxk, s_zr, z, r, private_key, k_inv, a, m1, m2, "-"]
                                )
                        else:
                            case_C_count += 1
                            if case_C_count <= output_count:
                                rows.append(
                                    ["C", s, s_zk, s_rxk, s_zr, z, r, private_key, k_inv, a, m1, "-", "-"]
                                )
                    # A, C cases
                    elif m1.denominator == 1 and m2.denominator != 1:
                        if m1 == 1:
                            case_A_count += 1
                            if case_A_count <= output_count:
                                rows.append(
                                    ["A", s, s_zk, s_rxk, s_zr, z, r, private_key, k_inv, a, m1, "-", "-"]
                                )
                        elif m1 > 1:
                            case_C_count += 1
                            if case_C_count <= output_count:
                                rows.append(
                                    ["C", s, s_zk, s_rxk, s_zr, z, r, private_key, k_inv, a, m1, "-", "-"]
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
                                rows.append(
                                    [f"D{digit}", s, s_zk, s_rxk, s_zr, z, r, private_key, k_inv, a, "-", "-", f_str]
                                )

        if i % progress_step == 0:
            print(f"{i} keys ({i * transaction_limit_per_key} transactions) generated...")

    elapsed = time.time() - start

    # project dynamic case_D counts into flat stats
    dynamic_stats = {f"case_D{idx}_count": cnt for idx, cnt in sorted(case_D_counts.items())}

    stats = {
        "total_key_count": total_key_count,
        "transaction_limit_per_key": transaction_limit_per_key,
        "total_transaction_count": total_key_count * transaction_limit_per_key,
        "total_cases": total_cases,
        "case_A_count": case_A_count,
        "case_B_count": case_B_count,
        "case_C_count": case_C_count,
        "case_D_count": case_D_count,
        **dynamic_stats,
        "spent_time_sec": elapsed,
    }

    return rows, stats


def _select_curve(mode: str) -> CurveParams:
    if mode == "test_small":
        return TEST_PARAMS_SMALL
    if mode == "test_large":
        return TEST_PARAMS_LARGE
    if mode == "legacy":
        return LEGACY_PARAMS
    raise ValueError("Mode must be 'test_small' or 'test_large' or 'legacy'!")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="secp256k1 transaction data generator")
    p.add_argument("--mode", choices=["test_small", "test_large", "legacy"], default="test_small", help="Curve mode")
    p.add_argument("--private_key", type=int, default=0, help="Private key to use (if '0' then random else specific key)")
    p.add_argument("--keys", type=int, default=9965, help="Total unique keys to generate")
    p.add_argument("--tx_per_key", type=int, default=1, help="Transactions per key")
    p.add_argument("--output_count", type=int, default=1000, help="Number of output transactions to generate")
    p.add_argument("--demo", action="store_true", help="Run demo of key generation, signing, and verification")
    return p.parse_args(argv)


def main() -> None:
    args = parse_args()
    curve = _select_curve(args.mode)
    ec = Secp256k1(curve)
    cfg = _build_report_config(curve)

    if args.demo:
        _print_once_demo(ec)

    rows, stats = _collect_rows(
        ec=ec,
        cfg=cfg,
        total_key_count=args.keys,
        private_key=args.private_key,
        transaction_limit_per_key=args.tx_per_key,
        output_count=args.output_count,
    )
    path = _write_report(curve, cfg, rows, stats)
    print(f"Wrote report: {path}")


if __name__ == "__main__":
    main()
