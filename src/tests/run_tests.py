#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression suite with a tabular console report.

Run from anywhere:

    python3 tests/run_tests.py                # table
    python3 tests/run_tests.py -k window      # only tests matching a substring
    python3 tests/run_tests.py --no-color     # plain ASCII, no escape codes
    python3 tests/run_tests.py --failfast     # stop at the first failure
    python3 tests/run_tests.py -v             # full tracebacks for failures

Exit status is 0 when everything passes and 1 otherwise, so the script drops
straight into a CI step.

Everything asserted here was verified by hand before being written down; the
point of the file is that it stays verified after the next edit.  Each test
also reports a short measured value, so the table shows what was actually
observed rather than a column of "ok".
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import sys
import time
import traceback
import unittest
from dataclasses import dataclass
from fractions import Fraction
from typing import Dict, List, Optional, Sequence, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (
    os.path.abspath(os.path.join(_HERE, os.pardir, "src")),
    os.path.abspath(os.path.join(_HERE, os.pardir, "src", "utils")),
    os.path.abspath(os.path.join(_HERE, os.pardir)),
):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from ecurve.secp256k1 import (  # noqa: E402
    Secp256k1, TEST_PARAMS, LEGACY_PARAMS,
    mod_sqrt_all, recover_x_from_s_zk, compress_public_key,
)
from ecurve._ripemd160 import ripemd160  # noqa: E402
from utils.generate_transactions import (  # noqa: E402
    _detect_half_difference_split, _half_difference_parts, _guesses_case_b,
    _check_hypothesis_001, _format_ratio, recover_private_keys,
)
from utils.find_common_private_key import (  # noqa: E402
    ECDSATransaction, exact_level, s_zk_window, window_size, find_common_x,
)


# ======================================================================
# TEST BASE
# ======================================================================
class ResearchTestCase(unittest.TestCase):
    """Base case that lets a test hand a measured value to the reporter."""

    def note(self, text: str) -> None:
        self._note = text


def _signature(ec, d, rnd):
    """Produce one (z, r, s, k_inv) on the given curve, test-mode style."""
    n = ec.curve.n
    while True:
        z = rnd.randrange(1, n - 1)
        k = rnd.randrange(1, n - 1)
        point = ec.scalar_multiply(k, ec.curve.g)
        if point is None:
            continue
        r = point[0] % n
        if r == 0:
            continue
        k_inv = pow(k, -1, n)
        s = ((z + r * d) * k_inv) % n
        if s:
            return z, r, s, k_inv


# ======================================================================
# CURVE AND PRIMITIVES
# ======================================================================
class TestCurve(ResearchTestCase):
    GROUP = "Curve parameters and primitives"
    TEST_ORDER = (
        "test_test_curve_parameters",
        "test_rfc6979_vectors",
        "test_ripemd160_vectors",
        "test_sign_verify_roundtrip",
        "test_compress_public_key_field_size",
        "test_mod_sqrt_all",
    )

    def test_test_curve_parameters(self):
        """Test curve is a real curve of prime order"""
        ec = Secp256k1(TEST_PARAMS)
        c = TEST_PARAMS
        self.assertTrue(ec.is_on_curve(c.g))
        self.assertIsNone(ec.scalar_multiply(c.n, c.g))
        order = 1
        for x in range(c.p):
            rhs = (x * x * x + c.a * x + c.b) % c.p
            if rhs == 0:
                order += 1
            elif pow(rhs, (c.p - 1) // 2, c.p) == 1:
                order += 2
        self.assertEqual(order, c.n, "group order must equal n (cofactor 1)")
        self.note(f"#E = n = {c.n}, cofactor 1, G on curve")

    def test_rfc6979_vectors(self):
        """RFC 6979 nonce matches published secp256k1 vectors"""
        ec = Secp256k1(LEGACY_PARAMS)
        n = LEGACY_PARAMS.n
        vectors = [
            (0x01, b"Satoshi Nakamoto",
             0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15),
            (0x01, b"All those moments will be lost in time, like tears in rain. "
                   b"Time to die...",
             0x38AA22D72376B4DBC472E06C3BA403EE0A394DA63FC58D88686C611ABA98D6B3),
            (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140,
             b"Satoshi Nakamoto",
             0x33A19B60E25FB6F4435AF53A3D42D493644827367E6453928554F43E49AA6F90),
        ]
        for d, msg, expected in vectors:
            z = int.from_bytes(hashlib.sha256(msg).digest(), "big") % n
            self.assertEqual(ec._rfc6979_generate_k(d, z), expected)
        self.note(f"{len(vectors)}/{len(vectors)} published vectors")

    def test_ripemd160_vectors(self):
        """RIPEMD-160 fallback matches the official test vectors"""
        cases = {
            b"": "9c1185a5c5e9fc54612808977ee8f548b2258d31",
            b"abc": "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
            b"message digest": "5d0689ef49d2fae572b881b123a85ffa21595f36",
            b"1234567890" * 8: "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
        }
        for data, digest in cases.items():
            self.assertEqual(ripemd160(data).hex(), digest)
        self.note(f"{len(cases)}/{len(cases)} official vectors, multi-block included")

    def test_sign_verify_roundtrip(self):
        """Signing verifies; an off-curve public key does not"""
        for params in (TEST_PARAMS, LEGACY_PARAMS):
            ec = Secp256k1(params, rng=random.Random(1))
            d, pub = ec.generate_keypair()
            sig = ec.sign_message(d, b"regression", min_start_range=1)
            self.assertTrue(ec.verify_signature(pub, sig))
            self.assertFalse(ec.verify_signature((1, 1), sig),
                             "off-curve public key must be rejected")
        self.note("2 curves OK, off-curve pubkey rejected")

    def test_compress_public_key_field_size(self):
        """SEC encoding follows the field size instead of a hardcoded 32"""
        self.assertEqual(len(compress_public_key((5, 4), field_bytes=3)), 4)
        self.assertEqual(len(compress_public_key((5, 4))), 33)
        self.note("3-byte field -> 4 B, 32-byte field -> 33 B")

    def test_mod_sqrt_all(self):
        """Local modular square root replaces sympy on both moduli"""
        checked = 0
        for p in (99667, 10007):
            squares = {(i * i) % p for i in range(p)}
            for a in range(0, p, 97):
                roots = mod_sqrt_all(a, p)
                checked += 1
                if a in squares:
                    self.assertTrue(roots and all((r * r) % p == a for r in roots))
                else:
                    self.assertEqual(roots, [])
        n = LEGACY_PARAMS.n  # n % 4 == 1 -> Tonelli-Shanks path
        rnd = random.Random(4)
        for _ in range(50):
            base = rnd.randrange(1, n)
            for root in mod_sqrt_all(base * base % n, n):
                self.assertEqual(root * root % n, base * base % n)
            checked += 1
        self.note(f"{checked} residues, both p%4 branches")


# ======================================================================
# RECOVERY
# ======================================================================
class TestRecovery(ResearchTestCase):
    GROUP = "Key recovery from public data"
    TEST_ORDER = (
        "test_recover_and_verify_public_only",
        "test_case_b_quadratic",
        "test_half_difference_split",
        "test_case_a_and_e_recover_real_signatures",
        "test_case_e_covers_both_parity_branches",
        "test_hypothesis_001_matches_definition",
    )

    def test_recover_and_verify_public_only(self):
        """recover_x_from_s_zk round-trips; verify_x_candidate is decisive"""
        checked = 0
        for params in (TEST_PARAMS, LEGACY_PARAMS):
            ec = Secp256k1(params, rng=random.Random(2))
            n = params.n
            rnd = random.Random(3)
            for _ in range(20):
                d = rnd.randrange(1, n - 1)
                z, r, s, k_inv = _signature(ec, d, rnd)
                s_zk = (z * k_inv) % n
                self.assertEqual(recover_x_from_s_zk(s_zk, s, z, r, n), d)
                self.assertTrue(ec.verify_x_candidate(d, z, r, s))
                self.assertFalse(ec.verify_x_candidate((d + 1) % n, z, r, s))
                checked += 1
        self.note(f"{checked} signatures, 0 mismatches, d+1 always rejected")

    def test_case_b_quadratic(self):
        """Case-B quadratic recovers a*m1 on both curves"""
        checked = 0
        for params in (TEST_PARAMS, LEGACY_PARAMS):
            n = params.n
            rnd = random.Random(5)
            for _ in range(50):
                a = rnd.randrange(1, n)
                m1 = rnd.randrange(2, 10_000)
                s = rnd.randrange(1, n)
                s_rxk = (s - a * m1) % n
                if s_rxk == 0:
                    continue
                s_zr = (m1 * s_rxk - s) % n
                self.assertIn((a * m1) % n, _guesses_case_b(s, s_zr, a, n))
                checked += 1
        self.note(f"{checked}/{checked} roots contain the true s_zk")

    def test_half_difference_split(self):
        """Case-E split is integral exactly for S = 1 or 2 (mod 4)"""
        n = TEST_PARAMS.n
        checked = 0
        for big_s in range(2, 40_000):
            larger, smaller = _half_difference_parts(big_s)
            integral = (larger + smaller == big_s
                        and abs(larger - smaller) == big_s // 2 + 1)
            self.assertEqual(integral, big_s % 4 in (1, 2),
                             f"S={big_s} integrality disagrees with S%4")
            if big_s % 4 not in (1, 2):
                continue
            larger, smaller = _half_difference_parts(big_s)
            self.assertEqual(larger + smaller, big_s)
            self.assertEqual(abs(larger - smaller), big_s // 2 + 1)
            if larger < n and smaller < n and larger + smaller <= big_s:
                detected, _ = _detect_half_difference_split(big_s, larger, smaller, n)
                self.assertTrue(detected)
            checked += 1
        self.note(f"{checked} values of S; integral iff S%4 in (1,2)")

    def test_case_a_and_e_recover_real_signatures(self):
        """Real case-A and case-E signatures yield a verified key"""
        ec = Secp256k1(TEST_PARAMS, rng=random.Random(6))
        n = TEST_PARAMS.n
        r_of_k, point = [0] * n, None
        for k in range(1, n):
            point = ec.point_add(point, TEST_PARAMS.g)
            r_of_k[k] = point[0] % n

        rnd = random.Random(11)
        seen_a = seen_e = scanned = 0
        for _ in range(700_000):
            if seen_a and seen_e:
                break
            scanned += 1
            d = rnd.randrange(1, n - 1)
            k = rnd.randrange(1, n - 1)
            z = rnd.randrange(1, n - 1)
            r = r_of_k[k]
            if r == 0:
                continue
            k_inv = pow(k, -1, n)
            s = ((z + r * d) * k_inv) % n
            if s == 0:
                continue
            s_zk = (z * k_inv) % n
            s_rxk = (r * d * k_inv) % n
            s_zr = (z * r) % n

            detected, case = _detect_half_difference_split(s, s_zk, s_rxk, n)
            if detected:
                seen_e += 1
                keys, _ = recover_private_keys(ec, case, s, 0, z, r, 0)
                self.assertIn(d, keys)

            if s_zr <= s:
                continue
            a = s % ((s_zr - s) % n)
            if not (0 < a != s) or s_zk != a:
                continue
            seen_a += 1
            keys, _ = recover_private_keys(ec, "A", s, s_zr, z, r, a)
            self.assertIn(d, keys)
        self.assertTrue(seen_a and seen_e, "scan found no case A / case E sample")
        self.note(f"{scanned:,} scanned -> A x{seen_a}, E x{seen_e}, all verified")

    def test_case_e_covers_both_parity_branches(self):
        """Case E is detected for S = 1 (mod 4) as well as S = 2 (mod 4)"""
        ec = Secp256k1(TEST_PARAMS, rng=random.Random(21))
        n = TEST_PARAMS.n
        rnd = random.Random(22)
        seen = {1: 0, 2: 0}
        for _ in range(400_000):
            if seen[1] and seen[2]:
                break
            d = rnd.randrange(1, n - 1)
            z, r, s, k_inv = _signature(ec, d, rnd)
            s_zk = (z * k_inv) % n
            s_rxk = (s - s_zk) % n
            big_s = s_zk + s_rxk
            if abs(s_zk - s_rxk) != big_s // 2 + 1:
                continue
            branch = big_s % 4
            if branch not in seen:
                continue
            detected, case = _detect_half_difference_split(s, s_zk, s_rxk, n)
            self.assertTrue(detected, f"S%4={branch} must be detected")
            keys, _ = recover_private_keys(ec, case, s, 0, z, r, 0)
            self.assertIn(d, keys)
            seen[branch] += 1
        self.assertTrue(seen[1] and seen[2],
                        f"did not sample both branches: {seen}")
        self.note(f"S%4=1 seen {seen[1]}x, S%4=2 seen {seen[2]}x, both recovered")

    def test_hypothesis_001_matches_definition(self):
        """HYP-001 agrees with its algebraic definition, never divides by zero"""
        rnd = random.Random(7)
        fired = 0
        trials = 20_000
        for _ in range(trials):
            a = rnd.randrange(1, 10 ** 6)
            s_zk = rnd.randrange(1, 10 ** 6)
            s = rnd.randrange(1, 10 ** 6)
            level = s_zk // a
            w = s_zk - level * a
            result = _check_hypothesis_001(level, s, s_zk, a)
            if not (level > 1 and s > s_zk and s_zk % 2 == 0 and w > 0):
                self.assertEqual(result, "-")
                continue
            expected = level * w - ((level * a % w) - ((level + 1) * a % w)) == a
            self.assertEqual(result == "HYP-001", expected)
            fired += bool(expected)
        self.note(f"{trials:,} triples, 0 deviations, fired {fired}x "
                  f"({100 * fired / trials:.2f}%)")


# ======================================================================
# FORMATTING
# ======================================================================
class TestFormatting(ResearchTestCase):
    GROUP = "Exact numeric formatting"
    TEST_ORDER = (
        "test_format_ratio_is_exact",
        "test_exact_level_rejects_float",
    )

    def test_format_ratio_is_exact(self):
        """Ratio rendering is exact and never uses exponent form"""
        rnd = random.Random(8)
        trials = 5_000
        for _ in range(trials):
            num = rnd.randrange(1, 10 ** 80)
            den = rnd.randrange(1, 10 ** 20)
            text = _format_ratio(num, den, 20)
            self.assertNotIn("E", text)
            whole, frac = text.split(".")
            low = Fraction(int(whole)) + Fraction(int(frac), 10 ** 20)
            self.assertLessEqual(low, Fraction(num, den))
            self.assertLess(Fraction(num, den), low + Fraction(1, 10 ** 20))
        self.note(f"{trials:,} ratios up to 1e80, 0 rounding errors")

    def test_exact_level_rejects_float(self):
        """float is refused; str and Fraction floors are exact"""
        with self.assertRaises(TypeError):
            exact_level(11.25)
        self.assertEqual(exact_level("4.9999999999999999"), 4)
        self.assertEqual(exact_level(Fraction(37, 8)), 4)
        self.assertEqual(exact_level("0.9999"), 0)
        self.note("float refused; 4.999...9 -> 4 (float would give 5)")


# ======================================================================
# SEARCH
# ======================================================================
class TestSearch(ResearchTestCase):
    GROUP = "Common-x search"
    TEST_ORDER = (
        "test_window_contains_true_s_zk",
        "test_window_size_survives_legacy_scale",
        "test_verification_removes_false_positives",
        "test_legacy_window_is_refused",
    )

    def test_window_contains_true_s_zk(self):
        """Every level window contains the s_zk it was built from"""
        ec = Secp256k1(TEST_PARAMS, rng=random.Random(9))
        n = TEST_PARAMS.n
        rnd = random.Random(10)
        checked = 0
        for _ in range(3_000):
            d = rnd.randrange(1, n - 1)
            z, r, s, k_inv = _signature(ec, d, rnd)
            s_zk = (z * k_inv) % n
            s_zr = (z * r) % n
            if s_zr <= s:
                continue
            a = s % ((s_zr - s) % n)
            if not (0 < a != s):
                continue
            level = exact_level(Fraction(s_zk, a))
            self.assertIn(s_zk, s_zk_window(a, level))
            checked += 1
        self.assertGreater(checked, 100)
        self.note(f"{checked} windows, 0 misses")

    def test_window_size_survives_legacy_scale(self):
        """Window size is arithmetic; len() would overflow ssize_t"""
        window = s_zk_window(LEGACY_PARAMS.n // 4, 1)
        size = window_size(window)
        self.assertGreater(size, 2 ** 63)
        self.note(f"span ~2^{size.bit_length() - 1}, len() would raise OverflowError")

    def test_verification_removes_false_positives(self):
        """On-curve verification collapses the intersection to the true key"""
        ec = Secp256k1(TEST_PARAMS, rng=random.Random(12))
        n = TEST_PARAMS.n
        rnd = random.Random(13)

        def make_tx(d):
            while True:
                z, r, s, k_inv = _signature(ec, d, rnd)
                s_zk = (z * k_inv) % n
                s_zr = (z * r) % n
                if s_zr <= s:
                    continue
                a = s % ((s_zr - s) % n)
                if not (0 < a != s) or s_zk % a == 0:
                    continue
                return ECDSATransaction.from_ratio(
                    s=s, z=z, r=r, a=a, f=Fraction(s_zk, a),
                    s_zk_true=s_zk, x_expected=d,
                )

        runs = 25
        raw_extra = ver_extra = 0
        for _ in range(runs):
            d = rnd.randrange(1, n - 1)
            txs = [make_tx(d) for _ in range(4)]
            raw = {x for x, _ in find_common_x(txs, ec, verify=False)}
            ver = {x for x, _ in find_common_x(txs, ec, verify=True)}
            self.assertIn(d, raw)
            self.assertEqual(ver, {d})
            raw_extra += len(raw - {d})
            ver_extra += len(ver - {d})
        self.assertEqual(ver_extra, 0)
        self.assertGreater(raw_extra, 0, "unverified search should admit impostors")
        self.note(f"{runs} runs: {raw_extra / runs:.2f} impostors raw -> "
                  f"{ver_extra / runs:.2f} verified")

    def test_legacy_window_is_refused(self):
        """A secp256k1-scale window is rejected, not attempted"""
        ec = Secp256k1(LEGACY_PARAMS)
        txs = [
            ECDSATransaction(s=1, z=2, r=3, a=LEGACY_PARAMS.n // 4, level=1),
            ECDSATransaction(s=4, z=5, r=6, a=LEGACY_PARAMS.n // 4, level=1),
        ]
        with self.assertRaises(ValueError):
            find_common_x(txs, ec)
        self.note("ValueError raised before any enumeration")


SUITE: Tuple[type, ...] = (TestCurve, TestRecovery, TestFormatting, TestSearch)


# ======================================================================
# TABULAR REPORTER
# ======================================================================
PASS, FAIL, ERROR, SKIP, XFAIL, XPASS = "PASS", "FAIL", "ERROR", "SKIP", "XFAIL", "XPASS"

_COLORS = {
    PASS: "\033[32m", FAIL: "\033[31m", ERROR: "\033[35m",
    SKIP: "\033[33m", XFAIL: "\033[33m", XPASS: "\033[31m",
}
_BOLD, _DIM, _RESET = "\033[1m", "\033[2m", "\033[0m"
_BROKEN = (FAIL, ERROR, XPASS)


@dataclass
class Record:
    group: str
    name: str
    status: str
    seconds: float
    detail: str = ""
    trace: str = ""


class TableResult(unittest.TestResult):
    """Collects one Record per test instead of streaming dots."""

    def __init__(self) -> None:
        super().__init__()
        self.records: List[Record] = []
        self._started = 0.0

    @staticmethod
    def _group(test) -> str:
        return getattr(type(test), "GROUP", type(test).__name__)

    @staticmethod
    def _name(test) -> str:
        doc = (test._testMethodDoc or "").strip().splitlines()
        if doc and doc[0].strip():
            return doc[0].strip()
        name = test._testMethodName
        return (name[5:] if name.startswith("test_") else name).replace("_", " ")

    @staticmethod
    def _first_line(err) -> str:
        text = traceback.format_exception_only(err[0], err[1])
        line = text[-1].strip() if text else err[0].__name__
        return line.splitlines()[0] if line else err[0].__name__

    def _add(self, test, status: str, detail: str = "", trace: str = "") -> None:
        self.records.append(Record(
            group=self._group(test),
            name=self._name(test),
            status=status,
            seconds=time.perf_counter() - self._started,
            detail=detail or getattr(test, "_note", ""),
            trace=trace,
        ))

    def startTest(self, test):
        super().startTest(test)
        self._started = time.perf_counter()

    def addSuccess(self, test):
        super().addSuccess(test)
        self._add(test, PASS)

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._add(test, FAIL, self._first_line(err),
                  "".join(traceback.format_exception(*err)))

    def addError(self, test, err):
        super().addError(test, err)
        self._add(test, ERROR, self._first_line(err),
                  "".join(traceback.format_exception(*err)))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._add(test, SKIP, reason)

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self._add(test, XFAIL, self._first_line(err))

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._add(test, XPASS, "expected to fail but passed")


class TableRunner:
    """Runs a suite and prints a single aligned table."""

    MAX_DETAIL = 62

    def __init__(self, stream=None, color: bool = True, verbose: bool = False,
                 failfast: bool = False) -> None:
        self.stream = stream or sys.stdout
        self.color = color
        self.verbose = verbose
        self.failfast = failfast

    # -- output helpers ------------------------------------------------
    def _paint(self, text: str, code: str) -> str:
        """Colour is applied after padding, so column widths stay correct."""
        return f"{code}{text}{_RESET}" if self.color else text

    def _write(self, text: str = "") -> None:
        self.stream.write(text + "\n")

    # -- driver --------------------------------------------------------
    def run(self, suite) -> TableResult:
        result = TableResult()
        result.failfast = self.failfast
        started = time.perf_counter()
        suite(result)
        self._report(result, time.perf_counter() - started)
        return result

    # -- rendering -----------------------------------------------------
    def _report(self, result: TableResult, total: float) -> None:
        records = result.records
        if not records:
            self._write("No tests selected.")
            return

        widths = (
            max(3, len(str(len(records)))),
            max([len(r.name) + 2 for r in records]
                + [len(r.group) for r in records] + [len("Test")]),
            6,
            max(8, max(len(f"{r.seconds:.3f}s") for r in records)),
            min(self.MAX_DETAIL,
                max([len(r.detail) for r in records] + [len("Detail")])),
        )
        rule = "+".join("-" * (w + 2) for w in widths)
        banner = "=" * len(rule)

        self._write(banner)
        self._write(self._paint(
            f" ECDSA-Research regression suite"
            f"   |   {time.strftime('%Y-%m-%d %H:%M:%S')}"
            f"   |   python {sys.version.split()[0]}", _BOLD))
        self._write(banner)
        self._write(self._row(("#", "Test", "Status", "Time", "Detail"), widths))
        self._write(rule)

        counts: Dict[str, int] = {}
        number = 0
        last_group: Optional[str] = None
        for record in records:
            counts[record.status] = counts.get(record.status, 0) + 1
            if record.group != last_group:
                if last_group is not None:
                    self._write(rule)
                self._write(self._row(("", record.group.upper(), "", "", ""),
                                      widths, emphasis=True))
                last_group = record.group
            number += 1
            self._write(self._row(
                (str(number), "  " + record.name, record.status,
                 f"{record.seconds:.3f}s", record.detail),
                widths, status=record.status))

        self._write(banner)
        self._write(self._summary(counts, len(records), total))
        self._write(banner)

        ok = result.wasSuccessful()
        self._write(self._paint(
            " RESULT: OK -- every check passed" if ok else
            " RESULT: FAILED -- details below",
            _COLORS[PASS if ok else FAIL]))
        self._write(banner)

        broken = [r for r in records if r.status in _BROKEN]
        if broken:
            self._write("")
            self._write(self._paint(" FAILURE DETAILS", _BOLD))
            self._write("-" * len(rule))
            for record in broken:
                self._write(self._paint(
                    f" [{record.status}] {record.group} / {record.name}",
                    _COLORS[record.status]))
                self._write(f"   {record.detail}")
                if self.verbose and record.trace:
                    for line in record.trace.rstrip().splitlines():
                        self._write(f"   | {line}")
                self._write("")
            if not self.verbose:
                self._write(" Re-run with -v for full tracebacks.")

    def _row(self, cells: Sequence[str], widths: Sequence[int],
             status: Optional[str] = None, emphasis: bool = False) -> str:
        out = []
        for i, (cell, width) in enumerate(zip(cells, widths)):
            text = cell if len(cell) <= width else cell[:width - 1] + "~"
            padded = f" {text:^{width}} " if i == 2 else f" {text:<{width}} "
            if i == 2 and status in _COLORS:
                padded = self._paint(padded, _BOLD + _COLORS[status])
            elif emphasis and i == 1:
                padded = self._paint(padded, _BOLD)
            out.append(padded)
        return "|".join(out)

    def _summary(self, counts: Dict[str, int], total_tests: int, seconds: float) -> str:
        parts = [self._paint(f"TOTAL {total_tests}", _BOLD)]
        for status in (PASS, FAIL, ERROR, SKIP, XFAIL, XPASS):
            count = counts.get(status, 0)
            if not count and status not in (PASS, FAIL, ERROR):
                continue
            chunk = f"{status} {count}"
            parts.append(self._paint(chunk, _COLORS[status] if count else _DIM))
        parts.append(f"{seconds:.3f}s")
        return " " + "  |  ".join(parts)


# ======================================================================
# CLI
# ======================================================================
def build_suite(pattern: Optional[str] = None) -> unittest.TestSuite:
    """Build the suite in declaration order rather than alphabetical order.

    Each class lists its methods in ``TEST_ORDER``; the default loader sorts
    with ``dir()`` and would scatter related checks across the table.  The
    cross-check below also catches a test that was added but never listed.
    """
    suite = unittest.TestSuite()
    for cls in SUITE:
        declared = set(cls.TEST_ORDER)
        found = {name for name in dir(cls) if name.startswith("test_")}
        if found - declared:
            raise RuntimeError(
                f"{cls.__name__}.TEST_ORDER is missing: {sorted(found - declared)}")
        if declared - found:
            raise RuntimeError(
                f"{cls.__name__}.TEST_ORDER lists unknown: {sorted(declared - found)}")
        for name in cls.TEST_ORDER:
            if pattern and pattern.lower() not in f"{cls.__name__}.{name}".lower():
                continue
            suite.addTest(cls(name))
    return suite


def _enable_windows_vt() -> bool:
    """Turn on ANSI escape handling in a Windows console.

    Returns True when escapes will render.  cmd.exe and conhost need
    ENABLE_VIRTUAL_TERMINAL_PROCESSING set explicitly; without it the table
    would be littered with literal ``ESC[32m`` noise.  Redirected output makes
    GetConsoleMode fail, which is the correct signal to drop colour anyway.
    """
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _use_color(flag: str) -> bool:
    if flag == "never":
        return False
    if flag == "always":
        return _enable_windows_vt()
    if os.environ.get("NO_COLOR"):
        return False
    if not (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()):
        return False
    return _enable_windows_vt()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ECDSA-Research regression suite")
    parser.add_argument("-k", dest="pattern", default=None,
                        help="run only tests whose Class.method contains this substring")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print full tracebacks for failures")
    parser.add_argument("--failfast", action="store_true",
                        help="stop at the first failure")
    parser.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    parser.add_argument("--no-color", dest="color", action="store_const", const="never",
                        help="alias for --color never")
    args = parser.parse_args(argv)

    result = TableRunner(
        color=_use_color(args.color),
        verbose=args.verbose,
        failfast=args.failfast,
    ).run(build_suite(args.pattern))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
