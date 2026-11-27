#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression suite with a tabular console report.

Run from anywhere:

    python3 src/tests/run_tests.py                # table
    python3 src/tests/run_tests.py -k window      # only tests matching a substring
    python3 src/tests/run_tests.py --no-color     # plain ASCII, no escape codes
    python3 src/tests/run_tests.py --failfast     # stop at the first failure
    python3 src/tests/run_tests.py -v             # full tracebacks for failures

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
import io
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
from contextlib import redirect_stdout
from dataclasses import dataclass
from fractions import Fraction
from typing import Dict, List, Optional, Sequence, Tuple
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.abspath(os.path.join(_HERE, os.pardir))   # <repo>/src
# The suite lives in <repo>/src/tests; the modules are imported from <repo>/src.
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from ecurve.secp256k1 import (  # noqa: E402
    Secp256k1, TEST_PARAMS, LEGACY_PARAMS,
    mod_sqrt_all, recover_x_from_s_zk, compress_public_key,
    make_bitcoin_legacy_sighash_message, make_bitcoin_segwit_sighash_message,
)
from ecurve._ripemd160 import ripemd160  # noqa: E402
from utils.generate_transactions import (  # noqa: E402
    _detect_half_difference_split, _half_difference_parts, _guesses_case_b,
    _check_hypothesis_001, _format_ratio, recover_private_keys, _write_report,
    _collect_rows, _build_report_config, _build_message, _collect_forged_rows,
    build_ec, parse_args, rand_bytes, signature_space, _format_count,
)
from utils.generate_found_classes import (  # noqa: E402
    ECDSAClassGenerator, ClassConstructionError, classify,
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
        # n must be prime, or "order n" would not imply "order of G is n".
        self.assertTrue(all(c.n % q for q in range(2, int(c.n ** 0.5) + 1)),
                        "n must be prime")
        # Order of G checked with real arithmetic: scalar_multiply(n, G)
        # short-circuits to None for ANY n (k % n == 0), so it cannot fail.
        minus_g = ec.scalar_multiply(c.n - 1, c.g)
        self.assertEqual(minus_g, (c.g[0], (-c.g[1]) % c.p))
        self.assertIsNone(ec.point_add(minus_g, c.g))
        order = 1
        for x in range(c.p):
            rhs = (x * x * x + c.a * x + c.b) % c.p
            if rhs == 0:
                order += 1
            elif pow(rhs, (c.p - 1) // 2, c.p) == 1:
                order += 2
        self.assertEqual(order, c.n, "group order must equal n (cofactor 1)")
        self.note(f"#E = n = {c.n} prime, (n-1)G = -G, G on curve")

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
        """SEC encoding length follows the curve's field size"""
        self.assertEqual(len(compress_public_key((5, 4), field_bytes=3)), 4)
        self.assertEqual(len(compress_public_key((5, 4))), 33)
        self.note("3-byte field -> 4 B, 32-byte field -> 33 B")

    def test_mod_sqrt_all(self):
        """Modular square roots: all roots of a residue, none otherwise"""
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
        self.assertEqual(n % 4, 1)
        rnd = random.Random(4)
        residues = non_residues = 0
        for _ in range(100):
            value = rnd.randrange(1, n)
            roots = mod_sqrt_all(value, n)
            if pow(value, (n - 1) // 2, n) == 1:
                # A residue has exactly two roots; an empty result fails here.
                self.assertEqual(len(roots), 2)
                self.assertTrue(all(root * root % n == value for root in roots))
                residues += 1
            else:
                self.assertEqual(roots, [])
                non_residues += 1
            checked += 1
        self.assertTrue(residues and non_residues)
        self.note(f"{checked} values; Tonelli-Shanks: {residues} QR, "
                  f"{non_residues} non-QR")


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
        "test_case_b_roots_return_the_unordered_pair",
        "test_recovery_counters_are_consistent",
        "test_d_case_digit_scopes_rows_and_hypothesis",
    )

    def test_recover_and_verify_public_only(self):
        """recover_x_from_s_zk round-trips; d passes the r-check, d+1 fails"""
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
        """HYP-001 equals floor(a/w) == N - delta, and is stricter than {N, N-1}"""
        # Checks the independently derived closed form proved in the
        # _check_hypothesis_001 docstring:
        #
        #     HYP-001  <=>  floor(a/w) == N - delta,
        #     delta = 1 if ((N*t) mod w) + t >= w else 0,   t = a mod w
        #
        # and records that the weaker condition floor(a/w) in {N, N-1} is
        # implied but NOT equivalent.
        rnd = random.Random(7)
        fired = 0
        weak_only = 0
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
            t = a % w
            delta = 1 if ((level * t) % w) + t >= w else 0
            expected = (a // w) == level - delta
            self.assertEqual(result == "HYP-001", expected)
            weak = (a // w) in (level, level - 1)
            if expected:
                # the exact form must imply the weak one, never the reverse
                self.assertTrue(weak)
                fired += 1
            elif weak:
                weak_only += 1
        self.assertGreater(
            weak_only, 0,
            "the weak condition floor(a/w) in {N, N-1} must be strictly weaker",
        )
        self.note(f"{trials:,} triples: 0 deviations, fired {fired} "
                  f"({100 * fired / trials:.2f}%), weak-only {weak_only}")

    def test_case_b_roots_return_the_unordered_pair(self):
        """Case-B quadratic returns exactly {s_zk, s_rxk}, by Vieta"""
        # mu + mu' = s/a, so a*mu' = s - a*mu = s_rxk.  The second root is
        # therefore never wasted work: it is the other half of the split, and
        # the recovery path has to try both because which is which is unknown.
        checked = 0
        for params in (TEST_PARAMS, LEGACY_PARAMS):
            n = params.n
            rnd = random.Random(11)
            for _ in range(50):
                a = rnd.randrange(1, n)
                m1 = rnd.randrange(2, 10_000)
                s = rnd.randrange(1, n)
                s_zk = (a * m1) % n
                s_rxk = (s - s_zk) % n
                if s_rxk == 0:
                    continue
                s_zr = (m1 * s_rxk - s) % n
                guesses = set(_guesses_case_b(s, s_zr, a, n))
                self.assertIn(s_zk, guesses)
                self.assertIn(s_rxk, guesses)
                self.assertLessEqual(len(guesses), 2)
                checked += 1
        self.note(f"{checked} quadratics, both roots are {{s_zk, s_rxk}}")

    def test_recovery_counters_are_consistent(self):
        """Classes partition the run; recovery counters add up per class"""
        _rows, stats = _collect_rows(
            ec=Secp256k1(TEST_PARAMS, rng=random.Random(21)),
            cfg=_build_report_config(TEST_PARAMS),
            total_key_count=150,
            private_key=0,
            transaction_limit_per_key=400,
            output_count=3,
            d_case_digit=-1,
            min_start_range=1000,
            progress=False,     # keep generator progress out of the table
        )
        # Every signature has exactly one class or none.
        observed = sum(stats[f"case_{c}_count"] for c in "ABCDE")
        self.assertEqual(stats["total_observed_cases"], observed)
        self.assertEqual(observed + stats["unclassified_count"],
                         stats["total_transaction_count"])
        self.assertEqual(sum(stats["case_D_level_counts"].values()),
                         stats["case_D_count"])
        self.assertGreater(stats["case_D_count"], 0)
        self.assertGreater(stats["unclassified_count"], 0)
        by_class = ("a", "b", "e")
        self.assertEqual(
            stats["recovery_attempts"],
            sum(stats[f"recovery_attempts_{c}"] for c in by_class),
        )
        self.assertEqual(
            stats["recovery_verified"],
            sum(stats[f"recovery_verified_{c}"] for c in by_class),
        )
        self.assertEqual(
            stats["recovery_rejected"],
            stats["recovery_attempts"] - stats["recovery_verified"],
        )
        # The formula of each class always contains the true s_zk, and x*G == Q
        # accepts the signer's key only: every A, B and E signature yields
        # exactly one verified key.
        for c in by_class:
            self.assertEqual(stats[f"recovery_verified_{c}"],
                             stats[f"case_{c.upper()}_count"])
        self.note(f"{stats['total_transaction_count']:,} = {observed:,} classified"
                  f" + {stats['unclassified_count']:,} unclassified; "
                  f"verified {stats['recovery_verified']}")


    def test_d_case_digit_scopes_rows_and_hypothesis(self):
        """--d-case-digit prints one D level; HYP-001 count = marked rows"""
        def run(digit):
            return _collect_rows(
                ec=Secp256k1(TEST_PARAMS, rng=random.Random(21)),
                cfg=_build_report_config(TEST_PARAMS),
                total_key_count=50,
                private_key=0,
                transaction_limit_per_key=400,
                output_count=10**6,     # no truncation: every in-group row
                d_case_digit=digit,
                min_start_range=1000,
                progress=False,
            )

        def marked(rows):
            return sum(1 for row in rows if row[-1] == "HYP-001")

        all_rows, all_stats = run(-1)
        self.assertEqual(all_stats["hypothesis_001_count"], marked(all_rows))
        self.assertGreater(all_stats["hypothesis_001_count"], 0)
        by_level: Dict[str, int] = {}
        for row in all_rows:
            if row[-1] == "HYP-001":
                by_level[row[0]] = by_level.get(row[0], 0) + 1
        checked = []
        # 0 and 1 are below the gate N > 1 (never flagged); 2 and 3 fire.
        for digit in (0, 1, 2, 3):
            rows, stats = run(digit)
            label = f"D{digit}"
            self.assertTrue(rows)
            # Only the selected group is printed: no A/B/C/E or other D level.
            self.assertEqual({row[0] for row in rows}, {label})
            self.assertEqual(len(rows), stats["case_D_level_counts"][digit])
            # The counter is scoped to the group and agrees with the rows.
            self.assertEqual(stats["hypothesis_001_count"], marked(rows))
            self.assertEqual(marked(rows), by_level.get(label, 0))
            # Class counts stay run-wide.
            for c in "ABCDE":
                self.assertEqual(stats[f"case_{c}_count"],
                                 all_stats[f"case_{c}_count"])
            checked.append(f"{label}:{marked(rows)}/{len(rows)}")
        self.assertEqual(by_level.get("D0", 0) + by_level.get("D1", 0), 0)
        self.assertGreater(by_level.get("D2", 0) + by_level.get("D3", 0), 0)
        self.note(f"HYP-001/rows {', '.join(checked)}; "
                  f"all levels {all_stats['hypothesis_001_count']}")


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


# ======================================================================
# REPRODUCIBILITY AND REPORT OUTPUT
# ======================================================================
class TestReproducibility(ResearchTestCase):
    GROUP = "Reproducibility and report output"
    TEST_ORDER = (
        "test_seeded_run_is_fully_reproducible",
        "test_seeded_legacy_messages_replay",
        "test_unseeded_keys_use_system_entropy",
        "test_report_filenames_do_not_collide",
    )

    def test_seeded_run_is_fully_reproducible(self):
        """An explicit rng fixes the keys, not just z and k"""
        def run(seed, params):
            ec = Secp256k1(params, rng=random.Random(seed))
            keys = ec.generate_unique_keys(4, 1)
            return keys, [ec.sign_message(d, b"regression", 1) for d in keys]

        for params in (TEST_PARAMS, LEGACY_PARAMS):
            first, second = run(77, params), run(77, params)
            # The keys must replay too, not only z and k.
            self.assertEqual(first[0], second[0], "seeded keys must replay")
            self.assertEqual(first[1], second[1], "seeded signatures must replay")
            self.assertNotEqual(run(78, params)[0], first[0],
                                "a different seed must give different keys")
            # Seeded keys stay in [1, n-1].
            self.assertTrue(all(1 <= d < params.n for d in first[0]))
        self.note("2 curves: keys+signatures replay, seed 78 differs, range OK")

    def test_seeded_legacy_messages_replay(self):
        """A seeded legacy run replays its messages, not only its keys"""
        # prev_txid and the amounts come from the rng, so the legacy
        # preimages -- hence every z -- replay with the seed.
        def run(seed, sig_type):
            ec = Secp256k1(LEGACY_PARAMS, rng=random.Random(seed))
            d = ec.generate_unique_keys(1, 100)[0]
            _, pub = ec.generate_keypair(d)
            msgs = [_build_message(ec, pub, sig_type) for _ in range(3)]
            return msgs, [ec.sign_message(d, m, 100)[:4] for m in msgs]

        for sig_type in ("p2pkh", "p2wpkh"):
            first = run(91, sig_type)
            self.assertEqual(run(91, sig_type), first,
                             f"{sig_type}: a seeded run must replay its messages")
            self.assertNotEqual(run(92, sig_type)[0], first[0],
                                f"{sig_type}: a different seed must differ")
            self.assertEqual(len(set(first[0])), 3,
                             f"{sig_type}: messages within a run must differ")
        self.note("p2pkh+p2wpkh: preimages and (z, r, s) replay; seed 92 differs")

    def test_unseeded_keys_use_system_entropy(self):
        """Without an rng, keys still come from secrets rather than a seed"""
        default = Secp256k1(TEST_PARAMS)
        seeded = Secp256k1(TEST_PARAMS, rng=random.Random(0))
        self.assertFalse(default.rng_is_explicit)
        self.assertTrue(seeded.rng_is_explicit)
        # The CLI default passes no rng either, so its keys come from secrets.
        self.assertFalse(build_ec(parse_args([])).rng_is_explicit)
        self.assertTrue(build_ec(parse_args(["--seed", "1"])).rng_is_explicit)
        a = Secp256k1(TEST_PARAMS).generate_unique_keys(8, 1)
        b = Secp256k1(TEST_PARAMS).generate_unique_keys(8, 1)
        self.assertNotEqual(a, b, "unseeded runs must not be reproducible")
        self.note("class and CLI default not explicit; 8-key draws differ")

    def test_report_filenames_do_not_collide(self):
        """Reports written in the same second get distinct filenames"""
        import tempfile
        stats = {"spent_time_sec": 0.0, "case_D_level_counts": {}}
        with tempfile.TemporaryDirectory() as tmp:
            written = [
                _write_report(TEST_PARAMS, [], stats, "p2pkh", tmp)
                for _ in range(8)
            ]
            names = [os.path.basename(p) for p in written]
            # 8 writes in the same second -> 8 files.
            self.assertEqual(len(set(names)), 8, "filenames collided")
            self.assertEqual(len(os.listdir(tmp)), 8, "reports overwrote each other")
            for name in names:
                self.assertTrue(name.startswith("transaction_list_"))
                self.assertTrue(name.endswith(".txt"))
                stamp, tag = name[len("transaction_list_"):-4].split("_")
                self.assertEqual(len(stamp), 14)      # YYYYMMDDHHMMSS preserved
                self.assertTrue(stamp.isdigit())
                self.assertEqual(len(tag), 8)         # random uniquifier
                int(tag, 16)                          # must be hex
        self.note("8 writes -> 8 distinct files, timestamp + 8-hex tag")


# ======================================================================
# LEGACY TRANSACTION PREIMAGES
# ======================================================================
class _ExtremeDraws(random.Random):
    """An rng whose ``randint`` returns one end of the requested range.

    Bit i of ``mask`` selects the upper bound for the i-th call.  Running every
    mask drives each draw to both extremes in every combination, so the test
    does not need to know which draw is the input amount and which the fee.
    """

    def __init__(self, mask: int) -> None:
        super().__init__(0)
        self.mask = mask
        self.calls = 0

    def randint(self, a: int, b: int) -> int:
        bit = (self.mask >> self.calls) & 1
        self.calls += 1
        return b if bit else a


class TestLegacyPreimages(ResearchTestCase):
    GROUP = "Legacy transaction preimages"
    TEST_ORDER = (
        "test_amounts_never_go_negative",
    )

    def test_amounts_never_go_negative(self):
        """Synthetic amounts never produce a negative or dust output"""
        # The fee is capped by the input, so the output can neither go
        # negative (int.to_bytes would raise OverflowError) nor fall below the
        # 546-sat dust threshold.
        draws = 3  # prev_index, input amount, fee
        builders = {
            "p2pkh": make_bitcoin_legacy_sighash_message,
            "p2wpkh": make_bitcoin_segwit_sighash_message,
        }
        outputs = []
        for sig_type, builder in builders.items():
            target = f"utils.generate_transactions.{builder.__name__}"
            for mask in range(1 << draws):
                rng = _ExtremeDraws(mask)
                with mock.patch(target, wraps=builder) as spy:
                    _build_message(Secp256k1(LEGACY_PARAMS, rng=rng),
                                   LEGACY_PARAMS.g, sig_type)
                # An extra draw would leave combinations untested: fail loudly.
                self.assertEqual(rng.calls, draws, "update `draws` to match _build_message")
                output = spy.call_args.args[-1]
                self.assertGreaterEqual(output, 546, f"{sig_type} mask {mask:03b}")
                if sig_type == "p2wpkh":  # only BIP 143 takes the input amount
                    fee = spy.call_args.args[-2] - output
                    self.assertTrue(1_000 <= fee <= 50_000, f"fee {fee} out of range")
                outputs.append(output)
        # The worst corner (smallest input, largest fee) must actually be hit.
        self.assertEqual(min(outputs), 546)
        self.note(f"2 sig types x {1 << draws} corner draws, min output "
                  f"{min(outputs)} sat")


# ======================================================================
# VERIFICATION AND PUBLIC-ONLY RECOVERY
# ======================================================================
class TestVerification(ResearchTestCase):
    GROUP = "Verification and public-only recovery"
    TEST_ORDER = (
        "test_verify_accepts_zero_message_hash",
        "test_public_key_check_rejects_twin",
        "test_case_e_recovery_ignores_secret_sublabel",
    )

    def test_verify_accepts_zero_message_hash(self):
        """A valid signature with z = 0 (mod n) verifies"""
        # u1 = z/s = 0 makes u1*G the point at infinity, a legitimate summand.
        checked = 0
        for params in (TEST_PARAMS, LEGACY_PARAMS):
            ec = Secp256k1(params)
            n = params.n
            rnd = random.Random(30)
            for _ in range(3):
                x = rnd.randrange(1, n)
                k = rnd.randrange(1, n)
                _, pub = ec.generate_keypair(x)
                r = ec.scalar_multiply(k, params.g)[0] % n
                s = r * x * pow(k, -1, n) % n
                if not (r and s):
                    continue
                self.assertTrue(ec.verify_x_candidate(x, 0, r, s))
                self.assertTrue(ec.verify_signature(pub, (0, r, None, s, None, None)))
                self.assertFalse(ec.verify_signature(pub, (1, r, None, s, None, None)))
                checked += 1
        self.note(f"{checked} z=0 signatures accepted, z=1 variants rejected")

    def test_public_key_check_rejects_twin(self):
        """The twin key passes verify_x_candidate; only x*G == Q is decisive"""
        # (z, r, s) also passes the r-check under the twin key -x - 2*z/r
        # (nonce n - k), so verify_x_candidate alone cannot certify a key.
        checked = 0
        for params in (TEST_PARAMS, LEGACY_PARAMS):
            ec = Secp256k1(params, rng=random.Random(31))
            n = params.n
            rnd = random.Random(32)
            for _ in range(10):
                d = rnd.randrange(1, n)
                _, pub = ec.generate_keypair(d)
                z, r, s, _k_inv = _signature(ec, d, rnd)
                twin = (-d - 2 * z * pow(r, -1, n)) % n
                if twin in (0, d):
                    continue
                self.assertTrue(ec.verify_x_candidate(twin, z, r, s))
                self.assertFalse(ec.matches_public_key(twin, pub))
                self.assertTrue(ec.matches_public_key(d, pub))
                checked += 1
        self.note(f"{checked} signatures: twin passes r-check, fails x*G == Q")

    def test_case_e_recovery_ignores_secret_sublabel(self):
        """Case-E recovery needs only the class, not the secret E1/E2 label"""
        # The E1/E2 sub-label is computed from s_zk + s_rxk > s, i.e. from the
        # secret split, so recovery must not depend on it: it tries both S.
        ec = Secp256k1(TEST_PARAMS, rng=random.Random(33))
        gen = ECDSAClassGenerator(ec)
        seen = {"E1": 0, "E2": 0}
        for _ in range(60):
            fs = gen.generate("E")
            pub = ec.scalar_multiply(fs.x, TEST_PARAMS.g)
            keys, attempts = recover_private_keys(ec, "E", fs.s, 0, fs.z, fs.r_x, 0, pub)
            self.assertEqual(keys, [fs.x])
            self.assertIn(attempts, (2, 4))
            for label in ("E1", "E2"):   # the sub-label is accepted and ignored
                self.assertEqual(
                    recover_private_keys(ec, label, fs.s, 0, fs.z, fs.r_x, 0, pub)[0],
                    [fs.x])
            seen[fs.case] += 1
        self.assertTrue(seen["E1"] and seen["E2"])
        self.note(f"E1 x{seen['E1']}, E2 x{seen['E2']}: recovered from (z, r, s) + class")


# ======================================================================
# DIRECT CLASS CONSTRUCTION
# ======================================================================
class TestConstruction(ResearchTestCase):
    GROUP = "Direct class construction"
    TEST_ORDER = (
        "test_constructed_rows_verify_and_recover",
        "test_constructed_report_counts_are_measured",
        "test_secp256k1_construction",
    )

    def test_constructed_rows_verify_and_recover(self):
        """Constructed A/B/E rows verify against Q and recover exactly x"""
        ec = Secp256k1(TEST_PARAMS, rng=random.Random(40))
        gen = ECDSAClassGenerator(ec)
        n = TEST_PARAMS.n
        for cls in ("A", "B", "E"):
            for _ in range(15):
                fs = gen.generate(cls)
                pub = ec.scalar_multiply(fs.x, TEST_PARAMS.g)
                sig = (fs.z, fs.r_x, fs.r_y, fs.s, fs.k, fs.k_inv)
                self.assertTrue(ec.verify_signature(pub, sig))
                self.assertEqual(fs.recovered, [fs.x])
                self.assertEqual(fs.case[0], cls)
                self.assertEqual(classify(fs.s, fs.s_zk, fs.s_rxk, fs.s_zr, n)[0], fs.case)
                self.assertFalse(fs.is_message_bound)
        self.note("45 rows: ECDSA-valid, label re-derived, key == [x]")

    def test_constructed_report_counts_are_measured(self):
        """Constructed reports: constructed classes only, recovery measured"""
        # A constructed report counts each row once, under the class it was
        # built for (no C, D, unclassified or HYP-001), while the recovery
        # lines are measured.
        ec = Secp256k1(TEST_PARAMS, rng=random.Random(41))
        with redirect_stdout(io.StringIO()):
            rows, st, built, skipped = _collect_forged_rows(ec, ["A", "B", "E"], 12)
        self.assertEqual(built, {"A": 12, "B": 12, "E": 12})
        self.assertEqual(skipped, {})
        self.assertEqual(len(rows), 36)
        for c in "ABE":
            self.assertEqual(st[f"case_{c}_count"], 12)
        for key in ("case_C_count", "case_D_count", "unclassified_count",
                    "hypothesis_001_count"):
            self.assertEqual(st[key], 0, key)
        self.assertEqual(st["case_D_level_counts"], {})
        self.assertEqual(st["total_observed_cases"], 36)
        self.assertEqual(st["total_transaction_count"], 36)
        for agg in ("attempts", "verified"):
            self.assertEqual(st[f"recovery_{agg}"],
                             sum(st[f"recovery_{agg}_{c}"] for c in "abe"))
        self.assertEqual(st["recovery_rejected"],
                         st["recovery_attempts"] - st["recovery_verified"])
        self.assertEqual(st["recovery_attempts_a"], 12)          # 1 per A row
        self.assertTrue(12 <= st["recovery_attempts_b"] <= 24)   # 1-2 per B row
        self.assertTrue(24 <= st["recovery_attempts_e"] <= 48)   # 2-4 per E row
        for c in "abe":
            self.assertEqual(st[f"recovery_verified_{c}"], 12)
        self.note(f"A/B/E 12 each, C=D=0; attempts {st['recovery_attempts']}, "
                  f"rejected {st['recovery_rejected']}")

    def test_secp256k1_construction(self):
        """secp256k1: A and E are built and recovered, B is refused"""
        ec = Secp256k1(LEGACY_PARAMS, rng=random.Random(42))
        gen = ECDSAClassGenerator(ec)
        for cls in ("A", "E"):
            fs = gen.generate(cls)
            self.assertEqual(fs.recovered, [fs.x])
        with self.assertRaises(ClassConstructionError) as ctx:
            gen.generate("B")
        message = str(ctx.exception)
        self.assertIn("not constructible on real secp256k1", message)
        self.note("A, E recovered on secp256k1; B refused with reason")


# ======================================================================
# COMMAND-LINE ENTRY POINTS
# ======================================================================
def _run(args: Sequence[str], cwd: str) -> "subprocess.CompletedProcess[str]":
    return subprocess.run([sys.executable, *args], cwd=cwd, capture_output=True,
                          text=True, timeout=600)


class TestCommandLine(ResearchTestCase):
    GROUP = "Command-line entry points and portability"
    TEST_ORDER = (
        "test_flat_layout_runs_every_script",
        "test_common_key_search_refuses_legacy",
        "test_demo_writes_no_report",
        "test_rand_bytes_is_randbytes_compatible",
    )

    def test_flat_layout_runs_every_script(self):
        """All three scripts run from a flat folder, --tx-with-classes too"""
        files = [os.path.join(_SRC, "ecurve", "secp256k1.py"),
                 os.path.join(_SRC, "ecurve", "_ripemd160.py"),
                 os.path.join(_SRC, "utils", "generate_transactions.py"),
                 os.path.join(_SRC, "utils", "generate_found_classes.py"),
                 os.path.join(_SRC, "utils", "find_common_private_key.py")]
        with tempfile.TemporaryDirectory() as tmp:
            for f in files:
                shutil.copy(f, tmp)
            runs = {
                "construct": _run(["generate_transactions.py", "--tx-with-classes",
                                   "A", "E", "--output-count", "2", "--seed", "1",
                                   "--out-dir", tmp], tmp),
                "sample": _run(["generate_transactions.py", "--keys", "3",
                                "--seed", "1", "--out-dir", tmp], tmp),
                "search": _run(["find_common_private_key.py"], tmp),
            }
            for name, proc in runs.items():
                self.assertEqual(proc.returncode, 0, f"{name}: {proc.stderr[-300:]}")
            self.assertIn("-> OK", runs["search"].stdout)
            reports = [f for f in os.listdir(tmp) if f.startswith("transaction_list_")]
            self.assertEqual(len(reports), 2)
        self.note("3 scripts, flat folder: exit 0, 2 reports, self-check OK")

    def test_common_key_search_refuses_legacy(self):
        """find_common_private_key --curve-mode legacy exits with an error"""
        script = os.path.join(_SRC, "utils", "find_common_private_key.py")
        proc = _run([script, "--curve-mode", "legacy"], _SRC)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("refusing --curve-mode legacy", proc.stderr)
        self.assertNotIn("MISMATCH", proc.stdout)
        self.note(f"exit {proc.returncode}, refusal on stderr, no search run")

    def test_demo_writes_no_report(self):
        """--demo runs one round and writes nothing"""
        script = os.path.join(_SRC, "utils", "generate_transactions.py")
        with tempfile.TemporaryDirectory() as tmp:
            proc = _run([script, "--demo", "--out-dir", tmp], tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr[-300:])
            self.assertIn("Signature validation: True", proc.stdout)
            self.assertEqual(os.listdir(tmp), [])
        self.note("signature validated, 0 files written")

    def test_rand_bytes_is_randbytes_compatible(self):
        """rand_bytes works without Random.randbytes and replays seeded runs"""
        # Random.randbytes exists only from Python 3.9; the documented
        # minimum is 3.8.
        for seed in range(5):
            got = rand_bytes(random.Random(seed), 32)
            self.assertEqual(len(got), 32)
            if hasattr(random.Random, "randbytes"):   # 3.9+: byte-identical
                self.assertEqual(got, random.Random(seed).randbytes(32))
        self.assertEqual(len(rand_bytes(random.SystemRandom(), 32)), 32)
        self.note(f"seeded output == Random.randbytes on python "
                  f"{sys.version_info[0]}.{sys.version_info[1]}")


# ======================================================================
# SIGNATURE SPACE
# ======================================================================
class TestSignatureSpace(ResearchTestCase):
    GROUP = "Signature space in the statistics block"
    TEST_ORDER = (
        "test_signature_space_is_one_formula",
        "test_test_curve_signer_draws_the_counted_domain",
        "test_test_curve_redraws_remove_3e_5_of_the_domain",
        "test_legacy_signs_one_nonce_per_hash",
        "test_report_prints_the_signature_space",
    )

    def test_signature_space_is_one_formula(self):
        """Signature space: one formula on both curves, exact formatting"""
        # Nz*Nk per key and Nx*Nz*Nk over all keys on both curves.  Only the
        # domain sizes differ, and they follow the nonce rule, not the curve.
        for params in (TEST_PARAMS, LEGACY_PARAMS):
            n = params.n
            for m in (1, 100, n - 1):
                sp = signature_space(params, m)
                self.assertEqual(sp.keys, n - m)                  # keys on [m, n-1]
                if params.mode == "test":                         # z, k on [m, n-1]
                    self.assertEqual((sp.hashes, sp.nonces_per_hash), (n - m, n - m))
                else:                                 # z = dSHA256 mod n, RFC 6979
                    self.assertEqual((sp.hashes, sp.nonces_per_hash), (n, 1))
                self.assertEqual(sp.per_key, sp.hashes * sp.nonces_per_hash)
                self.assertEqual(sp.all_keys, sp.keys * sp.per_key)
            with self.assertRaises(ValueError):
                signature_space(params, n)
        # The report figures for the default --min-start-range 100.
        pinned = {
            TEST_PARAMS.name: ("9.913587e+09", "9.870662e+14"),
            LEGACY_PARAMS.name: ("1.157921e+77", "1.340781e+154"),
        }
        for params in (TEST_PARAMS, LEGACY_PARAMS):
            sp = signature_space(params, 100)
            self.assertEqual((_format_count(sp.per_key), _format_count(sp.all_keys)),
                             pinned[params.name])
        # Exact formatting: what float prints wherever float is exact, and no
        # OverflowError beyond the float range.
        rnd = random.Random(36)
        for _ in range(2_000):
            value = rnd.randrange(1, 2 ** 53)
            self.assertEqual(_format_count(value), f"{float(value):.6e}")
        self.assertEqual(_format_count(10 ** 400), "1.000000e+400")
        self.note("test (n-m)^2 / (n-m)^3, legacy n / (n-m)*n; e+09 .. e+400")

    def test_test_curve_signer_draws_the_counted_domain(self):
        """Test curve: the signer draws exactly the counted (z, k) domain"""
        # m = n - 30 shrinks every domain to 30 values, so it can be exhausted.
        # Each emitted (z, r, s) gives its own k back, and the only (z, k)
        # pairs never emitted are those with s = 0.
        params = TEST_PARAMS
        n, m = params.n, params.n - 30
        sp = signature_space(params, m)
        ec = Secp256k1(params, rng=random.Random(37))
        self.assertEqual(sorted(ec.generate_unique_keys(sp.keys, m)), list(range(m, n)))
        r_of = {k: ec.scalar_multiply(k, params.g)[0] % n for k in range(m, n)}
        # Pick the key so that one pair of the domain has s = 0.
        k0 = next(k for k in range(m, n) if r_of[k])
        z0 = m + 2
        x = (-z0 * pow(r_of[k0], -1, n)) % n
        valid = {(z, k) for z in range(m, n) for k in range(m, n)
                 if r_of[k] and (z + r_of[k] * x) % n}
        emitted = set()
        for _ in range(15_000):
            z, r, _r_y, s, k, _k_inv = ec.sign_message(x, b"", m)
            self.assertTrue(m <= z < n and m <= k < n)
            self.assertEqual(k, (z + r * x) * pow(s, -1, n) % n)
            emitted.add((z, k))
        rejected = sp.per_key - len(valid)
        self.assertEqual(emitted, valid)
        self.assertNotIn((z0, k0), emitted)
        self.assertGreaterEqual(rejected, 1)
        self.note(f"m = n-30: {len(valid)} of {sp.per_key} (z, k) emitted, "
                  f"{rejected} with s = 0")

    def test_test_curve_redraws_remove_3e_5_of_the_domain(self):
        """Test curve: r = 0 / s = 0 redraws remove ~3.0e-5 of the domain"""
        # Two nonces have r = 0 (their point has x = n, and n < p), and about
        # one nonce per z gives s = 0, so a key emits about 3/(n-m) fewer
        # distinct triples than Nz*Nk.  Exact count for one key, m = 100.
        params = TEST_PARAMS
        n, m = params.n, 100
        sp = signature_space(params, m)
        ec = Secp256k1(params)
        xs, point = [0], None                  # xs[k] = (k*G).x
        for _ in range(1, n):
            point = ec.point_add(point, params.g)
            xs.append(point[0])
        zero_r = [k for k in range(m, n) if xs[k] % n == 0]
        self.assertEqual(len(zero_r), 2)
        self.assertTrue(all(xs[k] == n for k in zero_r))
        key = 12_345
        s_zero = sum(1 for k in range(m, n)
                     if xs[k] % n and (-(xs[k] % n) * key) % n >= m)
        rejected = len(zero_r) * sp.hashes + s_zero
        fraction = rejected / sp.per_key
        self.assertAlmostEqual(fraction * (n - m), 3, delta=0.01)
        self.note(f"r=0: 2 nonces, s=0: {s_zero:,} pairs -> {fraction:.2e} of Nz*Nk")

    def test_legacy_signs_one_nonce_per_hash(self):
        """secp256k1: one nonce per hash, so the space per key is n"""
        # RFC 6979 derives k from (x, z): neither the run's rng nor
        # --min-start-range reaches it, and z = dSHA256(preimage) mod n is not
        # confined to [m, n-1].  Hence Nk = 1 and Nz = n.
        params = LEGACY_PARAMS
        n = params.n
        d = random.Random(39).randrange(1, n)
        a = Secp256k1(params, rng=random.Random(1))
        b = Secp256k1(params, rng=random.Random(2))
        below_floor = 0
        for i in range(5):
            msg = f"message {i}".encode()
            sig = a.sign_message(d, msg, 1)
            self.assertEqual(b.sign_message(d, msg, n - 1), sig)  # other rng, other m
            digest = hashlib.sha256(hashlib.sha256(msg).digest()).digest()
            self.assertEqual(sig[0], int.from_bytes(digest, "big") % n)
            below_floor += sig[0] < n - 1
        self.assertEqual(below_floor, 5)
        sp = signature_space(params, 100)
        self.assertEqual((sp.per_key, sp.all_keys), (n, (n - 100) * n))
        self.note("same (x, z) -> same k under 2 rngs and 2 floors; per key = n")

    def test_report_prints_the_signature_space(self):
        """Report: Signature Space lines follow the formula, not --keys"""
        for params in (TEST_PARAMS, LEGACY_PARAMS):
            sp = signature_space(params, 100)
            expected = (_format_count(sp.per_key), _format_count(sp.all_keys))
            for keys, tx, fixed in ((1, 1, 0), (3, 2, 0), (1, 2, 4_242)):
                _rows, stats = _collect_rows(
                    ec=Secp256k1(params, rng=random.Random(40)),
                    cfg=_build_report_config(params),
                    total_key_count=keys,
                    private_key=fixed,
                    transaction_limit_per_key=tx,
                    output_count=0,
                    d_case_digit=-1,
                    min_start_range=100,
                    progress=False,
                )
                self.assertEqual((stats["signature_space_per_key"],
                                  stats["signature_space_all_keys"]), expected)
            with tempfile.TemporaryDirectory() as tmp:
                path = _write_report(params, [], stats, "p2pkh", tmp)
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
            self.assertIn(f"Signature Space Per Key: {expected[0]}\n", text)
            self.assertIn(f"Signature Space All Keys: {expected[1]}\n", text)
        self.note("2 curves x 3 runs (keys, tx per key, fixed key): same lines")


SUITE: Tuple[type, ...] = (
    # tests 1-25
    TestCurve, TestRecovery, TestFormatting, TestSearch, TestReproducibility,
    TestLegacyPreimages,
    # tests 26-35
    TestVerification, TestConstruction, TestCommandLine,
    # tests 36-40
    TestSignatureSpace,
)


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
