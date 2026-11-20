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
    case E:  {s_zk, s_rxk} == {u, S - u},    u = (S + S//2 + 1) // 2,
                                             S in {s, s+n} with S % 4 in {1, 2}
    case C:  s_zk/a is an integer > 1        (m1 not fixed by public data)
    case D:  s_zk/a is not an integer

The LABELS are computed from the secret split and are research annotations;
an attacker cannot evaluate them.  The recovery FORMULAS use public data only:
given the class, case E tries both parts of both admissible S, i.e. it does
not use the secret E1/E2 sub-label.

Every candidate is checked on the curve before it is reported.  With the
signer's public key Q (which the sampling pipeline always has) the check is
the decisive ``x*G == Q``; without it, ``verify_x_candidate`` is used, which
also accepts the twin key -x - 2*z*r^-1 (see README, Known issue 2).
Rejected candidates are counted, not printed as results.

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
from dataclasses import dataclass, field
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
    # Per-class breakdown: the aggregates above must equal the sum of these.
    # Printing them makes a silently dropped class visible instead of leaving
    # the reader to factor 1564 = 224 + 2*670 by hand.
    "recovery_attempts_a",
    "recovery_attempts_b",
    "recovery_attempts_e",
    "recovery_verified_a",
    "recovery_verified_b",
    "recovery_verified_e",
    # Signatures with at least one verified key; unlike Recovery Verified this
    # does not count an A/E overlap twice.
    "recovered_signature_count",
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
    discards the whole ``S % 4 == 1`` family: exactly half of all case-E
    pairs (66,442 of 132,884 on the test curve, by exhaustive count).

    The E1/E2 sub-label depends on the secret parts; the recovery path does
    not use it (``_guesses_case_e`` tries both admissible S).
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
    ec: Secp256k1,
    guesses: Iterable[int],
    s: int,
    z: int,
    r: int,
    public_key: Optional[Tuple[int, int]] = None,
) -> Tuple[List[int], int]:
    """Map s_zk guesses to private keys, keeping only those the curve accepts.

    With ``public_key`` the acceptance test is the decisive ``x*G == Q``;
    without it, ``verify_x_candidate``, which also accepts the twin key.
    Returns ``(verified_keys, attempts)``.
    """
    n = ec.curve.n
    keys: List[int] = []
    attempts = 0
    for s_zk in dict.fromkeys(g % n for g in guesses):   # dedupe, keep order
        if s_zk == 0:
            continue
        attempts += 1
        x = recover_x_from_s_zk(s_zk, s, z, r, n)
        if x is None or x in keys:
            continue
        if public_key is not None:
            accepted = ec.matches_public_key(x, public_key)
        else:
            accepted = ec.verify_x_candidate(x, z, r, s)
        if accepted:
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


def _guesses_case_e(s: int, curve_n: int) -> List[int]:
    """Case E from public data: both parts of every admissible S.

    ``S`` is ``s`` (E1) or ``s + n`` (E2).  Which one applies depends on the
    secret parts, so a recovery that uses public data only must try both.
    An ``S`` is admissible when ``S % 4`` is 1 or 2 and both parts are valid
    scalars (``1 <= smaller`` and ``larger < n``).  At most four guesses.

    The previous version took the E1/E2 sub-label as an argument and tried only
    the matching ``S`` -- i.e. it used secret information to halve the work.
    """
    guesses: List[int] = []
    for big_s in (s, s + curve_n):
        if big_s % 4 not in (1, 2):
            continue
        larger, smaller = _half_difference_parts(big_s)
        if 1 <= smaller and larger < curve_n:
            guesses += [larger, smaller]
    return guesses


def recover_private_keys(
    ec: Secp256k1,
    case: str,
    s: int,
    s_zr: int,
    z: int,
    r: int,
    a: int,
    public_key: Optional[Tuple[int, int]] = None,
) -> Tuple[List[int], int]:
    """Dispatch to the case-specific guess, then verify. Returns (keys, attempts).

    ``case`` is the class: "A", "B" or "E" ("E1"/"E2" are accepted and treated
    as "E" -- the sub-label is not used).  Cases C and D leave ``s_zk``
    undetermined by public data, so they yield nothing rather than a
    fabricated value.  Pass ``public_key`` for the decisive ``x*G == Q`` test.
    """
    n = ec.curve.n
    if case == "A":
        guesses = _guesses_case_a(a)
    elif case == "B":
        guesses = _guesses_case_b(s, s_zr, a, n)
    elif case.startswith("E"):
        guesses = _guesses_case_e(s, n)
    else:
        return [], 0
    return _verified(ec, guesses, s, z, r, public_key)


# ======================================================================
# HYPOTHESES
# ======================================================================
def _check_hypothesis_001(digit: int, s: int, s_zk: int, a: int) -> str:
    """HYP-001 for case D.

    GATE.  The test is evaluated only when all three hold; otherwise "-":

        N > 1,    s > s_zk,    s_zk even

    The gate is part of the definition.  Without it the identity below fires
    on about 8 % of random triples instead of about 0.5 %
    (``docs/readme_measurements.py`` reproduces both figures).

    With ``N = floor(s_zk/a)`` and ``w = s_zk mod a`` the tested identity is

        N*w - ((N*a mod w) - ((N+1)*a mod w)) == a                        (1)

    EXACT REDUCTION.  Write ``a = q*w + t`` with ``q = floor(a/w)`` and
    ``0 <= t < w``.  Then ``N*a mod w == N*t mod w`` and
    ``(N+1)*a mod w == ((N*t mod w) + t) - delta*w`` where

        delta = 1 if ((N*t) mod w) + t >= w else 0

    so the left-hand side of (1) equals ``w*(N - delta) + t``, and

        (1)  <=>  floor(a/w) == N - delta                                 (2)

    (2) is an identity, not an approximation: it matched (1) on 5e5 random
    (N, a, w) triples with zero deviations.

    CAUTION.  The weaker condition ``floor(a/w) in {N, N-1}`` -- which earlier
    documentation gave as the reduction -- is implied by (1) but does NOT imply
    it: which of the two values occurs is fixed by ``delta``.  On 10^6 uniform
    gated triples below 2^64 the weak form holds about 2.2 times as often as
    (1) (``docs/readme_measurements.py``).  Do not substitute the weaker form.

    (2) constrains the first two partial quotients of the continued fraction of
    ``s_zk/a``.  For independent uniform ``s_zk`` and ``a`` the law of that
    ratio does not depend on the size of n, which is why the firing rate is
    scale-invariant.  That law is not Gauss-Kuzmin: in the gated population
    P(floor(a/w) = 1) is about 0.436, against 0.415 under Gauss-Kuzmin.
    Both ``s_zk`` and ``a`` are needed to evaluate HYP-001 and ``s_zk`` is
    secret, so it is a statistical observation, not a recovery path.

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
# SHARED CLASSIFICATION AND COUNTING
# ======================================================================
# One classifier and one accumulator serve both the sampling run and the
# --tx-with-classes construction.  The construction used to fill its report
# with hard-coded counters (attempts == rows, rejected == 0) and left the
# per-class recovery lines at 0; it now counts exactly like a sampling run.
@dataclass(frozen=True)
class SignatureAnalysis:
    """Research labels of one signature (computed from the secret split)."""

    e_detected: bool
    e_label: str                 # "E1" or "E2"; meaningful only if e_detected
    a: Optional[int]             # auxiliary a, None when no valid a exists
    label: Optional[str]         # "A", "B", "C", "D" or None (no valid a)
    m1: Optional[Fraction]
    m2: Optional[Fraction]
    level: Optional[int]         # floor(s_zk / a) for case D
    hypothesis: str              # "HYP-001" or "-"


def auxiliary_a(s: int, s_zr: int, curve_n: int) -> Optional[int]:
    """``a = s mod ((s_zr - s) mod n)`` when it is valid, else None.

    Valid means ``s_zr > s`` and ``0 < a != s``.  The guard ``a != s_zr`` of
    the original was unreachable, since a < s_zr - s < s_zr.
    """
    if s_zr <= s:
        return None
    a = s % ((s_zr - s) % curve_n)
    return a if 0 < a != s else None


def analyse_signature(
    s: int, s_zk: int, s_rxk: int, s_zr: int, curve_n: int
) -> SignatureAnalysis:
    """Classify one signature exactly as the report does.

    Case A is tested first and on m1 alone: the original also required m2 to
    be non-integral, so a perfectly good ``s_zk == a`` was relabelled C -- and
    silently not recovered -- whenever m2 happened to be an integer too.
    """
    e_detected, e_label = _detect_half_difference_split(s, s_zk, s_rxk, curve_n)
    a = auxiliary_a(s, s_zr, curve_n)
    if a is None:
        return SignatureAnalysis(e_detected, e_label, None, None, None, None, None, "-")

    m1 = Fraction(s_zk, a)
    m2 = Fraction(s + s_zr, s_rxk) if s_rxk else None
    level: Optional[int] = None
    hypothesis = "-"
    if m1 == 1:
        label = "A"
    elif m2 is not None and m1.denominator == 1 and m2.denominator == 1 and m1 == m2:
        label = "B"
    elif m1.denominator == 1:
        label = "C"
    else:
        label = "D"
        level = s_zk // a
        hypothesis = _check_hypothesis_001(level, s, s_zk, a)
    return SignatureAnalysis(e_detected, e_label, a, label, m1, m2, level, hypothesis)


@dataclass
class RecoveryOutcome:
    """Keys recovered from public data for one signature, per class path."""

    e_keys: List[int] = field(default_factory=list)
    e_attempts: int = 0
    ab_keys: List[int] = field(default_factory=list)
    ab_attempts: int = 0


def recover_for_analysis(
    ec: Secp256k1,
    analysis: SignatureAnalysis,
    s: int,
    s_zr: int,
    z: int,
    r: int,
    public_key: Optional[Tuple[int, int]] = None,
) -> RecoveryOutcome:
    """Run the recovery formula of every class the signature belongs to."""
    out = RecoveryOutcome()
    if analysis.e_detected:
        out.e_keys, out.e_attempts = recover_private_keys(
            ec, "E", s, 0, z, r, 0, public_key)
    if analysis.label in ("A", "B"):
        out.ab_keys, out.ab_attempts = recover_private_keys(
            ec, analysis.label, s, s_zr, z, r, analysis.a or 0, public_key)
    return out


class RunStats:
    """Accumulates the statistics block of a report.

    Sampled reports (``add``):
      * every E signature counts in case E; if it also has a valid ``a`` it
        counts in A/B/C/D as well, and in ``case_E_overlapping_a_cases``;
      * ``total_observed_cases`` subtracts that overlap;
      * recovery runs the formula of each class the signature belongs to, so a
        signature that is both E and A/B contributes to both per-class lines,
        while ``recovered_signature_count`` counts it once.

    Constructed reports (``add_constructed``): each row counts once, under the
    class it was constructed for (A, B or E).  Cases C and D, HYP-001 and the
    E/A overlap stay 0 by design, ``transactions_with_valid_a`` counts the A and
    B rows, and the recovery lines are the attempts and keys of the recovery of
    that class -- measured, not assumed.
    """

    def __init__(self) -> None:
        self.counters = {"A": 0, "B": 0, "C": 0, "D": 0, "E": 0}
        self.level_counts: Dict[int, int] = {}
        self.with_valid_a = 0
        self.e_overlap = 0
        self.hyp_001 = 0
        self.attempts = {"A": 0, "B": 0, "E": 0}
        self.verified = {"A": 0, "B": 0, "E": 0}
        self.recovered_signatures = 0

    def add(self, analysis: SignatureAnalysis, outcome: RecoveryOutcome) -> None:
        if analysis.e_detected:
            self.counters["E"] += 1
            self.attempts["E"] += outcome.e_attempts
            self.verified["E"] += len(outcome.e_keys)
        if analysis.label is not None:
            self.with_valid_a += 1
            if analysis.e_detected:
                self.e_overlap += 1
            self.counters[analysis.label] += 1
            if analysis.label in ("A", "B"):
                self.attempts[analysis.label] += outcome.ab_attempts
                self.verified[analysis.label] += len(outcome.ab_keys)
            if analysis.label == "D" and analysis.level is not None:
                self.level_counts[analysis.level] = (
                    self.level_counts.get(analysis.level, 0) + 1)
                if analysis.hypothesis == "HYP-001":
                    self.hyp_001 += 1
        if outcome.e_keys or outcome.ab_keys:
            self.recovered_signatures += 1

    def add_constructed(self, cls: str, keys: Sequence[int], attempts: int) -> None:
        """One directly constructed row, counted under its constructed class only."""
        self.counters[cls] += 1
        if cls in ("A", "B"):
            self.with_valid_a += 1
        self.attempts[cls] += attempts
        self.verified[cls] += len(keys)
        if keys:
            self.recovered_signatures += 1

    def as_dict(self) -> Dict[str, object]:
        attempts = sum(self.attempts.values())
        verified = sum(self.verified.values())
        return {
            "transactions_with_valid_a": self.with_valid_a,
            "total_observed_cases": sum(self.counters.values()) - self.e_overlap,
            "case_A_count": self.counters["A"],
            "case_B_count": self.counters["B"],
            "case_C_count": self.counters["C"],
            "case_D_count": self.counters["D"],
            "case_E_count": self.counters["E"],
            "case_E_overlapping_a_cases": self.e_overlap,
            "hypothesis_001_count": self.hyp_001,
            "recovery_attempts": attempts,
            "recovery_verified": verified,
            "recovery_rejected": attempts - verified,
            "recovery_attempts_a": self.attempts["A"],
            "recovery_attempts_b": self.attempts["B"],
            "recovery_attempts_e": self.attempts["E"],
            "recovery_verified_a": self.verified["A"],
            "recovery_verified_b": self.verified["B"],
            "recovery_verified_e": self.verified["E"],
            "recovered_signature_count": self.recovered_signatures,
            "case_D_level_counts": dict(self.level_counts),
        }


def _keys_text(keys: Sequence[int]) -> str:
    return ", ".join(map(str, keys)) if keys else "-"


def rand_bytes(rng: random.Random, n: int) -> bytes:
    """``n`` random bytes from ``rng`` on every supported Python.

    ``random.Random.randbytes`` exists only from Python 3.9, so calling it
    broke legacy mode on 3.8.  For a seeded ``random.Random`` this expression
    is byte-for-byte what ``randbytes`` returns on CPython 3.9+, so seeded runs
    replay unchanged.
    """
    return rng.getrandbits(8 * n).to_bytes(n, "little")


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
        for attr in ("name", "mode", "p", "a", "b", "g", "n"):
            fh.write(f"{attr} = {getattr(curve, attr)}\n")
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
        prev_txid = rand_bytes(ec.rng, 32)  # from the rng, so --seed covers --demo
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
        # Test mode draws z directly (Secp256k1.hash_message ignores the
        # message), so no message is built.  The previous version drew a
        # random string here that was never used.
        return b""

    # prev_txid comes from the run's rng like every other draw.  It used to be
    # os.urandom(32), which bypassed --seed: a seeded legacy run replayed its
    # keys but not a single z.  ``rand_bytes`` instead of ``Random.randbytes``
    # keeps legacy mode working on Python 3.8.
    prev_txid = rand_bytes(ec.rng, 32)
    prev_index = ec.rng.randint(0, 3)
    input_value_sats = ec.rng.randint(10_000, 100_0000_0000)
    # Cap the fee so the output stays at or above 546 sat, the P2PKH dust
    # threshold.  The fee used to be drawn independently of the input, so any
    # input under 50_000 sat could get a larger fee: the output went negative
    # and int.to_bytes raised OverflowError in the preimage builder (about one
    # transaction in 612k, which is why short legacy runs rarely showed it).
    fee_sats = ec.rng.randint(1_000, min(50_000, input_value_sats - 546))
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
    progress: bool = True,
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
    printed = {"A": 0, "B": 0, "C": 0, "D": 0, "E": 0}
    run_stats = RunStats()
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

            analysis = analyse_signature(s, s_zk, s_rxk, s_zr, n)
            # Recovery uses public data only; the public key makes the final
            # check decisive (x*G == Q), so a twin key can never be reported.
            outcome = recover_for_analysis(ec, analysis, s, s_zr, z, r_x, public_key)
            run_stats.add(analysis, outcome)

            # ---------- case E row -----------------------------------
            if analysis.e_detected and printed["E"] < output_count:
                printed["E"] += 1
                rows.append([
                    analysis.e_label, s, s_zk, s_rxk, "-", z, r_x, r_y, current_key,
                    k, k_inv, "-", "-", "-", "-", _keys_text(outcome.e_keys), "-",
                ])

            # ---------- case A / B / C / D row -----------------------
            case = analysis.label
            if case is None:
                continue
            a = analysis.a
            if case == "D":
                level = analysis.level
                if printed["D"] >= output_count or d_case_digit not in (-1, level):
                    continue
                printed["D"] += 1
                rows.append([
                    f"D{level}", s, s_zk, s_rxk, s_zr, z, r_x, r_y, current_key,
                    k, k_inv, a, "-", "-",
                    _format_ratio(s_zk, a, cfg.precision), "-", analysis.hypothesis,
                ])
                continue

            if printed[case] >= output_count:
                continue
            printed[case] += 1
            rows.append([
                case, s, s_zk, s_rxk, s_zr, z, r_x, r_y, current_key, k, k_inv, a,
                analysis.m1, analysis.m2 if case == "B" else "-", "-",
                _keys_text(outcome.ab_keys), "-",
            ])

        if progress and key_index % progress_step == 0:
            print(f"{key_index} keys ({generated_tx_count} transactions) generated...")

    elapsed = time.time() - start

    # For a fixed key d, a signature is determined by the pair (k, z), so the
    # space is (n-1)^2 per key and (n-1)^3 over all possible keys -- the latter
    # does not depend on --keys.  The original reported (n-1)^4 "where 4 =
    # number of parameters (z, r, x, k^-1)", but r is a function of k and s is
    # a function of the rest, so that count was not an upper bound on anything.
    stats: Dict[str, object] = {
        "total_key_count": len(uniq_keys),
        "transaction_limit_per_key": transaction_limit_per_key,
        "total_transaction_count": generated_tx_count,
        "signature_space_per_key": f"{float((n - 1) ** 2):.6e}",
        "signature_space_all_keys": f"{float((n - 1) ** 3):.6e}",
    }
    stats.update(run_stats.as_dict())
    stats["spent_time_sec"] = elapsed
    return rows, stats


# ======================================================================
# DIRECT CLASS CONSTRUCTION  (--tx-with-classes)
# ======================================================================
def _import_class_forge():
    """Lazy import of the constructor module.

    ``generate_found_classes`` imports the classifier and the recovery routine
    from THIS module at its top level.  Importing it lazily -- only once this
    module has finished initialising -- keeps that a one-way dependency and
    avoids an import cycle.  The fallback covers the flat layout (all files in
    one folder); it used to repeat the package import and therefore failed with
    ``No module named 'utils'`` exactly where it was needed.
    """
    try:
        from utils.generate_found_classes import (  # type: ignore[import-not-found]
            ECDSAClassGenerator,
            ClassConstructionError,
        )
    except ImportError:
        from generate_found_classes import (  # type: ignore[no-redef]
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
    recovered = _keys_text(fs.recovered)
    if fs.case.startswith("E"):
        return [fs.case, fs.s, fs.s_zk, fs.s_rxk, "-", fs.z, fs.r_x, fs.r_y,
                fs.x, fs.k, fs.k_inv, "-", "-", "-", "-", recovered, "-"]
    return [fs.case, fs.s, fs.s_zk, fs.s_rxk, fs.s_zr, fs.z, fs.r_x, fs.r_y,
            fs.x, fs.k, fs.k_inv, fs.a, fs.m1,
            fs.m2 if fs.case == "B" else "-", "-", recovered, "-"]


def _collect_forged_rows(
    ec: Secp256k1, requested: Sequence[str], per_class_count: int,
) -> Tuple[List[Sequence[object]], Dict[str, object], Dict[str, int], Dict[str, str]]:
    """Construct ``per_class_count`` signatures for each requested class.

    Unlike ``_collect_rows`` -- which signs random messages and *classifies* the
    outcome -- this asks ``ECDSAClassGenerator`` to *construct* signatures that
    already land in the requested class.  Every returned row is an honest ECDSA
    signature: it verifies against ``Q = x*G`` and its key is re-derived from
    the public ``(z, r, s)`` by ``recover_private_keys``.  Class B on real
    secp256k1 is skipped with an explanatory message (it is infeasible there).

    Each row is counted once, under the class it was constructed for, so cases
    C and D, HYP-001 and the E/A overlap are 0 by design.  The recovery lines
    are measured: the attempts and keys of that class's public-only recovery
    (1 attempt per A row, 2 per B row, 2-4 per E row).  They used to be
    constants: attempts == rows, rejected == 0, per-class lines 0.

    Returns ``(rows, stats, built, skipped)``: ``built`` maps each requested
    class to the number of rows made, ``skipped`` maps a class to the reason it
    produced no rows.
    """
    ECDSAClassGenerator, ClassConstructionError = _import_class_forge()
    gen = ECDSAClassGenerator(ec)

    rows: List[Sequence[object]] = []
    run_stats = RunStats()
    built: Dict[str, int] = {}
    skipped: Dict[str, str] = {}
    start = time.time()

    for raw in requested:
        cls = raw.strip().upper()
        if cls in built:            # a class asked for twice is built once
            continue
        built[cls] = 0
        for _ in range(per_class_count):
            try:
                fs = gen.generate(cls)
            except ClassConstructionError as exc:
                if built[cls] == 0:
                    skipped[cls] = str(exc)
                    print(f"[skip] class {cls}: {exc}")
                else:
                    print(f"[stop] class {cls}: built {built[cls]} row(s), then: {exc}")
                break
            rows.append(_forged_row(fs))
            run_stats.add_constructed(cls, fs.recovered, fs.recovery_attempts)
            built[cls] += 1
        else:
            print(f"[ok]   class {cls}: built {built[cls]} row(s).")

    elapsed = time.time() - start
    total = len(rows)
    na = "n/a (directly constructed)"
    stats: Dict[str, object] = {
        "total_key_count": total,
        "transaction_limit_per_key": 1,
        "total_transaction_count": total,
        "signature_space_per_key": na,
        "signature_space_all_keys": na,
    }
    stats.update(run_stats.as_dict())
    stats["spent_time_sec"] = elapsed
    return rows, stats, built, skipped


def _forged_preamble(built: Dict[str, int], skipped: Dict[str, str]) -> str:
    made = " ".join(c for c in sorted(built) if built[c] > 0) or "none"
    note = (
        f"Directly constructed signatures for taxonomy classes {made}. "
        "z is CHOSEN so that each signature lands in its class -- it is not "
        "the hash of any particular message. Every row is nonetheless an "
        "honest ECDSA signature: it verifies against Q = x*G, and the private "
        "key x* is re-derived from the public (z, r, s) by the recovery routine "
        "and confirmed against Q. Constructing such a signature requires "
        "already knowing x, so none of this transfers to a signature you did "
        "not create yourself."
    )
    if skipped:
        note += " Requested but not constructed: " + "; ".join(
            f"class {c} ({reason.split('.')[0]})" for c, reason in sorted(skipped.items())
        ) + "."
    return note


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
                   help="Lower bound for test-mode z and k, and for drawn keys "
                        "(both modes)")
    p.add_argument("--seed", type=int, default=None,
                   help="Seed for reproducible runs: fixes the keys and every "
                        "signed message, so z, k and the report rows replay on "
                        "both curves (default: system entropy)")
    p.add_argument("--out-dir", default=None,
                   help="Directory for the report (default: <repo>/data if present, else CWD)")
    p.add_argument("--demo", action="store_true",
                   help="Run one key-generation / signing / verification round and exit")
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


def build_ec(args: argparse.Namespace) -> Secp256k1:
    """Curve object for the parsed arguments.

    Without ``--seed`` no rng is passed, so ``Secp256k1`` uses its defaults:
    ``SystemRandom`` for z and k, ``secrets`` for keys.  The CLI used to pass
    ``SystemRandom()`` explicitly, which made ``rng_is_explicit`` true and
    contradicted that documented default.
    """
    rng = random.Random(args.seed) if args.seed is not None else None
    return Secp256k1(_select_curve(args.curve_mode), rng=rng)


def main(argv: Optional[Sequence[str]] = None) -> None:
    args = parse_args(argv)
    ec = build_ec(args)
    curve = ec.curve
    cfg = _build_report_config(curve)

    if args.keys > curve.n - 1:
        raise ValueError("Requested more unique keys than possible for this curve!")
    if args.tx_per_key < 1:
        raise ValueError("--tx-per-key must be >= 1")
    if args.output_count < 0:
        raise ValueError("--output-count must be >= 0")
    if not 1 <= args.min_start_range < curve.n:
        raise ValueError("--min-start-range must be in [1, n-1]")

    if args.demo:
        # --demo is one round and nothing else.  It used to fall through into a
        # full default run (5000 keys) and write a report as a side effect.
        _print_once_demo(ec, args.sig_type)
        return

    if args.tx_with_classes:
        rows, stats, built, skipped = _collect_forged_rows(
            ec, args.tx_with_classes, args.output_count)
        path = _write_report(
            curve, rows, stats, args.sig_type,
            args.out_dir or _default_out_dir(),
            preamble_note=_forged_preamble(built, skipped),
        )
        print(f"Wrote report: {path}")
        print(f"Constructed {len(rows)} row(s); recovery verified "
              f"{stats['recovery_verified']} of {stats['recovery_attempts']} candidate(s).")
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
    print(f"Recovered and verified: {stats['recovery_verified']} "
          f"of {stats['recovery_attempts']} candidate(s).")


if __name__ == "__main__":
    main()
