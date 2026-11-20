#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Direct generator for ECDSA signatures of taxonomy classes A, B and E.

WHAT THIS MODULE DOES
=====================
``generate_transactions.py`` signs random messages and *classifies* the result.
Because classes A, B and E are rare coincidences, that pipeline finds them only
by luck -- on real secp256k1 at a rate near ``2**-256``. This module goes the
other way: it *constructs* a signature that already lands in a requested class,
then hands it back with every field the report needs.

The construction is honest ECDSA. For a private key ``x`` and nonce ``k`` a
signature obeys

    r      = (k*G).x mod n                 (depends on k only)
    s_zk   = z * k^-1  mod n
    s_rxk  = r * x * k^-1  mod n
    s      = s_zk + s_rxk  mod n           (the additive split)
    s_zr   = z * r  mod n

So if we pick a nonce ``k`` (hence ``r``) and two additive parts
``(s_zk, s_rxk)``, the remaining unknowns fall out exactly:

    z = s_zk * k          mod n
    x = s_rxk * k * r^-1  mod n
    s = s_zk + s_rxk      mod n

The result verifies against ``Q = x*G`` like any other signature; this is
checked with ``Secp256k1.verify_x_candidate`` before anything is returned.

THE ONE THING YOU CANNOT CONTROL
================================
``s_zr = z*r = s_zk * (k*r) mod n``. The factor ``P = k*r mod n`` is fixed the
moment ``k`` is chosen, and ``k -> k*(k*G).x`` is effectively a random oracle on
secp256k1 -- there is no known way to steer it to a chosen value. That single
fact decides which classes are constructible on which curve:

* **class E** -- its condition uses only ``s_zk`` and ``s_rxk``, never ``s_zr``.
  Constructible directly on *both* curves.
* **class A** -- needs a divisor ``D`` of ``s_zr - s_zk`` with ``s_zk < D``.
  With ``s_zk = 1`` this is ``D = 2`` whenever ``P`` is odd, which we simply read
  off the freely chosen ``k``. Constructible on *both* curves (about two nonces
  tried on average).
* **class B** -- pins the ratio ``s_zr : s_zk`` to a specific rational (e.g.
  ``29:4``). That is a fixed target for the uncontrollable ``P``. On the toy
  curve we enumerate all ``k`` (~1e5) and pick one that hits it; on secp256k1
  that search is ``2**-256`` per nonce, so this module *refuses* class B in
  legacy mode with ``ClassConstructionError`` rather than pretend otherwise.

HONEST CAVEAT ABOUT z
=====================
To make ``s_zk`` land where we need it, ``z`` is chosen as ``s_zk * k mod n``.
It is therefore **not** the hash of any particular message (in class A it even
equals the nonce). ``is_message_bound`` is always ``False`` on the returned
object. This is the same limitation the repository already documents for its
"test" mode -- and it is exactly why constructing these signatures is not an
attack: it requires already knowing ``x``, ``k`` and being free to choose ``z``.
A real signer's ``x`` is secret and its ``z`` is a fixed message hash, so none
of this transfers to a signature you did not create yourself.
"""

from __future__ import annotations

import math
import os
import random
import sys
from dataclasses import dataclass
from fractions import Fraction
from typing import Dict, List, Optional, Tuple

# ----------------------------------------------------------------------
# IMPORT SHIM -- identical policy to generate_transactions.py so this file
# also runs from a flat directory (secp256k1.py + this file side by side).
# NOTE: we import the *detectors and recovery* from generate_transactions but
# generate_transactions imports THIS module only lazily (inside its forge path),
# so there is no import cycle.
# ----------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
for _candidate in (os.path.abspath(os.path.join(_HERE, os.pardir)), _HERE):
    if _candidate not in sys.path:
        sys.path.insert(0, _candidate)

try:  # package layout: src/ecurve, src/utils
    from ecurve.secp256k1 import Secp256k1, CurveParams  # type: ignore
    from utils.generate_transactions import (  # type: ignore
        _detect_half_difference_split,
        _half_difference_parts,
        recover_private_keys,
    )
except ImportError:  # flat layout
    try:
        from secp256k1 import Secp256k1, CurveParams  # type: ignore[no-redef]
        from generate_transactions import (  # type: ignore[no-redef]
            _detect_half_difference_split,
            _half_difference_parts,
            recover_private_keys,
        )
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "Cannot import secp256k1.py / generate_transactions.py. Supported "
            "layouts:\n"
            "  <repo>/src/ecurve/secp256k1.py + <repo>/src/utils/*.py\n"
            "  ./secp256k1.py + ./generate_transactions.py (flat)\n"
            f"searched: {sys.path[:2]}"
        ) from exc


VALID_CLASSES: Tuple[str, ...] = ("A", "B", "E")


class ClassConstructionError(RuntimeError):
    """Raised when a class cannot be constructed for the active curve/budget.

    The message always says *why* -- most importantly, that class B is not
    constructible on real secp256k1 because it would require steering the
    uncontrollable product ``k*r mod n`` onto a fixed rational.
    """


@dataclass(frozen=True)
class ForgedSignature:
    """One constructed signature plus every value the report prints.

    ``x`` is the private key the construction produced; ``recovered`` is what
    the public-only recovery returns for this signature (it contains ``x`` by
    construction -- that equality is asserted before the object is built).
    ``is_message_bound`` is always False: ``z`` was chosen, not hashed.
    """

    case: str            # "A", "B", "E1" or "E2"
    z: int
    r_x: int
    r_y: int
    s: int
    k: int
    k_inv: int
    x: int
    s_zk: int
    s_rxk: int
    s_zr: int
    a: Optional[int]     # None for class E (no 'a' is defined there)
    m1: Optional[Fraction]
    m2: Optional[Fraction]
    recovered: List[int]
    is_message_bound: bool = False


# ======================================================================
# CLASSIFIER MIRROR
# ======================================================================
# This reproduces, verbatim, the A/B/C/D decision inlined in
# ``generate_transactions._collect_rows`` (case E is delegated to the shared
# detector ``_detect_half_difference_split``). It is used to LABEL a forged row
# exactly as a real run would. A mislabel cannot corrupt output: every forged
# signature is additionally required to recover its own key via the authoritative
# ``recover_private_keys`` (see ``_validate``), so a wrong label just triggers a
# retry rather than a bad row.
def classify(
    s: int, s_zk: int, s_rxk: int, s_zr: int, n: int
) -> Tuple[Optional[str], Optional[int], Optional[Fraction], Optional[Fraction]]:
    """Return ``(label, a, m1, m2)`` for a signature's derived scalars.

    ``label`` is one of ``E1``/``E2``/``A``/``B``/``C``/``D`` or ``None`` when no
    class applies. Case E is reported when the half-difference detector fires;
    otherwise the A/B/C/D branch runs (which needs ``s_zr > s``).
    """
    detected, split_case = _detect_half_difference_split(s, s_zk, s_rxk, n)
    if detected:
        return split_case, None, None, None

    if s_zr <= s:
        return None, None, None, None
    a = s % ((s_zr - s) % n)
    if not (0 < a != s):
        return None, None, None, None

    m1 = Fraction(s_zk, a)
    m2 = Fraction(s + s_zr, s_rxk) if s_rxk else None
    if m1 == 1:
        return "A", a, m1, m2
    if (m2 is not None and m1.denominator == 1
            and m2.denominator == 1 and m1 == m2):
        return "B", a, m1, m2
    if m1.denominator == 1:
        return "C", a, m1, m2
    return "D", a, m1, m2


# ======================================================================
# GENERATOR
# ======================================================================
class ECDSAClassGenerator:
    """Construct ECDSA signatures that fall into taxonomy classes A, B, E.

    Parameters
    ----------
    ec : Secp256k1
        The curve to build on. Works for both ``TEST_PARAMS`` and
        ``LEGACY_PARAMS`` (real secp256k1), with the class-B restriction noted
        above.
    rng : random.Random, optional
        Randomness source. Defaults to ``ec.rng`` so a seeded ``Secp256k1`` makes
        the generator reproducible too.
    max_attempts : int
        Cap on nonce trials per signature before giving up with
        ``ClassConstructionError``.
    divisor_budget : int
        Trial-division ceiling used by the class-A divisor search.
    """

    def __init__(
        self,
        ec: Secp256k1,
        rng: Optional[random.Random] = None,
        *,
        max_attempts: int = 200_000,
        divisor_budget: int = 200_000,
    ) -> None:
        self._ec = ec
        self._n = ec.curve.n
        self._rng = rng if rng is not None else ec.rng
        self._max_attempts = max_attempts
        self._divisor_budget = divisor_budget

        # Lazily built, test-curve only.
        self._r_table: Optional[List[int]] = None          # r_of_k[k] = (kG).x % n
        self._p_index: Optional[Dict[int, List[int]]] = None  # (k*r)%n -> [k, ...]
        self._b_families: Optional[List[Tuple[int, int, int, int, int]]] = None

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------
    def generate(self, target_class: str) -> ForgedSignature:
        """Construct and fully validate one signature of ``target_class``.

        ``target_class`` is case-insensitive and must be one of A, B, E. For E,
        the E1/E2 sub-label is chosen automatically (both are produced across
        repeated calls).
        """
        key = target_class.strip().upper()
        if key not in VALID_CLASSES:
            raise ValueError(
                f"target_class must be one of {VALID_CLASSES}; got {target_class!r}"
            )
        if key == "E":
            return self._forge_e()
        if key == "A":
            return self._forge_a()
        return self._forge_b()

    # ------------------------------------------------------------------
    # REALIZATION + VALIDATION (shared by every class)
    # ------------------------------------------------------------------
    def _build(
        self, want: str, s_zk: int, s_rxk: int, k: int, r_x: int, r_y: int
    ) -> Optional[ForgedSignature]:
        """Realize, classify, recover and package -- or return None to retry."""
        n = self._n
        if r_x == 0:
            return None
        k_inv = pow(k, -1, n)
        z = (s_zk * k) % n
        if z == 0:
            return None
        x = (s_rxk * k * pow(r_x, -1, n)) % n
        if not 1 <= x < n:
            return None
        s = (s_zk + s_rxk) % n
        if s == 0:
            return None

        # Recompute the derived scalars from (z, r, s, x, k) exactly as the
        # report pipeline does -- do not trust the target values blindly.
        act_s_zk = (z * k_inv) % n
        act_s_rxk = (r_x * x * k_inv) % n
        act_s_zr = (z * r_x) % n

        label, a, m1, m2 = classify(s, act_s_zk, act_s_rxk, act_s_zr, n)
        if label is None:
            return None
        # Class match: E accepts E1/E2; A/B must match exactly.
        if want == "E" and not label.startswith("E"):
            return None
        if want in ("A", "B") and label != want:
            return None

        # Authoritative, public-only recovery must return this very key.
        s_zr_for_rec = act_s_zr if want in ("A", "B") else 0
        a_for_rec = a if a is not None else 0
        keys, _attempts = recover_private_keys(
            self._ec, label, s, s_zr_for_rec, z, r_x, a_for_rec
        )
        if x not in keys:
            return None
        # Independent ECDSA sanity check on the curve.
        if not self._ec.verify_x_candidate(x, z, r_x, s):
            return None

        return ForgedSignature(
            case=label, z=z, r_x=r_x, r_y=r_y, s=s, k=k, k_inv=k_inv, x=x,
            s_zk=act_s_zk, s_rxk=act_s_rxk, s_zr=act_s_zr,
            a=a, m1=m1, m2=m2, recovered=keys, is_message_bound=False,
        )

    def _random_nonce_point(self) -> Tuple[int, int, int]:
        """Draw a usable nonce and return ``(k, r_x, r_y)`` with ``r_x != 0``."""
        n = self._n
        while True:
            k = self._rng.randrange(1, n - 1)
            point = self._ec.scalar_multiply(k, self._ec.curve.g)
            if point is None:
                continue
            r_x = point[0] % n
            if r_x == 0:
                continue
            return k, r_x, point[1]

    # ------------------------------------------------------------------
    # CLASS E
    # ------------------------------------------------------------------
    def _forge_e(self) -> ForgedSignature:
        """Class E: pick a valid half-difference split, realize with any nonce.

        The split depends only on ``S`` (the integer sum of the two parts), so
        no curve constraint is involved. E1 (``S < n``) and E2 (``S in
        [n, ~4n/3)``) are chosen at random so both sub-labels appear.
        """
        n = self._n
        for _ in range(self._max_attempts):
            # Force S % 4 in {1, 2} up front to avoid wasted picks.
            residue = self._rng.choice((1, 2))
            if self._rng.random() < 0.5:                 # aim for E1: S < n
                hi = (n - residue) // 4
                if hi < 2:
                    continue
                big_s = 4 * self._rng.randrange(1, hi) + residue
            else:                                        # aim for E2: n <= S
                lo = (n - residue) // 4 + 1
                hi = (n + n // 3 - residue) // 4
                if hi <= lo:
                    continue
                big_s = 4 * self._rng.randrange(lo, hi) + residue

            larger, smaller = _half_difference_parts(big_s)
            if not (1 <= smaller and larger < n and larger != smaller):
                continue

            # Either assignment of (s_zk, s_rxk) satisfies the detector; pick one
            # at random for variety.
            if self._rng.random() < 0.5:
                s_zk, s_rxk = larger, smaller
            else:
                s_zk, s_rxk = smaller, larger

            k, r_x, r_y = self._random_nonce_point()
            forged = self._build("E", s_zk, s_rxk, k, r_x, r_y)
            if forged is not None:
                return forged
        raise ClassConstructionError(
            "could not construct a class-E signature within the attempt budget"
        )

    # ------------------------------------------------------------------
    # CLASS A
    # ------------------------------------------------------------------
    def _forge_a(self) -> ForgedSignature:
        """Class A: ``s_zk == a``. Read ``P = k*r`` off a random nonce, then find
        a divisor ``D`` of ``s_zr - s_zk`` with ``s_zk < D < s_zr`` and set
        ``s = s_zr - D`` (so ``a = s mod D == s_zk``).

        ``s_zk = 1`` with ``D = 2`` works for every odd ``P`` and needs no
        factoring -- the robust path on secp256k1. On the toy curve a small
        divisor search also admits larger ``s_zk`` for variety.
        """
        n = self._n
        legacy = self._ec.curve.mode == "legacy"
        for _ in range(self._max_attempts):
            k, r_x, r_y = self._random_nonce_point()
            p_val = (k * r_x) % n

            # Candidate remainders (== target s_zk). 1 is always tried; on the
            # toy curve we also try a few small values for variety.
            candidates = [1]
            if not legacy:
                candidates += sorted(
                    {self._rng.randrange(2, 64) for _ in range(3)}
                )

            for s_zk in candidates:
                s_zr = (s_zk * p_val) % n         # == z*r for z = s_zk*k
                diff = s_zr - s_zk
                if diff <= 0:
                    continue
                d = self._smallest_divisor_above(diff, s_zk)
                if d is None or d >= s_zr:
                    continue
                s = s_zr - d
                s_rxk = (s - s_zk) % n
                if s_rxk == 0:
                    continue
                forged = self._build("A", s_zk, s_rxk, k, r_x, r_y)
                if forged is not None:
                    return forged
        raise ClassConstructionError(
            "could not construct a class-A signature within the attempt budget"
        )

    def _smallest_divisor_above(self, m: int, lo: int) -> Optional[int]:
        """Smallest divisor ``d`` of ``m`` with ``d > lo`` (bounded search).

        Fast path: if ``m`` is even and ``lo < 2`` return 2. Otherwise trial the
        primes/factors up to ``min(sqrt(m), budget)`` and also consider the large
        cofactors. Returns None if nothing suitable is found within budget.
        """
        if m <= lo:
            return None
        if lo < 2 and m % 2 == 0:
            return 2
        limit = min(self._isqrt(m), self._divisor_budget)
        # Collect small divisors and their cofactors, pick the least one > lo.
        best: Optional[int] = None
        d = 2
        while d <= limit:
            if m % d == 0:
                for cand in (d, m // d):
                    if cand > lo and (best is None or cand < best):
                        best = cand
            d += 1 if d == 2 else 2
        # m itself is a divisor > lo when m has no factor <= limit (m prime) or
        # simply as a fallback candidate.
        if best is None and m > lo:
            best = m
        return best

    @staticmethod
    def _isqrt(m: int) -> int:
        return math.isqrt(m)

    # ------------------------------------------------------------------
    # CLASS B
    # ------------------------------------------------------------------
    def _forge_b(self) -> ForgedSignature:
        """Class B: ``m1 == m2`` integral. Requires the ratio ``s_zr : s_zk`` to
        equal a specific rational, i.e. a fixed value for ``P = k*r mod n``.

        On real secp256k1 that is a ``2**-256`` search per nonce, so this is
        refused. On the toy curve every ``k`` is enumerable, so we index the
        table by ``P`` once and pick a nonce that already hits a family's ratio,
        then scale by a random ``a`` for distinct rows.
        """
        if self._ec.curve.mode == "legacy":
            raise ClassConstructionError(
                "class B is not constructible on real secp256k1: it pins the "
                "ratio s_zr : s_zk to a fixed rational, which requires steering "
                "P = k*r mod n onto a chosen value. The map k -> k*(k*G).x is a "
                "random oracle here, so hitting the target is a 2**-256 search "
                "per nonce. Class B is available only in test-curve mode, where "
                "every nonce can be enumerated. (The repository's own README "
                "reports class B has never occurred in a real run.)"
            )

        families = self._case_b_families()
        p_index = self._p_value_index()
        n = self._n

        # Families that actually have a nonce hitting their ratio.
        usable: List[Tuple[Tuple[int, int, int, int, int], List[int]]] = []
        for fam in families:
            zk_u, rxk_u, s_u, zr_u, _amax = fam
            target = (zr_u * pow(zk_u, -1, n)) % n
            ks = p_index.get(target)
            if ks:
                usable.append((fam, ks))
        if not usable:
            raise ClassConstructionError(
                "no class-B family ratio was hit by any nonce on this curve; "
                "extend the family table"
            )

        for _ in range(self._max_attempts):
            (zk_u, rxk_u, s_u, zr_u, a_max), ks = self._rng.choice(usable)
            k = self._rng.choice(ks)
            r_x = self._r_table[k]                       # table is built by now
            point = self._ec.scalar_multiply(k, self._ec.curve.g)
            r_y = point[1] if point is not None else 0
            a = self._rng.randrange(1, a_max + 1)
            forged = self._build("B", zk_u * a, rxk_u * a, k, r_x, r_y)
            if forged is not None:
                return forged
        raise ClassConstructionError(
            "could not construct a class-B signature within the attempt budget"
        )

    # ---- test-curve caches -------------------------------------------
    def _ensure_r_table(self) -> List[int]:
        """Build ``r_of_k[k] = (k*G).x mod n`` for every k (test curve only)."""
        if self._r_table is not None:
            return self._r_table
        if self._ec.curve.mode == "legacy":  # pragma: no cover - guarded earlier
            raise ClassConstructionError("r-table is only built for the test curve")
        n = self._n
        table = [0] * n
        point = None
        g = self._ec.curve.g
        for k in range(1, n):
            point = self._ec.point_add(point, g)
            table[k] = point[0] % n
        self._r_table = table
        return table

    def _p_value_index(self) -> Dict[int, List[int]]:
        """Index nonces by ``P = (k*r) mod n`` (test curve only)."""
        if self._p_index is not None:
            return self._p_index
        table = self._ensure_r_table()
        n = self._n
        index: Dict[int, List[int]] = {}
        for k in range(1, n):
            r_x = table[k]
            if r_x == 0:
                continue
            index.setdefault((k * r_x) % n, []).append(k)
        self._p_index = index
        return index

    def _case_b_families(self) -> List[Tuple[int, int, int, int, int]]:
        """Return validated class-B families.

        Each entry is ``(s_zk_unit, s_rxk_unit, s_unit, s_zr_unit, a_max)`` in
        units of ``a``: multiplying the first four by any ``a in [1, a_max]``
        yields integers below ``n`` whose derived scalars classify as B. Families
        are generated from the quadratic's integer solutions and then *checked*
        against the real classifier at ``a = 1`` before being kept.
        """
        if self._b_families is not None:
            return self._b_families
        n = self._n
        families: List[Tuple[int, int, int, int, int]] = []
        # Solve the integer form of the case-B relations for small (m, q):
        #   s = a*(q*m^2 - 1)/(q*(m-2) - 1),  s_zk = m*a,  s_rxk = s - s_zk,
        #   s_zr = (m-1)*s_rxk - m*a          (all in units of a).
        for m in range(4, 60):
            for q in range(1, 6):
                denom = q * (m - 2) - 1
                if denom <= 0:
                    continue
                numer = q * m * m - 1
                if numer % denom != 0:
                    continue
                s_u = numer // denom
                zk_u = m
                rxk_u = s_u - zk_u
                if rxk_u <= 0:
                    continue
                zr_u = (m - 1) * rxk_u - m
                if zr_u <= s_u:            # need s_zr > s
                    continue
                # Validate at a = 1 with the real classifier (pure integers < n).
                label, a_val, m1, m2 = classify(s_u, zk_u, rxk_u, zr_u, n)
                if label != "B":
                    continue
                a_max = max(1, (n - 1) // zr_u)   # keep every scaled value < n
                families.append((zk_u, rxk_u, s_u, zr_u, a_max))
        # Deduplicate by the (zk_u, rxk_u) shape.
        seen = set()
        unique: List[Tuple[int, int, int, int, int]] = []
        for fam in families:
            key = (fam[0], fam[1])
            if key not in seen:
                seen.add(key)
                unique.append(fam)
        self._b_families = unique
        return unique


__all__ = [
    "ECDSAClassGenerator",
    "ForgedSignature",
    "ClassConstructionError",
    "classify",
    "VALID_CLASSES",
]
