#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PEP 8 compliant secp256k1 demo with key generation, signing, and
verification for both test and legacy parameters.

POINT REPRESENTATION
====================
The point at infinity is represented by ``None`` -- and ONLY by ``None``.
The original code had two competing sentinels (``None`` from ``point_add``
and ``(0, 0)`` from ``scalar_multiply``); ``(0, 0)`` is not on either curve
and leaked silently into callers.

SIGNATURE TUPLE
===============
``sign_message`` returns ``(z, r_x, r_y, s, k, k_inv)`` where:
  * ``r_x`` is ``(k*G).x mod n``  -- the ECDSA r value, reduced mod n by spec
  * ``r_y`` is ``(k*G).y mod p``  -- the RAW affine coordinate, NOT reduced
  * ``s`` is the ECDSA s value, reduced mod n by spec
  * ``k`` is the ephemeral nonce, which is normally secret and never returned

PUBLIC-ONLY HELPERS
===================
``recover_x_from_s_zk`` and ``Secp256k1.verify_x_candidate`` operate on
``(z, r, s)`` only.  They take a *guess* for ``s_zk = z*k^-1 mod n`` and turn
it into a private-key candidate, then confirm or reject that candidate on the
curve.  No secret input is consumed by either function; ``verify_x_candidate``
is what makes a guess into a proven key rather than an unchecked one.

RANDOMNESS
==========
``Secp256k1`` takes an optional ``rng``.  It defaults to
``random.SystemRandom()`` so that statistics gathered in "test" mode are not
contaminated by the linear structure of MT19937.  Pass ``random.Random(seed)``
explicitly when a reproducible run is wanted.

An explicitly supplied ``rng`` drives EVERY draw, key generation included.
Previously ``_generate_private_key`` always went to ``secrets``, so a seeded
instance reproduced its ``z`` and ``k`` but not its keys -- ``--seed`` therefore
promised a reproducible run and did not deliver one.  ``secrets`` is now used
only as the default source, i.e. when no ``rng`` was passed.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
import random
import secrets
import time
from typing import Iterator, Optional, Tuple

try:  # works as a package module (python -m ecurve.secp256k1)
    from ._ripemd160 import ripemd160 as _ripemd160_fallback
except ImportError:  # and standalone (python secp256k1.py from inside ecurve/)
    from _ripemd160 import ripemd160 as _ripemd160_fallback

Point = Optional[Tuple[int, int]]


@dataclass(frozen=True)
class CurveParams:
    """Elliptic curve parameters for secp256k1."""

    name: str
    mode: str  # "test" | "legacy"
    p: int
    a: int
    b: int
    g: Tuple[int, int]
    n: int

TEST_PARAMS = CurveParams(
    name="secp17k1",
    mode="test",
    p=100003,
    a=0,
    b=2,
    g=(20002, 57568),
    n=99667
)

LEGACY_PARAMS = CurveParams(
    name="secp256k1",
    mode="legacy",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    g=(
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    ),
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)


def encode_varint(i: int) -> bytes:
    """Bitcoin varint encoding."""
    if i < 0:
        raise ValueError("varint cannot encode a negative value")
    if i < 0xfd:
        return i.to_bytes(1, "little")
    if i <= 0xffff:
        return b"\xfd" + i.to_bytes(2, "little")
    if i <= 0xffffffff:
        return b"\xfe" + i.to_bytes(4, "little")
    return b"\xff" + i.to_bytes(8, "little")


def compress_public_key(pub: Tuple[int, int], field_bytes: int = 32) -> bytes:
    """Return compressed SEC representation of a public key.

    ``field_bytes`` is the byte length of the coordinate field; 32 for
    secp256k1.  The original code hardcoded 32, which silently produced a
    malformed encoding for any curve with a different field size and would
    raise ``OverflowError`` for a larger one.
    """
    x, y = pub
    prefix = 0x02 | (y & 1)
    return bytes([prefix]) + x.to_bytes(field_bytes, "big")


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) - Bitcoin HASH160."""
    sha = hashlib.sha256(data).digest()
    try:
        return hashlib.new("ripemd160", sha).digest()
    except (ValueError, TypeError):
        return _ripemd160_fallback(sha)


def make_bitcoin_legacy_sighash_message(
    public_key: Tuple[int, int],
    prev_txid: bytes = b"\x00" * 32,
    prev_index: int = 0,
    output_value_sats: int = 49_9999_0000,
) -> bytes:
    """
    Build a Bitcoin legacy SIGHASH_ALL preimage for a simple 1-in-1-out P2PKH transaction.

    Parameters
    ----------
    public_key : Tuple[int, int]
        Public key (x, y) of the signer; it is compressed internally.
    prev_txid : bytes
        32-byte txid of the UTXO being spent (little-endian, per protocol).
    prev_index : int
        Output index within the previous transaction (vout).
    output_value_sats : int
        Value sent to the single output, in satoshi (input minus fee).
        Note: legacy SIGHASH_ALL does NOT commit to input value - only to
        output value.  This is the vulnerability that BIP 143 fixes.
    """
    # Version
    version = (1).to_bytes(4, "little")

    # Compressed public key and HASH160
    compressed_pub = compress_public_key(public_key)
    pubkey_hash = hash160(compressed_pub)

    # Standard P2PKH scriptPubKey: OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
    script_pubkey = (
        b"\x76"          # OP_DUP
        b"\xa9"          # OP_HASH160
        b"\x14"          # PUSH 20
        + pubkey_hash +
        b"\x88"          # OP_EQUALVERIFY
        b"\xac"          # OP_CHECKSIG
    )

    # For legacy SIGHASH_ALL preimage, scriptCode = scriptPubKey of the UTXO being spent
    script_code = script_pubkey

    # One input
    input_count = encode_varint(1)

    prev_index_bytes = prev_index.to_bytes(4, "little")

    script_code_len = encode_varint(len(script_code))
    sequence = (0xFFFFFFFF).to_bytes(4, "little")

    tx_in = (
        prev_txid +
        prev_index_bytes +
        script_code_len +
        script_code +
        sequence
    )

    # One output
    output_count = encode_varint(1)

    value = output_value_sats.to_bytes(8, "little")

    script_pubkey_len = encode_varint(len(script_pubkey))

    tx_out = (
        value +
        script_pubkey_len +
        script_pubkey
    )

    # Locktime and SIGHASH type
    locktime = (0).to_bytes(4, "little")
    sighash_all = (1).to_bytes(4, "little")  # SIGHASH_ALL = 0x00000001

    # Final preimage
    preimage = (
        version +
        input_count +
        tx_in +
        output_count +
        tx_out +
        locktime +
        sighash_all
    )

    return preimage


def make_bitcoin_segwit_sighash_message(
    public_key: Tuple[int, int],
    prev_txid: bytes = b"\x00" * 32,
    prev_index: int = 0,
    input_value_sats: int = 50_0000_0000,
    output_value_sats: int = 49_9999_0000,
) -> bytes:
    """
    Build a Bitcoin SegWit v0 (BIP 143) SIGHASH_ALL preimage for a simple
    1-in-1-out P2WPKH transaction.

    BIP 143 defines a fundamentally different serialization than legacy:
      1.  nVersion              (4 bytes LE)
      2.  hashPrevouts          (32 bytes) - dSHA256 of all input outpoints
      3.  hashSequence          (32 bytes) - dSHA256 of all input sequences
      4.  outpoint              (36 bytes) - txid + vout of the input being signed
      5.  scriptCode            (variable) - for P2WPKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
      6.  value                 (8 bytes LE) - satoshi value of the UTXO being spent
      7.  nSequence             (4 bytes LE) - sequence of the input being signed
      8.  hashOutputs           (32 bytes) - dSHA256 of all serialized outputs
      9.  nLockTime             (4 bytes LE)
      10. nHashType             (4 bytes LE)

    Parameters
    ----------
    public_key : Tuple[int, int]
        Public key (x, y) of the signer; it is compressed internally.
    prev_txid : bytes
        32-byte txid of the UTXO being spent (little-endian, per protocol).
    prev_index : int
        Output index within the previous transaction (vout).
    input_value_sats : int
        Value of the UTXO being spent, in satoshi.  BIP 143 commits to this
        value - this is the critical anti-fee-manipulation field.
    output_value_sats : int
        Value sent to the single output, in satoshi (input minus fee).

    Reference: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    """
    # --- Transaction metadata ---
    n_version = (2).to_bytes(4, "little")  # version 2 (common for SegWit tx)
    n_locktime = (0).to_bytes(4, "little")
    n_hashtype = (1).to_bytes(4, "little")  # SIGHASH_ALL

    # --- Single input: outpoint from the UTXO being spent ---
    prev_vout = prev_index.to_bytes(4, "little")
    outpoint = prev_txid + prev_vout

    sequence = (0xFFFFFFFF).to_bytes(4, "little")

    # hashPrevouts = dSHA256(outpoint)  (only one input)
    hash_prevouts = hashlib.sha256(hashlib.sha256(outpoint).digest()).digest()

    # hashSequence = dSHA256(sequence)  (only one input)
    hash_sequence = hashlib.sha256(hashlib.sha256(sequence).digest()).digest()

    # --- scriptCode for P2WPKH ---
    compressed_pub = compress_public_key(public_key)
    pubkey_hash = hash160(compressed_pub)
    script_code = (
        b"\x19"          # length: 25 bytes
        b"\x76"          # OP_DUP
        b"\xa9"          # OP_HASH160
        b"\x14"          # PUSH 20
        + pubkey_hash +
        b"\x88"          # OP_EQUALVERIFY
        b"\xac"          # OP_CHECKSIG
    )

    # --- Value of the UTXO being spent (BIP 143 critical field!) ---
    value = input_value_sats.to_bytes(8, "little")

    # --- Single output: pay to same pubkey hash ---
    out_script_pubkey = (
        b"\x76\xa9\x14"
        + pubkey_hash
        + b"\x88\xac"
    )
    out_value = output_value_sats.to_bytes(8, "little")
    serialized_output = (
        out_value
        + encode_varint(len(out_script_pubkey))
        + out_script_pubkey
    )

    # hashOutputs = dSHA256(serialized outputs)  (only one output)
    hash_outputs = hashlib.sha256(hashlib.sha256(serialized_output).digest()).digest()

    # --- BIP 143 preimage assembly ---
    preimage = (
        n_version
        + hash_prevouts
        + hash_sequence
        + outpoint
        + script_code
        + value
        + sequence
        + hash_outputs
        + n_locktime
        + n_hashtype
    )

    return preimage


# ======================================================================
# PUBLIC-ONLY ECDSA RELATIONS
# ======================================================================
def inverse_mod_safe(k: int, m: int) -> Optional[int]:
    """Modular inverse, or ``None`` when ``k`` is not invertible mod ``m``."""
    try:
        return pow(k, -1, m)
    except ValueError:
        return None


def mod_sqrt_all(a: int, p: int) -> list[int]:
    """All square roots of ``a`` modulo the odd prime ``p``.

    Returns ``[]`` when ``a`` is a quadratic non-residue.  Replaces the former
    ``sympy.sqrt_mod`` dependency, which was undeclared and pulled in for this
    single call.  Uses the p % 4 == 3 shortcut when the field prime allows it
    -- both shipped curves qualify, since secp17k1's p = 100003 and secp256k1's
    p are each congruent to 3 mod 4 -- and Tonelli-Shanks otherwise. The
    Tonelli-Shanks branch is therefore correct but unexercised by the shipped
    parameters. (The earlier claim that secp256k1 took this branch confused the
    field prime p, on which this routine operates, with the group order n.)
    """
    a %= p
    if p == 2:
        return [a]
    if a == 0:
        return [0]
    if pow(a, (p - 1) // 2, p) != 1:
        return []

    if p % 4 == 3:
        r = pow(a, (p + 1) // 4, p)
        return sorted({r, p - r})

    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1

    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    m, c = s, pow(z, q, p)
    t, r = pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c = i, b * b % p
        t = t * c % p
        r = r * b % p
    return sorted({r, p - r})


def recover_x_from_s_zk(s_zk: int, s: int, z: int, r: int, n: int) -> Optional[int]:
    """Turn a guess for ``s_zk = z*k^-1 mod n`` into a private-key candidate.

    From the signature identity ``s = (z + r*x) * k^-1``:

        s_rxk = s - s_zk           = r*x*k^-1
        k^-1  = s_zk * z^-1
        x     = z*(s - s_zk) * (r*s_zk)^-1   (mod n)

    Every input is public.  Returns ``None`` when the denominator is not
    invertible.  This is the single primitive behind every case-A/B/E
    recovery; the original code re-derived it three times, once with ``k`` as
    the name of a variable that actually held ``k^-1``.
    """
    den_inv = inverse_mod_safe((r * s_zk) % n, n)
    if den_inv is None:
        return None
    return (z % n) * ((s - s_zk) % n) % n * den_inv % n


class Secp256k1:
    """Elliptic curve cryptography implementation for secp256k1."""

    def __init__(self, params: CurveParams, rng: Optional[random.Random] = None):
        """Initialize curve with given parameters.

        ``rng`` supplies the randomness used by "test" mode for z and k, and --
        when it is passed explicitly -- for key generation as well.  It defaults
        to ``random.SystemRandom()``: the previous code used the module-level
        ``random``, i.e. MT19937, whose known linear structure is a poor
        foundation for statistics about "hidden structure" in the resulting
        triples.  Pass ``random.Random(seed)`` for reproducibility.

        ``_rng_explicit`` records whether the caller supplied the source. Key
        generation consults it: an explicit rng is honoured (so a seeded run is
        reproducible end to end), while the default path stays on ``secrets``.
        """
        self._curve = params
        self._rng_explicit = rng is not None
        self._rng = rng if rng is not None else random.SystemRandom()

    @property
    def curve(self) -> CurveParams:
        """Return elliptic curve parameters."""
        return self._curve

    @property
    def rng(self) -> random.Random:
        """Return the random source used by test-mode signing."""
        return self._rng

    # ------------------------------------------------------------------
    # RFC 6979 (deterministic nonce)
    # ------------------------------------------------------------------
    @staticmethod
    def _bits2int(data: bytes, qlen: int) -> int:
        """RFC 6979 section 2.3.2."""
        value = int.from_bytes(data, "big")
        blen = len(data) * 8
        if blen > qlen:
            value >>= (blen - qlen)
        return value

    @staticmethod
    def _int2octets(value: int, rolen: int) -> bytes:
        """RFC 6979 section 2.3.3."""
        return value.to_bytes(rolen, "big")

    def _rfc6979_k_candidates(self, private_key: int, z: int) -> Iterator[int]:
        """Yield RFC 6979 nonce candidates, in specification order."""
        n = self._curve.n
        qlen = n.bit_length()
        holen = hashlib.sha256().digest_size
        rolen = (qlen + 7) // 8

        bx = self._int2octets(private_key, rolen) + self._int2octets(z, rolen)

        v = b"\x01" * holen
        k = b"\x00" * holen

        k = hmac.new(k, v + b"\x00" + bx, hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
        k = hmac.new(k, v + b"\x01" + bx, hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()

        while True:
            t = b""
            while len(t) < rolen:
                v = hmac.new(k, v, hashlib.sha256).digest()
                t += v
            candidate = self._bits2int(t, qlen)
            if 1 <= candidate < n:
                yield candidate
            # Reached either because the candidate was out of range (spec
            # rejection path) or because the caller rejected it and asked for
            # the next one. Same ladder advance in both cases.
            k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
            v = hmac.new(k, v, hashlib.sha256).digest()

    def _rfc6979_generate_k(self, private_key: int, z: int) -> int:
        """Return the first RFC 6979 nonce candidate for (private_key, z)."""
        return next(self._rfc6979_k_candidates(private_key, z))

    @property
    def rng_is_explicit(self) -> bool:
        """True when the caller supplied the random source (e.g. a seeded run).

        When this is True, key generation draws from ``rng`` too, so the whole
        run is reproducible; when it is False, keys come from ``secrets``.
        """
        return self._rng_explicit

    def _generate_private_key(self) -> int:
        """Generate a random private key within the valid range.

        Draws from ``self._rng`` when the caller supplied one, and from
        ``secrets`` otherwise. Both paths use the same rejection sampling over
        ``n.bit_length()`` bits, so the distribution is uniform on [1, n-1]
        either way -- only the source differs.

        The old version always called ``secrets.randbits``, which made
        ``--seed`` a half-promise: z and k replayed, keys did not.
        """
        n_bits = self._curve.n.bit_length()
        randbits = self._rng.getrandbits if self._rng_explicit else secrets.randbits
        while True:
            private_key = randbits(n_bits)
            if 1 <= private_key < self._curve.n:
                return private_key

    @staticmethod
    def inverse_mod(k: int, p: int) -> int:
        """Compute modular multiplicative inverse of k mod p."""
        if k % p == 0:
            raise ZeroDivisionError("division by zero")
        return pow(k, -1, p)

    def is_on_curve(self, point: Point) -> bool:
        """Check whether a given point lies on the elliptic curve.

        ``None`` is the point at infinity and is a member of the group by
        definition, hence True.
        """
        if point is None:
            return True
        x, y = point
        return (y**2 - x**3 - self._curve.a * x - self._curve.b) % self._curve.p == 0

    def point_add(self, p1: Point, p2: Point) -> Point:
        """Add two elliptic curve points using group law."""
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2

        if x1 == x2 and (y1 + y2) % self._curve.p == 0:
            # p2 == -p1 (covers the y1 == y2 == 0 doubling case, which is a
            # point of order two).
            return None

        if x1 == x2:
            m = (3 * x1**2 + self._curve.a) * self.inverse_mod(2 * y1, self._curve.p)
            m %= self._curve.p
            x3 = (m**2 - 2 * x1) % self._curve.p
        else:
            m = (y2 - y1) * self.inverse_mod((x2 - x1) % self._curve.p, self._curve.p)
            m %= self._curve.p
            x3 = (m**2 - x1 - x2) % self._curve.p
        y3 = (m * (x1 - x3) - y1) % self._curve.p

        return x3, y3

    def scalar_multiply(self, k: int, p: Point) -> Point:
        """Perform scalar multiplication of a point by integer k."""
        if p is None:
            return None
        if k % self._curve.n == 0:
            return None
        if k < 0:
            k = k % self._curve.n

        q: Point = None
        while k:
            if k & 1:
                q = self.point_add(q, p)
            k >>= 1
            if k:  # skip the final, unused doubling
                p = self.point_add(p, p)

        return q

    def generate_keypair(self, private_key: Optional[int] = None) -> Tuple[int, Tuple[int, int]]:
        """Generate private and public key pair."""
        if private_key is None:
            private_key = self._generate_private_key()
        if not 1 <= private_key < self._curve.n:
            # `private_key != 0 and private_key < n` test.
            raise ValueError(
                f"private key must be in [1, n-1]; got {private_key}"
            )
        public_key = self.scalar_multiply(private_key, self._curve.g)
        if public_key is None:
            raise ValueError("private key maps to the point at infinity")
        return private_key, public_key

    def hash_message(self, message: bytes, min_start_range: int) -> int:
        """Return integer hash of a message modulo curve order.

        NOTE: in "test" mode z is randomised and NOT bound to the message.
        That is deliberate for the test curve but means test mode is not a
        signing oracle. Kept as-is; see README.
        """
        if self._curve.mode == "test":
            return self._rng.randrange(min_start_range, self._curve.n - 1)
        # legacy / real secp256k1: use Bitcoin-style double SHA256
        digest = hashlib.sha256(hashlib.sha256(message).digest()).digest()
        return int.from_bytes(digest, "big") % self._curve.n

    def _k_candidates(self, private_key: int, z: int, min_start_range: int) -> Iterator[int]:
        """Yield nonce candidates appropriate for the curve mode.

        ``min_start_range`` applies to test mode only.  The original code
        applied it as a post-filter over the RFC 6979 stream as well, which is
        a silent deviation from the specification: a conforming verifier
        derives the first in-range candidate, not the first candidate above an
        arbitrary floor.  It never fired at 256 bits, but it was wrong.
        """
        if self._curve.mode == "legacy":
            yield from self._rfc6979_k_candidates(private_key, z)
        else:
            while True:
                yield self._rng.randrange(min_start_range, self._curve.n - 1)

    def sign_message(
        self,
        private_key: int,
        message: bytes,
        min_start_range: int = 1,
    ) -> Tuple[int, int, int, int, int, int]:
        """Create ECDSA signature for a message using private key."""
        if not 1 <= private_key < self._curve.n:
            raise ValueError(f"private key must be in [1, n-1]; got {private_key}")
        if not 1 <= min_start_range < self._curve.n - 1:
            raise ValueError(
                f"min_start_range must be in [1, n-2]; got {min_start_range}"
            )

        z = self.hash_message(message, min_start_range)
        for k in self._k_candidates(private_key, z, min_start_range):
            point = self.scalar_multiply(k, self._curve.g)
            if point is None:
                continue
            x, y = point
            r_x = x % self._curve.n
            r_y = y
            if r_x == 0:
                continue
            k_inv = self.inverse_mod(k, self._curve.n)
            s = ((z + r_x * private_key) * k_inv) % self._curve.n
            if s != 0:
                return z, r_x, r_y, s, k, k_inv
        raise RuntimeError("nonce candidate stream exhausted")  # unreachable

    def verify_x_candidate(self, x: int, z: int, r: int, s: int) -> bool:
        """Confirm a private-key candidate using public data only.

        For a genuine key, ``k = (z + r*x) * s^-1`` must reproduce the very r
        that was signed, i.e. ``(k*G).x mod n == r``.  Nothing secret is used.

        This is the step the original pipeline was missing: candidates were
        printed as ``d_recovered`` without ever being checked, so a guess that
        happened to be wrong was reported exactly like one that was right.
        """
        n = self._curve.n
        if not 1 <= x < n:
            return False
        if not (1 <= r < n and 1 <= s < n):
            return False
        s_inv = inverse_mod_safe(s, n)
        if s_inv is None:
            return False
        k = ((z + r * x) % n) * s_inv % n
        if k == 0:
            return False
        point = self.scalar_multiply(k, self._curve.g)
        return point is not None and point[0] % n == r

    def verify_signature(self, public_key: Tuple[int, int], signature: Tuple[int, int, int, int, int, int]) -> bool:
        """Verify ECDSA signature against a given public key."""
        z, r, _, s, _, _ = signature
        if not (1 <= r < self._curve.n and 1 <= s < self._curve.n):
            return False
        # The original skipped public-key validation entirely and would happily
        # "verify" against a point that is not on the curve. The on-curve guard
        # below is what stops invalid-curve attacks (see test_G / TestPackage).
        if public_key is None or not self.is_on_curve(public_key):
            return False
        # No separate subgroup/order check: both shipped curves have prime order
        # n with cofactor 1, so an on-curve point other than O already has order
        # exactly n. A prior revision ran ``scalar_multiply(self._curve.n,
        # public_key)`` here and rejected on a non-None result -- but that is
        # dead code: scalar_multiply short-circuits to None whenever k % n == 0,
        # and n % n is 0, so the branch could never fire and validated nothing.
        # Reuse on a cofactor > 1 curve would need a real check, e.g.
        # ``scalar_multiply(n - 1, Q) == inverse_point(Q, p)``.
        w = self.inverse_mod(s, self._curve.n)
        u1 = (z * w) % self._curve.n
        u2 = (r * w) % self._curve.n
        p1 = self.scalar_multiply(u1, self._curve.g)
        p2 = self.scalar_multiply(u2, public_key)
        if p1 is None or p2 is None:
            return False
        total = self.point_add(p1, p2)
        if total is None:
            return False
        x, _y = total
        return (x % self._curve.n) == r

    @staticmethod
    def inverse_point(p: Tuple[int, int], mod_p: int) -> Tuple[int, int]:
        """Return additive inverse of a point modulo p."""
        x, y = p
        return x, (-y) % mod_p

    def generate_unique_keys(self, count: int, min_start_range: int) -> list[int]:
        """Generate a list of unique random integers within a specified range."""
        if count < 0:
            raise ValueError("count must be non-negative")
        if min_start_range < 1:
            raise ValueError("min_start_range must be >= 1")
        available = self._curve.n - min_start_range
        if count > available:
            raise ValueError(
                f"cannot draw {count} unique keys from [{min_start_range}, "
                f"{self._curve.n - 1}] ({available} values available)"
            )

        seen: set[int] = set()
        ordered: list[int] = []
        while len(ordered) < count:
            candidate = self._generate_private_key()
            if candidate < min_start_range:
                continue
            if candidate not in seen:
                seen.add(candidate)
                ordered.append(candidate)  # insertion order preserved
        return ordered


def print_curve_run(curve: CurveParams, private_key: Optional[int] = None, sig_type: str = "p2pkh") -> None:
    """Run full demo sequence: key generation, signing, verification, analysis."""
    ec = Secp256k1(curve)

    print("Elliptic curve parameters:")
    print(f"name = {curve.name}")
    print(f"mode = {curve.mode}")
    print(f"p = {curve.p}")
    print(f"a = {curve.a}")
    print(f"b = {curve.b}")
    print(f"g = {curve.g}")
    print(f"n = {curve.n}\n")

    t0 = time.time()
    if private_key is not None:
        _, public_key_Q = ec.generate_keypair(private_key=private_key)
    else:
        private_key, public_key_Q = ec.generate_keypair()
    print("Private key:")
    print(f"  d: {hex(private_key)[2:]}, {private_key}, ({bin(private_key)[2:]})")
    print("Public key:")
    print(f"  x: {hex(public_key_Q[0])[2:]}, {public_key_Q[0]}")
    print(f"  y: {hex(public_key_Q[1])[2:]}, {public_key_Q[1]}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    print(f"Is the point on curve?: {ec.is_on_curve(public_key_Q)}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    if curve.mode == "legacy":
        prev_txid = os.urandom(32)
        if sig_type == "p2wpkh":
            message = make_bitcoin_segwit_sighash_message(public_key_Q, prev_txid)
            print("Using BIP 143 SegWit v0 preimage for signing.")
        else:
            message = make_bitcoin_legacy_sighash_message(public_key_Q, prev_txid)
            print("Using legacy P2PKH preimage for signing.")
    else:
        message = b"Hello, secp256k1!"
        print("Using arbitrary message for signing (test curve).")
    signature = ec.sign_message(private_key, message, min_start_range=1)
    print("Signature parameters:")
    print(f"  z:     {hex(signature[0])[2:]}, {signature[0]}")
    print(f"  r:     {hex(signature[1])[2:]}, {signature[1]}")
    print(f"  s:     {hex(signature[3])[2:]}, {signature[3]}")
    print(f"  k:     {hex(signature[4])[2:]}, {signature[4]}")
    print(f"  k_inv: {hex(signature[5])[2:]}, {signature[5]}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    print(f"Signature validation: {ec.verify_signature(public_key_Q, signature)}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")


def main() -> None:
    """Run demo for both test and legacy curves."""
    print("============================================================")
    print("========== DEMO RUNS FOR PREDEFINED 'private_key' ==========")
    print("============================================================")
    print("")
    print("=========== TEST CURVE ===========")
    d = 99661
    print_curve_run(curve=TEST_PARAMS, private_key=d)

    print("========== LEGACY CURVE ==========")
    d = 64389052532870313044990203562685705333461655978490098671693221677551702405611
    print_curve_run(curve=LEGACY_PARAMS, private_key=d)
    print("========== LEGACY CURVE ==========")
    print_curve_run(curve=LEGACY_PARAMS, private_key=d, sig_type="p2wpkh")

    print("")

    print("============================================================")
    print("============ DEMO RUNS FOR DYNAMIC 'private_key' ===========")
    print("============================================================")
    print("")
    print("=========== TEST CURVE ===========")
    print_curve_run(curve=TEST_PARAMS)

    print("========== LEGACY CURVE ==========")
    print_curve_run(curve=LEGACY_PARAMS)
    print("========== LEGACY CURVE ==========")
    print_curve_run(LEGACY_PARAMS, sig_type="p2wpkh")


if __name__ == "__main__":
    main()
