#!/usr/bin/env python3
"""Measurements quoted in the README that are not exhaustive counts.

Standard library only; uses the repository's own modules from src/.  Every
section is seeded, so the output replays exactly.  Run time: about 1-2 minutes.

  1. HYP-001 on independent uniform triples (a, s_zk, s): with the gate the
     code applies (N > 1, s > s_zk, s_zk even) and without it; the weak form
     floor(a/w) in {N, N-1}; and the law of q = floor(a/w) against
     Gauss-Kuzmin and against 1/(q(q+1)).
  2. README Known issue 3: signatures on which the case-B *formula* recovers
     the key although the label is not B, built on both curves.
  3. Class-A construction cost on secp256k1 (nonces per signature).
  4. Unverified common-key search: impostors per random 4-transaction bundle.
"""
import math
import os
import random
import sys
import time
from fractions import Fraction

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, os.pardir, "src"))

from ecurve.secp256k1 import (  # noqa: E402
    LEGACY_PARAMS, TEST_PARAMS, Secp256k1, mod_sqrt_all,
)
from utils.find_common_private_key import ECDSATransaction, find_common_x  # noqa: E402
from utils.generate_found_classes import ECDSAClassGenerator, classify  # noqa: E402
from utils.generate_transactions import _check_hypothesis_001, recover_private_keys  # noqa: E402


def hyp001_null_model():
    print("1. HYP-001 on independent uniform triples (a, s_zk, s) < 2^bits")
    rnd = random.Random(2026)
    for bits in (17, 64, 256, 512):
        top = 1 << bits
        trials = 1_000_000
        gated = weak = ungated = 0
        q_hist = {}
        for _ in range(trials):
            a, s_zk, s = rnd.randrange(1, top), rnd.randrange(1, top), rnd.randrange(1, top)
            level = s_zk // a
            w = s_zk - level * a
            if w == 0:
                continue
            t = a % w
            delta = 1 if (level * t) % w + t >= w else 0
            q = a // w
            ungated += q == level - delta
            if _check_hypothesis_001(level, s, s_zk, a) == "HYP-001":
                gated += 1
            if level > 1 and s > s_zk and s_zk % 2 == 0:
                weak += q in (level, level - 1)
                if bits == 64:
                    q_hist[min(q, 6)] = q_hist.get(min(q, 6), 0) + 1
        print(f"   2^{bits:<3}: gated {100 * gated / trials:.3f} %   "
              f"weak form {100 * weak / trials:.3f} % (x{weak / gated:.2f})   "
              f"ungated {100 * ungated / trials:.2f} %")
        if bits == 64:
            tot = sum(q_hist.values())
            print("            q = floor(a/w) in the gated population:")
            for q in range(1, 6):
                gk = -math.log2(1 - 1 / (q + 1) ** 2)
                print(f"              q={q}: {q_hist.get(q, 0) / tot:.4f}   "
                      f"Gauss-Kuzmin {gk:.4f}   1/(q(q+1)) {1 / (q * (q + 1)):.4f}")


def _b_formula_signature(ec, rnd, q_max=60):
    """Known issue 3: s_zk * s_rxk == a * (s + s_zr) without steering P."""
    n = ec.curve.n
    trials = 0
    while True:
        trials += 1
        k = rnd.randrange(1, n)
        r = ec.scalar_multiply(k, ec.curve.g)[0] % n
        if r == 0:
            continue
        s_zk = rnd.randrange(1, n)
        s_zr = s_zk * (k * r % n) % n
        for q in range(1, q_max + 1):
            c2, c1 = (q + 1) % n, (s_zr - s_zk) % n
            c0 = (s_zk * s_zk - q * s_zr * s_zr) % n
            for root in mod_sqrt_all((c1 * c1 - 4 * c2 * c0) % n, n):
                s = (-c1 + root) * pow(2 * c2, -1, n) % n
                if not 0 < s < s_zr or s == s_zk:
                    continue
                d = s_zr - s
                if s // d != q or s % d == 0:
                    continue
                z = s_zk * k % n
                x = (s - s_zk) * k * pow(r, -1, n) % n
                if z and x:
                    return dict(k=k, r=r, s=s, z=z, x=x, s_zk=s_zk, s_zr=s_zr,
                                a=s % d, trials=trials)


def b_formula_construction():
    print("2. Case-B formula event built directly (README Known issue 3)")
    for params, count in ((TEST_PARAMS, 200), (LEGACY_PARAMS, 20)):
        ec = Secp256k1(params, rng=random.Random(1))
        rnd = random.Random(99)
        n = params.n
        labels, recovered, trials = {}, 0, 0
        t0 = time.time()
        for _ in range(count):
            c = _b_formula_signature(ec, rnd)
            trials += c["trials"]
            s_rxk = (c["s"] - c["s_zk"]) % n
            assert c["s_zk"] * s_rxk % n == c["a"] * (c["s"] + c["s_zr"]) % n
            pub = ec.scalar_multiply(c["x"], params.g)
            keys, _ = recover_private_keys(ec, "B", c["s"], c["s_zr"], c["z"], c["r"],
                                           c["a"], pub)
            recovered += keys == [c["x"]]
            label = classify(c["s"], c["s_zk"], s_rxk, c["s_zr"], n)[0]
            labels[label] = labels.get(label, 0) + 1
        ms = 1000 * (time.time() - t0) / count
        print(f"   {params.name}: {recovered}/{count} keys recovered by the B formula; "
              f"labels {labels}; {trials / count:.1f} nonce trials each; {ms:.0f} ms each")


def class_a_cost():
    print("3. Class-A construction on secp256k1")
    ec = Secp256k1(LEGACY_PARAMS, rng=random.Random(5))
    gen = ECDSAClassGenerator(ec)
    draws = {"nonces": 0}
    original = gen._random_nonce_point

    def counted():
        draws["nonces"] += 1
        return original()

    gen._random_nonce_point = counted
    odd = even = 0
    count = 60
    for _ in range(count):
        fs = gen.generate("A")
        if fs.k * fs.r_x % LEGACY_PARAMS.n % 2:
            odd += 1
        else:
            even += 1
    print(f"   {draws['nonces'] / count:.2f} nonces per signature over {count}; "
          f"P = k*r odd {odd}, even {even}")


def unverified_impostors():
    print("4. Unverified common-key search over random 4-transaction bundles")
    n = TEST_PARAMS.n
    ec = Secp256k1(TEST_PARAMS, rng=random.Random(1))
    rnd = random.Random(101)

    def make_tx(d):
        while True:
            z, k = rnd.randrange(1, n), rnd.randrange(1, n)
            r = ec.scalar_multiply(k, TEST_PARAMS.g)[0] % n
            if r == 0:
                continue
            k_inv = pow(k, -1, n)
            s = (z + r * d) * k_inv % n
            s_zk, s_zr = z * k_inv % n, z * r % n
            if s == 0 or s_zr <= s:
                continue
            a = s % (s_zr - s)
            if not 0 < a != s or s_zk % a == 0:
                continue
            return ECDSATransaction.from_ratio(s=s, z=z, r=r, a=a, f=Fraction(s_zk, a))

    runs, extra, verified_extra = 150, 0, 0
    for _ in range(runs):
        d = rnd.randrange(1, n)
        txs = [make_tx(d) for _ in range(4)]
        extra += len({x for x, _ in find_common_x(txs, ec, verify=False)} - {d})
        verified_extra += len({x for x, _ in find_common_x(txs, ec, verify=True)} - {d})
    print(f"   {runs} bundles: {extra / runs:.2f} impostors per bundle unverified, "
          f"{verified_extra / runs:.2f} verified")


if __name__ == "__main__":
    for section in (hyp001_null_model, b_formula_construction, class_a_cost,
                    unverified_impostors):
        t0 = time.time()
        section()
        print(f"   [{time.time() - t0:.1f}s]", flush=True)
