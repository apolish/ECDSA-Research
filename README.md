# ECDSA-Research

An experimental study of the additive decomposition of the ECDSA signature
scalar on a small test curve and on real secp256k1.

> ⚠️ **NOTICE:** This is **not** a vulnerability disclosure. It describes no attack, no
> partial attack, and no weakening of any deployed parameter set. It does not threaten
> secp256k1 or any system that uses it, and it does not claim to.

Every ECDSA signature satisfies

```text
s = (z + r*x) * k^-1  (mod n)
```

which splits additively into two terms:

```text
s_zk  = z * k^-1        (mod n)
s_rxk = r * x * k^-1    (mod n)
s     = s_zk + s_rxk    (mod n)
```

`s_zk` and `s_rxk` are normally secret, because both contain `k^-1`. This
repository classifies signatures by whether `s_zk` happens to be pinned down by
a formula in the **public** data `(z, r, s)` alone — and, when it is, recovers
the private key and proves the recovery on the curve.

---

## Repository layout

```text
ECDSA-Research/
├── data/                                         # generated reports (created on first run)
│   ├── transaction_list_20260808232542.txt       # test curve   (5K   tx;   C,D)
│   ├── transaction_list_20260808233004.txt       # legacy curve (5K   tx;     D)
│   └── transaction_list_20260809003013.txt       # test curve   (100M tx; A,C,D,E)
├── src/
│   ├── ecurve/
│   │   ├── secp256k1.py                          # curve arithmetic, RFC 6979, sighash preimages,
│   │   └── _ripemd160.py                         # pure-Python RIPEMD-160 (OpenSSL 3.x fallback)
│   └── utils/
│       ├── generate_transactions.py              # signature generator + case classifier + report writer
│       └── find_common_private_key.py            # search for a key shared by several transactions
├── tests/
│   └── run_tests.py                              # regression suite with a tabular console report
├── LICENSE
└── README.md
```

Both scripts in `src/utils/` also run from a flat directory — put
`secp256k1.py`, `_ripemd160.py` and the script side by side and they will find
each other.

---

## Requirements

Python **3.8 or newer**. Standard library only — no `pip install` step.

(`pow(x, -1, m)` is the 3.8 floor. Earlier revisions depended on `sympy` for a
modular square root; that is now `mod_sqrt_all` in `secp256k1.py`.)

---

## Quick start

```bash
git clone <this-repo> && cd ECDSA-Research

python3 tests/run_tests.py                       # 17 checks, tabular output
python3 src/utils/generate_transactions.py       # test curve, 5000 keys -> data/
python3 src/utils/find_common_private_key.py     # bundled 4-transaction demo
```

---

## The curves

|---|`test`|`legacy`|
|---|---|---|
|name|`secp17k1`|`secp256k1`|
|p|100003|2²⁵⁶ − 2³² − 977|
|curve|y² = x³ + 2|y² = x³ + 7|
|n|99667 (prime, cofactor 1)|the standard group order|
|z|random, **not bound to the message**|dSHA256 of a Bitcoin sighash preimage|
|k|random (`SystemRandom` by default)|RFC 6979, deterministic|

The test curve is a genuine elliptic curve: `G` lies on it, `#E = n = 99667`, and
the cofactor is 1 — all three are asserted in the test suite.

Note the asymmetry: in `test` mode `z` is drawn at random and is **not** a hash
of the message, so `test` mode is a source of valid `(z, r, s)` triples, not a
signing oracle. That is deliberate — it makes the test curve a fast statistical
sandbox — but it means test-mode results describe the algebra of the triples,
not the behaviour of a deployed signer.

---

## The case taxonomy

With `s_zr = z*r mod n` and, when `s_zr > s`,

```python
a = s mod ((s_zr - s) mod n)
m1 = s_zk / a
m2 = (s + s_zr) / s_rxk
```

| Case | Condition | Is `s_zk` fixed by public data? |
| --- | --- | --- |
| **A** | `m1 == 1`, i.e. `s_zk == a` | yes — guess `s_zk = a` |
| **B** | `m1 == m2`, both integral | yes — `m1` solves `a*m1² − s*m1 + (s + s_zr) ≡ 0 (mod n)` |
| **C** | `m1` integral, `m1 > 1` | no — `m1` is not determined by `(z, r, s)` |
| **D** | `m1` not integral | no |
| **E** | `s_zk + s_rxk == S` and `abs(s_zk − s_rxk) == S//2 + 1`, where `S ∈ {s, s+n}` and `S % 4 == 2` | yes — both parts follow from `S` |

Cases A, B and E are therefore *guesses computable from the signature alone*.
Each guess is turned into a key candidate by

```text
x = z*(s - s_zk) * (r*s_zk)^-1  (mod n)
```

and then **confirmed on the curve**: recompute `k = (z + r*x) * s^-1` and check
that `(k*G).x mod n == r`. That check also uses public data only. A candidate
that fails it is counted under `Recovery Rejected` and never reported as a key.

Cases C and D leave `s_zk` undetermined and yield nothing.

### Case E naming

The case-E detector is `_detect_half_difference_split`: it tests whether the
additive split of `S` has difference exactly `S//2 + 1`.

---

## `generate_transactions.py`

Generates signatures, classifies them, and writes a fixed-width report to
`data/transaction_list_<timestamp>.txt`.

```bash
python3 src/utils/generate_transactions.py \
    --curve-mode test --keys 5000 --tx-per-key 20 --output-count 1000 --seed 42
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--curve-mode {test,legacy}` | `test` | which curve |
| `--keys N` | 5000 | unique private keys to draw |
| `--private-key D` | 0 | use one fixed key instead (0 = draw randomly) |
| `--tx-per-key N` | 1 | signatures per key |
| `--output-count N` | 1000 | maximum **printed** rows per case (counting is unaffected) |
| `--d-case-digit N` | -1 | print only this case-D level (-1 = all) |
| `--min-start-range N` | 1000 | lower bound for test-mode `z` and `k` |
| `--seed N` | — | reproducible run; omit for `SystemRandom` |
| `--out-dir PATH` | `data/` | report destination |
| `--sig-type {p2pkh,p2wpkh}` | `p2pkh` | legacy-mode sighash flavour |
| `--demo` | off | one key-generation / signing / verification round |

### Report columns

```text
case  s  s_zk*  s_rxk*  s_zr  z  r_x  r_y  x*  k*  k^{-1}*  a  m1*  m2*  f*  x_recovered  hypothesis
```

A trailing `*` marks a column that is **not** available to an attacker; it is
printed for research validation. `x_recovered` holds only candidates that
passed the on-curve check. Column widths are computed from the data, so a
256-bit `Fraction` cannot shift the table.

### Statistics block

```text
Total Key Count: 5000
Transaction Limit Per Key: 20000
Total Transaction Count: 100000000
Signature Space Per Key: 9.933312e+09
Signature Space All Keys: 9.900134e+14
Transactions With Valid A: 24985980
Total Observed Cases: 24986477
Case A Count: 224
Case B Count: 0
Case C Count: 55964
Case D Count: 24929792
Case E Count: 670
Case E Overlapping A Cases: 173
Hypothesis 001 Count: 300744
Recovery Attempts: 1564
Recovery Verified: 894
Recovery Rejected: 670
Case D0 Count: 1749153
...
```

`Signature Space Per Key` is `(n−1)²`: for a fixed key a signature is determined
by the pair `(k, z)`. `Total Observed Cases` subtracts the A–D/E overlap so
nothing is counted twice.

---

## `find_common_private_key.py`

Given several transactions believed to share a key, searches each level window

```text
s_zk ∈ [a*N, a*(N+1) - 1],   N = floor(s_zk / a)
```

intersects the resulting candidate sets, and verifies the survivors on the
curve.

```bash
python3 src/utils/find_common_private_key.py
python3 src/utils/find_common_private_key.py --no-verify   # show the raw intersection
```

```text
tx1: N = 11, s_zk in [36091, 39371], window = 3,281
tx2: N = 0,  s_zk in [1,      5724], window = 5,724
tx3: N = 4,  s_zk in [17504, 21879], window = 4,376
tx4: N = 0,  s_zk in [1,     12241], window = 12,241

Candidates actually evaluated: 25,622
Naive Cartesian product (not performed): 1.006005e+15
Expected coincidental survivors before verification: 1.016

Found common x = 32768  [verified on curve]
```

Three things to read carefully:

* **Cost.** The algorithm builds one index per transaction and intersects, so
  the work is `Σ|Wᵢ|` — about 25.6 k here. The Cartesian product is printed
  only to make clear that it is *not* what happens.
* **`Expected coincidental survivors` = `Π|Wᵢ| / n^(k−1)`.** When that number
  approaches 1, the intersection alone proves nothing; measured over 150 random
  4-transaction bundles the unverified search returned **≈3 impostors per run**
  alongside the true key. With the on-curve check the count is **0**. Choose
  bundles that keep this figure well below 1, and never trust `--no-verify`
  output.
* **`N` is an input.** It comes from `f = s_zk/a`, which is derived from the
  secret `s_zk`. The search narrows a window it was given; it does not discover
  the level.

`f` must be passed as `str`, `Fraction`, `Decimal` or `int`. `float` is refused
with an explanation: it holds ~16 significant digits, the reports carry 20 (test)
or 80 (legacy), and at 256-bit scale `int(float(f))` misses the true floor by
about 4.3·10³⁸.

`--max-window` (default 50,000,000) rejects windows too wide to enumerate. On
secp256k1 a level window is roughly the size of `a` itself, so `legacy` mode is
refused with a clear error instead of hanging.

---

## Tests

```bash
python3 tests/run_tests.py            # table
python3 tests/run_tests.py -k window  # filter by Class.method substring
python3 tests/run_tests.py -v         # full tracebacks on failure
python3 tests/run_tests.py --no-color
```

Exit status is 0 on success and 1 otherwise. The `Detail` column reports the
value each test actually measured rather than a column of "ok":

```text
 #   | Test                                                    | Status | Time   | Detail
-----+---------------------------------------------------------+--------+--------+--------------------------------------
     | CURVE PARAMETERS AND PRIMITIVES                         |        |        |
 1   |   Test curve is a real curve of prime order             |  PASS  | 0.102s | #E = n = 99667, cofactor 1, G on curve
 2   |   RFC 6979 nonce matches published secp256k1 vectors    |  PASS  | 0.000s | 3/3 published vectors
...
 18  |   A secp256k1-scale window is rejected, not attempted   |  PASS  | 0.000s | ValueError raised before any enumeration
```

Independently confirmed by the suite: the test curve's group order equals `n`
with cofactor 1; the RFC 6979 implementation reproduces the published
secp256k1 test vectors; the RIPEMD-160 fallback matches the official vectors
including a multi-block input.

---

## Measured results

Case A and case E do recover a private key from public parameters alone, and
the curve confirms it. How often they fire is the load-bearing question, and
the answer is on the repository's own 10⁸-transaction run on the test curve:

| case   | observed rate                      |
|:-------|:-----------------------------------|
| case A | 224 / 100,000,000 = 2.24·10⁻⁶      |
| case E | 670 / 100,000,000 = 6.70·10⁻⁶      |

**Case B** is extremely rare even for a test curve and therefore requires
several billion generated transactions to catch at least one such case
(1 / 6,826,438,356 = 1.46·10⁻¹⁰).

That is the rate of guessing `k^-1` at random. The formulas do not find `s_zk`;
they name one value out of `n`, and occasionally it is the right one.

The consequence for real secp256k1 is arithmetic, not opinion: the same events
occur with probability ≈ 2⁻²⁵⁶ per signature. Nothing here is a practical
attack on Bitcoin keys, and the code makes no attempt to be one — `legacy` mode
exists so the same algebra can be checked at full scale, and
`find_common_private_key.py` refuses to run there.

### HYP-001

The **hypothesis feature** was added to support further research and
hypothesis testing, so hypothesis HYP-001 is provided here as an example only.

The case-D hypothesis reduces to a relation between the first two partial
quotients of the continued fraction of `s_zk/a`:

```text
floor(a / (s_zk mod a)) ∈ { N, N-1 },   N = floor(s_zk / a)
```

Evaluated on completely random, independent `(s, s_zk, a)` triples it fires at:

| modulus scale | 2¹⁷    | 2⁶⁴    | 2²⁵⁶   | 2⁵¹²   |
|:--------------|:-------|:-------|:-------|:-------|
| HYP-001 rate  | 0.49 % | 0.50 % | 0.50 % | 0.49 % |

Scale-invariant, and matching the Gauss–Kuzmin distribution of continued-fraction
quotients. It is a property of the ratio `s_zk/a`, not of ECDSA. Rates observed
in real runs (0.73 %, 0.90 % over ~1230 rows) are within noise of 0.50 %.

---

## Known limits

* `test`-mode `z` is not a hash of the message, so test-mode triples are not
  signatures a verifier would accept against a message.
* Cases C and D are not recoverable: `m1` is not a function of the public data.
* Case B has never been observed in a real run; its quadratic is validated
  synthetically in the test suite.
* Level windows are only usable at toy scale.
* The classification is representative-dependent by construction. `s % 2`,
  `s_zr > s` and `m1 > 1` treat elements of ℤₙ as integers, and `n` is odd, so
  `s` and `s + n` are the same group element with different parity — case E
  relies on exactly this by choosing `S ∈ {s, s+n}`. Any statistic drawn from
  these tests describes the chosen integer representatives, not the group.

---

## Prior publications

Earlier write-ups of classes A and B. **Superseded by the assessment above: their
"vulnerability" framing is no longer endorsed by the author.** Kept for the record.

```text
https://doi.org/10.6084/m9.figshare.29223701
https://doi.org/10.21203/rs.3.rs-6790872/v1
```

---

## References

* SEC 2: *Recommended Elliptic Curve Domain Parameters* (secp256k1).
* RFC 6979, *Deterministic Usage of DSA and ECDSA* — Pornin, 2013.
* Boneh & Venkatesan, *Hardness of Computing the Most Significant Bits of Secret
  Keys in Diffie-Hellman* — CRYPTO 1996 (origin of the HNP).
* Howgrave-Graham & Smart, *Lattice Attacks on Digital Signature Schemes* —
  Designs, Codes and Cryptography, 2001.
* Nguyen & Shparlinski, *The Insecurity of the Elliptic Curve Digital Signature
  Algorithm with Partially Known Nonces* — J. Cryptology, 2003.
* BIP 143, *Transaction Signature Verification for Version 0 Witness Program*.
* Dobbertin, Bosselaers & Preneel, *RIPEMD-160: A Strengthened Version of
  RIPEMD* — FSE 1996.

---

## Author

**Andriy Polishchuk** — CRYPTON Systems Lab
📧 andriy.polishchuk.a@gmail.com

*Independent researcher. CRYPTON Systems Lab is an independent research group and not an
institutional affiliation.*

---

## License

Released under the MIT License (see `LICENSE`).

---

## Project on JIRA

Tracking and monitoring tasks related to the current project can be found here:

[![Go to JIRA](https://img.shields.io/badge/JIRA-Visit-blue)](https://cryptonsystemslab.atlassian.net/jira/core/projects/CSL/board?filter=&groupBy=status&atlOrigin=eyJpIjoiZWYwNGI4ODlhYmZjNDdkNGIwMGM3NWUwNzk0MTBjNGYiLCJwIjoiaiJ9)
