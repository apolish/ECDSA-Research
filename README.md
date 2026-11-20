# ECDSA-Research

An experimental study of the additive decomposition of the ECDSA signature
scalar on a small test curve and on real secp256k1.

> ⚠️ **NOTICE:** This is **not** a vulnerability disclosure. It describes no attack, no
> partial attack, and no weakening of any deployed parameter set. It does not threaten
> secp256k1 or any system that uses it, and it does not claim to.
>
> 🚧 **STATUS — work in progress (20 November 2026).** The paper linked under
> [Current publications](#current-publications) (v2, August 2026) is a preliminary report.
> Issues found after its publication, and their corrections, are listed in
> [Known issues and corrections](#known-issues-and-corrections). Wherever the paper and
> that section disagree, **that section takes precedence**. A final report will follow
> when the study is complete.

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
the private key and proves the recovery against the signer's public key.

---

## Repository layout

```text
ECDSA-Research/
├── data/                                              # generated reports (committed; see "Data files")
│   ├── transaction_list_20261120185543_337c7bed.txt   # test curve   (10M  tx sampled;     A,_,C,D,E cases)
│   ├── transaction_list_20261120193557_d7870627.txt   # legacy curve (100K tx sampled;     _,_,_,D,_ cases)
│   ├── transaction_list_20261120210827_1b96a014.txt   # test curve   (3K   tx constructed; A,B,_,_,E cases)
│   └── transaction_list_20261120211000_0d254a9b.txt   # legacy curve (2K   tx constructed; A,_,_,_,E cases)
├── docs/
│   ├── ECDSA_coincidence_classes.pdf                  # published paper
│   ├── null_model_experiment.py, .txt                 # attachment for the paper (corrected: Known issue 8), output
│   ├── exact_class_counts.py, .txt                    # exhaustive class counts quoted below, output
│   └── readme_measurements.py, .txt                   # sampled measurements quoted below, output
├── src/
│   ├── ecurve/
│   │   ├── secp256k1.py, .txt                         # curve arithmetic, RFC 6979, sighash preimages; demo output
│   │   └── _ripemd160.py                              # pure-Python RIPEMD-160 (OpenSSL 3.x fallback)
│   ├── utils/
│   │   ├── generate_transactions.py                   # signature generator + case classifier + report writer
│   │   ├── generate_found_classes.py                  # direct constructor for class A/B/E signatures
│   │   └── find_common_private_key.py, .txt           # search for a key shared by several transactions; demo output
│   └── tests/
│       └── run_tests.py, .txt                         # regression suite with a tabular console report; last run
├── .gitattributes                                     # LF line endings for every text file
├── LICENSE
└── README.md
```

All three scripts in `src/utils/` also run from a flat directory — put
`secp256k1.py`, `_ripemd160.py` and the scripts side by side and they will find
each other (checked by test 32).

---

## Requirements

Python **3.8 or newer**. Everything under `src/` is standard library only — no
`pip install` step. The suite passes on 3.8.20, 3.9.25 and 3.13.

`docs/null_model_experiment.py` and `docs/exact_class_counts.py` need **numpy**;
`docs/readme_measurements.py` is standard library only.

(`pow(x, -1, m)` is the 3.8 floor. Earlier revisions depended on `sympy` for a
modular square root; that is now `mod_sqrt_all` in `secp256k1.py`. Legacy mode
used `random.Random.randbytes`, which needs 3.9; it now uses `rand_bytes`, which
gives the same bytes for a seeded run.)

---

## Quick start

```bash
git clone <this-repo> && cd ECDSA-Research

python3 src/tests/run_tests.py                   # 35 checks, tabular output
python3 src/utils/generate_transactions.py       # test curve, 5000 keys -> data/
python3 src/utils/find_common_private_key.py     # bundled 4-transaction demo
```

---

## The curves

| | `test` | `legacy` |
| --- | --- | --- |
| name | `secp17k1` | `secp256k1` |
| p | 100003 | 2²⁵⁶ − 2³² − 977 |
| curve | y² = x³ + 2 | y² = x³ + 7 |
| n | 99667 (prime, cofactor 1) | the standard group order |
| z | random, **not bound to the message** | dSHA256 of a Bitcoin sighash preimage |
| k | random (`SystemRandom` by default) | RFC 6979, deterministic |
| s | as computed | as computed — **no** low-S normalisation, **no** low-R grinding |

The test curve is a genuine elliptic curve: `G` lies on it, `#E = n = 99667`,
`n` is prime and `(n−1)·G = −G`, hence the cofactor is 1 — all of this is
asserted in the test suite.

Note the asymmetry: in `test` mode `z` is drawn at random and is **not** a hash
of the message, so `test` mode is a source of valid `(z, r, s)` triples, not a
signing oracle. That is deliberate — it makes the test curve a fast statistical
sandbox — but it means test-mode results describe the algebra of the triples,
not the behaviour of a deployed signer.

`legacy` mode is not Bitcoin Core's signer either. libsecp256k1 always emits
low-S signatures (`s ≤ n/2`), and Bitcoin Core (since 0.17) also grinds the
nonce until `r < 2²⁵⁵`. `legacy` mode does neither: in
`data/transaction_list_20261120193557_d7870627.txt` 493 of 1000 rows are high-S,
507 high-R, and only 240 have the shape Bitcoin Core would emit. Because the
classification depends on the integer representative of `s` (see
[Known limits](#known-limits)), legacy-mode statistics describe plain RFC 6979
signatures, not the signatures found on the Bitcoin blockchain.

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
| **E** | `s_zk + s_rxk == S` and `abs(s_zk − s_rxk) == S//2 + 1`, where `S ∈ {s, s+n}` and `S % 4 in {1, 2}` | yes — both parts follow from `S` |

The **labels** are computed from `s_zk` and `s_rxk`, i.e. from secret values:
they are research annotations that an attacker cannot evaluate. The recovery
**formulas** need only `(z, r, s)` and the class. Cases A, B and E are therefore
*guesses computable from the signature alone*: one guess for A, at most two
for B, at most four for E (both parts of both admissible `S`; the E1/E2
sub-label, which depends on the secret parts, is not used). Each guess is
turned into a key candidate by

```text
x = z*(s - s_zk) * (r*s_zk)^-1  (mod n)
```

and then **checked**. With the signer's public key `Q` — which any verifier
needs anyway, and which the generator always knows — the check is `x̂*G == Q`,
and that is decisive. Without `Q`, `verify_x_candidate` recomputes
`k = (z + r*x̂) * s^-1` and tests `(k*G).x mod n == r`; that test accepts every
key under which the signature verifies, which always includes a second key
besides the true one — see [Known issues](#known-issues-and-corrections), item 2.
A candidate that fails is counted under `Recovery Rejected` and never reported
as a key.

Cases C and D have no formula of their own and yield nothing when recovery is
run by label. A signature labelled D can still be recovered by the case-B
formula — see [Known issues](#known-issues-and-corrections), item 3.

### Case E naming

The case-E detector is `_detect_half_difference_split`: it tests whether the
additive split of `S` has difference exactly `S//2 + 1`.

---

## `generate_transactions.py`

Generates signatures, classifies them, and writes a fixed-width report to
`data/transaction_list_<timestamp>_<tag>.txt`. The timestamp resolves to one
second, so a short random `<tag>` is appended: without it two reports written
inside the same second silently overwrote each other.

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
| `--min-start-range N` | 100 | lower bound for test-mode `z` and `k` and for drawn keys (both modes); values are drawn from `[N, n−1]` |
| `--seed N` | — | reproducible run: fixes the **keys** and every signed message, so `z`, `k` and the report rows replay on both curves (legacy `prev_txid` included); omit for system entropy |
| `--out-dir PATH` | `data/` | report destination |
| `--sig-type {p2pkh,p2wpkh}` | `p2pkh` | legacy-mode sighash flavour |
| `--demo` | off | one key-generation / signing / verification round, then exit (writes no report) |
| `--tx-with-classes A B E` | — | **construct** signatures of the named classes instead of sampling (see below) |

Without `--seed`, `z` and `k` come from `random.SystemRandom` and keys from
`secrets`.

### Report columns

```text
case  s  s_zk*  s_rxk*  s_zr  z  r_x  r_y  x*  k*  k^{-1}*  a  m1*  m2*  f*  x_recovered  hypothesis
```

A trailing `*` marks a column that is **not** available to an attacker; it is
printed for research validation. `case` and `hypothesis` are computed from
starred columns, so they are not available to an attacker either.
`x_recovered` holds only candidates that passed the check against the public
key. Column widths are computed from the data, so a 256-bit `Fraction` cannot
shift the table.

### Statistics block

```text
Total Key Count: 5000
Transaction Limit Per Key: 2000
Total Transaction Count: 10000000
Signature Space Per Key: 9.933312e+09
Signature Space All Keys: 9.900134e+14
Transactions With Valid A: 2498633
Total Observed Cases: 2498732
Case A Count: 25
Case B Count: 0
Case C Count: 5408
Case D Count: 2493200
Case E Count: 140
Case E Overlapping A Cases: 41
Hypothesis 001 Count: 30083
Recovery Attempts: 305
Recovery Verified: 165
Recovery Rejected: 140
Recovery Attempts A: 25
Recovery Attempts B: 0
Recovery Attempts E: 280
Recovery Verified A: 25
Recovery Verified B: 0
Recovery Verified E: 140
Recovered Signature Count: 165
Case D0 Count: 175101
...
```

The figures are those of `data/transaction_list_20261120185543_337c7bed.txt`
(5,000 keys × 2,000 signatures). That file was produced by the generator as of
commit `aa5afa7`, which differs from the current one in three ways that do not
touch the classification (a differential test over 4·10⁵ signatures gave
identical labels, `a`, `m1`, `m2` and keys): `z` and `k` were drawn from
`[100, n−2]` instead of `[100, n−1]`; case E was recovered with the secret
E1/E2 sub-label, i.e. 2 attempts per E signature instead of 2–4; and keys were
confirmed with `verify_x_candidate` instead of `x̂*G == Q`.

`Signature Space Per Key` is `(n−1)²`: for a fixed key a signature is determined
by the pair `(k, z)`. `Signature Space All Keys` is `(n−1)³` — all possible
keys, independent of `--keys`. `Total Observed Cases` subtracts the A–D/E
overlap so nothing is counted twice: 25 + 0 + 5,408 + 2,493,200 + 140 − 41 =
2,498,732.

`Case E Overlapping A Cases` counts case-E signatures that also have a valid
auxiliary `a`, i.e. that are additionally classified as one of A/B/C/D. It is
*not* the number of signatures that are both case E and case A — despite how
the label reads. In this file that number is 0: the 165 recovered signatures
are 25 (A) + 140 (E), with no overlap.

Recovery runs the formula of every class a signature belongs to, so
`Recovery Attempts` = 25 (A) + 0 (B) + 280 (E) = 305, `Recovery Verified` =
25 + 0 + 140 = 165, and `Recovery Rejected` = 140 — the second part of each E
split. `Recovery Verified` would count a signature twice if it were both
case E and case A or B; `Recovered Signature Count` never does.

---

## `generate_found_classes.py` — constructing class A/B/E signatures

Sampling waits for a rare coincidence. `generate_found_classes.py` goes the other way and
**constructs** a signature that already lands in a requested class. Reached from
the CLI with `--tx-with-classes`, which takes one or more of `A B E`
(case-insensitive) and emits `--output-count` rows per class:

```bash
# test curve, all three classes, 5 rows each
python3 src/utils/generate_transactions.py --tx-with-classes A B E --output-count 5

# real secp256k1: A and E are constructed, B is skipped with a reason
python3 src/utils/generate_transactions.py --tx-with-classes A E B --curve-mode legacy
```

The two constructed reports in `data/` were made with `--output-count 1000
--seed 20261120` (test curve: `--tx-with-classes A B E`; legacy: the same plus
`--curve-mode legacy`, where B is skipped).

### How it works

The construction is honest ECDSA. Choosing a nonce `k` (hence `r`) and the two
additive parts `(s_zk, s_rxk)` fixes everything else exactly:

```text
z = s_zk * k          mod n
x = s_rxk * k * r^-1  mod n
s = s_zk + s_rxk      mod n
```

Every emitted row is checked twice, independently, before it is returned:
`verify_signature` runs standard ECDSA verification against `Q = x*G`, and
`recover_private_keys` re-derives the key from the public `(z, r, s)` and
accepts it only if `x̂*G == Q`.

In a constructed report every row is counted once, under the class it was
constructed for: `Case C Count`, `Case D Count`, `Case E Overlapping A Cases`
and `Hypothesis 001 Count` are 0 by design, and `Transactions With Valid A` is
the number of A and B rows. The recovery lines are measured, not assumed: each
A row costs 1 attempt, each B row 2 (both roots of the quadratic; 1 if they
coincide) and each E row 2–4 (both parts of both admissible `S`), so the second
root or part shows up under `Recovery Rejected`.

### What cannot be steered

`s_zr = s_zk * (k*r)`, and `P = k*r mod n` is fixed the moment `k` is chosen —
`k → k*(k*G).x` is effectively a random oracle. That single fact decides which
classes are constructible where:

| class | depends on `P`? | test curve | legacy secp256k1 |
| --- | --- | --- | --- |
| A | no — any `P` works (`P` odd: `D = 2`; `P` even: an odd divisor of `P − 1`) | yes | yes (1.02 nonces per signature, measured) |
| B | yes — pins `s_zr : s_zk` to a fixed rational | yes (nonces enumerable) | **refused**: each nonce hits the target with probability ≈ 2⁻²⁵⁶ |
| E | no — uses only `s_zk`, `s_rxk` | yes | yes |

Class B on the legacy curve raises `ClassConstructionError` with that
explanation rather than looping forever or pretending otherwise.

This separation concerns the class-B **label** (integral `m1 == m2`). The weaker
event on which the case-B *recovery formula* succeeds does not involve `P` and
can be constructed on real secp256k1 as well — see
[Known issues](#known-issues-and-corrections), item 3.

### Honest caveat

`z` is **chosen** as `s_zk * k`, so it is not the hash of any particular
message; `is_message_bound` is always `False`, and the report says so in its
preamble. This is why constructing such a signature is not an attack: it
requires already knowing `x` and `k` and being free to pick `z`. A real signer's
`x` is secret and its `z` is a fixed message hash, so none of this transfers to
a signature you did not create yourself. The module is a source of synthetic
test vectors for the classifier and the recovery path — nothing more.

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
tx2: N = 0, s_zk in [1, 5724], window = 5,724
tx3: N = 4, s_zk in [17504, 21879], window = 4,376
tx4: N = 0, s_zk in [1, 12241], window = 12,241

Candidates actually evaluated: 25,622
Naive Cartesian product (not performed): 1.006005e+15
Expected coincidental survivors before verification: 1.016

Found common x = 32768  [verified on curve]
```

Three things to read carefully:

* **Cost.** The algorithm builds one index per transaction and intersects, so
  the work is `Σ|Wᵢ|` — about 25.6 k here. The Cartesian product is printed
  only to make clear that it is *not* what happens.
* **`Expected coincidental survivors` = `Π|Wᵢ| / n^(T−1)`** for `T`
  transactions. When that number approaches 1, the intersection alone proves
  nothing. This particular demo bundle happens to leave no impostor, but over
  150 random 4-transaction bundles the unverified search returned **3.81
  impostors per bundle** alongside the true key (`docs/readme_measurements.py`,
  section 4). With the on-curve check the count is **0**. Choose bundles that
  keep this figure well below 1, and never trust `--no-verify` output.
* **`N` is an input.** It comes from `f = s_zk/a`, which is derived from the
  secret `s_zk`. The search narrows a window it was given; it does not discover
  the level.

`f` must be passed as `str`, `Fraction`, `Decimal` or `int`. `float` is refused
with an explanation: it holds ~16 significant digits, while the reports carry 20
(test) or 80 (legacy). A ratio within about 10⁻¹⁶ (relative) of an integer is
floored to the wrong level (`float("4.9999999999999999")` is `5.0`), and above
2⁵³ even the integer part is no longer exact.

`--max-window` (default 50,000,000) rejects windows too wide to enumerate; on
secp256k1 a level window is roughly the size of `a` itself. The CLI's only input
is the bundled secp17k1 demo, so `--curve-mode legacy` is refused with an error
and a non-zero exit status instead of running that bundle modulo the secp256k1
order.

---

## Tests

```bash
python3 src/tests/run_tests.py            # table
python3 src/tests/run_tests.py -k window  # filter by Class.method substring
python3 src/tests/run_tests.py -v         # full tracebacks on failure
python3 src/tests/run_tests.py --no-color
```

Exit status is 0 on success and 1 otherwise. The `Detail` column reports the
value each test actually measured rather than a column of "ok". Tests 1–25 keep
the numbers they had before 20 November 2026; tests 26–35 were added then
(full last run: `src/tests/run_tests.txt`):

```text
 #   | Test                                                                    | Status | Time     | Detail
-----+-------------------------------------------------------------------------+--------+----------+---------------------------------------------------------------
     | CURVE PARAMETERS AND PRIMITIVES                                         |        |          |
 1   |   Test curve is a real curve of prime order                             |  PASS  | 0.144s   | #E = n = 99667 prime, (n-1)G = -G, G on curve
 2   |   RFC 6979 nonce matches published secp256k1 vectors                    |  PASS  | 0.000s   | 3/3 published vectors
 3   |   RIPEMD-160 fallback matches the official test vectors                 |  PASS  | 0.001s   | 4/4 official vectors, multi-block included
 4   |   Signing verifies; an off-curve public key does not                    |  PASS  | 0.038s   | 2 curves OK, off-curve pubkey rejected
 5   |   SEC encoding follows the field size instead of a hardcoded 32         |  PASS  | 0.000s   | 3-byte field -> 4 B, 32-byte field -> 33 B
 6   |   Local modular square root replaces sympy on both moduli               |  PASS  | 0.107s   | 1232 values; Tonelli-Shanks: 52 QR, 48 non-QR
-----+-------------------------------------------------------------------------+--------+----------+---------------------------------------------------------------
     | KEY RECOVERY FROM PUBLIC DATA                                           |        |          |
 7   |   recover_x_from_s_zk round-trips; d passes the r-check, d+1 fails      |  PASS  | 0.594s   | 40 signatures, 0 mismatches, d+1 always rejected
 8   |   Case-B quadratic recovers a*m1 on both curves                         |  PASS  | 0.060s   | 100/100 roots contain the true s_zk
 9   |   Case-E split is integral exactly for S = 1 or 2 (mod 4)               |  PASS  | 0.074s   | 19999 values of S; integral iff S%4 in (1,2)
 10  |   Real case-A and case-E signatures yield a verified key                |  PASS  | 1.053s   | 368,448 scanned -> A x1, E x5, all verified
 11  |   Case E is detected for S = 1 (mod 4) as well as S = 2 (mod 4)         |  PASS  | 6.563s   | S%4=1 seen 1x, S%4=2 seen 1x, both recovered
 12  |   HYP-001 equals floor(a/w) == N - delta, and is stricter than {N, N-1} |  PASS  | 0.026s   | 20,000 triples: 0 deviations, fired 91 (0.46%), weak-only 127
 13  |   Case-B quadratic returns exactly {s_zk, s_rxk}, by Vieta              |  PASS  | 0.047s   | 100 quadratics, both roots are {s_zk, s_rxk}
 14  |   Per-class recovery counters sum to the reported aggregates            |  PASS  | 2.016s   | attempts 2 = A 0 + B 0 + E 2
-----+-------------------------------------------------------------------------+--------+----------+---------------------------------------------------------------
     | EXACT NUMERIC FORMATTING                                                |        |          |
 15  |   Ratio rendering is exact and never uses exponent form                 |  PASS  | 0.052s   | 5,000 ratios up to 1e80, 0 rounding errors
 16  |   float is refused; str and Fraction floors are exact                   |  PASS  | 0.000s   | float refused; 4.999...9 -> 4 (float would give 5)
-----+-------------------------------------------------------------------------+--------+----------+---------------------------------------------------------------
     | COMMON-X SEARCH                                                         |        |          |
 17  |   Every level window contains the s_zk it was built from                |  PASS  | 0.083s   | 800 windows, 0 misses
 18  |   Window size is arithmetic; len() would overflow ssize_t               |  PASS  | 0.000s   | span ~2^253, len() would raise OverflowError
 19  |   On-curve verification collapses the intersection to the true key      |  PASS  | 1.552s   | 25 runs: 0.56 impostors raw -> 0.00 verified
 20  |   A secp256k1-scale window is rejected, not attempted                   |  PASS  | 0.000s   | ValueError raised before any enumeration
-----+-------------------------------------------------------------------------+--------+----------+---------------------------------------------------------------
     | REPRODUCIBILITY AND REPORT OUTPUT                                       |        |          |
 21  |   An explicit rng fixes the keys, not just z and k                      |  PASS  | 0.083s   | 2 curves: keys+signatures replay, seed 78 differs, range OK
 22  |   A seeded legacy run replays its messages, not only its keys           |  PASS  | 0.178s   | p2pkh+p2wpkh: preimages and (z, r, s) replay; seed 92 differs
 23  |   Without an rng, keys still come from secrets rather than a seed       |  PASS  | 0.001s   | class and CLI default not explicit; 8-key draws differ
 24  |   Reports written in the same second get distinct filenames             |  PASS  | 0.001s   | 8 writes -> 8 distinct files, timestamp + 8-hex tag
-----+-------------------------------------------------------------------------+--------+----------+---------------------------------------------------------------
     | LEGACY TRANSACTION PREIMAGES                                            |        |          |
 25  |   Synthetic amounts never produce a negative or dust output             |  PASS  | 0.003s   | 2 sig types x 8 corner draws, min output 546 sat
-----+-------------------------------------------------------------------------+--------+----------+---------------------------------------------------------------
     | VERIFICATION AND PUBLIC-ONLY RECOVERY                                   |        |          |
 26  |   A valid signature with z = 0 (mod n) verifies                         |  PASS  | 0.144s   | 6 z=0 signatures accepted, z=1 variants rejected
 27  |   The twin key passes verify_x_candidate; only x*G == Q is decisive     |  PASS  | 0.399s   | 20 signatures: twin passes r-check, fails x*G == Q
 28  |   Case-E recovery needs only the class, not the secret E1/E2 label      |  PASS  | 0.028s   | E1 x32, E2 x28: recovered from (z, r, s) + class
-----+-------------------------------------------------------------------------+--------+----------+---------------------------------------------------------------
     | DIRECT CLASS CONSTRUCTION                                               |        |          |
 29  |   Constructed A/B/E rows verify against Q and recover exactly x         |  PASS  | 0.172s   | 45 rows: ECDSA-valid, label re-derived, key == [x]
 30  |   Constructed reports: constructed classes only, recovery measured      |  PASS  | 0.144s   | A/B/E 12 each, C=D=0; attempts 72, rejected 36
 31  |   secp256k1: A and E are built and recovered, B is refused              |  PASS  | 0.079s   | A, E recovered on secp256k1; B refused with reason
-----+-------------------------------------------------------------------------+--------+----------+---------------------------------------------------------------
     | COMMAND-LINE ENTRY POINTS AND PORTABILITY                               |        |          |
 32  |   All three scripts run from a flat folder, --tx-with-classes too       |  PASS  | 0.291s   | 3 scripts, flat folder: exit 0, 2 reports, self-check OK
 33  |   find_common_private_key --curve-mode legacy exits with an error       |  PASS  | 0.062s   | exit 1, refusal on stderr, no search run
 34  |   --demo runs one round and writes nothing                              |  PASS  | 0.066s   | signature validated, 0 files written
 35  |   rand_bytes works without Random.randbytes and replays seeded runs     |  PASS  | 0.000s   | seeded output == Random.randbytes on python 3.13
```

Independently confirmed by the suite: the test curve's group order equals `n`,
`n` is prime and `(n−1)·G = −G`; the RFC 6979 implementation reproduces the
published secp256k1 test vectors; the RIPEMD-160 fallback matches the official
vectors including a multi-block input; both branches of the modular square root
(including Tonelli–Shanks, which case-B recovery uses on secp256k1) return the
roots of residues and nothing for non-residues.

---

## Measured results

Case A and case E do recover a private key from public parameters alone, and
the public key confirms it. How often they fire is the load-bearing question.
On the test curve every rate can be computed **exactly** by exhaustive
enumeration (`docs/exact_class_counts.py`); the sampled runs agree with it:

| case | exact rate per signature | 10⁷ run (`…185543_337c7bed`) | archived 10⁸ run |
| :----- | :------------------------- | :----------------------------- | :----------------- |
| A | 2.5073·10⁻⁶ ≈ 1/(4(n−1)) (null model); 2.5071·10⁻⁶ with the real nonce map | 25 (25.1 expected) | 224 (250.7 expected) |
| E | 4/(3n) = 1.3378·10⁻⁵ (132,884 of the (n−1)² pairs) | 140 (133.8 expected) | 670 — earlier detector, see below |
| B (label) | 1.6709·10⁻¹⁰ (165,421 of (n−1)³) | 0 (0.0017 expected) | none sampled — see Known issue 1 |

The archived 10⁸ run is `data/transaction_list_20260809003013.txt`, removed from
the working tree in commit `aa5afa7`; retrieve it with
`git show aa5afa7^:data/transaction_list_20260809003013.txt`.

> ⚠️ The case-E figure of the archived run is the rate of the **earlier**
> detector, which required `S` to be even and therefore discarded the whole
> `S % 4 == 1` family. Every one of its 670 case-E rows has `S % 4 == 2`. The
> current detector finds both families (67 of the 140 E rows of the 10⁷ run have
> `S % 4 == 1`), so the rate is **twice** as high:
>
> ```text
> current detector:  4 / (3n) = 1.34·10⁻⁵    (1338 per 10⁸ on secp17k1)
> earlier detector:  2 / (3n) = 6.69·10⁻⁶    ( 669 per 10⁸ — matches the 670 above)
> ```
>
> Both figures are exact counts, not estimates: enumerating all `(n-1)²` pairs
> `(s_zk, s_rxk)` on the test curve gives 132,884 and 66,442 class-E hits
> respectively, split E1:E2 = 3:1 in both cases.

Cases A and E fire at about the rate of guessing `k^-1` at random — of order
`1/n`. The formulas do not find `s_zk`; they name one value (A) or a few values
(E) out of `n`, and occasionally one of them is the right one.

**Case B** is far rarer still: `Pr[B] = 165,421 / (n−1)³ = 1.67·10⁻¹⁰` per
signature (≈ 1.66/n²), i.e. 0.017 expected per 10⁸ signatures. The observations
agree: the sampled runs recorded none (the class-B row once present in the
archived 10⁸ file was constructed and appended afterwards — see
[Known issues](#known-issues-and-corrections), item 1), a 1.2·10⁹
Monte-Carlo of the same generator caught none (0.20 expected), and an earlier
run of 6,826,438,356 signatures caught one (1.14 expected).

The case-B *recovery formula* succeeds far more often than the case-B *label*:
about as often as case A — see [Known issues](#known-issues-and-corrections),
item 3.

The consequence for real secp256k1 is arithmetic, not opinion: the same events
occur with probability ≈ 2⁻²⁵⁶ per signature. Nothing here is a practical
attack on Bitcoin keys, and the code makes no attempt to be one — `legacy` mode
exists so the same algebra can be checked at full scale, and
`find_common_private_key.py` refuses to run there.

### HYP-001

The **hypothesis feature** was added to support further research and
hypothesis testing, so hypothesis HYP-001 is provided here as an example only.

HYP-001 is evaluated on case-D signatures only, and only when a **gate** holds:

```text
N > 1,   s > s_zk,   s_zk even            (otherwise the column shows "-")
```

Under the gate the case-D hypothesis reduces to a relation between the first two
partial quotients of the continued fraction of `s_zk/a`:

```text
N = floor(s_zk / a),  w = s_zk mod a,  t = a mod w
delta = 1 if ((N*t) mod w) + t >= w else 0

floor(a / w) == N - delta
```

The gate is part of the definition: without it the same identity fires on about
**8 %** of random triples. Evaluated with the gate on completely random,
independent `(s, s_zk, a)` triples (10⁶ per scale, `docs/readme_measurements.py`)
it fires at:

| modulus scale | 2¹⁷    | 2⁶⁴    | 2²⁵⁶   | 2⁵¹²   |
|:--------------|:-------|:-------|:-------|:-------|
| HYP-001 rate  | 0.51 % | 0.48 % | 0.50 % | 0.50 % |

Scale-invariant, because for independent uniform `s_zk` and `a` the law of the
ratio `s_zk/a` does not depend on the modulus. It is a property of that ratio,
not of ECDSA. The law of the second quotient is **not** Gauss–Kuzmin, as
earlier revisions of this file said: in the gated population
`P(floor(a/w) = 1) = 0.436`, against 0.415 under Gauss–Kuzmin.

Two cautions. First, the weaker condition `floor(a/w) ∈ { N, N-1 }` — which
earlier revisions of this file gave as the reduction — is *implied by* the
identity but does not imply it: `delta` fixes which of the two values must
occur. On the same gated triples the weaker condition holds about 2.2 times as
often as the identity (e.g. 1.081 % against 0.483 % at 2⁶⁴). Second, the
null-model rate is not the rate on the case-D population: in the 10⁷ run it is
30,083 / 2,493,200 = **1.21 %** (the archived 10⁸ run gave 300,744 / 24,929,792 =
1.21 %, reproduced to three digits by a 1.2·10⁹ Monte-Carlo), and in the legacy
100K run 277 / 25,124 = 1.10 %. The null model and the observed population are
not conditioned the same way; the earlier claim that 0.73 % and 0.90 % over
~1230 rows are "within noise of 0.50 %" does not survive a larger sample.

---

## Known limits

* `test`-mode `z` is not a hash of the message, so test-mode triples are not
  signatures a verifier would accept against a message.
* `legacy` mode signs with plain RFC 6979 — no low-S normalisation, no low-R
  grinding — so its signatures are not distributed like Bitcoin Core's
  ([The curves](#the-curves)).
* Cases C and D have no recovery formula of their own: `m1` is not a function
  of the public data. A signature labelled C or D can still be recovered by the
  case-B formula ([Known issues](#known-issues-and-corrections), item 3).
* Case B (the integrality label) has not been observed in the sampled 10⁷, 10⁸
  and 1.2·10⁹ runs, and once in an earlier 6.8·10⁹ run — as the exact rate
  predicts. Its quadratic is also validated synthetically in the test suite.
  `generate_found_classes.py` constructs the label directly only on the test curve,
  where nonces are enumerable — not on secp256k1.
* The two sampled reports under `data/` were produced by the generator as of
  commit `aa5afa7` (see [Statistics block](#statistics-block) for how it differs
  from the current one); the two constructed reports by the current code.
  Re-generate before quoting a recovery counter from the sampled ones.
* Level windows are only usable at toy scale.
* The classification is representative-dependent by construction. `s % 2`,
  `s_zr > s` and `m1 > 1` treat elements of ℤₙ as integers, and `n` is odd, so
  `s` and `s + n` are the same group element with different parity — case E
  relies on exactly this by choosing `S ∈ {s, s+n}`. Any statistic drawn from
  these tests describes the chosen integer representatives, not the group.

---

## Known issues and corrections

*Status: work in progress, 20 November 2026.* The paper (v2, August 2026) is a
preliminary report. The items below were found after it was published and will
be folded into the final report. Until then this section takes precedence over
the paper wherever they disagree. None of the items changes the scale statement
of this repository: every recovery is the event "the nonce equals one of at most
seven public values", with probability of order `1/n` — about 10⁻⁷⁷ per
signature on secp256k1.

### 1. The class-B row of the archived 10⁸ report was not observed in that run

Line 2909 of the archived `data/transaction_list_20260809003013.txt` (`z = 3481`,
`r = 33385`, `s = 1197`) was appended in commit `924f400`, together with
`src/utils/class_forge.py` (renamed `generate_found_classes.py` in `aa5afa7`).
The same commit changed `Case B Count` from 0 to 1 and `Total Observed Cases`
from 24,986,477 to 24,986,478, but left `Transactions With Valid A` (24,985,980)
and the recovery counters unchanged, so the file reports A + B + C + D =
24,985,981 signatures with a valid `a` against 24,985,980.

The row is an honest signature that verifies against its key, and it matches
the `generate_found_classes.py` family `(m, q) = (5, 4)` at `a = 133`: it is a
constructed test vector, not a sample. Earlier revisions of this README stated that
the archived run "caught exactly one" case-B signature, and the internal description
(`docs/ECDSA_coincidence_classes_internal.pdf`, §6.3, §7.2; removed in `aa5afa7`)
treats the row as a genuine observation. Both are wrong: the sampled run recorded
none, which is what the exact rate predicts — at 1.67·10⁻¹⁰ per signature, the
chance of at least one in 10⁸ is 1.7 %.

### 2. The on-curve confirmation check is not decisive

`verify_x_candidate` recomputes `k = (z + r*x̂) * s^-1` and tests
`(k*G).x mod n == r`. It accepts exactly the keys under which `(z, r, s)` is a
valid signature, and there are always at least two of them:

```text
x̃ = -x - 2*z*r^-1   (mod n)      # its nonce is n - k
```

A third or fourth key exists only when a curve point has x-coordinate `r + n`
(on secp17k1 that needs `r < p − n = 336`). The twin `x̃` passes the check on
every row of the current reports — 5,165 test-curve rows and 3,000 legacy rows.
The paper's statement (§2) that the check "accepts the true key and rejects
everything else" is therefore incorrect.

Impact on the reported results: none. Within cases A, B and E the formulas never
propose `−s_zk`. A public scan that tries every formula on every signature is
different: candidates equal to `−s_zk` occur as often as candidates equal to
`s_zk` (in 2·10⁸ simulated signatures the case-A formula produced 490 twins
against 498 true keys), so about half of the keys accepted by this check alone
would be wrong. The decisive public test is `x̂*G == Q` against the signer's
public key `Q`. Since 20 November 2026 the generator and the constructor use
exactly that test (`Secp256k1.matches_public_key`), and test 27 documents that the
twin passes `verify_x_candidate` but fails `x̂*G == Q`.

### 3. The constructive separation holds for the case-B label, not for the case-B formula

The label B requires integrality (`m1 == m2`, both integers), which pins
`P = k*r mod n` to a fixed rational — that part of the paper (§5) stands. But the
case-B recovery formula (`_guesses_case_b`) succeeds on a much weaker event:
`s_zk` is a root of `σ² − s*σ + a*(s + s_zr) ≡ 0 (mod n)` if and only if

```text
s_zk * s_rxk ≡ a * (s + s_zr)   (mod n)
```

This event

* **occurs by chance as often as case A.** Exhaustive enumeration on secp17k1
  gives 2,482,066,537 of the `(n−1)³` configurations, i.e. 2.51·10⁻⁶ ≈ `1/(4n)`
  per signature — 15,005 times the rate of the label
  (`docs/exact_class_counts.py`). In 2·10⁸ simulated generator signatures it
  occurred 480 times; 479 of them carry the label D and one the label C.
* **is constructible on real secp256k1 without steering `P`.** Fix `k` and
  `s_zk` (hence `s_zr = s_zk*P`). On the range where `floor(s / (s_zr − s)) = q`
  the auxiliary value is `a = (q+1)*s − q*s_zr`, so the event becomes a quadratic
  congruence in `s`:

  ```text
  (q+1)*s² + (s_zr − s_zk)*s + (s_zk² − q*s_zr²) ≡ 0   (mod n)
  ```

  For `q = 1, 2, …` solve it, keep a root that lies in that range, and set
  `z = s_zk*k`, `x = (s − s_zk)*k*r^-1`. It takes about 4.5 nonce trials per
  signature (`docs/readme_measurements.py`, section 2). On every signature built
  this way the repository's own `_guesses_case_b` recovers the key and the public
  key confirms it: 200 of 200 on secp17k1 and 20 of 20 on secp256k1, all labelled
  D by the classifier. As with `generate_found_classes.py`, `z` is chosen, so this
  is a statement about what a signer can do with their own key, not an attack.

Consequences for the paper: the statements that class B is not signer-forgeable
(abstract, §5, Table 5), that it "passes" the expensive-to-produce test and "is
precisely the class that never occurs at all" (§6), and that it is "out of
reach" (§9) hold only for the integrality label, which cannot be computed from
public data. For the formula a scanner would actually run, case B is as cheap
to manufacture as cases A and E; the preimage method named in §7.5 is not needed
for this. The negative result and the defensive recommendation are not weakened
— they now apply to all three formulas: none of them is a usable indicator of a
weak key.

### 4. Exact class-B rate

Exhaustive enumeration on secp17k1 gives 165,421 class-B configurations,
`Pr[B] = 1.67·10⁻¹⁰` per signature (≈ 1.66/n²; `docs/exact_class_counts.py`).
It replaces the paper's estimate of about 5·10⁻¹⁰ (§4.3, Table 4); the exact
value lies inside the 95 % interval the paper gives for that estimate.

### 5. Recovery totals of the archived 10⁸ report

Re-running recovery over the 2,895 rows of the archived report gives 1,566
attempts, 895 verified and 671 rejected (A 224/224, B 2/1, E 1,340/670). Earlier
revisions of this README, and the internal description (§5.10, §7.2), gave 896
verified and 670 rejected. The file itself prints 1,564 attempts and 894
verified (`224 + 2*670` and `224 + 670`): its class-B row was appended after the
run, so that row's two attempts and one verification were never counted.

### 6. Generator default and documentation paths

The default of `--min-start-range` is 100, not 1000 as previously documented.
The archived 10⁸ run used 100 (its smallest `z` is 143 and smallest `k` 147); an
earlier 5K run used 1000. The regression suite lives in `src/tests/` and now has
35 checks; earlier revisions of this README pointed to `tests/` and quoted 21,
23 and 25.

### 7. Code corrections of 20 November 2026

Found by an audit of the repository; each item is covered by a test:

* **Python 3.8.** Legacy mode called `random.Random.randbytes` (3.9+) and crashed
  on 3.8, the documented minimum; it now uses `rand_bytes`, which returns the same
  bytes for a seeded run (test 35).
* **Flat layout.** The fallback import of the class constructor repeated the
  package import, so `--tx-with-classes` failed with `No module named 'utils'`
  in a flat folder (test 32).
* **Common-key search on secp256k1.** `--curve-mode legacy` ran the toy demo
  modulo the secp256k1 order and printed "No common x found … MISMATCH" with exit
  status 0; it is now refused with an error (test 33).
* **Constructed reports.** Their recovery statistics were constants
  (attempts = rows, rejected = 0, every per-class line 0); they are now measured,
  with each row counted once under its constructed class (test 30). The preamble
  now names only the classes actually constructed.
* **Verification.** `verify_signature` rejected every valid signature with
  `z ≡ 0 (mod n)` (test 26). Keys are confirmed with `x̂*G == Q` (item 2).
* **Case-E recovery** no longer uses the secret E1/E2 sub-label; it tries both
  admissible `S` (test 28).
* **`--demo`** ran a full 5,000-key collection after the demo and wrote a report;
  it now stops after the demo (test 34).
* **Ranges.** `z` and `k` were drawn with `randrange(…, n − 1)`, which never
  returns `n − 1`; they are now uniform on `[min_start_range, n − 1]`.
* **Randomness.** Without `--seed` the CLI passed `SystemRandom()` explicitly, so
  keys did not come from `secrets` as documented (test 23).
* **Tests.** Test 1 asserted `scalar_multiply(n, G) is None`, which holds for any
  `n` because of a short-circuit; it now checks primality of `n` and
  `(n−1)·G = −G`. The Tonelli–Shanks part of test 6 passed even if the branch
  returned nothing; it now requires both roots of every residue.

### 8. `docs/null_model_experiment.py` used the same seed for both samples

The "real" and "null" samples were drawn from the same seed, so the null sample
was built from the very random numbers of the real one (null `s_zk` = real `k`,
null `s_rxk` = real `z`, null `P` = real `x`). The two-sample Poisson z-test it
prints assumes independent samples. The script now uses independent child seeds;
the conclusion is unchanged — no significant real-vs-null difference
(`docs/null_model_experiment.txt`; case A: real 258, null 226, z = +1.45). The
figures in the paper come from the earlier version (git: `aa5afa7`). The script
also ran only from inside `docs/`; it now runs from any directory.

### 9. Corrections to the HYP-001 description

Earlier revisions of this README gave HYP-001 without its gate (`N > 1`,
`s > s_zk`, `s_zk` even), which the code has always applied; without the gate the
identity fires on about 8 %, not 0.5 %, of random triples. They also quoted
"380 firings against 912 for the weak condition over 3·10⁵ random triples"
(0.13 %), which does not match the 0.5 % rate and whose sampling was not stated;
it is replaced by reproducible figures. The law of the second quotient was
called Gauss–Kuzmin; it is not (see [HYP-001](#hyp-001)).

---

## Prior publications

Earlier write-ups of classes A and B. **Superseded by the assessment above: their
"vulnerability" framing is no longer endorsed by the author.** Kept for the record.

```text
https://doi.org/10.21203/rs.3.rs-6790872/v1
```

---

## Current publications

Algebraic Coincidence Classes in ECDSA: Chance-Rate Occurrence and a Constructive
Separation (v2, August 2026 — preliminary; read together with
[Known issues and corrections](#known-issues-and-corrections))

```text
https://doi.org/10.6084/m9.figshare.33235473
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
  Algorithm with Partially Known Nonces* — Designs, Codes and Cryptography 30(2),
  2003.
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
