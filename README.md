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
the private key and proves the recovery against the signer's public key.

---

## Repository layout

```text
ECDSA-Research/
├── data/                                              # generated reports (committed; see "Data files")
│   ├── transaction_list_20261120210827_1b96a014.txt   # test curve   (3K   tx constructed; A,B,_,_,E cases)
│   ├── transaction_list_20261120211000_0d254a9b.txt   # legacy curve (2K   tx constructed; A,_,_,_,E cases)
│   ├── transaction_list_20261120214204_d7286821.txt   # test curve   (10M  tx sampled;     A,_,C,D,E cases)
│   └── transaction_list_20261120215029_8ce2f082.txt   # legacy curve (100K tx sampled;     _,_,_,D,_ cases)
├── docs/
│   ├── ECDSA_coincidence_classes.pdf                  # see "Current publications"
│   ├── ECDSA_coincidence_classes_extended.pdf         # see "Current publications"
│   ├── null_model_experiment.py, .txt                 # class census, real vs null model; output
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
each other (checked by test 33).

### Data files

Every report in `data/` was written by `generate_transactions.py` with:

| file | curve | arguments |
| --- | --- | --- |
| `…210827_1b96a014` | test | `--tx-with-classes A B E --output-count 1000 --seed 20261120` (3,000 constructed signatures) |
| `…211000_0d254a9b` | legacy | the same plus `--curve-mode legacy` (2,000 constructed signatures; class B is skipped) |
| `…214204_d7286821` | test | `--keys 5000 --tx-per-key 2000 --seed 20261120` (10⁷ sampled signatures) |
| `…215029_8ce2f082` | legacy | `--curve-mode legacy --keys 5000 --tx-per-key 20 --seed 20261120` (10⁵ sampled signatures) |

With `--seed` a run replays its rows and its counts exactly; only the file name
(time stamp and random tag) and `Spent time` differ.

---

## Requirements

Python **3.8 or newer**. Everything under `src/` is standard library only — no
`pip install` step. The suite passes on 3.8.20, 3.9.25 and 3.13.

`docs/null_model_experiment.py` and `docs/exact_class_counts.py` need **numpy**;
`docs/readme_measurements.py` is standard library only.

`pow(x, -1, m)` sets the 3.8 floor.

---

## Quick start

```bash
git clone <this-repo> && cd ECDSA-Research

python3 src/tests/run_tests.py                   # 41 checks, tabular output
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
nonce until `r < 2²⁵⁵`. `legacy` mode does neither: of the 1000 rows printed in
`data/transaction_list_20261120215029_8ce2f082.txt`, 519 are high-S, 509 high-R,
and only 229 have the shape Bitcoin Core would emit. Because the
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

Every signature gets **at most one** class. Case E is tested first; otherwise
the signature is A, B, C or D when `a` is valid (`s_zr > s` and `0 < a ≠ s`);
otherwise it is **unclassified**. Within A–D, case A is decided on `m1` alone,
so `s_zk == a` is case A even when `m2` is integral too. Case E carries the
sub-label E1 (`S = s`) or E2 (`S = s + n`).

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
besides the true one ([The twin key](#the-twin-key)). A candidate that fails is
counted under `Recovery Rejected` and never reported as a key.

Cases C and D have no formula of their own and yield nothing when recovery is
run by class. A signature labelled C or D can still be recovered by the case-B
formula ([The case-B formula event](#the-case-b-formula-event)).

### Case E naming

The case-E detector is `_detect_half_difference_split`: it tests whether the
additive split of `S` has difference exactly `S//2 + 1`.

### The twin key

`verify_x_candidate` accepts exactly the keys under which `(z, r, s)` is a valid
signature, and there are always at least two of them:

```text
x̃ = -x - 2*z*r^-1   (mod n)      # its nonce is n - k
```

A third or fourth key exists only when a curve point has x-coordinate `r + n`
(on secp17k1 that needs `r < p − n = 336`). The twin passes
`verify_x_candidate` on every row of the reports in `data/` (8,157 rows).

In cases A and B the guesses are the true parts themselves (`a = s_zk`; the two
roots are `{s_zk, s_rxk}` by Vieta), and every candidate must pass `x̂*G == Q`,
so the twin never appears in a report. A public scan that tries every formula
on every signature is different: for every `(s, s_zr)` with a valid `a`, the
configuration `s_zk = a` yields the true key and `s_zk = n − a` yields the twin,
and under the uniform model both are equally likely — so about half of the keys
accepted by `verify_x_candidate` alone would be wrong. The decisive public test
is `x̂*G == Q` (`Secp256k1.matches_public_key`); test 28 shows the twin passing
`verify_x_candidate` and failing `x̂*G == Q`.

---

## `generate_transactions.py`

Generates signatures, classifies them, and writes a fixed-width report to
`data/transaction_list_<timestamp>_<tag>.txt`; the random `<tag>` keeps reports
written within the same second apart.

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
| `--d-case-digit N` | -1 | print only this case-D level (-1 = all); rows of other classes and levels are not printed, and `Hypothesis 001 Count` counts only this level (class counts stay run-wide) |
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
shift the table. Unclassified signatures are counted but not printed.

### Statistics block

```text
Total Key Count: 5000
Transaction Limit Per Key: 2000
Total Transaction Count: 10000000
Signature Space Per Key: 9.913587e+09
Signature Space All Keys: 9.870662e+14
Total Observed Cases: 2499947
Case A Count: 27
Case B Count: 0
Case C Count: 5547
Case D Count: 2494243
Case E Count: 130
Unclassified Count: 7500053
Hypothesis 001 Count: 29874
Recovery Attempts: 357
Recovery Verified: 157
Recovery Rejected: 200
Recovery Attempts A: 27
Recovery Attempts B: 0
Recovery Attempts E: 330
Recovery Verified A: 27
Recovery Verified B: 0
Recovery Verified E: 130
Case D0 Count: 175082
...
```

The figures are those of `data/transaction_list_20261120214204_d7286821.txt`
(5,000 keys × 2,000 signatures).

#### Signature space

`Signature Space Per Key` and `Signature Space All Keys` give the size of the
space the generator draws its signatures from. They describe the generator,
not the run: `--keys`, `--private-key` and `--tx-per-key` do not enter them.
For a key `x` the generator picks a message hash `z` and a nonce `k`; the pair
fixes the row's triple `(z, r, s)`, and the triple gives the nonce back as
`k = s⁻¹·(z + r·x)`, so every choice is a different signature. One formula
serves both curves:

```text
Signature Space Per Key  = Nz · Nk
Signature Space All Keys = Nx · Nz · Nk

Nx   keys the generator can draw
Nz   message hashes it can sign
Nk   nonces it can pair with one (key, hash)
```

The sizes are the signer's own domains, with `m = --min-start-range`:

| | `test` (secp17k1) | `legacy` (secp256k1) |
| --- | --- | --- |
| Nx | keys on `[m, n−1]` → `n − m` | keys on `[m, n−1]` → `n − m` |
| Nz | `z` uniform on `[m, n−1]` → `n − m` | `z = dSHA256(preimage) mod n` → `n` |
| Nk | `k` uniform on `[m, n−1]`, independent of `z` → `n − m` | RFC 6979, `k = f(x, z)` → `1` |
| Per Key | `(n − m)²` = 9.913587e+09 | `n` = 1.157921e+77 |
| All Keys | `(n − m)³` = 9.870662e+14 | `(n − m)·n` = 1.340781e+154 |

The figures are for the default `m = 100`. The closed forms differ because the
nonce rule differs, not the curve: an RFC 6979 signer on secp17k1 would give
`n`, and a random-nonce signer on secp256k1 `(n − m)²`.

* **What is counted.** A signature is the triple `(z, r, s)` of a report row,
  not the bare pair `(r, s)`: for one key, `(k, z)` and `(n − k, −z − 2·r·x)`
  give the same `(r, s)`. `All Keys` counts (key, triple) pairs; in `test` mode
  the [twin key](#the-twin-key) emits the same triple with nonce `n − k`, and
  it is counted once per key.
* **Exactness.** In `legacy` mode every `z` yields exactly one signature
  (RFC 6979 moves to its next candidate when `r` or `s` would be 0), so `n` is
  exact. In `test` mode a draw with `r = 0` or `s = 0` is redrawn, so a key
  emits slightly fewer distinct triples than `Nz · Nk`: on secp17k1 two nonces
  have `r = 0` (their point has `x = n`, and `n < p`) and about one nonce per
  `z` gives `s = 0` — 3.0·10⁻⁵ of the domain, visible from the fifth
  significant digit (test 39).
* **Not the configuration counts.** The `(n−1)²` and `(n−1)³` of
  [Measured results](#measured-results) count configurations of the uniform
  model over `[1, n−1]` (`docs/exact_class_counts.py`), not the generator.

Every signature is counted exactly once — in one class or as unclassified — so
the counts add up:

```text
A + B + C + D + E                         = Total Observed Cases
27 + 0 + 5,547 + 2,494,243 + 130          = 2,499,947

Total Observed Cases + Unclassified Count = Total Transaction Count
2,499,947 + 7,500,053                     = 10,000,000
```

The `Case D<N> Count` lines split `Case D Count` by the level
`N = floor(s_zk / a)` and add up to it. `Hypothesis 001 Count` counts case-D
signatures on which [HYP-001](#hyp-001) holds; with `--d-case-digit N` it
counts only level `N`, so it equals the number of `HYP-001` marks in the rows
unless `--output-count` truncated them. Because the gate requires `N > 1`,
levels D0 and D1 are never flagged.

Recovery runs the formula of the signature's class: 1 attempt per A signature,
1–2 per B, 2–4 per E (here 330 attempts for 130 E signatures). C, D and
unclassified signatures cost none. The aggregate lines are the sums of the
per-class lines: `Recovery Attempts` = 27 + 0 + 330 = 357,
`Recovery Verified` = 27 + 0 + 130 = 157, and `Recovery Rejected` = 357 − 157 =
200 — every candidate that is not the signer's key (here the second part of the
true split and both parts of the other admissible `S`). Because `x̂*G == Q`
accepts only the signer's key, a signature yields at most one verified key, and
every A, B and E signature is recovered: `Recovery Verified X` equals
`Case X Count` for X = A, B, E.

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

### How it works

The construction is honest ECDSA. Choosing a nonce `k` (hence `r`) and the two
additive parts `(s_zk, s_rxk)` fixes everything else exactly:

```text
z = s_zk * k          mod n
x = s_rxk * k * r^-1  mod n
s = s_zk + s_rxk      mod n
```

Every emitted row is checked twice, independently, before it is returned:
`verify_signature` runs standard ECDSA verification against `Q = x*G`, and the
report's own recovery re-derives the key from the public `(z, r, s)` and
accepts it only if `x̂*G == Q`. The row's label is computed by the report's own
classifier.

In a constructed report every row is counted once, under the class it was
constructed for, so `Case C Count`, `Case D Count`, `Unclassified Count` and
`Hypothesis 001 Count` are 0 by design. The recovery lines are measured, not
assumed: each A row costs 1 attempt, each B row 2 (both roots of the quadratic;
1 if they coincide) and each E row 2–4 (both parts of both admissible `S`), and
every candidate that is not the signer's key shows up under `Recovery Rejected`.

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
can be constructed on real secp256k1 as well
([The case-B formula event](#the-case-b-formula-event)).

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
2⁵³ even the integer part is not exact.

`--max-window` (default 50,000,000) rejects windows too wide to enumerate; on
secp256k1 a level window is roughly the size of `a` itself. The CLI's only input
is the bundled secp17k1 demo, so `--curve-mode legacy` is refused with an error
and a non-zero exit status.

---

## Tests

```bash
python3 src/tests/run_tests.py            # table
python3 src/tests/run_tests.py -k window  # filter by Class.method substring
python3 src/tests/run_tests.py -v         # full tracebacks on failure
python3 src/tests/run_tests.py --no-color
```

Exit status is 0 on success and 1 otherwise. The `Detail` column reports the
value each test actually measured rather than a column of "ok" (full last run:
`src/tests/run_tests.txt`):

```text
 #   | Test                                                                    | Status | Time     | Detail
-----+-------------------------------------------------------------------------+--------+----------+----------------------------------------------------------------
     | CURVE PARAMETERS AND PRIMITIVES                                         |        |          |
 1   |   Test curve is a real curve of prime order                             |  PASS  | 0.107s   | #E = n = 99667 prime, (n-1)G = -G, G on curve
 2   |   RFC 6979 nonce matches published secp256k1 vectors                    |  PASS  | 0.000s   | 3/3 published vectors
 3   |   RIPEMD-160 fallback matches the official test vectors                 |  PASS  | 0.001s   | 4/4 official vectors, multi-block included
 4   |   Signing verifies; an off-curve public key does not                    |  PASS  | 0.029s   | 2 curves OK, off-curve pubkey rejected
 5   |   SEC encoding length follows the curve's field size                    |  PASS  | 0.000s   | 3-byte field -> 4 B, 32-byte field -> 33 B
 6   |   Modular square roots: all roots of a residue, none otherwise          |  PASS  | 0.078s   | 1232 values; Tonelli-Shanks: 52 QR, 48 non-QR
-----+-------------------------------------------------------------------------+--------+----------+----------------------------------------------------------------
     | KEY RECOVERY FROM PUBLIC DATA                                           |        |          |
 7   |   recover_x_from_s_zk round-trips; d passes the r-check, d+1 fails      |  PASS  | 0.472s   | 40 signatures, 0 mismatches, d+1 always rejected
 8   |   Case-B quadratic recovers a*m1 on both curves                         |  PASS  | 0.046s   | 100/100 roots contain the true s_zk
 9   |   Case-E split is integral exactly for S = 1 or 2 (mod 4)               |  PASS  | 0.041s   | 19999 values of S; integral iff S%4 in (1,2)
 10  |   Real case-A and case-E signatures yield a verified key                |  PASS  | 0.934s   | 368,448 scanned -> A x1, E x5, all verified
 11  |   Case E is detected for S = 1 (mod 4) as well as S = 2 (mod 4)         |  PASS  | 6.412s   | S%4=1 seen 1x, S%4=2 seen 1x, both recovered
 12  |   HYP-001 equals floor(a/w) == N - delta, and is stricter than {N, N-1} |  PASS  | 0.026s   | 20,000 triples: 0 deviations, fired 91 (0.46%), weak-only 127
 13  |   Case-B quadratic returns exactly {s_zk, s_rxk}, by Vieta              |  PASS  | 0.047s   | 100 quadratics, both roots are {s_zk, s_rxk}
 14  |   Classes partition the run; recovery counters add up per class         |  PASS  | 1.974s   | 60,000 = 15,016 classified + 44,984 unclassified; verified 1
 15  |   --d-case-digit prints one D level; HYP-001 count = marked rows        |  PASS  | 3.143s   | HYP-001/rows D0:0/347, D1:0/371, D2:38/318, D3:11/378; all le~
-----+-------------------------------------------------------------------------+--------+----------+----------------------------------------------------------------
     | EXACT NUMERIC FORMATTING                                                |        |          |
 16  |   Ratio rendering is exact and never uses exponent form                 |  PASS  | 0.049s   | 5,000 ratios up to 1e80, 0 rounding errors
 17  |   float is refused; str and Fraction floors are exact                   |  PASS  | 0.000s   | float refused; 4.999...9 -> 4 (float would give 5)
-----+-------------------------------------------------------------------------+--------+----------+----------------------------------------------------------------
     | COMMON-X SEARCH                                                         |        |          |
 18  |   Every level window contains the s_zk it was built from                |  PASS  | 0.081s   | 800 windows, 0 misses
 19  |   Window size is arithmetic; len() would overflow ssize_t               |  PASS  | 0.000s   | span ~2^253, len() would raise OverflowError
 20  |   On-curve verification collapses the intersection to the true key      |  PASS  | 1.397s   | 25 runs: 0.56 impostors raw -> 0.00 verified
 21  |   A secp256k1-scale window is rejected, not attempted                   |  PASS  | 0.000s   | ValueError raised before any enumeration
-----+-------------------------------------------------------------------------+--------+----------+----------------------------------------------------------------
     | REPRODUCIBILITY AND REPORT OUTPUT                                       |        |          |
 22  |   An explicit rng fixes the keys, not just z and k                      |  PASS  | 0.090s   | 2 curves: keys+signatures replay, seed 78 differs, range OK
 23  |   A seeded legacy run replays its messages, not only its keys           |  PASS  | 0.185s   | p2pkh+p2wpkh: preimages and (z, r, s) replay; seed 92 differs
 24  |   Without an rng, keys still come from secrets rather than a seed       |  PASS  | 0.001s   | class and CLI default not explicit; 8-key draws differ
 25  |   Reports written in the same second get distinct filenames             |  PASS  | 0.001s   | 8 writes -> 8 distinct files, timestamp + 8-hex tag
-----+-------------------------------------------------------------------------+--------+----------+----------------------------------------------------------------
     | LEGACY TRANSACTION PREIMAGES                                            |        |          |
 26  |   Synthetic amounts never produce a negative or dust output             |  PASS  | 0.002s   | 2 sig types x 8 corner draws, min output 546 sat
-----+-------------------------------------------------------------------------+--------+----------+----------------------------------------------------------------
     | VERIFICATION AND PUBLIC-ONLY RECOVERY                                   |        |          |
 27  |   A valid signature with z = 0 (mod n) verifies                         |  PASS  | 0.142s   | 6 z=0 signatures accepted, z=1 variants rejected
 28  |   The twin key passes verify_x_candidate; only x*G == Q is decisive     |  PASS  | 0.398s   | 20 signatures: twin passes r-check, fails x*G == Q
 29  |   Case-E recovery needs only the class, not the secret E1/E2 label      |  PASS  | 0.032s   | E1 x32, E2 x28: recovered from (z, r, s) + class
-----+-------------------------------------------------------------------------+--------+----------+----------------------------------------------------------------
     | DIRECT CLASS CONSTRUCTION                                               |        |          |
 30  |   Constructed A/B/E rows verify against Q and recover exactly x         |  PASS  | 0.161s   | 45 rows: ECDSA-valid, label re-derived, key == [x]
 31  |   Constructed reports: constructed classes only, recovery measured      |  PASS  | 0.162s   | A/B/E 12 each, C=D=0; attempts 72, rejected 36
 32  |   secp256k1: A and E are built and recovered, B is refused              |  PASS  | 0.092s   | A, E recovered on secp256k1; B refused with reason
-----+-------------------------------------------------------------------------+--------+----------+----------------------------------------------------------------
     | COMMAND-LINE ENTRY POINTS AND PORTABILITY                               |        |          |
 33  |   All three scripts run from a flat folder, --tx-with-classes too       |  PASS  | 0.245s   | 3 scripts, flat folder: exit 0, 2 reports, self-check OK
 34  |   find_common_private_key --curve-mode legacy exits with an error       |  PASS  | 0.065s   | exit 1, refusal on stderr, no search run
 35  |   --demo runs one round and writes nothing                              |  PASS  | 0.071s   | signature validated, 0 files written
 36  |   rand_bytes works without Random.randbytes and replays seeded runs     |  PASS  | 0.000s   | seeded output == Random.randbytes on python 3.13
-----+-------------------------------------------------------------------------+--------+----------+----------------------------------------------------------------
     | SIGNATURE SPACE IN THE STATISTICS BLOCK                                 |        |          |
 37  |   Signature space: one formula on both curves, exact formatting         |  PASS  | 0.004s   | test (n-m)^2 / (n-m)^3, legacy n / (n-m)*n; e+09 .. e+400
 38  |   Test curve: the signer draws exactly the counted (z, k) domain        |  PASS  | 0.539s   | m = n-30: 899 of 900 (z, k) emitted, 1 with s = 0
 39  |   Test curve: r = 0 / s = 0 redraws remove ~3.0e-5 of the domain        |  PASS  | 0.130s   | r=0: 2 nonces, s=0: 99,465 pairs -> 3.01e-05 of Nz*Nk
 40  |   secp256k1: one nonce per hash, so the space per key is n              |  PASS  | 0.082s   | same (x, z) -> same k under 2 rngs and 2 floors; per key = n
 41  |   Report: Signature Space lines follow the formula, not --keys          |  PASS  | 0.108s   | 2 curves x 3 runs (keys, tx per key, fixed key): same lines
```

Independently confirmed by the suite: the test curve's group order equals `n`,
`n` is prime and `(n−1)·G = −G`; the RFC 6979 implementation reproduces the
published secp256k1 test vectors; the RIPEMD-160 fallback matches the official
vectors including a multi-block input; both branches of the modular square root
(including Tonelli–Shanks, which case-B recovery uses on secp256k1) return the
roots of residues and nothing for non-residues; and the two `Signature Space`
lines equal the domain the signer actually draws from on both curves — on
secp17k1 by exhausting a reduced domain, on secp256k1 by the RFC 6979 nonce
being fixed by `(x, z)` (tests 37–41).

---

## Measured results

Case A and case E do recover a private key from public parameters alone, and
the public key confirms it. How often they fire is the load-bearing question.
On the test curve every rate can be computed **exactly** by exhaustive
enumeration (`docs/exact_class_counts.py`); the 10⁷ sampled run agrees with it:

| case | exact rate per signature | 10⁷ run (`…214204_d7286821`) |
| :----- | :------------------------- | :----------------------------- |
| A | 2.5073·10⁻⁶ ≈ 1/(4(n−1)) (null model); 2.5071·10⁻⁶ with the real nonce map | 27 (25.1 expected) |
| E | 4/(3n) = 1.3378·10⁻⁵ (132,884 of the (n−1)² pairs) | 130 (133.8 expected) |
| B (label) | 1.6709·10⁻¹⁰ (165,421 of (n−1)³) | 0 (0.0017 expected) |

Case E has two families, `S % 4 == 1` and `S % 4 == 2`, of exactly equal size
(66,442 pairs each); the 130 E rows of the 10⁷ run split 65:65 between them.
The sub-labels split E1:E2 = 99,664:33,220, i.e. 3:1 up to four pairs; the
run has 96:34.

Cases A and E fire at about the rate of guessing `k^-1` at random — of order
`1/n`. The formulas do not find `s_zk`; they name one value (A) or a few values
(E) out of `n`, and occasionally one of them is the right one.

**Case B** is far rarer still: `Pr[B] = 165,421 / (n−1)³ = 1.67·10⁻¹⁰` per
signature (≈ 1.66/n²), i.e. 0.0017 expected in the 10⁷ run, which recorded none.

**Real vs. null model.** `docs/null_model_experiment.py` labels 10⁸ signatures
of the real generator model (`r` taken from the actual nonce map) and 10⁸ tuples
of the uniform null model with the same exclusive classes. No class differs
significantly: the largest deviation is case A, 258 against 226 (z = +1.45;
`docs/null_model_experiment.txt`).

Every recovery here is the event "the nonce equals one of at most seven public
values" (one guess for A, two for B, four for E), with probability of order
`1/n`. The consequence for real secp256k1 is arithmetic, not opinion: the same
events occur with probability ≈ 2⁻²⁵⁶ per signature. Nothing here is a practical
attack on Bitcoin keys, and the code makes no attempt to be one — `legacy` mode
exists so the same algebra can be checked at full scale, and
`find_common_private_key.py` refuses to run there.

### The case-B formula event

The label B requires integrality (`m1 == m2`, both integers), which pins
`P = k*r mod n` to a fixed rational ([What cannot be steered](#what-cannot-be-steered)).
The case-B recovery formula (`_guesses_case_b`) succeeds on a much weaker event:
`s_zk` is a root of `σ² − s*σ + a*(s + s_zr) ≡ 0 (mod n)` if and only if

```text
s_zk * s_rxk ≡ a * (s + s_zr)   (mod n)
```

This event

* **occurs by chance as often as case A.** Exhaustive enumeration on secp17k1
  gives 2,482,066,537 of the `(n−1)³` configurations, i.e. 2.51·10⁻⁶ ≈ `1/(4n)`
  per signature — 15,005 times the rate of the label
  (`docs/exact_class_counts.py`).
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

So the B formula, like the A and E formulas, fires at chance rate, and none of
the three is a usable indicator of a weak key.

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
not of ECDSA. The law of the second quotient is **not** Gauss–Kuzmin: in the
gated population `P(floor(a/w) = 1) = 0.436`, against 0.415 under Gauss–Kuzmin.

Two cautions. First, the weaker condition `floor(a/w) ∈ { N, N-1 }` is
*implied by* the identity but does not imply it: `delta` fixes which of the two
values must occur. On the same gated triples the weaker condition holds about
2.2 times as often as the identity (e.g. 1.081 % against 0.483 % at 2⁶⁴).
Second, the null-model rate is not the rate on the case-D population: in the
10⁷ run it is 29,874 / 2,494,243 = **1.20 %**, and in the legacy 10⁵ run
327 / 24,874 = **1.31 %**. The null model and the observed population are not
conditioned the same way.

---

## Known limits

* `test`-mode `z` is not a hash of the message, so test-mode triples are not
  signatures a verifier would accept against a message.
* `legacy` mode signs with plain RFC 6979 — no low-S normalisation, no low-R
  grinding — so its signatures are not distributed like Bitcoin Core's
  ([The curves](#the-curves)).
* Cases C and D have no recovery formula of their own: `m1` is not a function
  of the public data. A signature labelled C or D can still be recovered by the
  case-B formula ([The case-B formula event](#the-case-b-formula-event)).
* Case B (the integrality label) is not observed in the sampled 10⁷ run, as the
  exact rate predicts (0.0017 expected). Its quadratic is validated synthetically
  in the test suite, and `generate_found_classes.py` constructs the label
  directly only on the test curve, where nonces are enumerable — not on
  secp256k1.
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
https://doi.org/10.21203/rs.3.rs-6790872/v1
```

---

## Current publications

Algebraic Coincidence Classes in ECDSA: Chance-Rate Occurrence and a Constructive
Separation

```text
https://doi.org/10.6084/m9.figshare.33235473
```

On the Public-Actionability of Algebraic Coincidences in ECDSA Signatures

```text
https://doi.org/10.6084/m9.figshare.35124685
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
