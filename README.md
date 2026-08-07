# ECDSA Research: Coincidence Classes in the ECDSA State Space

**A negative result.** This repository documents an investigation into recurring algebraic
coincidences in ECDSA signatures generated under ideal, uniformly-random nonces — and the
theorem that proves the whole family of them cannot carry information.

📄 **Paper:** [`docs/Coincidence_Classes_ECDSA_Zero_Yield.pdf`](docs/Coincidence_Classes_ECDSA_Zero_Yield.pdf)
 · Andriy Polishchuk, CRYPTON Systems Lab, August 2026

> ⚠️ **NOTICE:** This is **not** a vulnerability disclosure. It describes no attack, no
> partial attack, and no weakening of any deployed parameter set. It does not threaten
> secp256k1 or any system that uses it, and it does not claim to. The main theorem proves
> that the techniques catalogued here cannot outperform exhaustive key search, which is
> itself ~2¹²⁸ times more expensive than the generic attack the curve was designed to
> resist.

---

## 🔍 Overview

The signing equation `s = (z + r·x)·k⁻¹ mod n` splits additively into a hidden hash/nonce
part and a hidden key part:

```text
ζ = s_zk  = z·k⁻¹        mod n      (hidden)
ξ = s_rxk = r·x·k⁻¹      mod n      (hidden)
s = ζ + ξ mod n                     (public)
```

The integer sum `σ = ζ + ξ` is either `s` or `s + n`; which one is invisible publicly, and
the distinction matters for classes B and E.

This work catalogues five classes (A–E) according to how the hidden pair `(ζ, ξ)` relates
to publicly-derivable quantities — `s_zr = z·r`, `d = s_zr − s`, `a = s mod d` — and
derives closed-form recovery for A, B, E plus a cross-transaction search for D.

Then it proves that all of this is a change of coordinates.

---

## 🧭 The main result

Every class is a **rule**: a map from public data to a set `C` of candidate values for the
hidden `ζ`. The paper's central theorem is a conservation law.

> **Zero-Yield Theorem.** For *any* rule computable from public data,
>
> ```text
> Pr[ζ ∈ C] = E|C| / (n − 2)
> ```
>
> exactly. The success probability **per candidate tested** is therefore the constant
> `1/(n − 2)` for every rule — identical to sampling uniformly from `Z*_n \ {s}`.

**Consequence.** A classification can change only *how many* candidates are emitted, never
their *quality*. No public-data classification of ECDSA signatures — existing, proposed, or
not yet conceived — can beat random guessing. The best conceivable rule wins by a factor of
`1 + 1/(n − 2) ≈ 1 + 8.6·10⁻⁷⁸` on secp256k1, and that residual advantage is bought by the
observation `ζ ≠ s` rather than by any of the algebra.

This is why the classes below are exercises rather than results. They differ only in `E|C|`.

---

## 🧩 The classes

All recovery ultimately uses one identity. Given the **true** hidden `ζ`,

```text
x = z·(s − ζ)·(r·ζ)⁻¹ mod n
```

The map `ζ ↦ x` is a **Möbius bijection** — injective on `Z*_n \ {s}`. So knowing `ζ` is
*equivalent* to knowing `x`; the formula transports no information from public data to the
secret. It is an algebraic restatement of the textbook fact that knowing the nonce reveals
the key. Every class below is just a different guess at `ζ`.

| Class | Condition on the hidden pair | Recovery | `E\|C\|` per signature | Pr[class] |
|---|---|---|---|---|
| **A** | `ζ = a`, where `a = s mod d` | one candidate | `Pr[Q] → 1/4` | `Pr[Q]/(n−2) ≈ 1/(4n)` |
| **B** | `m₁ = m₂ ∈ ℤ`, `m₁ = ζ/a`, `m₂ = (s+s_zr)/ξ` | **integer** quadratic, ≤ 4 candidates | `≈ 0.19·ln n / n` | `≈ 0.19·ln n / n²` |
| **C** | `m₁ ∈ ℤ`, `m₁ > 1`, `m₁ ≠ m₂` | none derived | — | small-field only |
| **D** | `f = ζ/a ∉ ℤ`; level `N = ⌊f⌋` | window `[a·N, a·(N+1)]`, width `Θ(n)` | `Θ(n)` | generic case, `= Pr[Q] = 1/4` |
| **E** | `ζ = 3ξ + 2` or `ξ = 3ζ + 2` | 2 candidates per admissible branch of `σ` | `5/6` | `2⌊(n−3)/3⌋/(n−1)² ≈ 2/(3n)` |

### Class E, restated

The published condition was `|ζ − ξ| = ⌊σ/2⌋ + 1` with `σ` even. That is **exactly
equivalent** to the affine line

```text
ζ = 3·ξ + 2      or      ξ = 3·ζ + 2       (over ℤ)
```

and it forces `σ ≡ 2 (mod 4)`. Recovery: with `σ ∈ {s, s+n}`, `σ ≡ 2 (mod 4)`,

```text
α = (3σ + 2) / 4        β = σ − α = (σ − 2) / 4        {ζ, ξ} = {α, β}
```

Note both branches of `σ` must be tried; the earlier formulation silently assumed `σ = s`.

### Class versus detector

`Pr[rule E succeeds] = 5/(6(n−2))` exceeds `Pr[class E] = 2/(3n)`. No contradiction: the
*class* is defined using the **secret** `σ`, while the *rule* must try both branches and so
also scores accidental hits from the wrong one. Conflating the two is where informal
treatments of this subject usually go wrong.

---

## 📊 Measured versus predicted

Datasets were generated on genuine elliptic curves, so no abscissa heuristic was involved
in producing them.

| Curve | `n` | Tx sampled | A pred / obs | B pred / obs | E pred / obs | C | D | Pr[Q] obs |
|---|---|---|---|---|---|---|---|---|
| tiny  | 9 967 | 99 323 922 | 2 491.8 / **2 465** | 1.75 / **2** | 6 642.2 / **6 746** | 335 131 | 24 407 153 | 0.249132 |
| small | 99 667 | 1 000 000 | 2.51 / **4** | 2e−4 / **0** | 6.69 / **12** | 580 | 248 814 | 0.249398 |
| large | 1 241 630 743 | 1 000 000 | 2e−4 / **0** | 3e−12 / **0** | 5e−4 / **0** | 0 | 250 311 | 0.250311 |

Poisson residuals: A `−0.54σ`, `+0.94σ`, `−0.01σ`; E `+1.27σ`, `+2.05σ`, `−0.02σ`. Every
one is ordinary fluctuation. `Pr[Q]` is the fraction `(A+B+C+D)/N` and converges to the
predicted `1/4` from below at the rate `Θ(log n / n)`.

Independently, exhaustive enumeration of the **entire** state space for seven primes
(1.66·10⁹ states, `n ≤ 1009`) confirms the class-A and class-E identities to every digit —
run `analysis/enumerate_states.py`.

---

## 🔬 Honest assessment

The points below are the corrected conclusions of this project. Each is reproducible in
minutes.

**1. The recovery formula is a tautology, not an attack.** `x = z·(s − ζ)·(r·ζ)⁻¹ mod n` is
exact only when `ζ` is the true `z·k⁻¹`. The map is a bijection, so recovering `x` from `ζ`
is a relabelling of the same search space of size `n − 1`. No class produces `ζ` from public
data alone for an arbitrary signature.

**2. No rule can beat guessing — and this is a theorem, not an observation.** By the
Zero-Yield Theorem the yield per tested candidate is `1/(n − 2)` for *every* public-data
rule. Searching for more coincidence classes is therefore provably futile: the space of
arithmetic coincidences is infinite, and each new member will have the same yield.

**3. A and E are `Θ(1/n)` coincidences; B is `Θ(log n / n²)`.** Each class is the event "the
secret pair happens to land on one specific, publicly-computable target." On secp256k1:

```text
Pr[A]              = 2.159042e−78   = 2^−258.00
Pr[E]              = 5.757446e−78   = 2^−256.58
Pr[B]              ≈ 2.5e−153       ≈ 2^−506.9
Pr[A ∪ B ∪ E]      = 7.916488e−78   = 2^−256.24
one blind guess    = 8.636169e−78   = 2^−256.00   ← larger than all of the above
```

Across every secp256k1 signature ever produced (≲10¹⁰), the expected number of instances of
all three classes combined is ≈ 8·10⁻⁶⁸.

**4. E's "Goldbach structure" is decorative — now proved, not just measured.** "Symmetric
pair around `σ/2`" is vacuous: *every* pair summing to `σ` is symmetric about `σ/2` by
definition. The only content is fixing the difference to one value, and by the paper's
offset-invariance theorem, for **any** integer `c` the class `|ζ − ξ| = σ/2 + c` is exactly
`ζ = 3ξ + 2c`, with the same frequency `2/(3n)`. The Goldbach value `+1` is one of `Θ(n)`
interchangeable choices. The control experiment in `analysis/e_control.py` measured a flat
`≈0.67/n` across offsets; that flatness is a two-line corollary of the class's own algebra.

**5. Class D gives no computational advantage and is circular.** The level `N = ⌊ζ/a⌋` is
computed from the **secret** `ζ`. Without it you do not know `N`; trying all `N` is exactly
brute-forcing `ζ ∈ [1, n]`. Even granting `N` for free, the window width `a` is `Θ(n)` on
average, so `E|C_D| = Θ(n)` and the Zero-Yield Theorem gives success probability `Θ(1)` at
cost `Θ(n)` — i.e. exhaustive search, ~2¹²⁸ times worse than Pollard rho. The demo "works"
on `test_small` only because `O(n)` is trivial when `n` is tiny.

**6. The "~25% anomaly rate" is a lattice area, not an exposure rate.** Qualification holds
iff `s < s_zr ≤ 2s` and `d ∤ s`. That region has area exactly `1/4` in the unit square, so
`Pr[Q] = 1/4 − Θ(log n / n)` on **every** curve. It measures the geometry of comparing two
residues mod `n` and has no bearing on key recoverability. Its constancy across curves is a
reason to expect no exploitability, not a reason to hope for it.

**7. Abundance without density.** The classes are not empty on secp256k1: `#A ≈ 3.9·10²³⁰`
and `#E ≈ 1.0·10²³¹` instances exist in a space of `1.8·10³⁰⁸`. Both statements are true and
both are consequence-free — there are equally many private keys beginning with any given
256-bit prefix. **Absolute counts in this subject must never be quoted without the density
`≈10⁻⁷⁷` beside them.**

---

## 📌 Errata

Three claims from earlier material in this repository are withdrawn. All are recorded in
§12 of the paper.

| # | Claim | Status | Correction |
|---|---|---|---|
| 1 | `Pr[E] = 1/(n−1)` | ❌ wrong | Correct value `2⌊(n−3)/3⌋/(n−1)² ≈ 2/(3n)`. The old formula predicts 9 966.5 events on the tiny curve against 6 746 observed — a **−32.3σ** deviation. It was excluded by the data published alongside it. |
| 2 | Class B needs a modular square root (Euler criterion, `√Δ mod n`) | ⚠️ superseded | The quadratic `a·m² − σ·m + (s+s_zr) = 0` holds over **ℤ**, so `Δ` must be a *perfect square* — far more restrictive than quadratic residuosity mod `n`. Verified on all 3 823 enumerated instances. The old form also fixed `σ = s`, ignoring wrap-around. |
| 3 | "The detector loses to guessing by 3.3×" (draft) | ⚠️ superseded | Artefact of the cost accounting. At equal numbers of tested candidates the result is an **exact tie**, up to `1 + 1/(n−2)`. The corrected statement is stronger: a conservation law leaves nothing to optimise. |

The earlier "vulnerability" framing of the prior publications is **no longer endorsed by the
author**.

---

## 🎯 What a real result would look like

Exactly one direction here has non-zero potential: find a class whose frequency
**systematically exceeds** its `c/n` baseline by a factor `λ > 1` that persists as `n`
grows. That would contradict the uniformity underlying the Zero-Yield Theorem and would be
a genuine finding.

Do **not** look for more classes. Test the **distribution** directly. Sample sizes for
`α = 0.05`, 80% power, class E on the tiny curve:

| detect `λ =` | transactions needed |
|---|---|
| 2.00 | 6.8·10⁵ |
| 1.10 | 4.9·10⁷ |
| 1.01 | 4.7·10⁹ |

The existing 99.3 M-transaction dataset already resolves a 10% enrichment. Applied to the
data in hand it constrains `λ` to **1.016 ± 0.012** for class E and **0.989 ± 0.020** for
class A — excluding any enrichment above 4% at 95% confidence.

The informative experiment: take 10⁸–10⁹ transactions on a curve with `n ≈ 10⁴–10⁵`, form
the empirical law of `ζ = z·k⁻¹` conditioned on every available public statistic, and test
uniformity (chi-squared over `√N` bins, or a discrete Fourier test à la Bleichenbacher). A
null result closes the question. A positive result would announce itself as a bias in a
histogram, not as an elegant identity.

---

## 📁 Structure

```text
ECDSA-Research/
├── README.md
├── LICENSE
├── src/
│   ├── ecurve/
│   │   ├── find_curve.sage                       # Find test elliptic curve parameters
│   │   ├── secp256k1.py                          # Key-pair generation based on secp256k1
│   │   └── secp256k1.txt                         # Output of secp256k1.py
│   ├── utils/
│   │   ├── generate_transactions.py              # Generate synthetic transactions to a TXT file
│   │   ├── find_common_private_key.py            # Cross-transaction x-search (class D)
│   │   └── find_common_private_key.txt           # Output of the above
│   └── kaggle/                                   # Kaggle notebooks/datasets for large-scale runs
├── analysis/
│   ├── e_control.py                              # Control: E offset σ/2+c gives flat ~2/(3n)
│   └── enumerate_states.py                       # Exhaustive state-space sweep; Appendix A of the paper
├── data/
│   ├── transaction_list_20260221205853.txt       # test small  (~1M tx;   A,B,C,D,E)
│   ├── transaction_list_20260221212522.txt       # test large  (~1M tx;   A,B,C,D,E)
│   ├── transaction_list_20260221211749.txt       # legacy      (~10K tx;  A,B,C,D,E)
│   └── transaction_list_20260317204137.txt       # test tiny   (~100M tx; A,B,C,D,E)
└── docs/
    ├── Coincidence_Classes_ECDSA_Zero_Yield.pdf  # The paper (14 pp.)
    ├── Coincidence_Classes_ECDSA_Zero_Yield.tex  # LaTeX source
    └── ECDSA_Coincidence_Classes_Zero_Yield.html # Web version
```

## 🚀 Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/ECDSA-Research.git
cd ECDSA-Research/

# Generate and classify transactions on a test curve
python src/utils/generate_transactions.py --mode test_tiny --tx_per_key 9966

# Reproduce the E control (the Goldbach offset is not privileged)
python analysis/e_control.py

# Exhaustive verification of every identity in the paper (needs numpy)
python analysis/enumerate_states.py
```

`enumerate_states.py` is exhaustive for `n ≤ 1009`, so its output is exact. Every `assert`
in it is a restatement of a theorem; if one fails, the paper is wrong.

---

## 📚 Citation

```bibtex
@misc{polishchuk2026coincidence,
  author = {Andriy Polishchuk},
  title  = {Coincidence Classes in the {ECDSA} State Space:
            A Zero-Yield Theorem, with Exact Frequencies for Classes {A}, {B} and {E}},
  year   = {2026},
  note   = {Cryptology ePrint Archive, Paper [ID pending]},
  url    = {https://eprint.iacr.org/2026/[ID]}
}
```

## 📘 Prior publications

Earlier write-ups of classes A and B. **Superseded by the assessment above: their
"vulnerability" framing is no longer endorsed by the author.** Kept for the record.

```text
https://doi.org/10.6084/m9.figshare.29223701
https://doi.org/10.21203/rs.3.rs-6790872/v1
```

## 👤 Author

**Andriy Polishchuk** — CRYPTON Systems Lab
📧 andriy.polishchuk.a@gmail.com

*Independent researcher. CRYPTON Systems Lab is an independent research group and not an
institutional affiliation.*

## 🔗 License

Released under the MIT License (see `LICENSE`).

---

### STATUS: Concluded — negative result

The question this repository set out to answer is closed by the Zero-Yield Theorem. The
repository is kept public for transparency and as a record of a dead end that is easy to
walk into, so that others do not re-discover it as a "break."
