# ECDSA Research: Algebraic Coincidences in ECDSA Signatures

## 🔍 Overview

This repository documents an investigation into recurring **algebraic patterns** in ECDSA
signatures generated under ideal, uniformly-random nonces. It is published as a working
research journal, **not** as a vulnerability disclosure.

The signing equation `s = (z + r·x)·k⁻¹ mod n` is split additively into a hidden
hash/nonce part and a hidden key part:

```text
s_zk  = z·k⁻¹        mod n      (hidden)
s_rxk = r·x·k⁻¹      mod n      (hidden)
s     = s_zk + s_rxk mod n
```

The work catalogues five classes of "anomaly" (A, B, C, D, E) according to how the hidden
pair `(s_zk, s_rxk)` relates to publicly-derivable quantities, and provides closed-form
recovery for A, B, E and a cross-transaction search procedure for D.

**Important framing (read this before anything else).** After deriving and verifying the
formulas, the honest conclusion is that **none of these classes constitutes an attack on
ECDSA**, and the original "vulnerability" framing of the earlier publications was
overstated. The reasons are spelled out in [§ Honest assessment](#-honest-assessment) and
are reproducible in minutes. This repository is kept public for transparency and as a
record of a dead end that is easy to walk into — so others can avoid re-discovering it as
a "break."

> ⚠️ **NOTICE:** This is exploratory work on reduced-size test curves. It does **not**
> threaten secp256k1 or any deployed system, and it does not claim to.

## 🧩 The classes, briefly

All recovery ultimately uses one identity. Given the **true** hidden value `s_zk`, the
private key is

```text
x = z·(s − s_zk)·(r·s_zk)⁻¹ mod n
```

This is **not** a weakness — it is an algebraic restatement of the textbook fact that
`s_zk = z·k⁻¹` encodes the nonce `k`, and **knowing the nonce trivially reveals the key**.
Every class below is just a different guess at `s_zk`.

|Class|Condition on the hidden pair|Recovery|Frequency|
|---|------------------------------|----------|-----------|
|**A**|`s_zk = a` (where `a = s mod ((s_zr − s) mod n)`)|guess `s_zk = a`, one candidate|~`0.25/n`|
|**B**|`m1 = m2 > 1` (both integer)|modular quadratic, ≤ 2 candidates|~`1/n²` (vanishing)|
|**C**|`m1` integer `> 1`, `m1 ≠ m2`|none derived|small-field only|
|**D**|`f = s_zk/a` non-integer; level `N = ⌊f⌋`|search window `[a·N, a·(N+1)]` of width ~`a`|dominant (~25% of tx)|
|**E**|`abs(s_zk − s_rxk) = ⌊s/2⌋ + 1`, `s` even|guess `s_zk ∈ {α, β}`, 2 candidates|~`0.67/n`|

`α = (s + ⌊s/2⌋ + 1)//2`, `β = s − α`, derived by solving the linear system
{sum `= s`, difference `= s/2 + 1`} — both right-hand sides being functions of the public
`s`. This is the entire reason E recovers from public data.

## 🔬 Honest assessment

The points below are the corrected conclusions of this project. Each is reproducible.

**1. The recovery formula is a tautology, not an attack.**
`x = z·(s − s_zk)·(r·s_zk)⁻¹ mod n` is exact only when `s_zk` equals the true `z·k⁻¹`.
Recovering `x` from `s_zk` is identical to recovering `x` from the nonce `k`. No class
produces `s_zk` (equivalently `k`) from public data alone for an arbitrary signature.

**2. A, B, E are `~c/n` coincidences that vanish as the curve grows.** Each class is the
event "the secret pair happens to land on one specific, publicly-computable target." Its
probability is `O(1/n)`. Measured counts confirm the `1/n` scaling and the disappearance
on larger fields:

|Curve|`n`|Tx sampled|A|B|C|D|E|
|-----|-----|-----------|---|---|---|---|---|
|tiny|9 967|~99.3 M|2 465|2|335 131|24 407 153|6 746|
|small|99 667|1 M|4|0|580|248 814|12|
|large|1 241 630 743|1 M|0|0|0|250 311|0|

E drops ~10× when `n` grows ~10× (tiny → small) and hits **0** on the large curve. On
secp256k1 (`n ≈ 1.16·10⁷⁷`) the expected occurrence is ~`2⁻²⁵⁵` — effectively never.

**3. E's "Goldbach structure" is decorative.** The phrase "symmetric pair around `s/2`" is
vacuous: *every* pair summing to `s` is symmetric around `s/2` by definition. The only real
constraint E imposes is fixing the **difference** to one value (`s/2 + 1`), and that value
is arbitrary. A control experiment shifting the target difference to `s/2 + 3`, `s/2 + 5`,
`s/2 − 1`, … yields **the same frequency** (~`0.67/n` for every offset). The Goldbach value
`+1` is not privileged; it is one slice of a family of ~`n` equally-frequent classes.
(See `analysis/e_control.py`.)

**4. Class D gives no computational advantage and is circular.**
The level `N = ⌊s_zk/a⌋` is computed from the **secret** `s_zk`. Without the secret you do
not know `N`; trying all `N` is exactly brute-forcing all `s_zk ∈ [1, n]`, i.e. `O(n)`.
Even granting `N` for free, the window width is `a = s mod ((s_zr − s) mod n)`, which is
`O(n)` on average — so each transaction yields `O(n)` candidates and the cross-transaction
intersection costs `O(T·n)`. On secp256k1 this is `~2²⁵⁶` and infeasible. The demo
"works" on `test_small` only because `O(n)` is trivial when `n` is tiny.

**5. The "~25% anomaly rate" measures arithmetic, not exploitability.** The detection
condition (`s_zr > s`, `a` in range) holds for ~25% of signatures on every curve. This is a
property of comparing two residues mod `n`; it has no bearing on whether a key can be
recovered. Conflating "detection condition met" with "exploitable" is the central error of
the original framing.

## 🎯 What a real result would look like

There is exactly one direction here with non-zero potential: find a class whose frequency
**systematically exceeds** the `~c/n` baseline. That would indicate a genuine bias in the
distribution of `s_zk` — actual structure rather than coincidence. The control experiment
in point 3 currently shows a flat line (no enrichment), so as of now there is no such
result. This is the only question worth large-scale compute, and it can be attacked with
data-engineering tooling alone: scan the empirical distribution of `s_zk` (or of the
hidden difference) and test for deviations from uniformity. Until a measurable bias is
found, there is no vulnerability and no paper.

## 📁 Structure

```text
ECDSA-Research/
├── README.md
├── LICENSE
├── src/
│   ├── ecurve/
│   │   ├── find_curve.sage                  # Find test elliptic curve parameters
│   │   ├── secp256k1.py                     # Key-pair generation based on secp256k1
│   │   └── secp256k1.txt                    # Output of secp256k1.py
│   ├── utils/
│   │   ├── generate_transactions.py         # Generate synthetic transactions to a TXT file
│   │   ├── find_common_private_key.py       # Cross-transaction x-search (class D)
│   │   └── find_common_private_key.txt      # Output of the above
│   └── kaggle/                              # Kaggle notebooks/datasets for large-scale runs
├── analysis/
│   └── e_control.py                         # Control: E offset δ=s/2+k gives flat ~c/n frequency
├── data/
│   ├── transaction_list_20260221205853.txt  # test small  (~1M tx; A,B,C,D,E)
│   ├── transaction_list_20260221212522.txt  # test large  (~1M tx; A,B,C,D,E)
│   ├── transaction_list_20260221211749.txt  # legacy      (~10K tx; A,B,C,D,E)
│   ├── transaction_list_20260317204137.txt  # test tiny   (~100M tx; A,B,C,D,E)
│   ├── transaction_list_20260327174442.txt  # test small  (~10K tx; +D-hypothesis section)
│   ├── transaction_list_20260327174609.txt  # test large  (~10K tx; +D-hypothesis section)
│   └── transaction_list_20260327174950.txt  # legacy      (~10K tx; +D-hypothesis section)
├── docs/
│   ├── ECDSA_Anomalies_Math_Framework.html  # Full mathematical framework
│   └── ECDSA_Anomalies_Math_Framework.pdf   # Same, PDF
└── knowledge/
    └── ecdsa_research_knowledge.json        # Machine-readable research context
```

## 🚀 Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/ECDSA-Research.git
cd ECDSA-Research/

# Generate and classify transactions on a test curve
python src/utils/generate_transactions.py --mode test_tiny --tx_per_key 9966

# Reproduce the E control (Goldbach offset is not privileged)
python analysis/e_control.py
```

## 📘 Prior publications

The earlier write-ups of classes A and B. **They are superseded by the assessment above:
their "vulnerability" framing is no longer endorsed by the author.** Kept for the record.

```text
https://doi.org/10.6084/m9.figshare.29223701
https://doi.org/10.21203/rs.3.rs-6790872/v1
```

## 🔗 License

Released under the MIT License (see `LICENSE`).

### STATUS: Documented — not a vulnerability. No publication planned for class E.
