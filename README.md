# ECDSA Research: Research on Elliptic Curve Digital Signature Algorithm

## 🔍 Overview

This research investigates algebraic anomalies in ECDSA signatures — structured deviations in the internal arithmetic of the signing equation that arise under ideally-random nonce generation and expose exploitable mathematical relationships between public signature components.

The work identifies and formalizes five classes of anomalies (A, B, C, D, E), observed across synthetic test curves and the real-world elliptic curve **secp256k1**. For three of these classes — **A**, **B**, and **E** — closed-form analytical formulas for deterministic private-key recovery have been derived and verified. Anomaly **A** exploits a linear divisibility condition on the `s_zk` component; anomaly **B** requires solving a modular quadratic equation via discriminant and modular square root; anomaly **E** (subdivided into E1 and E2) is rooted in a Goldbach-type additive decomposition of the signature scalar `s`, enabling candidate private-key recovery from a pair of complementary component values.

The largest and most structurally diverse class — **D** — encompasses signatures where the ratio `f = s_zk / a` takes a non-integer value, with the integer part `⌊f⌋` defining a bounded search level. Anomaly D is currently under active research: a mathematical framework for narrowing the private-key search space via cross-transaction intersection of candidate `x` values has been developed and is being experimentally validated on both small test curves and the legacy secp256k1 curve.

The repository includes transaction generation scripts, analytical recovery tools, large-scale Kaggle-based computation notebooks, and experimental datasets containing up to ~1M classified ECDSA transactions across multiple curve configurations.

> ⚠️ **NOTICE:** This work is in active development. Some sections of the repository are incomplete and documentation may be unavailable at this stage.

## 📁 Structure

```markdown
ECDSA-Research/
├── README.md
├── LICENSE
├── src/
|   ├── ecurve/
│   │   ├── find_curve.sage                  # Script to find test elliptic curve parameters
│   │   ├── secp256k1.py                     # Advanced script to generate pairs of keys (private and public) based on 'secp256k1'
│   │   └── secp256k1.txt                    # The result of the work 'secp256k1.py' script
|   ├── utils/
│   │   ├── generate_transactions.py         # Script to generate sentetic transactions into local TXT file
│   │   ├── find_common_private_key.py       # Script to find the common private key for the group of transactions
│   │   ├── find_common_private_key.txt      # The result of the work 'find_common_private_key.py' script, coupled with the transaction list
|   └── kaggle/                              # Kaggle's notebooks, datasets, etc. for large-scale computing experiments
├──data/
│   ├── transaction_list_20260221205853.txt  # Transaction list for test small curve (~1M transactions processed for A, B, C, D[all], E cases)
│   ├── transaction_list_20260221212522.txt  # Transaction list for test large curve (~1M transactions processed for A, B, C, D[all], E cases)
│   └── transaction_list_20260221211749.txt  # Transaction list for legacy curve (~10K transactions processed for A, B, C, D[all], E cases)
└── docs/
    └── ECDSA_Anomalies_Math_Framework.html  # The document describes the full mathematical framework for all ECDSA anomalies
```

## 📘 Link

This work was inspired by the author's previous research on detecting algebraic anomalies in ECDSA transactions and modular remainders. You can read the corresponding publication through the following links:

```markdown
https://doi.org/10.6084/m9.figshare.29223701
https://doi.org/10.21203/rs.3.rs-6790872/v1
```

## 🔗 License

Released under MIT License (see LICENSE file).

## 🚀 Quick Start

Clone the repository and run the transaction generator:

```bash
git clone https://github.com/YOUR_USERNAME/ECDSA-Research.git
cd ECDSA-Research/
```

## 🔍 Project on JIRA

Tracking and monitoring tasks related to the current project can be found here:

[![Go to JIRA](https://img.shields.io/badge/JIRA-Visit-blue)](https://cryptonsystemslab.atlassian.net/jira/core/projects/CSL/board?filter=&groupBy=status&atlOrigin=eyJpIjoiZWYwNGI4ODlhYmZjNDdkNGIwMGM3NWUwNzk0MTBjNGYiLCJwIjoiaiJ9)

### STATUS: Active
