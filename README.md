# ECDSA Research: Research on Elliptic Curve Digital Signature Algorithm

## 🔍 Overview

This work investigates algebraic anomalies in ECDSA signatures that enable deterministic private-key recovery under ideal-randomness assumptions about the "k" nonce. We describe two classes of vulnerabilities (Case A and Case B), supported by analytical formulas, simulations, and experimental transaction datasets for small test elliptic curves. Additionally, work is underway to develop a mathematical framework for deterministic private-key recovery for a class of vulnerabilities (Case D) observed in ECDSA signatures on the real elliptic curve "secp256k1".

NOTICE!
This work is in the stage of active development and research; therefore, some sections of this repository are incomplete, and documentation may be unavailable at this stage.

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
│   │   ├── ...
│   │   └── ...
|   └── kaggle/                              # Kaggle's notebooks, datasets, etc. for large-scale computing experiments
├── data/
│   ├── instructions.txt                     # The description of instructions on how to use the 'data' section
│   ├── transaction_list_20251213234825.txt  # Transaction list for test small curve (~1M transactions processed for D[0] case)
│   ├── transaction_list_20251214001804.txt  # Transaction list for test large curve (~100M transactions processed for A, B, C, D[all], E cases)
│   ├── ...
│   └── ...
└── docs/
    ├── description.txt                      # Temporary description of the purpose of the 'docs' section
    ├── ...
    └── ...
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
