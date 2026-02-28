# Secure Messaging Prototype (AES & ChaCha20)

This repository contains a Python-based secure messaging prototype developed
as part of a Final Year Project.


Python scripts that demonstrate and evaluate **authenticated encryption** for secure messaging using:

- **AES-GCM** (AES)
- **ChaCha20-Poly1305** (ChaCha20 stream cipher + Poly1305 authenticator)

The project includes:
- **Correctness validation** using official test vectors (NIST / RFC 8439)
- **Benchmarking** across multiple message sizes (speed, throughput, safety, error rate)
- **Security analysis demos** (MITM resistance)
- **Graph generation** from benchmark output (`Results.csv`)


## Repository contents

| File| Purpose | Output |
| `secure_messaging_benchmark.py` | Validates implementations, runs benchmarks for AES-GCM vs ChaCha20-Poly1305 across 5 test cases, prints tables and saves CSV. | `Results.csv` |
| `performance_graphs.py` | Reads `Results.csv` and generates PNG graphs for reports. | `graph_*.png` |
| `security_analysis_attack_resistance.py` | Demonstrates MITM resistance conceptually + prints keyspace / brute-force feasibility analysis; saves a short text report. | `security_results.txt` |
| `README.md` | Project documentation.


## Requirements

- **Python 3.9+** recommended
- **PyCryptodome** (cryptographic primitives)
- **Matplotlib** (only for graph generation)

### Install dependencies

```bash
pip install pycryptodome
pip install matplotlib
```

## How to run

### 1) Benchmark + validation (creates `Results.csv`)

Run the benchmark script first (it also validates correctness using known test vectors):

python secure_messaging_benchmark.py
What it does:
- Validates AES against a **NIST FIPS 197** known-answer test.
- Validates ChaCha20 against **RFC 8439** test vectors.
- Runs 5 test cases × 2 algorithms × 200 iterations (by default).
- Measures:
  - Encryption time (ms)
  - Decryption time (ms)
  - Throughput (MB/s)
  - Safety (tamper detection via AEAD authentication)
  - Error rate (%)

Output:
- `Results.csv`

### 2) Generate graphs (requires `Results.csv`)

After benchmarking:

```bash
python performance_graphs.py
```

Outputs (PNG files):
- `graph_encryption_time.png`
- `graph_throughput.png`
- `graph_safety.png`
- `graph_summary.png`

---

### 3) Security analysis demo (creates `security_results.txt`)

```bash
python security_analysis_attack_resistance.py
```

This script:
- Demonstrates why a passive attacker cannot read intercepted ciphertext (MITM scenario)
- Prints a keyspace / brute-force feasibility comparison (AES-128, AES-256, ChaCha20)
- Saves `security_results.txt`

---

## Notes on security & correctness

- **AEAD matters:** Both AES-GCM and ChaCha20-Poly1305 provide confidentiality and integrity. If ciphertext is modified, decryption should fail.
- **Nonce uniqueness:** In real systems, **never reuse a nonce with the same key**. These scripts generate fresh random nonces and keys for each encryption call to keep the demo simple and safe.
- **Benchmark fairness:** The benchmark dataset is generated deterministically for binary test cases so both algorithms see identical inputs each run.

---

## Acknowledgements

- NIST FIPS 197 (AES) known-answer test vectors
- IETF RFC 8439 (ChaCha20 & Poly1305)
- PyCryptodome library
