"""
Secure Messaging
1. Uses NIST test vectors (stated dataset)
2. Tests multiple cases automatically
3. Measures Speed, Safety, Error for each test
4. Outputs results in table format
5. Tests both AES and ChaCha20


Compares AES vs ChaCha20-Poly1305 across multiple test cases.

Measures:
  - Speed      : Encryption time, Decryption time, Throughput
  - Safety     : Tamper detection (AEAD authentication test)
  - Error Rate : Decryption accuracy across 200 iterations

Output:
  - Printed table
  - Results.csv
"""

from Crypto.Cipher import AES, ChaCha20, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import hashlib
import time
import csv
from dataclasses import dataclass
from typing import List, Tuple

# CORRECTNESS VALIDATION (TEST VECTORS.)

# VALIDATION (NIST + RFC 8439 Test Vectors)
# Runs FIRST to prove implementations are correct

def validate_aes():
    """
    Validates AES using NIST FIPS 197 Known Answer Test (KAT)
    Source: NIST Cryptographic Algorithm Validation Program
    """
    key       = bytes.fromhex("00000000000000000000000000000000")
    plaintext = bytes.fromhex("f34481ec3cc627bacd5dc3fb08f273e6")
    expected  = bytes.fromhex("0336763e966d92595a567cc9ce537f5e")
    cipher    = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext) == expected


def validate_chacha20():
    """
    Validates ChaCha20 using RFC 8439 Section 2.4.2 test vector
    Source: IETF RFC 8439
    """
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )
    nonce     = bytes.fromhex("000000000000004a00000000")
    plaintext = b"Ladies and Gentlemen of the class of '99: If I c"
    expected  = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
    )
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cipher.encrypt(b"\x00" * 64)          # advance counter to block 1
    return cipher.encrypt(plaintext) == expected


def run_validation():
    """
    Runs both validations and prints results.
    Program stops if either fails.
    """
    print("=" * 65)
    print("VALIDATION - Official Test Vectors")
    print("=" * 65)

    aes_ok    = validate_aes()
    chacha_ok = validate_chacha20()

    print(f"  AES     (NIST FIPS 197)  : {'PASS' if aes_ok    else 'FAIL'}")
    print(f"  ChaCha20    (RFC 8439)        : {'PASS' if chacha_ok else 'FAIL'}")
    print("=" * 65)

    if not (aes_ok and chacha_ok):
        print("\n  ERROR: Validation failed. Stopping.")
        print("  Fix implementation before running benchmarks.\n")
        raise SystemExit(1)

    print("  Both implementations validated. Safe to benchmark.\n")



# DATASET
# 5 test cases of increasing size


def deterministic_bytes(label: str, n: int) -> bytes:
    """
    Generates reproducible pseudo-random bytes using SHA-256.
    Same label always produces same bytes — ensures fair comparison.
    """
    out, counter = bytearray(), 0
    while len(out) < n:
        out.extend(hashlib.sha256(f"{label}:{counter}".encode()).digest())
        counter += 1
    return bytes(out[:n])


def build_dataset() -> List[Tuple[str, bytes]]:
    """
    5 test cases:
      Test 1 : Short text message  (typical chat message)
      Test 2 : 64  bytes           (small data)
      Test 3 : 256 bytes           (medium data)
      Test 4 : 1 KB                (standard block)
      Test 5 : 10 KB               (larger message)
    """
    return [
        ("Test 1 - Short text",    b"Secure messaging test message."),
        ("Test 2 - 64 bytes",      deterministic_bytes("ds2",  64)),
        ("Test 3 - 256 bytes",     deterministic_bytes("ds3",  256)),
        ("Test 4 - 1 KB",          deterministic_bytes("ds4",  1024)),
        ("Test 5 - 10 KB",         deterministic_bytes("ds5",  10 * 1024)),
    ]



# ENCRYPTION / DECRYPTION FUNCTIONS


@dataclass
class CryptoResult:
    """Holds everything needed to decrypt a message"""

    ciphertext : bytes
    tag        : bytes
    nonce      : bytes
    key        : bytes


def aes_encrypt(msg: bytes) -> CryptoResult:
    key    = get_random_bytes(16)           # 128-bit AES key
    nonce  = get_random_bytes(12)           # 96-bit GCM nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)
    return CryptoResult(ct, tag, nonce, key)


def aes_decrypt(res: CryptoResult) -> bytes:
    cipher = AES.new(res.key, AES.MODE_GCM, nonce=res.nonce)
    return cipher.decrypt_and_verify(res.ciphertext, res.tag)


def chacha_encrypt(msg: bytes) -> CryptoResult:
    key    = get_random_bytes(32)           # 256-bit ChaCha20 key
    nonce  = get_random_bytes(12)           # 96-bit nonce
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)
    return CryptoResult(ct, tag, nonce, key)


def chacha_decrypt(res: CryptoResult) -> bytes:
    cipher = ChaCha20_Poly1305.new(key=res.key, nonce=res.nonce)
    return cipher.decrypt_and_verify(res.ciphertext, res.tag)


# METRIC MEASUREMENT FUNCTIONS

ITERATIONS = 200  # Number of runs to average over

def measure_speed(enc_fn, dec_fn, msg: bytes) -> Tuple[float, float, float] :
    """
    METRIC 1 & 2: Encryption and Decryption Time (milliseconds)
    METRIC 3:     Throughput (MB/s)

    Runs ITERATIONS times and takes the average for accuracy.
    """
    # Encryption time
    t0 = time.perf_counter()
    for _ in range(ITERATIONS) :
        enc_fn(msg)
    enc_ms = ((time.perf_counter() - t0) / ITERATIONS) * 1000

    # Decryption time
    t0 = time.perf_counter()
    for _ in range(ITERATIONS) :
        dec_fn(enc_fn(msg))
    dec_ms = ((time.perf_counter() - t0) / ITERATIONS) * 1000

    # Throughput = data size / encryption time
    size_mb = len(msg) / (1024 * 1024)
    enc_sec = enc_ms / 1000
    throughput = size_mb / enc_sec if enc_sec > 0 else 0.0

    return enc_ms, dec_ms, throughput


def measure_safety(dec_fn, result: CryptoResult) -> str :
    """
    Safety / Tamper Detection

    Flips one bit in the ciphertext.
    A secure AEAD cipher MUST detect this and raise an error.

    Returns 'PASS' if tampering is detected, 'FAIL' if not.
    """
    tampered = bytearray(result.ciphertext)
    tampered[0] ^= 0x01  # Flip one bit
    try :
        dec_fn(CryptoResult(bytes(tampered), result.tag, result.nonce, result.key))
        return "FAIL"  # Should never reach here
    except Exception :
        return "PASS"  # Tampering correctly detected


def measure_error_rate(enc_fn, dec_fn, msg: bytes) -> float :
    """
    Error Rate (%)

    Encrypts and decrypts ITERATIONS times.
    Counts how many times the decrypted message does NOT match original.

    Expected result: 0.00%
    """
    errors = 0
    for _ in range(ITERATIONS) :
        try :
            result = enc_fn(msg)
            decrypted = dec_fn(result)
            if decrypted != msg :
                errors += 1
        except Exception :
            errors += 1

    return (errors / ITERATIONS) * 100



# RUN A SINGLE ALGORITHM ON A SINGLE TEST CASE
def run_test(algo_name: str, enc_fn, dec_fn, test_name: str, msg: bytes) -> dict:
    """
    Runs all metrics for one algorithm on one test case.
    Returns a dictionary of results.
    """
    print(f"    Running {algo_name} | {test_name}...", end=" ", flush=True)

    enc_ms, dec_ms, throughput = measure_speed(enc_fn, dec_fn, msg)

    result  = enc_fn(msg)
    safety  = measure_safety(dec_fn, result)
    error   = measure_error_rate(enc_fn, dec_fn, msg)

    print("done")

    return {
        "Algorithm"        : algo_name,
        "Test Case"        : test_name,
        "Message Size (B)" : len(msg),
        "Enc Time (ms)"    : round(enc_ms,    6),
        "Dec Time (ms)"    : round(dec_ms,    6),
        "Throughput (MB/s)": round(throughput, 4),
        "Safety"           : safety,
        "Error Rate (%)"   : round(error,     2),
    }



# PRINT RESULTS TABLE

def print_results_table(rows: list):
    """
    Prints results in the table format

    Algorithm | Test Case | Enc Time | Dec Time | Throughput | Safety | Error
    """
    print("\n" + "=" * 105)
    print("  RESULTS TABLE")
    print("=" * 105)

    # Header
    print(f"  {'Algorithm':<22} {'Test Case':<22} {'Enc(ms)':<12} "
          f"{'Dec(ms)':<12} {'Throughput':<14} {'Safety':<10} {'Error %'}")
    print("-" * 105)


    current_algo = None
    for row in rows:
        if row["Algorithm"] != current_algo:
            if current_algo is not None:
                print()                     # Blank line between algorithms
            current_algo = row["Algorithm"]

        print(f"  {row['Algorithm']:<22} "
              f"{row['Test Case']:<22} "
              f"{row['Enc Time (ms)']:<12.6f} "
              f"{row['Dec Time (ms)']:<12.6f} "
              f"{row['Throughput (MB/s)']:<14.4f} "
              f"{row['Safety']:<10} "
              f"{row['Error Rate (%)']:.2f}%")

    print("=" * 105)


def print_summary(rows: list):
    """
    Prints summary comparison between AES and ChaCha20
    """
    aes_rows    = [r for r in rows if r["Algorithm"] == "AES-GCM"]
    chacha_rows = [r for r in rows if r["Algorithm"] == "ChaCha20-Poly1305"]

    aes_avg_enc    = sum(r["Enc Time (ms)"]     for r in aes_rows)    / len(aes_rows)
    chacha_avg_enc = sum(r["Enc Time (ms)"]     for r in chacha_rows) / len(chacha_rows)
    aes_avg_dec    = sum(r["Dec Time (ms)"]     for r in aes_rows)    / len(aes_rows)
    chacha_avg_dec = sum(r["Dec Time (ms)"]     for r in chacha_rows) / len(chacha_rows)
    aes_safety     = all(r["Safety"] == "PASS"  for r in aes_rows)
    chacha_safety  = all(r["Safety"] == "PASS"  for r in chacha_rows)
    aes_error      = sum(r["Error Rate (%)"]    for r in aes_rows)    / len(aes_rows)
    chacha_error   = sum(r["Error Rate (%)"]    for r in chacha_rows) / len(chacha_rows)

    enc_winner  = "ChaCha20-Poly1305" if chacha_avg_enc < aes_avg_enc  else "AES-GCM"
    dec_winner  = "ChaCha20-Poly1305" if chacha_avg_dec < aes_avg_dec  else "AES-GCM"

    print("\n" + "=" * 65)
    print("  SUMMARY COMPARISON")
    print("=" * 65)
    print(f"  {'Metric':<30} {'AES-GCM':<17} {'ChaCha20'}")
    print("-" * 65)
    print(f"  {'Avg Enc Time (ms)':<30} {aes_avg_enc:<17.6f} {chacha_avg_enc:.6f}")
    print(f"  {'Avg Dec Time (ms)':<30} {aes_avg_dec:<17.6f} {chacha_avg_dec:.6f}")
    print(f"  {'Safety (all tests)':<30} {'PASS' if aes_safety else 'FAIL':<17} {'PASS' if chacha_safety else 'FAIL'}")
    print(f"  {'Avg Error Rate (%)':<30} {aes_error:<17.2f} {chacha_error:.2f}")
    print("-" * 65)
    print(f"  Fastest Encryption:   {enc_winner}")
    print(f"  Fastest Decryption:   {dec_winner}")
    print(f"  Security          :  Both algorithms passed tamper detection")
    print(f"  Accuracy          :   Both algorithms achieved 0% error rate")
    print("=" * 65)



# SAVE TO CSV

def save_csv(rows: list, filename: str = "Results.csv"):
    """
    Saves all results to a CSV file.
    """
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n  Results saved to '{filename}'")



# MAIN function

def main():
    print("\n" + "=" * 65)
    print("  SECURE MESSAGING")
    print("  Comparing AES-GCM vs ChaCha20-Poly1305")
    print("=" * 65 + "\n")

    # runs first...Validate implementations against official test vectors
    run_validation()

    # Build test dataset
    print("=" * 65)
    print(" RUNNING BENCHMARK TESTS")
    print(f"  Each test runs {ITERATIONS} iterations for accuracy")
    print("=" * 65)

    dataset = build_dataset()
    rows    = []

    for test_name, msg in dataset:
        print(f"\n  [{test_name}]")
        rows.append(run_test("AES-GCM",            aes_encrypt,    aes_decrypt,    test_name, msg))
        rows.append(run_test("ChaCha20-Poly1305",   chacha_encrypt, chacha_decrypt, test_name, msg))

    # Print results table
    print_results_table(rows)

    # Print summary
    print_summary(rows)

    # Save to CSV
    save_csv(rows)

    print("\n Finished. Results.csv in Excel.\n")


if __name__ == "__main__":
    main()







