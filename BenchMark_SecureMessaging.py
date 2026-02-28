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
  - Results.csv.
"""

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import hashlib
import time
import csv
import random
import statistics
import math
from dataclasses import dataclass
from typing import List, Tuple

# CONFIGURATION


ITERATIONS = 500  # Increased for statistical rigor


# VALIDATION (NIST + RFC Test Vectors)


def validate_aes() :
    """NIST FIPS 197 Known Answer Test"""
    key = bytes.fromhex("00000000000000000000000000000000")
    plaintext = bytes.fromhex("f34481ec3cc627bacd5dc3fb08f273e6")
    expected = bytes.fromhex("0336763e966d92595a567cc9ce537f5e")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext) == expected


def validate_chacha20() :
    """RFC 8439 Section 2.4.2 test vector"""
    from Crypto.Cipher import ChaCha20
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )
    nonce = bytes.fromhex("000000000000004a00000000")
    plaintext = b"Ladies and Gentlemen of the class of '99: If I c"
    expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
    )
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cipher.encrypt(b"\x00" * 64)
    return cipher.encrypt(plaintext) == expected


def run_validation() :
    print("=" * 50)
    print("VALIDATION - Official Test Vectors")
    print("=" * 50)
    aes_ok = validate_aes()
    chacha_ok = validate_chacha20()
    print(f"  AES     (NIST FIPS 197): {'PASS' if aes_ok else 'FAIL ✗'}")
    print(f"  ChaCha20 (RFC 8439):     {'PASS' if chacha_ok else 'FAIL ✗'}")
    print("=" * 65)
    if not (aes_ok and chacha_ok) :
        raise SystemExit(1)
    print("  Both implementations validated. Safe to use.\n")


# DATA GENERATION


def deterministic_bytes(label: str, n: int) -> bytes :
    """Generates deterministic test data"""
    out, counter = bytearray(), 0
    while len(out) < n :
        out.extend(hashlib.sha256(f"{label}:{counter}".encode()).digest())
        counter += 1
    return bytes(out[:n])


def build_expanded_dataset() -> List[Tuple[str, bytes]] :
    """
    Expanded dataset
    - Original was 64B, 256B, 1KB, 10KB
    - Added: 50KB, 100KB for scalability analysis
    """
    return [
        ("Test 1 - 64 bytes", deterministic_bytes("test1", 64)),
        ("Test 2 - 256 bytes", deterministic_bytes("test2", 256)),
        ("Test 3 - 1 KB", deterministic_bytes("test3", 1024)),
        ("Test 4 - 10 KB", deterministic_bytes("test4", 10 * 1024)),
        ("Test 5 - 50 KB", deterministic_bytes("test5", 50 * 1024)),  # NEW
        ("Test 6 - 100 KB", deterministic_bytes("test6", 100 * 1024)),  # NEW
    ]


# ENCRYPTION/DECRYPTION


@dataclass
class CryptoResult :
    ciphertext: bytes
    tag: bytes
    nonce: bytes
    key: bytes


def aes_encrypt(msg: bytes) -> CryptoResult :
    key = get_random_bytes(16)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)
    return CryptoResult(ct, tag, nonce, key)


def aes_decrypt(res: CryptoResult) -> bytes :
    cipher = AES.new(res.key, AES.MODE_GCM, nonce=res.nonce)
    return cipher.decrypt_and_verify(res.ciphertext, res.tag)


def chacha_encrypt(msg: bytes) -> CryptoResult :
    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)
    return CryptoResult(ct, tag, nonce, key)


def chacha_decrypt(res: CryptoResult) -> bytes :
    cipher = ChaCha20_Poly1305.new(key=res.key, nonce=res.nonce)
    return cipher.decrypt_and_verify(res.ciphertext, res.tag)


# STATISTICAL MEASUREMENTS


def measure_with_statistics(enc_fn, dec_fn, msg: bytes) -> dict :
    """
    statistical measurement.
    Calculates: Mean, StdDev, Variance, 95% CI
    """
    enc_times = []
    dec_times = []

    for _ in range(ITERATIONS) :
        # Encryption time
        t0 = time.perf_counter()
        result = enc_fn(msg)
        enc_times.append((time.perf_counter() - t0) * 1000)

        # Decryption time
        t0 = time.perf_counter()
        dec_fn(result)
        dec_times.append((time.perf_counter() - t0) * 1000)

    # Calculate statistics
    enc_mean = statistics.mean(enc_times)
    enc_stdev = statistics.stdev(enc_times)
    enc_variance = statistics.variance(enc_times)
    enc_ci = 1.96 * (enc_stdev / math.sqrt(ITERATIONS))  # 95% CI

    dec_mean = statistics.mean(dec_times)
    dec_stdev = statistics.stdev(dec_times)
    dec_variance = statistics.variance(dec_times)
    dec_ci = 1.96 * (dec_stdev / math.sqrt(ITERATIONS))

    # Throughput
    size_mb = len(msg) / (1024 * 1024)
    enc_sec = enc_mean / 1000
    throughput = size_mb / enc_sec if enc_sec > 0 else 0.0

    return {
        'enc_mean' : enc_mean,
        'enc_stdev' : enc_stdev,
        'enc_variance' : enc_variance,
        'enc_ci' : enc_ci,
        'dec_mean' : dec_mean,
        'dec_stdev' : dec_stdev,
        'dec_variance' : dec_variance,
        'dec_ci' : dec_ci,
        'throughput' : throughput,
        'raw_enc_times' : enc_times
    }


# SAFETY & FAR TESTING


def test_safety_and_far(enc_fn, dec_fn, msg: bytes, trials: int = 200) -> Tuple[str, float] :
    """Tests tamper detection and calculates FAR"""
    result = enc_fn(msg)

    # Safety: Can we decrypt a legitimate message?
    try :
        decrypted = dec_fn(result)
        safety = "PASS" if decrypted == msg else "FAIL"
    except Exception :
        safety = "FAIL"

    # FAR: How often do we incorrectly accept tampered data?
    false_accepts = 0
    for _ in range(trials) :
        tampered = CryptoResult(
            bytearray(result.ciphertext),
            result.tag,
            result.nonce,
            result.key
        )
        # Flip random bit
        pos = random.randint(0, len(tampered.ciphertext) - 1)
        tampered.ciphertext[pos] ^= random.randint(1, 255)
        tampered.ciphertext = bytes(tampered.ciphertext)

        try :
            dec_fn(tampered)
            false_accepts += 1
        except Exception :
            pass

    far = (false_accepts / trials) * 100
    return safety, far


# MAIN BENCHMARK


def run_benchmark() :
    """Main benchmark with statistical accuracy"""
    print("\n" + "=" * 50)
    print("  ENHANCED BENCHMARK - STATISTICAL Accuracy")
    print("  " + str(ITERATIONS) + " iterations per test")
    print("=" * 50 + "\n")

    run_validation()

    print("Building expanded dataset...")
    dataset = build_expanded_dataset()
    print(f" {len(dataset)} test cases\n")

    rows = []

    for test_name, msg in dataset :
        print(f"Running: {test_name}")

        # AES-GCM
        print("  Testing AES-GCM...")
        aes_stats = measure_with_statistics(aes_encrypt, aes_decrypt, msg)
        aes_safety, aes_far = test_safety_and_far(aes_encrypt, aes_decrypt, msg)

        # ChaCha20-Poly1305
        print("  Testing ChaCha20-Poly1305...")
        chacha_stats = measure_with_statistics(chacha_encrypt, chacha_decrypt, msg)
        chacha_safety, chacha_far = test_safety_and_far(chacha_encrypt, chacha_decrypt, msg)

        # Store AES results
        rows.append({
            'Algorithm' : 'AES-GCM',
            'Test Case' : test_name,
            'Message Size (B)' : len(msg),
            'Enc Mean (ms)' : round(aes_stats['enc_mean'], 6),
            'Enc StdDev (ms)' : round(aes_stats['enc_stdev'], 6),
            'Enc 95% CI' : f"±{aes_stats['enc_ci']:.6f}",
            'Dec Mean (ms)' : round(aes_stats['dec_mean'], 6),
            'Throughput (MB/s)' : round(aes_stats['throughput'], 4),
            'Safety' : aes_safety,
            'FAR (%)' : round(aes_far, 2)
        })

        # Store ChaCha20 results
        rows.append({
            'Algorithm' : 'ChaCha20-Poly1305',
            'Test Case' : test_name,
            'Message Size (B)' : len(msg),
            'Enc Mean (ms)' : round(chacha_stats['enc_mean'], 6),
            'Enc StdDev (ms)' : round(chacha_stats['enc_stdev'], 6),
            'Enc 95% CI' : f"±{chacha_stats['enc_ci']:.6f}",
            'Dec Mean (ms)' : round(chacha_stats['dec_mean'], 6),
            'Throughput (MB/s)' : round(chacha_stats['throughput'], 4),
            'Safety' : chacha_safety,
            'FAR (%)' : round(chacha_far, 2)
        })

        print()

    # Display results
    print("=" * 70)
    print("RESULTS - Statistical Analysis")
    print("=" * 70)
    print(f"{'Algorithm':<25} {'Test':<20} {'Enc Mean±CI (ms)':<20} {'FAR %':<8}")
    print("-" * 70)

    for row in rows :
        enc_display = f"{row['Enc Mean (ms)']}{row['Enc 95% CI']}"
        print(f"{row['Algorithm']:<25} {row['Test Case']:<20} {enc_display:<20} {row['FAR (%)']:<8}")

    # Save to CSV
    print("\n" + "=" * 70)
    with open("Results.csv", "w", newline="") as f :
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(" Results saved to 'Results.csv'")
    print("  Contains: Mean, StdDev, 95% CI")
    print("=" * 70)


if __name__ == "__main__" :
    run_benchmark()






