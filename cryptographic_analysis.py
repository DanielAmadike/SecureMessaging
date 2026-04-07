
"""
Cryptographic Analysis Tests - WITH CSV OUTPUT
Tests avalanche effect and entropy for AES-GCM vs ChaCha20-Poly1305

Output: crypto_results.csv + crypto_Analysis_results.txt
"""

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import statistics
import math
import random
import csv


def aes_encrypt(msg) :
    """Encrypt with AES-GCM"""
    key = get_random_bytes(16)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)
    return {'ciphertext' : ct, 'tag' : tag, 'nonce' : nonce, 'key' : key}


def chacha_encrypt(msg) :
    """Encrypt with ChaCha20-Poly1305"""
    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)
    return {'ciphertext' : ct, 'tag' : tag, 'nonce' : nonce, 'key' : key}


def count_bit_differences(bytes1, bytes2) :
    """Count how many bits are different between two byte sequences"""
    diff_count = 0
    for b1, b2 in zip(bytes1, bytes2) :
        xor = b1 ^ b2
        diff_count += bin(xor).count('1')
    return diff_count


def test_avalanche_effect(enc_fn, msg_size=64, num_tests=100) :
    """Test avalanche effect: 1-bit input change should flip ~50% of output bits"""
    percentages = []

    for _ in range(num_tests) :
        # Create original message
        msg1 = get_random_bytes(msg_size)

        # Create modified message (flip 1 random bit)
        msg2 = bytearray(msg1)
        byte_pos = random.randint(0, len(msg2) - 1)
        bit_pos = random.randint(0, 7)
        msg2[byte_pos] ^= (1 << bit_pos)
        msg2 = bytes(msg2)

        # Encrypt both messages
        result1 = enc_fn(msg1)
        result2 = enc_fn(msg2)

        # Count bit differences in ciphertext
        diff_bits = count_bit_differences(result1['ciphertext'], result2['ciphertext'])
        total_bits = len(result1['ciphertext']) * 8
        percentage = (diff_bits / total_bits) * 100

        percentages.append(percentage)

    mean = statistics.mean(percentages)
    stdev = statistics.stdev(percentages) if len(percentages) > 1 else 0.0

    return mean, stdev


def calculate_entropy(data) :
    """Calculate Shannon entropy of byte sequence"""
    if len(data) == 0 :
        return 0.0

    # Count frequency of each byte value (0-255)
    freq = [0] * 256
    for byte in data :
        freq[byte] += 1

    # Calculate Shannon entropy
    length = len(data)
    entropy = 0.0

    for count in freq :
        if count > 0 :
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def test_entropy(enc_fn, msg_sizes=[64, 1024, 10240]) :
    """Test entropy of ciphertext for various message sizes"""
    results = []

    for size in msg_sizes :
        # Create random message
        msg = get_random_bytes(size)

        # Encrypt
        result = enc_fn(msg)

        # Calculate entropy of ciphertext
        entropy = calculate_entropy(result['ciphertext'])

        results.append((size, entropy))

    return results


def run_all_tests() :
    """Run all cryptographic property tests and save results"""

    print("=" * 70)
    print(" " * 15 + "CRYPTOGRAPHIC ANALYSIS TESTS")
    print("=" * 70)
    print("\nTesting AES-GCM vs ChaCha20-Poly1305")
    print("This validates cryptographic properties beyond AEAD guarantees\n")

    # AVALANCHE EFFECT
    print("-" * 70)
    print("TEST 1: AVALANCHE EFFECT")
    print("-" * 70)
    print("\nRunning 100 iterations per algorithm...")

    print("  Testing AES-GCM...")
    aes_avalanche, aes_stdev = test_avalanche_effect(aes_encrypt, msg_size=64, num_tests=100)

    print("  Testing ChaCha20-Poly1305...")
    chacha_avalanche, chacha_stdev = test_avalanche_effect(chacha_encrypt, msg_size=64, num_tests=100)

    print("\nRESULTS:")
    print(f"  AES-GCM:            {aes_avalanche:.2f}% +/- {aes_stdev:.2f}%")
    print(f"  ChaCha20-Poly1305:  {chacha_avalanche:.2f}% +/- {chacha_stdev:.2f}%")

    # ENTROPY ANALYSIS
    print("\n" + "-" * 70)
    print("TEST 2: ENTROPY ANALYSIS")
    print("-" * 70)
    print("\nTesting entropy at 64B, 1KB, 10KB...")

    msg_sizes = [64, 1024, 10240]

    print("  Testing AES-GCM...")
    aes_entropies = test_entropy(aes_encrypt, msg_sizes)

    print("  Testing ChaCha20-Poly1305...")
    chacha_entropies = test_entropy(chacha_encrypt, msg_sizes)

    print("\nRESULTS:")
    print(f"\n  {'Message Size':<15} {'AES-GCM':<10} {'ChaCha20-Poly1305'}")
    print("  " + "-" * 45)

    for (size_a, ent_a), (size_c, ent_c) in zip(aes_entropies, chacha_entropies) :
        if size_a < 1024 :
            size_str = f"{size_a}B"
        else :
            size_str = f"{size_a // 1024}KB"
        print(f"  {size_str:<15} {ent_a:<10.4f} {ent_c}")

    # SAVE TO CSV
    print("\n" + "=" * 70)
    print("SAVING RESULTS TO CSV")
    print("=" * 70)

    with open("crypto_results.csv", "w", newline='') as f :
        writer = csv.writer(f)
        writer.writerow(["Metric", "AES-GCM", "AES_StdDev", "ChaCha20-Poly1305", "ChaCha_StdDev"])

        # Avalanche row
        writer.writerow(["Avalanche_%", aes_avalanche, aes_stdev, chacha_avalanche, chacha_stdev])

        # Entropy rows
        for i, ((size, aes_ent), (_, chacha_ent)) in enumerate(zip(aes_entropies, chacha_entropies)) :
            if size < 1024 :
                size_label = f"Entropy_{size}B"
            else :
                size_label = f"Entropy_{size // 1024}KB"
            writer.writerow([size_label, aes_ent, 0, chacha_ent, 0])

    print("\nSaved: crypto_results.csv")

    # ALSO SAVE TEXT FILE (for reference)
    with open("crypto_Analysis_results.txt", "w", encoding="utf-8") as f :
        f.write("CRYPTOGRAPHIC PROPERTY TEST RESULTS\n")
        f.write("=" * 70 + "\n\n")
        f.write("AVALANCHE EFFECT:\n")
        f.write(f"  AES-GCM:            {aes_avalanche:.2f}% +/- {aes_stdev:.2f}%\n")
        f.write(f"  ChaCha20-Poly1305:  {chacha_avalanche:.2f}% +/- {chacha_stdev:.2f}%\n\n")
        f.write("ENTROPY ANALYSIS:\n")
        for (size, aes_ent), (_, chacha_ent) in zip(aes_entropies, chacha_entropies) :
            if size < 1024 :
                size_str = f"{size}B"
            else :
                size_str = f"{size // 1024}KB"
            f.write(f"  {size_str:<6} AES={aes_ent:.4f}  ChaCha={chacha_ent:.4f}\n")

    print("Saved: crypto_analysis_results.txt")

    print("\n" + "=" * 70)
    print("COMPLETE! Results saved to:")
    print("  - crypto_results.csv (for graphs)")
    print("  - crypto_analysis_results.txt")
    print("=" * 70 + "\n")


if __name__ == "__main__" :
    print("\nCRYPTOGRAPHIC PROPERTY TESTS")

    run_all_tests()

    print("Testing complete!\n")