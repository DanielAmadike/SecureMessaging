"""
Secure Messaging Prototype with Test Vector Validation
=======================================================
Enhanced version that validates encryption correctness before use
"""

import time
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes


# ============================================================
# TEST VECTOR VALIDATION FUNCTIONS
# ============================================================

def validate_aes() :
    """
    Validate AES implementation against NIST test vector
    Returns True if implementation is correct
    """
    print("\n[Validating AES against NIST test vector...]")

    # NIST FIPS 197 Test Vector
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    plaintext = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    expected_ciphertext = bytes.fromhex('3ad77bb40d7a3660a89ecaf32466ef97')

    # Test AES in ECB mode (simple mode for validation)
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.encrypt(plaintext)

    if result == expected_ciphertext :
        print("✓ AES validation PASSED - Implementation is correct")
        return True
    else :
        print("✗ AES validation FAILED - Implementation has errors")
        print(f"  Expected: {expected_ciphertext.hex()}")
        print(f"  Got:      {result.hex()}")
        return False


def validate_chacha20() :
    """
    Validate ChaCha20 implementation against RFC 8439 test vector
    Returns True if implementation is correct
    """
    print("[Validating ChaCha20 against RFC 8439 test vector...]")

    # RFC 8439 Section 2.4.2 Test Vector
    key = bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    nonce = bytes.fromhex('000000000000004a00000000')
    plaintext = b"Ladies and Gentlemen of the class of '99: If I c"
    expected_ciphertext = bytes.fromhex(
        '6e2e359a2568f98041ba0728dd0d6981'
        'e97e7aec1d4360c20a27afccfd9fae0b'
        'f91b65c5524733ab8f593dabcd62b357'
    )

    # Test ChaCha20
    cipher = ChaCha20.new(key=key, nonce=nonce)
    result = cipher.encrypt(plaintext)

    if result == expected_ciphertext :
        print("✓ ChaCha20 validation PASSED - Implementation is correct")
        return True
    else :
        print("✗ ChaCha20 validation FAILED - Implementation has errors")
        print(f"  Expected: {expected_ciphertext.hex()[:60]}...")
        print(f"  Got:      {result.hex()[:60]}...")
        return False


def run_validation() :
    """
    Run all test vector validations
    Returns True if all tests pass
    """
    print("=" * 70)
    print("CRYPTOGRAPHIC VALIDATION")
    print("=" * 70)

    aes_ok = validate_aes()
    chacha_ok = validate_chacha20()

    print("=" * 70)

    if aes_ok and chacha_ok :
        print("✓✓✓ ALL VALIDATIONS PASSED")
        print("Implementations are cryptographically correct!\n")
        return True
    else :
        print("✗✗✗ VALIDATION FAILED")
        print("Fix implementation errors before using!\n")
        return False


# ============================================================
# ENCRYPTION/DECRYPTION FUNCTIONS (Your Original Code)
# ============================================================

def encrypt_aes(plaintext) :
    """
    Encrypts a plaintext message using AES
    and measures the encryption time.
    """
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM)

    start = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    end = time.time()

    return {
        "ciphertext" : ciphertext,
        "tag" : tag,
        "nonce" : cipher.nonce,
        "key" : key,
        "time" : end - start
    }


def decrypt_aes(data) :
    """
    Decrypts AES ciphertext and verifies integrity
    using the authentication tag.
    """
    cipher = AES.new(data["key"], AES.MODE_GCM, nonce=data["nonce"])

    start = time.time()
    plaintext = cipher.decrypt_and_verify(data["ciphertext"], data["tag"])
    end = time.time()

    return plaintext.decode(), end - start


def encrypt_chacha20(plaintext) :
    """
    Encrypts a plaintext message using ChaCha20
    and measures encryption time.
    """
    key = get_random_bytes(32)
    cipher = ChaCha20.new(key=key)

    start = time.time()
    ciphertext = cipher.encrypt(plaintext.encode())
    end = time.time()

    return {
        "ciphertext" : ciphertext,
        "nonce" : cipher.nonce,
        "key" : key,
        "time" : end - start
    }


def decrypt_chacha20(data) :
    """
    Decrypts ChaCha20 ciphertext and measures
    decryption time.
    """
    cipher = ChaCha20.new(key=data["key"], nonce=data["nonce"])

    start = time.time()
    plaintext = cipher.decrypt(data["ciphertext"])
    end = time.time()

    return plaintext.decode(), end - start


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__" :
    # STEP 1: Validate implementations first
    if not run_validation() :
        print("ERROR: Validation failed. Exiting.")
        exit(1)

    # STEP 2: Run your prototype
    print("=" * 70)
    print("SECURE MESSAGING PROTOTYPE")
    print("=" * 70)

    message = input("\nEnter your message: ")

    print("\nChoose algorithm:")
    print("1. AES")
    print("2. ChaCha20")
    choice = input("Enter 1 or 2: ")

    if choice == "1" :
        print("\n--- AES Selected ---")
        encrypted = encrypt_aes(message)
        decrypted_text, dec_time = decrypt_aes(encrypted)

        print("\nCiphertext:", encrypted["ciphertext"].hex()[:50] + "...")
        print("Decrypted Text:", decrypted_text)
        print(f"Encryption Time: {encrypted['time']:.6f} seconds")
        print(f"Decryption Time: {dec_time:.6f} seconds")

    elif choice == "2" :
        print("\n--- ChaCha20 Selected ---")
        encrypted = encrypt_chacha20(message)
        decrypted_text, dec_time = decrypt_chacha20(encrypted)

        print("\nCiphertext:", encrypted["ciphertext"].hex()[:50] + "...")
        print("Decrypted Text:", decrypted_text)
        print(f"Encryption Time: {encrypted['time']:.6f} seconds")
        print(f"Decryption Time: {dec_time:.6f} seconds")
    else :
        print("Invalid choice. Exiting.")
