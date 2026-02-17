import time

# Import cryptographic algorithms from PyCryptodome
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes

# CORRECTNESS VALIDATION (TEST VECTORS)

# AES (AESAVS)
def validate_aes():
    print("Running AES validation test (AES")

    key = bytes.fromhex("00000000000000000000000000000000")
    plaintext = bytes.fromhex("f34481ec3cc627bacd5dc3fb08f273e6")
    expected_ciphertext = bytes.fromhex("0336763e966d92595a567cc9ce537f5e")

    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.encrypt(plaintext)

    if result == expected_ciphertext:
        print("AES test vector validation: PASS\n")
        return True
    else:
        print("AES test vector validation: FAIL\n")
        return False


# ChaCha20

def validate_chacha20():
    print("Running ChaCha20 test vector (RFC 8439)")

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

    result = cipher.encrypt(plaintext)

    if result == expected:
        print("ChaCha20 test vector validation: PASS\n")
        return True
    else:
        print("ChaCha20 test vector validation: FAIL\n")
        print("Got:     ", result.hex())
        print("Expected:", expected.hex(), "\n")
        return False


def run_validation_or_exit():
    ok_aes = validate_aes()
    ok_chacha = validate_chacha20()
    if not (ok_aes and ok_chacha):
        raise SystemExit("ERROR: One or more validations failed.")


# Run validation once when program starts
run_validation_or_exit()















# AES ENCRYPTION FUNCTION

def encrypt_aes(plaintext):
    """
    Encrypts a plaintext message using AES
    and measures the encryption time.
    """
    # Generate a random 128-bit (16 byte) AES key
    key = get_random_bytes(16)

    # Create a new AES cipher object in GCM mode
    cipher = AES.new(key, AES.MODE_GCM)

    # Start timing encryption
    start = time.time()

    # Encrypt the plaintext and generate authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

    # End timing encryption
    end = time.time()

    # Return all required values for decryption
    return {
        "ciphertext": ciphertext,
        "tag": tag,
        "nonce": cipher.nonce,
        "key": key,
        "time": end - start
    }



# AES DECRYPTION FUNCTION

def decrypt_aes(data):
    """
    Decrypts AES ciphertext and verifies integrity
    using the authentication tag.
    """
    # Recreate AES cipher using the same key and nonce
    cipher = AES.new(data["key"], AES.MODE_GCM, nonce=data["nonce"])

    # Start timing decryption
    start = time.time()

    # Decrypt and verify ciphertext
    plaintext = cipher.decrypt_and_verify(data["ciphertext"], data["tag"])

    # End timing decryption
    end = time.time()

    return plaintext.decode(), end - start



# CHACHA20 ENCRYPTION FUNCTION

def encrypt_chacha20(plaintext):
    """
    Encrypts a plaintext message using ChaCha20
    and measures encryption time.
    """
    # Generate a random 256-bit (32-byte) key for ChaCha20
    key = get_random_bytes(32)

    # Create a new ChaCha20 cipher object
    cipher = ChaCha20.new(key=key)

    # Start timing encryption
    start = time.time()

    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext.encode())

    # End timing encryption
    end = time.time()

    # Return encryption data
    return {
        "ciphertext": ciphertext,
        "nonce": cipher.nonce,
        "key": key,
        "time": end - start
    }



# CHACHA20 DECRYPTION FUNCTION

def decrypt_chacha20(data):
    """
    Decrypts ChaCha20 ciphertext and measures
    decryption time.
    """
    # Recreate ChaCha20 cipher using key and nonce
    cipher = ChaCha20.new(key=data["key"], nonce=data["nonce"])

    # Start timing decryption
    start = time.time()

    # Decrypt the ciphertext
    plaintext = cipher.decrypt(data["ciphertext"])

    # End timing decryption
    end = time.time()

    return plaintext.decode(), end - start



print("Secure Messaging Prototype\n")

# Ask user to input a message
message = input("Enter your message: ")

# Ask user to select encryption algorithm
print("\nChoose algorithm:")
print("1. AES")
print("2. ChaCha20")
choice = input("Enter 1 or 2: ")

# If AES is selected
if choice == "1":
    print("\n--- AES Selected ---")

    # Encrypts the message
    encrypted = encrypt_aes(message)

    # Decrypt the message
    decrypted_text, dec_time = decrypt_aes(encrypted)

    # Display results
    print("\nCiphertext:", encrypted["ciphertext"])
    print("Decrypted Text:", decrypted_text)
    print(f"AES Encryption Time: {encrypted['time']:.6f} seconds")
    print(f"AES Decryption Time: {dec_time:.6f} seconds")

# If ChaCha20 is selected
elif choice == "2":
    print("\n--- ChaCha20 Selected ---")

    # Encrypt the message
    encrypted = encrypt_chacha20(message)

    # Decrypt the message
    decrypted_text, dec_time = decrypt_chacha20(encrypted)

    # Display results
    print("\nCiphertext:", encrypted["ciphertext"])
    print("Decrypted Text:", decrypted_text)
    print(f"ChaCha20 Encryption Time: {encrypted['time']:.6f} seconds")
    print(f"ChaCha20 Decryption Time: {dec_time:.6f} seconds")


# Handle invalid input
else:
    print("Invalid choice. Exiting.")

