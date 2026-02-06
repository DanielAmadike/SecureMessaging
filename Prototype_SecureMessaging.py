import time

# Import cryptographic algorithms from PyCryptodome
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes


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

