
import time


from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pyexpat.errors import messages


# AES ENCRYPTION FUNCTION

def encrypt_aes(plaintext):
    """
    Encrypts a plaintext message using AES
    and measures the encryption time.
    """
    # Generate a random 128-bit (16-byte) AES key
    key = get_random_bytes(16)

    # Create a new AES cipher object in GCM mode
    cipher = AES.new(key, AES.MODE_GCM)

    #Encrypt the plaintext
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

    # Start timing encryption
    start = time.time()

    #End time
    end = time.time()

    return {
        "ciphertext": ciphertext,
        "tag": tag,
        "nonce": key,
        "time": end - start
    }



# AES Decryption Function

def decrypt_aes(data):
    """

    Decrypts AES ciphertext and verifies integrity
    using the authentication tag
    """
    # Recrates cipher sung same key and nonce
    cipher = AES.new(data["key"], AES.MODE_GCM, nonce=data["nonce"])

    # Start decryption timing
    start = time.time()\

    # Decrypts and verifies ciphertext
    plaintext = cipher.decrypt_and_verify(data["ciphertext"], data["tag"])

    # End timing decryption
    end = time.time()

    return plaintext.decode(), end - start




print("Secure Messaging prototype\n")

# Ask user for input
message = input("Enter your Message: ")

print("\nChoose algorithm:")
print("1. AES")
print("2. Chacha20")
choice = input("Enter 1 0r 2: ")

# If Aes is selected
if choice == "1":
    print("\n AES Selected ")

    # Encrypts message
    encrypted = encrypt_aes(message)

    # Decrypts message
    decrypted_text, dec_time = decrypt_aes(encrypted)

    # Display results
    print("\nCiphertext:", encrypted["ciphertext"])
    print("Decrypted Text:", decrypted_text)
    print(f"AES Encryption Time: {encrypted['time']:.6f} seconds")
    print(f"AES Decryption Time: {dec_time:.6f} seconds")
