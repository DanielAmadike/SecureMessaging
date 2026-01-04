
import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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



# next
