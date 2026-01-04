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

