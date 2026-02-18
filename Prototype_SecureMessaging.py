from Crypto.Cipher import AES, ChaCha20, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import time



# CORRECTNESS VALIDATION (TEST VECTORS.)

# AES (AESAVS)
def validate_aes():
    print("Running AES validation test (AESAVS")

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


# ChaCha20 (RFC 8439)

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
        raise SystemExit("ERROR: One or more validations failed. Fix before proceeding.")


# Run validation once when program starts
run_validation_or_exit()



# 2) SECURE MESSAGING PROTOTYPE (AEAD)
#  AES
#  ChaCha20

def aes_gcm_encrypt_decrypt(message: str):
    key = get_random_bytes(16)              # AES-128
    cipher = AES.new(key, AES.MODE_GCM)

    start_enc = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    end_enc = time.time()

    nonce = cipher.nonce

    cipher_dec = AES.new(key, AES.MODE_GCM, nonce=nonce)
    start_dec = time.time()
    decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)
    end_dec = time.time()

    return decrypted.decode(), end_enc - start_enc, end_dec - start_dec


def chacha20_poly1305_encrypt_decrypt(message: str):
    key = get_random_bytes(32)
    nonce = get_random_bytes(12)  # is 96 bit

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

    start_enc = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    end_enc = time.time()

    cipher_dec = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    start_dec = time.time()
    decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)
    end_dec = time.time()

    return decrypted.decode(), end_enc - start_enc, end_dec - start_dec


def main():
    print("Secure Messaging Prototype (AEAD)")
    message = input("Enter a message: ")

    print("\nChoose encryption method:")
    print("1. AES")
    print("2. ChaCha20")
    choice = input("Enter choice: ").strip()

    if choice == "1":
        decrypted, enc_time, dec_time = aes_gcm_encrypt_decrypt(message)
        print(f"\nDecrypted Message: {decrypted}")
        print(f"AES Encryption Time: {enc_time:.6f} seconds")
        print(f"AES Decryption Time: {dec_time:.6f} seconds")

    elif choice == "2":
        decrypted, enc_time, dec_time = chacha20_poly1305_encrypt_decrypt(message)
        print(f"\nDecrypted Message: {decrypted}")
        print(f"ChaCha20 Encryption Time: {enc_time:.6f} seconds")
        print(f"ChaCha20 Decryption Time: {dec_time:.6f} seconds")

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
