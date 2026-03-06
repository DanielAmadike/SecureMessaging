"""
Secure Messaging System
Full two-way messaging with test vector validation.

Features:
  1. NIST/RFC Test Vector Validation (proves correctness)
  2. Two-way messaging (Alice <-> Bob)
  3. Key Exchange
  4. Message Encryption/Decryption
  5. Digital Signatures (sender authentication)
  6. Message Storage (persistence)
  7. Complete send/receive workflow
"""

import time
import json
import os
import hashlib
import uuid
from datetime import datetime
from Crypto.Cipher import AES, ChaCha20, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from dataclasses import dataclass



# VALIDATION (NIST + RFC 8439 Test Vectors)


def validate_aes() :
    """
    Validates AES using NIST FIPS 197 Known Answer Test (KAT)
    Source: NIST Cryptographic Algorithm Validation Program
    """
    key = bytes.fromhex("00000000000000000000000000000000")
    plaintext = bytes.fromhex("f34481ec3cc627bacd5dc3fb08f273e6")
    expected = bytes.fromhex("0336763e966d92595a567cc9ce537f5e")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext) == expected


def validate_chacha20() :
    """
    Validates ChaCha20 using RFC 8439 Section 2.4.2 test vector
    Source: IETF RFC 8439
    """
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
    """
    Runs both validations and prints results.
    Program stops if either fails.
    """
    print("=" * 65)
    print("VALIDATION - Official Test Vectors")
    print("=" * 65)

    aes_ok = validate_aes()
    chacha_ok = validate_chacha20()

    print(f"  AES     (NIST FIPS 197)  : {'PASS' if aes_ok else 'FAIL ✗'}")
    print(f"  ChaCha20 (RFC 8439)      : {'PASS' if chacha_ok else 'FAIL ✗'}")
    print("=" * 65)

    if not (aes_ok and chacha_ok) :
        print("\n  ERROR: Validation failed. Stopping.")
        print("  Fix implementation before using.\n")
        raise SystemExit(1)

    print("  Both implementations validated. Safe to use.\n")



# KEY MANAGEMENT


class KeyManager :
    """
    Manages encryption keys for secure messaging.
    """

    @staticmethod
    def derive_key_from_password(password: str, algorithm="AES") :
        """
        Derives encryption key from shared password.
        Both users derive same key from same password.
        """
        key_size = 16 if algorithm == "AES" else 32
        key = hashlib.sha256(password.encode()).digest()[:key_size]
        return key

    @staticmethod
    def generate_keypair() :
        """
        Generates RSA keypair for digital signatures.
        """
        key = RSA.generate(2048)
        private_key = key
        public_key = key.publickey()
        return private_key, public_key



# MESSAGE STRUCTURE


@dataclass
class SecureMessage :
    """Structured message format"""
    message_id: str
    sender: str
    receiver: str
    timestamp: float
    ciphertext: str
    nonce: str
    tag: str
    algorithm: str
    signature: str = None

    def to_dict(self) :
        return {
            'message_id' : self.message_id,
            'sender' : self.sender,
            'receiver' : self.receiver,
            'timestamp' : self.timestamp,
            'datetime' : datetime.fromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            'ciphertext' : self.ciphertext,
            'nonce' : self.nonce,
            'tag' : self.tag,
            'algorithm' : self.algorithm,
            'signature' : self.signature
        }



# ENCRYPTION / DECRYPTION


def encrypt_message(plaintext: str, key: bytes, algorithm="AES") :
    """Encrypts message with chosen algorithm"""
    if algorithm == "AES" :
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    else :  # ChaCha20
        nonce = get_random_bytes(12)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

    return {
        'ciphertext' : ciphertext,
        'nonce' : nonce,
        'tag' : tag
    }


def decrypt_message(ciphertext: bytes, nonce: bytes, tag: bytes, key: bytes, algorithm="AES") :
    """Decrypts message and verifies authentication"""
    if algorithm == "AES" :
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    else :  # ChaCha20
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode()



# DIGITAL SIGNATURES


def sign_message(message_text: str, private_key) :
    """Signs message with sender's private key"""
    h = SHA256.new(message_text.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature.hex()


def verify_signature(message_text: str, signature_hex: str, public_key) :
    """Verifies message signature"""
    try :
        h = SHA256.new(message_text.encode())
        signature = bytes.fromhex(signature_hex)
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except :
        return False


# MESSAGE STORAGE (SHARED DATABASE)


class MessageDatabase :
    """
    Shared message storage for all users.
    Simulates centralized server/database.
    """

    def __init__(self, filename="messages_database.json") :
        self.filename = filename

    def save_message(self, message: SecureMessage) :
        """Saves encrypted message to shared database"""
        messages = self.load_all_messages()
        messages.append(message.to_dict())

        with open(self.filename, 'w') as f :
            json.dump(messages, f, indent=2)

        print(f"   Message saved to database (ID: {message.message_id[:8]}...)")

    def load_all_messages(self) :
        """Loads all stored messages"""
        if not os.path.exists(self.filename) :
            return []

        with open(self.filename, 'r') as f :
            return json.load(f)

    def get_messages_for_user(self, username: str) :
        """Retrieves all messages sent TO a specific user"""
        all_messages = self.load_all_messages()
        user_messages = [m for m in all_messages if m['receiver'] == username]
        return user_messages



# USER CLASS (Can Send AND Receive)


class MessagingUser :
    """
    Complete messaging user - can SEND and RECEIVE messages.
    """
    # Shared database and public key registry
    database = MessageDatabase()
    public_keys = {}  # username -> public_key mapping

    def __init__(self, username: str) :
        self.username = username
        self.private_key, self.public_key = KeyManager.generate_keypair()
        self.shared_keys = {}  # other_user -> {key, algorithm}

        # Register public key so others can verify signatures
        MessagingUser.public_keys[username] = self.public_key

        print(f" User '{username}' initialized")

    def establish_shared_key(self, other_user: str, password: str, algorithm="ChaCha20") :
        """
        Establishes shared encryption key with another user.
        Both users must use same password.
        """
        key = KeyManager.derive_key_from_password(password, algorithm)
        self.shared_keys[other_user] = {'key' : key, 'algorithm' : algorithm}
        print(f"   {self.username} established shared key with {other_user} ({algorithm})")
        return key

    def send_message(self, receiver: str, plaintext: str) :
        """
        Sends encrypted message to receiver.
        Complete workflow: encrypt -> sign -> store
        """
        # Check shared key exists
        if receiver not in self.shared_keys :
            print(f"  ✗ Error: {self.username} has no shared key with {receiver}")
            print(f"    Use establish_shared_key() first")
            return None

        key_info = self.shared_keys[receiver]
        key = key_info['key']
        algorithm = key_info['algorithm']

        print(f"\n  [Encryption Process]")
        print(f"  1. Encrypting with {algorithm}...")
        # Encrypt
        encrypted = encrypt_message(plaintext, key, algorithm)

        print(f"  2. Signing with RSA-2048...")
        # Sign
        signature = sign_message(plaintext, self.private_key)

        print(f"  3. Storing encrypted message...")
        # Create message
        message = SecureMessage(
            message_id=str(uuid.uuid4()),
            sender=self.username,
            receiver=receiver,
            timestamp=time.time(),
            ciphertext=encrypted['ciphertext'].hex(),
            nonce=encrypted['nonce'].hex(),
            tag=encrypted['tag'].hex(),
            algorithm=algorithm,
            signature=signature
        )

        # Save to database
        MessagingUser.database.save_message(message)

        print(f"   Message encrypted and sent to {receiver}")
        print(f"    Algorithm: {algorithm}")
        print(f"    Authenticated: Yes (RSA signature)")
        return message

    def check_messages(self) :
        """
        Checks for new messages sent TO this user.
        """
        messages = MessagingUser.database.get_messages_for_user(self.username)

        if not messages :
            print(f"  No messages for {self.username}")
            return []

        print(f"\n  Messages for {self.username} ({len(messages)} total):")
        print(f"  {'-' * 60}")

        for i, msg in enumerate(messages, 1) :
            print(f"  [{i}] From: {msg['sender']:<10} | Time: {msg['datetime']}")

        return messages

    def read_message(self, message_index: int) :
        """
        Decrypts and reads a specific message.
        """
        messages = MessagingUser.database.get_messages_for_user(self.username)

        if message_index < 1 or message_index > len(messages) :
            print(f"  ✗ Invalid message number")
            return

        msg_data = messages[message_index - 1]
        sender = msg_data['sender']

        # Check shared key
        if sender not in self.shared_keys :
            print(f"  ✗ Error: {self.username} has no shared key with {sender}")
            return

        key_info = self.shared_keys[sender]
        key = key_info['key']
        algorithm = msg_data['algorithm']

        # Decrypt
        print(f"\n  [Decryption Process]")
        print(f"  1. Decrypting with {algorithm}...")
        try :
            plaintext = decrypt_message(
                bytes.fromhex(msg_data['ciphertext']),
                bytes.fromhex(msg_data['nonce']),
                bytes.fromhex(msg_data['tag']),
                key,
                algorithm
            )
            print(f"  Decryption successful")
        except Exception as e :
            print(f"  ✗ Decryption failed: {e}")
            print(f"  Message may have been tampered with!")
            return

        # Verify signature
        print(f"  2. Verifying RSA-2048 signature...")
        sender_public_key = MessagingUser.public_keys.get(sender)
        if sender_public_key and msg_data.get('signature') :
            is_authentic = verify_signature(plaintext, msg_data['signature'], sender_public_key)
            if is_authentic :
                print(f"   Signature valid - sender authenticated")
                auth_status = " Verified"
            else :
                print(f"  ✗ WARNING: Invalid signature - possible forgery!")
                auth_status = "✗ INVALID!"
        else :
            auth_status = "? No signature"

        # Display
        print(f"\n  {'-' * 60}")
        print(f"  From: {sender}")
        print(f"  Time: {msg_data['datetime']}")
        print(f"  Auth: {auth_status}")
        print(f"  {'-' * 60}")
        print(f"  {plaintext}")
        print(f"  {'-' * 60}\n")

        return plaintext


# DEMO: TWO-WAY MESSAGING

def demo_two_way_messaging() :
    """
    Demonstrates complete two-way messaging.
    Alice and Bob can BOTH send and receive.
    """

    print("TWO-WAY SECURE MESSAGING DEMO")
    print("-" * 70)

    # Validate encryption first
    run_validation()

    print("=" * 70)
    print("SCENARIO: Alice and Bob exchange encrypted messages")
    print("=" * 70)

    # Initialize users
    print("\n[1] Creating users...")
    alice = MessagingUser("Alice")
    bob = MessagingUser("Bob")

    # Establish shared keys (both directions)
    print("\n[2] Establishing shared keys...")
    shared_password = "SecretPassword123"
    alice.establish_shared_key("Bob", shared_password, algorithm="ChaCha20")
    bob.establish_shared_key("Alice", shared_password, algorithm="ChaCha20")

    # Alice sends to Bob
    print("\n[3] Alice sends message to Bob...")
    alice.send_message("Bob", "Hey Bob! Meeting at 3pm tomorrow?")

    # Bob checks messages
    print("\n[4] Bob checks his messages...")
    bob.check_messages()

    input("\nPress Enter to let Bob read the message...")

    # Bob reads Alice's message
    print("\n[5] Bob reads message #1...")
    bob.read_message(1)

    input("Press Enter to let Bob reply...")

    # Bob sends reply to Alice
    print("\n[6] Bob sends reply to Alice...")
    bob.send_message("Alice", "Sounds good! See you at 3pm in Richmond.")

    # Alice checks messages
    print("\n[7] Alice checks her messages...")
    alice.check_messages()

    input("\nPress Enter to let Alice read Bob's reply...")

    # Alice reads Bob's reply
    print("\n[8] Alice reads message #1...")
    alice.read_message(1)

    # Another exchange
    input("\nPress Enter for another exchange...")

    print("\n[9] Alice sends another message...")
    alice.send_message("Bob", "Great! Don't forget to bring the documents.")

    print("\n[10] Bob checks messages again...")
    bob.check_messages()

    input("\nPress Enter to let Bob read message #2...")

    print("\n[11] Bob reads message #2...")
    bob.read_message(2)

    print("\n" + "=" * 70)
    print("TWO-WAY MESSAGING DEMO COMPLETE")
    print("=" * 70)
    print("\nDemonstrated:")
    print("   NIST/RFC test vector validation")
    print("   Alice -> Bob messaging")
    print("   Bob -> Alice messaging (reply)")
    print("   Multiple messages in both directions")
    print("   Encryption with ChaCha20-Poly1305")
    print("   Digital signature verification")
    print("   Shared message database")
    print("   Complete two-way workflow")



# INTERACTIVE MODE


def interactive_mode() :
    """
    Interactive two-way messaging.
    Can simulate multiple users sending/receiving.
    """
    print("\n" + "=" * 70)
    print("INTERACTIVE SECURE MESSAGING")
    print("=" * 70)

    # Validate first
    run_validation()

    # Create users
    print("\n" + "=" * 70)
    print("STEP 1: CREATE USERS")
    print("=" * 70)
    user1_name = input("User 1 name: ")
    user2_name = input("User 2 name: ")

    user1 = MessagingUser(user1_name)
    user2 = MessagingUser(user2_name)

    # Establish shared keys - MANDATORY
    print("\n" + "=" * 70)
    print("STEP 2: ESTABLISH SHARED ENCRYPTION KEY")
    print("=" * 70)
    print(f"Both {user1_name} and {user2_name} need a shared secret to encrypt messages.")
    print("This simulates secure key exchange (like Diffie-Hellman).")

    password = input(f"\nShared password for {user1_name} ↔ {user2_name}: ")

    print("\nAvailable algorithms:")
    print("  1. AES-GCM (128-bit, hardware-accelerated)")
    print("  2. ChaCha20-Poly1305 (256-bit, software-optimized)")
    algo_choice = input("Select algorithm (1/2) [2]: ").strip() or "2"
    algorithm = "AES" if algo_choice == "1" else "ChaCha20"

    print(f"\n[Key Exchange]")
    user1.establish_shared_key(user2_name, password, algorithm)
    user2.establish_shared_key(user1_name, password, algorithm)

    print("\n" + "=" * 70)
    print(" SECURE CHANNEL ESTABLISHED")
    print("=" * 70)
    print(f"  Encryption: {algorithm}")
    print(f"  Key Length: {'128-bit' if algorithm == 'AES' else '256-bit'}")
    print(f"  Authentication: {'GCM' if algorithm == 'AES' else 'Poly1305'}")
    print(f"  Digital Signatures: RSA-2048")
    print("=" * 70)

    input("\nPress Enter to start messaging...\n")

    # Messaging loop
    current_user = user1
    current_name = user1_name
    other_user = user2
    other_name = user2_name
    system_algorithm = algorithm

    while True :
        print(f"\n{'-' * 70}")
        print(f"Current user: {current_name}")
        print(f"{'-' * 70}")
        print(f"Security: Encrypted with {system_algorithm} + Digital Signatures")
        print(f"{'-' * 70}")
        print("1. Send message")
        print("2. Check messages")
        print("3. Read message")
        print("4. Switch user")
        print("5. Exit")

        choice = input("\nOption: ")

        if choice == "1" :
            msg = input(f"Message to {other_name}: ")
            current_user.send_message(other_name, msg)

        elif choice == "2" :
            current_user.check_messages()

        elif choice == "3" :
            try :
                msg_num = int(input("Message number (e.g., 1, 2, 3): "))
                current_user.read_message(msg_num)
            except ValueError :
                print("  ✗ Please enter a number (1, 2, 3, etc.), not the message ID!")

        elif choice == "4" :
            # Switch users
            current_user, other_user = other_user, current_user
            current_name, other_name = other_name, current_name
            print(f"\n Switched to {current_name}")

        elif choice == "5" :
            print("\nExiting. Goodbye!")
            break



# MAIN


if __name__ == "__main__" :
    print("=" * 70)
    print("COMPLETE SECURE MESSAGING SYSTEM - FINAL")


    print("\nFeatures:")
    print("   NIST/RFC test vector validation")
    print("   Two-way messaging (Alice <-> Bob)")
    print("   AES-GCM and ChaCha20-Poly1305 encryption")
    print("   Digital signatures (sender authentication)")
    print("   Shared message database")

    print("\nOptions:")
    print("  1. Demo mode (see complete two-way workflow)")
    print("  2. Interactive mode (send/receive messages)")

    mode = input("\nSelect mode (1/2): ")

    if mode == "2" :
        interactive_mode()
    else :
        demo_two_way_messaging()
