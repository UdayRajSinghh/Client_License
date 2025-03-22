from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# Function to generate a random AES key (256-bit)
def generate_aes_key():
    # AES supports key sizes of 128, 192, or 256 bits
    key_size = 32  # 256-bit key for AES-256
    aes_key = os.urandom(key_size)  # Generates a random AES key of the specified size
    return aes_key

# Generate and print the AES key
aes_key = generate_aes_key()
print("Generated AES Key:", aes_key.hex())