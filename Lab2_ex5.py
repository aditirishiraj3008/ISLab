"""5. Encrypt the message "Top Secret Data" using AES-192 with the key
"FEDCBA9876543210FEDCBA9876543210". Show all the steps involved in the
encryption process (key expansion, initial round, main rounds, final round)."""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

# AES-192 key (48 hex chars = 24 bytes)
key_hex = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
key = bytes.fromhex(key_hex)

plaintext = b"Top Secret Data"  # 15 bytes
BLOCK_SIZE = 16
padded_plaintext = pad(plaintext, BLOCK_SIZE)

print(f"Plaintext (padded): {padded_plaintext}")
print(f"Key length: {len(key)} bytes")
print(f"Key (hex): {key_hex}")

cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(padded_plaintext)
print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")



