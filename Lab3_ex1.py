"""1. Using RSA, encrypt the message "Asymmetric Encryption" with the public key (n,
e). Then decrypt the ciphertext with the private key (n, d) to verify the original
message."""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

message = b"Asymmetric Encryption"

# Generate RSA key pair (2048 bits)
key = RSA.generate(2048)

public_key = key.publickey()
encryptor = PKCS1_OAEP.new(public_key)

# Encrypt
ciphertext = encryptor.encrypt(message)
print("Ciphertext (bytes):", ciphertext)

# Decrypt
decryptor = PKCS1_OAEP.new(key)
decrypted_message = decryptor.decrypt(ciphertext)
print("Decrypted message:", decrypted_message.decode())
