"""2. Encrypt the message "Sensitive Information" using AES-128 with the following
key: "0123456789ABCDEF0123456789ABCDEF". Then decrypt the ciphertext to
verify the original message."""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os


def aes_encrypt(plaintext, hex_key):
    # Convert hex key string to bytes (16 bytes = 128 bits)
    key = bytes.fromhex(hex_key)
    # Create random 16-byte IV
    iv = os.urandom(16)
    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Pad plaintext to 16 bytes and encrypt
    padded = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    # Return base64 encoded iv and ciphertext (for display/storage)
    return b64encode(iv).decode('utf-8'), b64encode(ciphertext).decode('utf-8')


def aes_decrypt(b64_iv, b64_ciphertext, hex_key):
    key = bytes.fromhex(hex_key)
    iv = b64decode(b64_iv)
    ciphertext = b64decode(b64_ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_padded, AES.block_size).decode('utf-8')
    return plaintext

message = "Sensitive Information"
key_hex = "0123456789ABCDEF0123456789ABCDEF"
iv_b64, ciphertext_b64 = aes_encrypt(message, key_hex)
print("IV (base64):", iv_b64)
print("Ciphertext (base64):", ciphertext_b64)
decrypted_message = aes_decrypt(iv_b64, ciphertext_b64, key_hex)
print("Decrypted message:", decrypted_message)


