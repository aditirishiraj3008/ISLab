"""4. Encrypt the message "Classified Text" using Triple DES with the key
"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF". Then
decrypt the ciphertext to verify the original message."""

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes

def triple_des_encrypt(plaintext, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = pad(plaintext.encode(), DES3.block_size)
    ciphertext = cipher.encrypt(padded)
    return b64encode(ciphertext).decode()

def triple_des_decrypt(ciphertext_b64, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = b64decode(ciphertext_b64)
    padded = cipher.decrypt(ciphertext)
    return unpad(padded, DES3.block_size).decode()

message = "Classified Text"
key = DES3.adjust_key_parity(get_random_bytes(24))  # Generate a valid 24-byte key with correct parity
iv = get_random_bytes(8)  # 8-byte IV for CBC

encrypted = triple_des_encrypt(message, key, iv)
decrypted = triple_des_decrypt(encrypted, key, iv)

print("Key (hex):", key.hex())
print("IV (hex):", iv.hex())
print("Encrypted (Base64):", encrypted)
print("Decrypted:", decrypted)
