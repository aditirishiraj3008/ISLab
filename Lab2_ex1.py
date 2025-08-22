"""1. Encrypt the message "Confidential Data" using DES with the following key:
"A1B2C3D4". Then decrypt the ciphertext to verify the original message."""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64

def des_encrypt(message, key):
    des_key = key.encode('utf-8')  # key must be 8 bytes
    cipher = DES.new(des_key, DES.MODE_ECB)
    padded_text = pad(message.encode('utf-8'), DES.block_size)  # pad to 8 bytes
    encrypted_bytes = cipher.encrypt(padded_text)
    # Encode to base64 for readable format
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encrypted_b64

# Function to decrypt ciphertext (base64 encoded) using DES
def des_decrypt(encrypted_b64, key):
    des_key = key.encode('utf-8')
    cipher = DES.new(des_key, DES.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted_b64)
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    decrypted = unpad(decrypted_padded, DES.block_size).decode('utf-8')
    return decrypted

key = "A1B2C3D4"
message = "Confidential Data"
ciphertext = des_encrypt(message, key)
print("Encrypted (Base64):", ciphertext)
decrypted_message = des_decrypt(ciphertext, key)
print("Decrypted message:", decrypted_message)
