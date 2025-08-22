"""3. Compare the encryption and decryption times for DES and AES-256 for the
message "Performance Testing of Encryption Algorithms". Use a standard
implementation and report your findings."""

from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import time

def time_cipher(cipher_cls, key, block_size, text):
    cipher = cipher_cls.new(key, cipher_cls.MODE_ECB)
    data = pad(text.encode(), block_size)
    start_enc = time.perf_counter()
    encrypted = cipher.encrypt(data)
    end_enc = time.perf_counter()
    start_dec = time.perf_counter()
    decrypted = unpad(cipher.decrypt(encrypted), block_size)
    end_dec = time.perf_counter()
    return (end_enc - start_enc)*1000, (end_dec - start_dec)*1000

msg = "Performance Testing of Encryption Algorithms"
des_key = b"A1B2C3D4"  # DES key must be 8 bytes
aes_key = b"0123456789ABCDEF0123456789ABCDEF"  # AES-256 key must be 32 bytes

des_enc, des_dec = time_cipher(DES, des_key, DES.block_size, msg)
aes_enc, aes_dec = time_cipher(AES, aes_key, AES.block_size, msg)

print(f"DES Encryption time: {des_enc:.3f} ms")
print(f"DES Decryption time: {des_dec:.3f} ms")
print(f"AES-256 Encryption time: {aes_enc:.3f} ms")
print(f"AES-256 Decryption time: {aes_dec:.3f} ms")

