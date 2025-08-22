"""2. Using ECC (Elliptic Curve Cryptography), encrypt the message "Secure
Transactions" with the public key. Then decrypt the ciphertext with the private key
to verify the original message."""

from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii

def aes_gcm_encrypt(msg, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(msg)
    return ct, cipher.nonce, tag

def aes_gcm_decrypt(ct, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    return cipher.decrypt_and_verify(ct, tag)

def ecc_key_from_point(p):
    h = hashlib.sha256(int.to_bytes(p.x, 32, 'big'))
    h.update(int.to_bytes(p.y, 32, 'big'))
    return h.digest()

curve = registry.get_curve('brainpoolP256r1')

def ecc_encrypt(msg, pub):
    k = secrets.randbelow(curve.field.n)
    shared = k * pub
    key = ecc_key_from_point(shared)
    ct, nonce, tag = aes_gcm_encrypt(msg, key)
    return ct, nonce, tag, k * curve.g

def ecc_decrypt(enc_msg, priv):
    ct, nonce, tag, pub = enc_msg
    shared = priv * pub
    key = ecc_key_from_point(shared)
    return aes_gcm_decrypt(ct, nonce, tag, key)

msg = b"Secure Transactions"
priv = secrets.randbelow(curve.field.n)
pub = priv * curve.g

print("Original:", msg)
enc = ecc_encrypt(msg, pub)
print("Encrypted:", binascii.hexlify(enc[0]))
dec = ecc_decrypt(enc, priv)
print("Decrypted:", dec)
