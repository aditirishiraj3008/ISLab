"""4. Design and implement a secure file transfer system using RSA (2048-bit) and ECC
(secp256r1 curve) public key algorithms. Generate and exchange keys, then
encrypt and decrypt files of varying sizes (e.g., 1 MB, 10 MB) using both
algorithms. Measure and compare the performance in terms of key generation
time, encryption/decryption speed, and computational overhead. Evaluate the
security and efficiency of each algorithm in the context of file transfer, considering
factors such as key size, storage requirements, and resistance to known attacks.
Document your findings, including performance metrics and a summary of the
strengths and weaknesses of RSA and ECC for secure file transfer."""

import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from tinyec import registry
import hashlib
import secrets

# ECC helper function to derive AES key from shared secret
def ecc_derive_key(priv_key, pub_key):
    shared_point = priv_key * pub_key
    sha = hashlib.sha256(int.to_bytes(shared_point.x, 32, 'big'))
    sha.update(int.to_bytes(shared_point.y, 32, 'big'))
    return sha.digest()

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, cipher.nonce, tag

def aes_decrypt(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def generate_rsa_keys():
    start = time.time()
    rsa_key = RSA.generate(2048)
    return rsa_key, time.time() - start

def generate_ecc_keys():
    curve = registry.get_curve('secp256r1')
    start = time.time()
    priv_key = secrets.randbelow(curve.field.p - 1) + 1  # Random private key
    pub_key = priv_key * curve.g
    return priv_key, pub_key, time.time() - start

def rsa_encrypt_aes_key(aes_key, rsa_public_key):
    cipher = PKCS1_OAEP.new(rsa_public_key)
    return cipher.encrypt(aes_key)

def rsa_decrypt_aes_key(enc_aes_key, rsa_private_key):
    cipher = PKCS1_OAEP.new(rsa_private_key)
    return cipher.decrypt(enc_aes_key)

if __name__ == "__main__":
    # Simulate file data (1MB)
    file_data = os.urandom(1024 * 1024)

    rsa_key, rsa_keygen_time = generate_rsa_keys()
    print(f"RSA key generation time: {rsa_keygen_time:.4f} seconds")
    ecc_priv, ecc_pub, ecc_keygen_time = generate_ecc_keys()
    print(f"ECC key generation time: {ecc_keygen_time:.4f} seconds")
    aes_key = get_random_bytes(32)

    start = time.time()
    enc_aes_key_rsa = rsa_encrypt_aes_key(aes_key, rsa_key.publickey())
    rsa_aes_encrypt_time = time.time() - start
    start = time.time()
    dec_aes_key_rsa = rsa_decrypt_aes_key(enc_aes_key_rsa, rsa_key)
    rsa_aes_decrypt_time = time.time() - start

    curve = registry.get_curve('secp256r1')
    eph_priv = secrets.randbelow(curve.field.p - 1) + 1
    eph_pub = eph_priv * curve.g
    start = time.time()
    shared_key = ecc_derive_key(eph_priv, ecc_pub)
    ecc_key_derive_time = time.time() - start

    start = time.time()
    ciphertext_rsa, nonce_rsa, tag_rsa = aes_encrypt(file_data, dec_aes_key_rsa)
    rsa_file_enc_time = time.time() - start
    start = time.time()
    plaintext_rsa = aes_decrypt(ciphertext_rsa, nonce_rsa, tag_rsa, dec_aes_key_rsa)
    rsa_file_dec_time = time.time() - start
    start = time.time()
    ciphertext_ecc, nonce_ecc, tag_ecc = aes_encrypt(file_data, shared_key)
    ecc_file_enc_time = time.time() - start
    start = time.time()
    plaintext_ecc = aes_decrypt(ciphertext_ecc, nonce_ecc, tag_ecc, shared_key)
    ecc_file_dec_time = time.time() - start

    print(f"RSA AES key encrypt time: {rsa_aes_encrypt_time:.4f} seconds")
    print(f"RSA AES key decrypt time: {rsa_aes_decrypt_time:.4f} seconds")
    print(f"ECC AES key derive time: {ecc_key_derive_time:.4f} seconds")
    print(f"RSA AES file encrypt time: {rsa_file_enc_time:.4f} seconds")
    print(f"RSA AES file decrypt time: {rsa_file_dec_time:.4f} seconds")
    print(f"ECC AES file encrypt time: {ecc_file_enc_time:.4f} seconds")
    print(f"ECC AES file decrypt time: {ecc_file_dec_time:.4f} seconds")

    print("RSA decrypted file matches:", file_data == plaintext_rsa)
    print("ECC decrypted file matches:", file_data == plaintext_ecc)

    print(f"RSA key size (bits): {rsa_key.size_in_bits()}")
    ecc_pub_bytes = ecc_pub.x.to_bytes(32, 'big') + ecc_pub.y.to_bytes(32, 'big')
    print(f"ECC public key size (bytes): {len(ecc_pub_bytes)}")
    print(f"AES key size (bytes): {len(aes_key)}")
