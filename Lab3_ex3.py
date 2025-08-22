"""3. Given an ElGamal encryption scheme with a public key (p, g, h) and a private key
x, encrypt the message "Confidential Data". Then decrypt the ciphertext to retrieve
the original message."""

import random

# Modular exponentiation
def power(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

# Modular inverse
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

# Key generation
def generate_keys():
    # A large prime p
    p = 2357  # For demo
    # Primitive root modulo p
    g = 2
    # Private key x (random in [1, p-2])
    x = random.randint(1, p-2)
    # Public key h = g^x mod p
    h = power(g, x, p)
    return (p, g, h), x

def encrypt(public_key, plaintext):
    p, g, h = public_key
    c1_list = []
    c2_list = []
    k = random.randint(1, p-2)  # ephemeral key

    s = power(h, k, p)
    c1 = power(g, k, p)
    for char in plaintext:
        m = ord(char)
        c2 = (m * s) % p
        c1_list.append(c1)
        c2_list.append(c2)
    return (c1_list, c2_list)

# Decryption
def decrypt(private_key, p, ciphertext):
    c1_list, c2_list = ciphertext
    decrypted_chars = []
    for c1, c2 in zip(c1_list, c2_list):
        s = power(c1, private_key, p)
        s_inv = mod_inverse(s, p)
        m = (c2 * s_inv) % p
        decrypted_chars.append(chr(m))
    return ''.join(decrypted_chars)

public_key, private_key = generate_keys()
message = "Confidential Data"
print("Original message:", message)

cipher = encrypt(public_key, message)
print("Ciphertext:", cipher)
decrypted_msg = decrypt(private_key, public_key[0], cipher)
print("Decrypted message:", decrypted_msg)
