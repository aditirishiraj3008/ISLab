"""1. Encrypt the message "I am learning information security" using each of the following
ciphers. Ignore the space between words. Decrypt the message to get the original
plaintext:
a) Additive cipher with key = 20
b) Multiplicative cipher with key = 15`
c) Affine cipher with key = (15, 20)"""

alphabet = "abcdefghijklmnopqrstuvwxyz"

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No modular inverse")

def additive_cipher(plaintext, key, mode="encrypt"):
    result = ""
    for ch in plaintext:
        ix = alphabet.index(ch)
        if mode == "encrypt":
            result += alphabet[(ix + key) % 26]
        else:
            result += alphabet[(ix - key) % 26]
    return result

def multiplicative_cipher(plaintext, key, mode="encrypt"):
    result = ""
    inv = modinv(key, 26) if mode == "decrypt" else None
    for ch in plaintext:
        ix = alphabet.index(ch)
        if mode == "encrypt":
            result += alphabet[(ix * key) % 26]
        else:
            result += alphabet[(ix * inv) % 26]
    return result

def affine_cipher(plaintext, keys, mode="encrypt"):
    a, b = keys
    inv = modinv(a, 26) if mode == "decrypt" else None
    result = ""
    for ch in plaintext:
        ix = alphabet.index(ch)
        if mode == "encrypt":
            result += alphabet[(a * ix + b) % 26]
        else:
            result += alphabet[(inv * (ix - b)) % 26]
    return result

plaintext = "I am learning information security".lower().replace(" ", "")
additive_key = 20
multiplicative_key = 15
affine_key = (15, 20)

add_enc = additive_cipher(plaintext, additive_key, "encrypt")
add_dec = additive_cipher(add_enc, additive_key, "decrypt")
print("Additive Cipher:      ", add_enc, "->", add_dec)

mul_enc = multiplicative_cipher(plaintext, multiplicative_key, "encrypt")
mul_dec = multiplicative_cipher(mul_enc, multiplicative_key, "decrypt")
print("Multiplicative Cipher:", mul_enc, "->", mul_dec)

aff_enc = affine_cipher(plaintext, affine_key, "encrypt")
aff_dec = affine_cipher(aff_enc, affine_key, "decrypt")
print("Affine Cipher:        ", aff_enc, "->", aff_dec)