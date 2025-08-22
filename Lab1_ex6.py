"""Use a brute-force attack to decipher the following message. Assume that you know it is
an affine cipher and that the plaintext "ab" is enciphered to "GL":
XPALASXYFGFUKPXUSOGEUTKCDGFXANMGNVS"""

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def modinv(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_decrypt(ciphertext, a, b):
    a_inv = modinv(a, 26)
    if a_inv is None:
        raise ValueError("No modular inverse")
    plaintext = ""
    for ch in ciphertext:
        if ch in alphabet:
            ix = alphabet.index(ch)
            p_ix = (a_inv * (ix - b)) % 26
            plaintext += alphabet[p_ix]
        else:
            plaintext += ch
    return plaintext

def find_affine_key(plain_pair, cipher_pair):
    p1, p2 = plain_pair
    c1, c2 = cipher_pair
    p1_ix = alphabet.index(p1)
    p2_ix = alphabet.index(p2)
    c1_ix = alphabet.index(c1)
    c2_ix = alphabet.index(c2)

    possible_keys = []
    for a_candidate in range(1, 26):
        if modinv(a_candidate, 26) is None:
            continue
        for b_candidate in range(26):
            if (a_candidate * p1_ix + b_candidate) % 26 == c1_ix and \
               (a_candidate * p2_ix + b_candidate) % 26 == c2_ix:
                possible_keys.append((a_candidate, b_candidate))
    return possible_keys

ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGFXANMGNVS"

plain_pair = "AB"
cipher_pair = "GL"
keys = find_affine_key(plain_pair, cipher_pair)

print("Possible keys (a,b) for plaintext: 'AB' -> ciphertext :'GL':", keys)

for a, b in keys:
    decrypted = affine_decrypt(ciphertext, a, b)
    print(f"Decrypted with a={a}, b={b}:")
    print(decrypted)
