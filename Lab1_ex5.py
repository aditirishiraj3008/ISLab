"""5. John is reading a mystery book involving cryptography. In one part of the book, the
author gives a ciphertext "CIW" and two paragraphs later the author tells the reader that
this is a shift cipher and the plaintext is "yes". In the next chapter, the hero found a tablet
in a cave with "XVIEWYVI" engraved on it. John immediately found the actual meaning
of the ciphertext. Identify the type of attack and plaintext."""

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def caesar_decrypt(ciphertext, shift):
    plaintext = ""
    for ch in ciphertext:
        if ch in alphabet:
            ix = alphabet.index(ch)
            plain_ix = (ix - shift) % 26
            plaintext += alphabet[plain_ix]
        else:
            plaintext += ch
    return plaintext

ciphertext_known = "CIW"
plaintext_known = "YES"

def find_shift_key(plain, cipher):
    shift = (alphabet.index(cipher[0]) - alphabet.index(plain[0])) % 26
    return shift

shift_key = find_shift_key(plaintext_known, ciphertext_known)
print("Shift key: ", shift_key)
tablet_ciphertext = "XVIEWYVI"
decrypted_text = caesar_decrypt(tablet_ciphertext, shift_key)
print("Decrypted plaintext: ", decrypted_text)
