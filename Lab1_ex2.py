"""2. Encrypt the message "the house is being sold tonight" using each of the following
ciphers. Ignore the space between words. Decrypt the message to get the original
plaintext:
a) Vigenere cipher with key: "dollars"
b) Autokey _cipher with key = 7"""

def remove_spaces(text):
    return ''.join(text.lower().replace(' ', ''))

def letter_to_num(c):
    return ord(c) - ord('a')

def num_to_letter(n):
    return chr((n % 26) + ord('a'))

def vigenere_encrypt(plaintext, key):
    plaintext = remove_spaces(plaintext)
    key = key.lower()
    full_key = (key * (len(plaintext) // len(key) + 1))[:len(plaintext)]
    ciphertext = ''
    for p, k in zip(plaintext, full_key):
        c = (letter_to_num(p) + letter_to_num(k)) % 26
        ciphertext += num_to_letter(c)
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    full_key = (key * (len(ciphertext) // len(key) + 1))[:len(ciphertext)]
    plaintext = ''
    for c, k in zip(ciphertext, full_key):
        p = (letter_to_num(c) - letter_to_num(k)) % 26
        plaintext += num_to_letter(p)
    return plaintext


def autokey_encrypt(plaintext, key_num):
    plaintext = remove_spaces(plaintext)
    ciphertext = ''
    prev = key_num
    for i, p in enumerate(plaintext):
        p_val = letter_to_num(p)
        c = (p_val + prev) % 26
        ciphertext += num_to_letter(c)
        prev = p_val
    return ciphertext

def autokey_decrypt(ciphertext, key_num):
    ciphertext = ciphertext.lower()
    plaintext = ''
    prev = key_num
    for i, c in enumerate(ciphertext):
        c_val = letter_to_num(c)
        p = (c_val - prev) % 26
        plaintext += num_to_letter(p)
        prev = p
    return plaintext

message = "the house is being sold tonight"
vig_key = "dollars"
auto_key_num = 7

vig_cipher = vigenere_encrypt(message, vig_key)
vig_plain = vigenere_decrypt(vig_cipher, vig_key)

auto_cipher = autokey_encrypt(message, auto_key_num)
auto_plain = autokey_decrypt(auto_cipher, auto_key_num)

print("Vigenere Ciphertext:   ", vig_cipher)
print("Vigenere Decryption:   ", vig_plain)
print("Autokey Ciphertext:    ", auto_cipher)
print("Autokey Decryption:    ", auto_plain)
