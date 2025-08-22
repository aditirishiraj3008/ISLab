"""4. Use a Hill cipher to encipher the message "We live in an insecure world". Use the
following key:
𝐾 = [03 03
02 07]"""

import numpy as np

def preprocess_text(text):
    text = text.replace(" ", "").upper()
    if len(text) % 2 != 0:
        text += 'X'
    return text


def text_to_numbers(text):
    return [ord(c) - ord('A') for c in text]


def numbers_to_text(numbers):
    return ''.join(chr(n + ord('A')) for n in numbers)


def hill_encrypt(plaintext, key_matrix):
    plaintext = preprocess_text(plaintext)
    text_numbers = text_to_numbers(plaintext)

    ciphertext_numbers = []
    for i in range(0, len(text_numbers), 2):
        block = np.array(text_numbers[i:i + 2])
        cipher_block = np.dot(key_matrix, block) % 26
        ciphertext_numbers.extend(cipher_block)

    ciphertext = numbers_to_text(ciphertext_numbers)
    return ciphertext


key = np.array([[3, 3],
                [2, 7]])
message = "We live in an insecure world"
ciphertext = hill_encrypt(message, key)
print("Hill Cipher ciphertext:", ciphertext)
