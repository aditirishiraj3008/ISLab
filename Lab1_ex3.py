"""3. Use the Playfair cipher to encipher the message "The key is hidden under the door pad".
The secret key can be made by filling the first and part of the second row with the word
"GUIDANCE" and filling the rest of the matrix with the rest of the alphabet."""

import string

def prepare_playfair_key(key):
    key = key.upper().replace('J','I')
    seen = set()
    matrix = []
    for char in key:
        if char not in seen and char in string.ascii_uppercase:
            matrix.append(char)
            seen.add(char)
    for char in string.ascii_uppercase:
        if char == 'J':
            continue
        if char not in seen:
            matrix.append(char)
            seen.add(char)
    # 5x5 matrix
    return [matrix[i*5:(i+1)*5] for i in range(5)]

def find_position(matrix, letter):
    if letter == 'J':
        letter = 'I'
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == letter:
                return row, col
    return None

def process_plaintext(text):
    text = text.upper().replace('J','I')
    text = ''.join([c for c in text if c in string.ascii_uppercase])
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = ''
        if i+1 < len(text):
            b = text[i+1]
            if a == b:
                b = 'X'
                i += 1
            else:
                i += 2
        else:
            b = 'Z'
            i += 1
        pairs.append((a,b))
    return pairs

def playfair_encrypt(key, plaintext):
    matrix = prepare_playfair_key(key)
    pairs = process_plaintext(plaintext)
    ciphertext = ''
    for a, b in pairs:
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)
        if row1 == row2:
            # Same row: shift columns right
            enc_a = matrix[row1][(col1+1)%5]
            enc_b = matrix[row2][(col2+1)%5]
        elif col1 == col2:
            # Same column: shift rows down
            enc_a = matrix[(row1+1)%5][col1]
            enc_b = matrix[(row2+1)%5][col2]
        else:
            # Rectangle: swap columns
            enc_a = matrix[row1][col2]
            enc_b = matrix[row2][col1]
        ciphertext += enc_a + enc_b
    return ciphertext

def print_matrix(matrix):
    for row in matrix:
        print(' '.join(row))

plaintext = "The key is hidden under the door pad"
key = "GUIDANCE"
matrix = prepare_playfair_key(key)
print("Playfair Matrix:")
print_matrix(matrix)
ciphertext = playfair_encrypt(key, plaintext)
print("Playfair Ciphertext:", ciphertext)

