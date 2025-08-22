"""1. Using DES and AES (128, 192, and 256 bits key).encrypt the five different messages
using same key.
a. Consider different modes of operation
b. Plot the graph which shows execution time taken by each technique.
c. Compare time taken by different modes of operation"""

from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import time
import matplotlib.pyplot as plt

# test messages
messages = [
    b"Message one.",
    b"Message two.",
    b"Message three.",
    b"Message four.",
    b"Message five."
]

# Supported modes to test
modes = {
    "ECB": AES.MODE_ECB,
    "CBC": AES.MODE_CBC,
    "CFB": AES.MODE_CFB,
    "OFB": AES.MODE_OFB
}

def encrypt_with_timing(cipher, data, block_size):
    padded = pad(data, block_size)
    start = time.perf_counter()
    ct = cipher.encrypt(padded)
    end = time.perf_counter()
    return (ct, end - start)

des_key = get_random_bytes(8)         # DES key is always 8 bytes
aes_128_key = get_random_bytes(16)    # AES-128 key size: 16 bytes
aes_192_key = get_random_bytes(24)    # AES-192 key size: 24 bytes
aes_256_key = get_random_bytes(32)    # AES-256 key size: 32 bytes

times = {
    "DES": {},
    "AES-128": {},
    "AES-192": {},
    "AES-256": {}
}

for mode_name, mode_val in modes.items():
    des_time = 0
    for msg in messages:
        if mode_val in [DES.MODE_CBC, DES.MODE_CFB, DES.MODE_OFB]:
            iv = get_random_bytes(8)  # DES block size = 8 bytes
            cipher = DES.new(des_key, mode_val, iv=iv)
        else:
            cipher = DES.new(des_key, mode_val)
        _, t = encrypt_with_timing(cipher, msg, 8)
        des_time += t
    times["DES"][mode_name] = des_time

    # AES-128 encryption timing
    aes128_time = 0
    for msg in messages:
        if mode_val in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
            iv = get_random_bytes(16) # AES block size = 16 bytes
            cipher = AES.new(aes_128_key, mode_val, iv=iv)
        else:
            cipher = AES.new(aes_128_key, mode_val)
        _, t = encrypt_with_timing(cipher, msg, 16)
        aes128_time += t
    times["AES-128"][mode_name] = aes128_time

    # AES-192 encryption timing
    aes192_time = 0
    for msg in messages:
        if mode_val in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
            iv = get_random_bytes(16)
            cipher = AES.new(aes_192_key, mode_val, iv=iv)
        else:
            cipher = AES.new(aes_192_key, mode_val)
        _, t = encrypt_with_timing(cipher, msg, 16)
        aes192_time += t
    times["AES-192"][mode_name] = aes192_time

    # AES-256 encryption timing
    aes256_time = 0
    for msg in messages:
        if mode_val in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
            iv = get_random_bytes(16)
            cipher = AES.new(aes_256_key, mode_val, iv=iv)
        else:
            cipher = AES.new(aes_256_key, mode_val)
        _, t = encrypt_with_timing(cipher, msg, 16)
        aes256_time += t
    times["AES-256"][mode_name] = aes256_time

# Plotting the results
labels = list(modes.keys())
x = range(len(labels))

plt.figure(figsize=(10, 6))
plt.plot(x, [times["DES"][mode] for mode in labels], marker='o', label="DES (64-bit key)")
plt.plot(x, [times["AES-128"][mode] for mode in labels], marker='o', label="AES-128")
plt.plot(x, [times["AES-192"][mode] for mode in labels], marker='o', label="AES-192")
plt.plot(x, [times["AES-256"][mode] for mode in labels], marker='o', label="AES-256")
plt.xticks(x, labels)
plt.xlabel("Cipher Mode")
plt.ylabel("Total Encryption Time for 5 Messages (seconds)")
plt.title("Execution Time Comparison of DES and AES (various key sizes) Across Modes")
plt.legend()
plt.grid(True)
plt.show()

# Print the timing results
print("Execution time (seconds) for encryption of 5 messages:")
for mode in labels:
    print(f"\nMode: {mode}")
    for algo in ["DES", "AES-128", "AES-192", "AES-256"]:
        print(f"{algo}: {times[algo][mode]:.6f}")
