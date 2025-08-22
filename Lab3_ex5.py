"""5. As part of a project to enhance the security of communication in a peer-to-peer file
sharing system, you are tasked with implementing a secure key exchange
mechanism using the Diffie-Hellman algorithm. Each peer must establish a shared
secret key with another peer over an insecure channel. Implement the Diffie-Hellman key exchange protocol,
enabling peers to generate their public and private
keys and securely compute the shared secret key. Measure the time taken for key
generation and key exchange processes."""

import time
import secrets

# Modular exponentiation function
def mod_exp(base, exponent, modulus):
    return pow(base, exponent, modulus)

def diffie_hellman_key_exchange():
    # Publicly agreed parameters (large prime p and primitive root g)
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2

    # Peer A generates private and public key
    start_key_gen_a = time.time()
    private_key_a = secrets.randbelow(p - 2) + 1
    public_key_a = mod_exp(g, private_key_a, p)
    end_key_gen_a = time.time()

    # Peer B generates private and public key
    start_key_gen_b = time.time()
    private_key_b = secrets.randbelow(p - 2) + 1
    public_key_b = mod_exp(g, private_key_b, p)
    end_key_gen_b = time.time()

    # Peer A computes shared secret using B's public key
    start_shared_a = time.time()
    shared_secret_a = mod_exp(public_key_b, private_key_a, p)
    end_shared_a = time.time()

    # Peer B computes shared secret using A's public key
    start_shared_b = time.time()
    shared_secret_b = mod_exp(public_key_a, private_key_b, p)
    end_shared_b = time.time()

    assert shared_secret_a == shared_secret_b

    print(f"Peer A Key Generation Time: {end_key_gen_a - start_key_gen_a:.6f} seconds")
    print(f"Peer B Key Generation Time: {end_key_gen_b - start_key_gen_b:.6f} seconds")
    print(f"Peer A Shared Secret Computation Time: {end_shared_a - start_shared_a:.6f} seconds")
    print(f"Peer B Shared Secret Computation Time: {end_shared_b - start_shared_b:.6f} seconds")
    print(f"Shared secret: {shared_secret_a}")

if __name__ == "__main__":
    diffie_hellman_key_exchange()
