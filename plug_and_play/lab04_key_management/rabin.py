"""Rabin cryptosystem core for the Lab 4 healthcare key-manager question.

Key generation chooses distinct Blum primes p=q=3 mod 4 and publishes n=pq.
Encryption is c=m^2 mod n.  Decryption computes two square roots modulo each
prime and combines them with CRT, producing FOUR candidates.  A real encoding
must add redundancy so the receiver can recognize the intended candidate.
"""
from Crypto.Util.number import getPrime


def generate_blum_prime(bits: int) -> int:
    while True:
        value = getPrime(bits)
        if value % 4 == 3:
            return value


def rabin_keygen(bits: int = 1024):
    if bits < 32:
        raise ValueError("use at least 32 bits for a demo; 2048+ in real designs")
    p = generate_blum_prime(bits // 2)
    q = generate_blum_prime(bits - bits // 2)
    while p == q:
        q = generate_blum_prime(bits - bits // 2)
    return p*q, (p, q)


def rabin_encrypt(message_integer: int, public_n: int) -> int:
    if not 0 <= message_integer < public_n:
        raise ValueError("message integer must be in 0..n-1")
    return pow(message_integer, 2, public_n)


def rabin_decrypt_four_roots(ciphertext: int, private_key):
    p, q = private_key
    root_p = pow(ciphertext, (p+1)//4, p)
    root_q = pow(ciphertext, (q+1)//4, q)
    inverse_q = pow(q, -1, p)
    inverse_p = pow(p, -1, q)
    roots = {(a*q*inverse_q + b*p*inverse_p) % (p*q)
             for a in (root_p, -root_p) for b in (root_q, -root_q)}
    return sorted(roots)


if __name__ == "__main__":
    # Small fixed values make the four-root property obvious.
    private, public_n = (499, 547), 499*547
    encrypted = rabin_encrypt(42, public_n)
    roots = rabin_decrypt_four_roots(encrypted, private)
    print("ciphertext:", encrypted)
    print("roots     :", roots)
    print("42 found  :", 42 in roots)

