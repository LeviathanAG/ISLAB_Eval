"""Multiplicative and affine ciphers - standalone.

Affine encryption:  C = (aP + b) mod 26
Affine decryption:  P = a^-1(C - b) mod 26

Multiplicative is affine with b=0.  Additive is affine with a=1.
Requirement: gcd(a,26)=1, otherwise a has no modular inverse and decryption is
ambiguous.  Valid a values are 1,3,5,7,9,11,15,17,19,21,23,25.
"""
from math import gcd


def modular_inverse(value: int, modulus: int = 26) -> int:
    """Extended Euclidean algorithm; returns x where value*x = 1 mod modulus."""
    old_r, r = value % modulus, modulus
    old_x, x = 1, 0
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_x, x = x, old_x - quotient * x
    if old_r != 1:
        raise ValueError(f"{value} has no inverse modulo {modulus}")
    return old_x % modulus


def affine_encrypt(text: str, a: int, b: int) -> str:
    if gcd(a, 26) != 1:
        raise ValueError("a must be coprime to 26")
    return "".join(chr(65 + (a * (ord(c) - 65) + b) % 26)
                   for c in text.upper() if c.isascii() and c.isalpha())


def affine_decrypt(ciphertext: str, a: int, b: int) -> str:
    inverse = modular_inverse(a)
    return "".join(chr(65 + inverse * (ord(c) - 65 - b) % 26)
                   for c in ciphertext.upper() if c.isascii() and c.isalpha())


def multiplicative_encrypt(text: str, key: int) -> str:
    return affine_encrypt(text, key, 0)


def multiplicative_decrypt(text: str, key: int) -> str:
    return affine_decrypt(text, key, 0)


def affine_known_plaintext_attack(ciphertext: str, known_plain="AB", known_cipher="GL"):
    """Try all 12*26=312 valid keys and keep keys matching the known pair."""
    answers = []
    for a in range(26):
        if gcd(a, 26) != 1:
            continue
        for b in range(26):
            if affine_encrypt(known_plain, a, b) == known_cipher.upper():
                answers.append((a, b, affine_decrypt(ciphertext, a, b)))
    return answers


if __name__ == "__main__":
    message = "I am learning information security"
    for name, a, b in [("multiplicative", 15, 0), ("affine", 15, 20)]:
        encrypted = affine_encrypt(message, a, b)
        print(name, encrypted, affine_decrypt(encrypted, a, b))

