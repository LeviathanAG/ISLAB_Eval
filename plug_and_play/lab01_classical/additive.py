"""Additive (Caesar) cipher - standalone.

Math with A=0, B=1, ..., Z=25:
    encryption: C = (P + key) mod 26
    decryption: P = (C - key) mod 26

Input: any string.  Letters are transformed; punctuation and case are kept.
Key: any integer (it is reduced modulo 26).  The cipher is insecure because
there are only 26 possible keys, so brute force is immediate.
"""


def additive_encrypt(text: str, key: int) -> str:
    result = []
    for character in text:
        if character.isascii() and character.isalpha():
            base = ord("A") if character.isupper() else ord("a")
            number = ord(character) - base
            result.append(chr(base + (number + key) % 26))
        else:
            result.append(character)
    return "".join(result)


def additive_decrypt(ciphertext: str, key: int) -> str:
    return additive_encrypt(ciphertext, -key)


def brute_force_additive(ciphertext: str):
    """Return all 26 candidates as (key, plaintext) pairs."""
    return [(key, additive_decrypt(ciphertext, key)) for key in range(26)]


if __name__ == "__main__":
    message, key = "I am learning information security", 20
    encrypted = additive_encrypt(message, key)
    print("ciphertext:", encrypted)
    print("plaintext :", additive_decrypt(encrypted, key))

