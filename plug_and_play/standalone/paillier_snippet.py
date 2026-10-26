"""Paillier additive-homomorphism snippet.

Usage:
    python3 plug_and_play/standalone/paillier_snippet.py
    key = paillier_generate(); public = paillier_public(key)
    c_sum = paillier_add(paillier_encrypt(a, public), paillier_encrypt(b, public), public)

Paillier supports addition by multiplying ciphertexts modulo n².  It supports
scalar multiplication by raising a ciphertext to a known integer power.  It
does not natively support arbitrary ciphertext-ciphertext multiplication.
The small default key below is for a readable lab run, not production.
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from solved_pyqs.crypto_helpers import (
    paillier_add,
    paillier_decrypt,
    paillier_encrypt,
    paillier_generate,
    paillier_public,
)


def run_menu() -> None:
    """Demonstrate encrypted addition and scalar multiplication."""

    while True:
        print("\n=== Paillier menu ===")
        print("1. Add two encrypted numbers")
        print("2. Multiply an encrypted number by a known scalar")
        print("0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        if choice not in {"1", "2"}:
            print("Invalid choice.")
            continue
        key = paillier_generate(128)
        public = paillier_public(key)
        if choice == "1":
            encrypted_sum = paillier_add(
                paillier_encrypt(15, public), paillier_encrypt(25, public), public
            )
            print("Decrypted sum:", paillier_decrypt(encrypted_sum, key))
        else:
            encrypted = paillier_encrypt(15, public)
            scaled = pow(encrypted, 3, public["n"] ** 2)
            print("Decrypted 15 x 3:", paillier_decrypt(scaled, key))


if __name__ == "__main__":
    run_menu()

