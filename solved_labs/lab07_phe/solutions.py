"""Lab 7: Paillier addition, RSA multiplication, and ElGamal multiplication."""

from __future__ import annotations

import math
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from solved_pyqs.crypto_helpers import (
    generate_prime,
    make_additive_threshold_shares,
    combine_threshold_shares,
    paillier_add,
    paillier_decrypt,
    paillier_decrypt_with_private_parts,
    paillier_encrypt,
    paillier_generate,
    paillier_public,
)


def paillier_addition_demo() -> bool:
    """Encrypt 15 and 25, multiply ciphertexts, and decrypt only the sum."""

    key = paillier_generate(128)
    public = paillier_public(key)
    first = paillier_encrypt(15, public)
    second = paillier_encrypt(25, public)
    encrypted_sum = paillier_add(first, second, public)
    result = paillier_decrypt(encrypted_sum, key)
    print("Paillier ciphertext a:", first)
    print("Paillier ciphertext b:", second)
    print("Encrypted a+b:", encrypted_sum)
    print("Decrypted sum:", result)
    return result == 40


def rsa_multiplication_demo() -> bool:
    """Use textbook RSA's multiplicative property for the lab-size example."""

    p, q = generate_prime(64), generate_prime(64)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2
    d = pow(e, -1, phi)
    first, second = 7, 3
    encrypted_first, encrypted_second = pow(first, e, n), pow(second, e, n)
    encrypted_product = encrypted_first * encrypted_second % n
    product = pow(encrypted_product, d, n)
    print("RSA encrypted 7:", encrypted_first)
    print("RSA encrypted 3:", encrypted_second)
    print("Encrypted product:", encrypted_product)
    print("Decrypted product:", product)
    return product == first * second


def elgamal_multiplication_demo() -> bool:
    """Demonstrate component-wise ElGamal multiplication modulo a prime."""

    p = 2**127 - 1
    g = 5
    private = 23
    public = pow(g, private, p)

    def encrypt(message: int) -> tuple[int, int]:
        nonce = secrets.randbelow(p - 3) + 2
        return pow(g, nonce, p), message * pow(public, nonce, p) % p

    def decrypt(ciphertext: tuple[int, int]) -> int:
        first, second = ciphertext
        return second * pow(pow(first, private, p), -1, p) % p

    first, second = encrypt(7), encrypt(3)
    encrypted_product = (first[0] * second[0] % p, first[1] * second[1] % p)
    result = decrypt(encrypted_product)
    print("ElGamal encrypted product:", encrypted_product)
    print("Decrypted product:", result)
    return result == 21


def secure_data_sharing_demo() -> bool:
    """Combine encrypted values from two parties without opening either value."""

    key = paillier_generate(128)
    public = paillier_public(key)
    alice_ciphertext = paillier_encrypt(12, public)
    bob_ciphertext = paillier_encrypt(30, public)
    combined = paillier_add(alice_ciphertext, bob_ciphertext, public)
    result = paillier_decrypt(combined, key)
    print("Combined encrypted data decrypts to:", result)
    return result == 42


def performance_demo() -> bool:
    """Compare one Paillier addition with one ElGamal multiplication."""

    key = paillier_generate(128)
    public = paillier_public(key)
    start = time.perf_counter()
    paillier_add(paillier_encrypt(7, public), paillier_encrypt(3, public), public)
    paillier_time = time.perf_counter() - start

    prime = 2**127 - 1
    private = 23
    elgamal_public = pow(5, private, prime)
    start = time.perf_counter()
    nonce = secrets.randbelow(prime - 3) + 2
    first = (pow(5, nonce, prime), 7 * pow(elgamal_public, nonce, prime) % prime)
    nonce = secrets.randbelow(prime - 3) + 2
    second = (pow(5, nonce, prime), 3 * pow(elgamal_public, nonce, prime) % prime)
    product = (first[0] * second[0] % prime, first[1] * second[1] % prime)
    recovered = product[1] * pow(pow(product[0], private, prime), -1, prime) % prime
    elgamal_time = time.perf_counter() - start
    print(f"Paillier addition time: {paillier_time:.6f}s")
    print(f"ElGamal multiplication time: {elgamal_time:.6f}s")
    return recovered == 21


def threshold_demo() -> bool:
    """Show that two additive private shares are needed at election end."""

    key = paillier_generate(128)
    public = paillier_public(key)
    encrypted_sum = paillier_add(paillier_encrypt(4, public), paillier_encrypt(6, public), public)
    threshold = make_additive_threshold_shares(key)
    private_lambda, private_mu = combine_threshold_shares(threshold, 0, 1)
    result = paillier_decrypt_with_private_parts(
        encrypted_sum, public, private_lambda, private_mu
    )
    print("Threshold shares used: 2 of 2")
    print("Decrypted final aggregate:", result)
    return result == 10


def run_all() -> None:
    """Display outputs for all Lab 7 exercises and additions."""

    print("=== Lab 7.1 Paillier addition ===")
    print("passed:", paillier_addition_demo())
    print("=== Lab 7.2 RSA multiplication ===")
    print("passed:", rsa_multiplication_demo())
    print("=== Lab 7A.1 ElGamal multiplication ===")
    print("passed:", elgamal_multiplication_demo())
    print("=== Lab 7A.2 secure data sharing ===")
    print("passed:", secure_data_sharing_demo())
    print("=== Lab 7A.3 thresholding ===")
    print("passed:", threshold_demo())
    print("=== Lab 7A.4 performance analysis ===")
    print("passed:", performance_demo())


def run_menu() -> None:
    """Run one Lab 7 example at a time from an interactive menu."""

    actions = {
        "1": ("Paillier addition", paillier_addition_demo),
        "2": ("RSA multiplication", rsa_multiplication_demo),
        "3": ("ElGamal multiplication", elgamal_multiplication_demo),
        "4": ("Secure encrypted data sharing", secure_data_sharing_demo),
        "5": ("Threshold decryption", threshold_demo),
        "6": ("Performance comparison", performance_demo),
        "7": ("Run every example", run_all),
    }
    while True:
        print("\n=== Lab 7 menu ===")
        for number, (label, _action) in actions.items():
            print(f"{number}. {label}")
        print("0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        selected = actions.get(choice)
        if selected is None:
            print("Invalid choice.")
            continue
        try:
            selected[1]()
        except (OSError, ValueError) as exc:
            print(f"Example could not run: {exc}")


if __name__ == "__main__":  # pragma: no cover
    run_menu()

