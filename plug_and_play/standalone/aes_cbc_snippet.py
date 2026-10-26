"""AES-CBC snippet.

Usage:
    python3 plug_and_play/standalone/aes_cbc_snippet.py
    iv, ciphertext = encrypt(b"hello", key)
    plaintext = decrypt(ciphertext, key, iv)

AES accepts exactly 16-byte (AES-128), 24-byte (AES-192), or 32-byte
(AES-256) keys.  CBC needs a fresh unpredictable 16-byte IV and PKCS#7
padding.  CBC provides confidentiality but not authentication; use AES-GCM
when authenticated encryption is allowed, or pair CBC with an HMAC.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt with AES-CBC and return the public IV plus ciphertext."""

    if len(key) not in (16, 24, 32):
        raise ValueError("Use a 16, 24, or 32 byte AES key")
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv, cipher.update(padded) + cipher.finalize()


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt and remove PKCS#7 padding."""

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = cipher.update(ciphertext) + cipher.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def run_menu() -> None:
    """Show the AES-128, AES-192, and AES-256 examples interactively."""

    while True:
        print("\n=== AES-CBC menu ===")
        print("1. AES-128")
        print("2. AES-192")
        print("3. AES-256")
        print("0. Exit")
        choice = input("Choose a key size: ").strip()
        if choice == "0" or not choice:
            return
        sizes = {"1": 16, "2": 24, "3": 32}
        size = sizes.get(choice)
        if size is None:
            print("Invalid choice.")
            continue
        key = b"K" * size
        iv, ciphertext = encrypt(b"AES CBC example", key)
        print("IV:", iv.hex())
        print("Ciphertext:", ciphertext.hex())
        print("Plaintext:", decrypt(ciphertext, key, iv).decode())


if __name__ == "__main__":
    run_menu()

