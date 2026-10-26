"""RSA digital-signature snippet.

Usage:
    python3 plug_and_play/standalone/rsa_signature_snippet.py
    private, public = new_keys(2048)
    signature = sign(b"message", private)
    verify(b"message", signature, public)

Use RSA-PSS with SHA-256 for signatures.  Recommended key sizes are 2048 or
3072 bits; the e-voting PYQ deliberately requests a 4096-bit encryption key.
Never use textbook RSA as a signature and never reuse a private key casually.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def new_keys(bits: int = 2048):
    """Generate an RSA private/public key pair."""

    if bits < 2048:
        raise ValueError("Use at least 2048 bits for a practical signature demo")
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return private, private.public_key()


def sign(message: bytes, private_key) -> bytes:
    """Sign bytes using randomized RSA-PSS-SHA256."""

    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify(message: bytes, signature: bytes, public_key) -> bool:
    """Return False for a tampered message or signature."""

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def run_menu() -> None:
    """Generate a key and demonstrate signing and tamper rejection."""

    while True:
        print("\n=== RSA signature menu ===")
        print("1. Sign and verify a message")
        print("2. Show tamper rejection")
        print("0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        if choice not in {"1", "2"}:
            print("Invalid choice.")
            continue
        private, public = new_keys()
        message = b"Alice signs this document"
        signature = sign(message, private)
        print("Valid:", verify(message, signature, public))
        if choice == "2":
            print("Tampered message rejected:", not verify(message + b"!", signature, public))


if __name__ == "__main__":
    run_menu()

