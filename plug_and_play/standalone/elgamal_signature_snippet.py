"""Educational ElGamal-signature snippet.

Usage:
    python3 plug_and_play/standalone/elgamal_signature_snippet.py
    key = keygen(); signature = sign(b"message", key); verify(...)

The signature is (r,s), where r=g^k mod p and
s=k^-1(H(m)-x*r) mod (p-1).  The nonce k must be secret, random, and never
reused.  This file uses the repository's educational 255-bit group; use a
reviewed modern signature library for production systems.
"""

from __future__ import annotations

from pathlib import Path
import sys

# Make the shared helper import work when this file is run by path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from solved_pyqs.crypto_helpers import elgamal_keygen, elgamal_sign, elgamal_verify


def run_menu() -> None:
    """Demonstrate ElGamal signing and tamper rejection interactively."""

    while True:
        print("\n=== ElGamal signature menu ===")
        print("1. Sign and verify")
        print("2. Verify a tampered message")
        print("0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        if choice not in {"1", "2"}:
            print("Invalid choice.")
            continue
        private = elgamal_keygen(private=12345)
        public = {name: private[name] for name in ("p", "g", "y")}
        message = b"ElGamal signature example"
        signature = elgamal_sign(message, private)
        print("Valid:", elgamal_verify(message, signature, public))
        if choice == "2":
            print("Tampered message rejected:", not elgamal_verify(message + b"!", signature, public))


if __name__ == "__main__":
    run_menu()

