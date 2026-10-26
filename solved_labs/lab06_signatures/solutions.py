"""Lab 6 solutions: RSA, ElGamal, Schnorr, DSA-style DH, and CIA.

The manual's website screenshots are replaced by reproducible Python output.
RSA uses RSA-PSS from ``cryptography``; ElGamal, Schnorr, and DSA-style
examples use the readable educational equations in the repository.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

# Make ``python3 solved_labs/lab06_signatures/solutions.py`` work from any
# current directory while keeping the imports readable below.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from solved_pyqs.crypto_helpers import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    ensure_rsa_keypair,
    elgamal_keygen,
    elgamal_sign,
    elgamal_verify,
    rsa_decrypt,
    rsa_encrypt,
    rsa_sign,
    rsa_verify,
)
from digital_signatures import dsa_keygen, dsa_sign, dsa_verify, schnorr_keygen, schnorr_sign, schnorr_verify


def rsa_alice_bob_demo() -> tuple[bool, bool]:
    """Alice signs and Bob verifies; Bob then signs and Alice verifies."""

    with tempfile.TemporaryDirectory() as directory:
        private, public = ensure_rsa_keypair(Path(directory), bits=2048)
        alice_message = b"Alice's legal document"
        bob_message = b"BOB acknowledges Alice's document"
        alice_signature = rsa_sign(alice_message, private)
        bob_signature = rsa_sign(bob_message, private)
        alice_ok = rsa_verify(alice_message, alice_signature, public)
        bob_ok = rsa_verify(bob_message, bob_signature, public)
        tamper_rejected = not rsa_verify(b"Altered document", alice_signature, public)
        print("Alice signature verified by Bob:", alice_ok)
        print("Bob signature verified by Alice:", bob_ok)
        print("Altered document rejected:", tamper_rejected)
        return alice_ok, bob_ok


def elgamal_schnorr_demo() -> tuple[bool, bool]:
    """Run the manual's ElGamal and Schnorr signing exercises."""

    message = b"Digital signature lab"
    elgamal_private = elgamal_keygen(private=123456789)
    elgamal_signature = elgamal_sign(message, elgamal_private)
    elgamal_public = {name: elgamal_private[name] for name in ("p", "g", "y")}
    elgamal_ok = elgamal_verify(message, elgamal_signature, elgamal_public)
    schnorr_private, schnorr_public = schnorr_keygen(private=7)
    schnorr_signature = schnorr_sign(message, schnorr_private)
    schnorr_ok = schnorr_verify(message, schnorr_signature, schnorr_public)
    print("ElGamal verified:", elgamal_ok)
    print("Schnorr verified:", schnorr_ok)
    return elgamal_ok, schnorr_ok


def dh_style_dsa_demo() -> bool:
    """Show why plain DH needs a DSA-style signature layer for authenticity."""

    message = b"Authenticated key exchange transcript"
    private, public = dsa_keygen(private=7)
    signature = dsa_sign(message, private)
    verified = dsa_verify(message, signature, public)
    print("DH-style DSA signature verified:", verified)
    print("Plain Diffie-Hellman alone provides key agreement, not signatures.")
    return verified


def client_server_rsa_demo() -> bool:
    """Simulate a signed client/server message over an encrypted channel."""

    with tempfile.TemporaryDirectory() as directory:
        private, public = ensure_rsa_keypair(Path(directory), bits=2048)
        aes_key = b"K" * 32
        message = b"Client request: approve transfer"
        signature = rsa_sign(hashlib.sha256(message).digest(), private)
        iv, ciphertext = aes_cbc_encrypt(message, aes_key)
        server_plaintext = aes_cbc_decrypt(ciphertext, aes_key, iv)
        verified = server_plaintext == message and rsa_verify(
            hashlib.sha256(server_plaintext).digest(), signature, public
        )
        print("Client/server RSA-PSS verification:", verified)
        return verified


def cia_demo() -> dict[str, bool]:
    """Demonstrate confidentiality, integrity, and authenticity together."""

    with tempfile.TemporaryDirectory() as directory:
        private, public = ensure_rsa_keypair(Path(directory), bits=2048)
        plaintext = b"Confidential CIA-triad message"
        aes_key = b"A" * 32
        iv, ciphertext = aes_cbc_encrypt(plaintext, aes_key)  # confidentiality
        encrypted_key = rsa_encrypt(aes_key, public)
        recovered = aes_cbc_decrypt(ciphertext, rsa_decrypt(encrypted_key, private), iv)
        digest = hashlib.sha256(recovered).digest()  # integrity input
        signature = rsa_sign(digest, private)  # authenticity
        result = {
            "confidentiality": recovered == plaintext,
            "integrity": hashlib.sha256(recovered).digest() == digest,
            "authenticity": rsa_verify(digest, signature, public),
        }
        print(result)
        return result


def run_all() -> None:
    """Display outputs for every Lab 6 exercise."""

    print("=== Lab 6. RSA signature exchange ===")
    rsa_alice_bob_demo()
    print("=== Lab 6.1 ElGamal and Schnorr ===")
    elgamal_schnorr_demo()
    print("=== Lab 6.2 DH-style DSA ===")
    dh_style_dsa_demo()
    print("=== Lab 6.3 client/server ===")
    client_server_rsa_demo()
    print("=== Lab 6A.1 CIA triad ===")
    cia_demo()


def run_menu() -> None:
    """Run one Lab 6 example at a time from an interactive menu."""

    actions = {
        "1": ("RSA signature exchange", rsa_alice_bob_demo),
        "2": ("ElGamal and Schnorr signatures", elgamal_schnorr_demo),
        "3": ("DH-style DSA", dh_style_dsa_demo),
        "4": ("Signed client/server message", client_server_rsa_demo),
        "5": ("CIA triad", cia_demo),
        "6": ("Run every example", run_all),
    }
    while True:
        print("\n=== Lab 6 menu ===")
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

