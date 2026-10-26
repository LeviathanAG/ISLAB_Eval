"""Hashing snippet.

Usage:
    python3 plug_and_play/standalone/hashing_snippet.py
    digest(b"message", "sha256")

Supported hashlib names include md5, sha1, sha224, sha256, sha384, sha512,
sha3_256, and sha3_512.  MD5/SHA-1 are included for legacy lab comparisons,
not for new security designs.  A hash detects accidental changes; HMAC is
needed when an attacker can choose or replace the digest.
"""

from __future__ import annotations

import hashlib
import hmac


def digest(message: bytes, algorithm: str = "sha256") -> str:
    """Return one standard-library hexadecimal digest."""

    return hashlib.new(algorithm, message).hexdigest()


def keyed_digest(message: bytes, secret: bytes) -> str:
    """Return an HMAC-SHA256 for authenticated integrity."""

    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify_keyed_digest(message: bytes, secret: bytes, tag: str) -> bool:
    """Compare HMACs in constant time."""

    return hmac.compare_digest(keyed_digest(message, secret), tag)


def main() -> None:
    """Run the hash and HMAC examples from a small menu."""

    while True:
        print("\n=== Hashing menu ===")
        print("1. SHA-256")
        print("2. SHA-512")
        print("3. HMAC integrity check")
        print("0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        message = input("Message (Enter uses Information Security): ") or "Information Security"
        if choice == "1":
            print("SHA-256:", digest(message.encode()))
        elif choice == "2":
            print("SHA-512:", digest(message.encode(), "sha512"))
        elif choice == "3":
            secret = b"demo secret"
            tag = keyed_digest(message.encode(), secret)
            print("HMAC:", tag)
            print("HMAC verified:", verify_keyed_digest(message.encode(), secret, tag))
            print("Tamper rejected:", not verify_keyed_digest((message + "!").encode(), secret, tag))
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()

