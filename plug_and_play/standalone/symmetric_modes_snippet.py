"""AES mode comparison snippet.

Usage:
    python3 plug_and_play/standalone/symmetric_modes_snippet.py

The `cryptography` Cipher API exposes ECB, CBC, CFB, CFB8, OFB, CTR, and GCM
through this module.  ECB leaks equal plaintext blocks and should be avoided.
CBC/CFB/CFB8/OFB/CTR need a fresh unique IV/nonce and do not authenticate by
themselves.  GCM provides authenticated encryption and is the recommended
choice when the protocol permits it.  The demo uses one-block plaintext so
the no-padding modes stay easy to inspect.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def round_trip(mode_name: str, plaintext: bytes, key: bytes = b"K" * 32) -> bytes:
    """Encrypt and decrypt one block using the named AES mode."""

    iv = b"I" * 16
    if mode_name == "ECB":
        mode = modes.ECB()
    elif mode_name == "CBC":
        mode = modes.CBC(iv)
    elif mode_name == "CFB":
        mode = modes.CFB(iv)
    elif mode_name == "CFB8":
        mode = modes.CFB8(iv)
    elif mode_name == "OFB":
        mode = modes.OFB(iv)
    elif mode_name == "CTR":
        mode = modes.CTR(iv)
    elif mode_name == "GCM":
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, encryptor.tag)).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    else:
        raise ValueError("Choose ECB, CBC, CFB, CFB8, OFB, CTR, or GCM")

    encryptor = Cipher(algorithms.AES(key), mode).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    decryptor = Cipher(algorithms.AES(key), mode).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def run_menu() -> None:
    """Compare every supported AES mode or inspect one selected mode."""

    names = ("ECB", "CBC", "CFB", "CFB8", "OFB", "CTR", "GCM")
    while True:
        print("\n=== AES modes menu ===")
        print("1. Compare all modes")
        print("2. Test one mode")
        print("0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        if choice == "1":
            for name in names:
                print(name, round_trip(name, b"sixteen byte msg") == b"sixteen byte msg")
        elif choice == "2":
            name = input("Mode (ECB/CBC/CFB/CFB8/OFB/CTR/GCM): ").strip().upper()
            try:
                print(name, round_trip(name, b"sixteen byte msg") == b"sixteen byte msg")
            except ValueError as exc:
                print(exc)
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    run_menu()

