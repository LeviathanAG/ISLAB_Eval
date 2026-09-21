"""Hybrid/envelope encryption: the standard scalable KMS pattern.

A random AES data-encryption key (DEK) encrypts the possibly-large message.
RSA-OAEP wraps only that small DEK under the recipient's public key (KEK).
AES-GCM gives confidentiality and integrity; associated data (AAD) is verified
but not encrypted.  Never reuse an AES-GCM nonce with the same DEK.
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_kek(bits: int = 2048):
    """Return RSA key-encryption key pair. Use 2048 bits or larger."""
    if bits < 2048:
        raise ValueError("RSA KEK must be at least 2048 bits")
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return private, private.public_key()


def _oaep():
    """OAEP parameters must match exactly during wrap and unwrap."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def envelope_encrypt(plaintext: bytes, recipient_public_key,
                     aad: bytes = b"") -> dict[str, bytes]:
    """Return wrapped DEK, nonce and authenticated AES-GCM ciphertext.

    AESGCM appends a 16-byte authentication tag to ``ciphertext``.  The
    plaintext may have any length that fits memory.  RSA never encrypts the
    whole file: it wraps the fixed 32-byte AES-256 key.
    """
    dek = AESGCM.generate_key(bit_length=256)       # secret, random, per item
    nonce = os.urandom(12)                          # recommended GCM size
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    wrapped_dek = recipient_public_key.encrypt(dek, _oaep())
    return {"wrapped_dek": wrapped_dek, "nonce": nonce,
            "ciphertext": ciphertext, "aad": aad}


def envelope_decrypt(package: dict[str, bytes], recipient_private_key) -> bytes:
    """Unwrap the DEK, then authenticate/decrypt. Tampering raises an error."""
    dek = recipient_private_key.decrypt(package["wrapped_dek"], _oaep())
    return AESGCM(dek).decrypt(
        package["nonce"], package["ciphertext"], package.get("aad", b"")
    )


def package_to_json(package: dict[str, bytes]) -> str:
    """Encode binary fields for files/sockets. Base64 provides no secrecy."""
    return json.dumps({key: base64.b64encode(value).decode("ascii")
                       for key, value in package.items()}, separators=(",", ":"))


def package_from_json(encoded: str) -> dict[str, bytes]:
    item = json.loads(encoded)
    required = {"wrapped_dek", "nonce", "ciphertext", "aad"}
    if set(item) != required:
        raise ValueError(f"package fields must be exactly {sorted(required)}")
    return {key: base64.b64decode(value, validate=True)
            for key, value in item.items()}


if __name__ == "__main__":
    private_key, public_key = generate_kek()
    message = input("Data to protect: ").encode("utf-8")
    owner = input("AAD/context [student-record]: ").encode("utf-8") or b"student-record"
    protected = envelope_encrypt(message, public_key, owner)
    wire = package_to_json(protected)
    print("Transport JSON:", wire)
    print("Recovered:", envelope_decrypt(package_from_json(wire), private_key).decode())
