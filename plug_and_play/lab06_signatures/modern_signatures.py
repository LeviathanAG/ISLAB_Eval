"""Production-style digital-signature snippets using ``cryptography``.

Covered families
----------------
* RSA-PSS: recommended RSA signature padding; randomized.
* RSA-PKCS1v1.5: deterministic legacy compatibility mode.
* DSA: classic finite-field Digital Signature Algorithm.
* ECDSA P-256: compact elliptic-curve signature; randomized by this library.
* Ed25519: modern, compact and simple API; deterministic signatures.

Messages may have any byte length.  The library hashes internally for RSA,
DSA and ECDSA.  Ed25519 internally performs its specified hashing procedure.
Signing uses the PRIVATE key; verification uses the PUBLIC key.  A signature
authenticates data but does not hide it.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, padding, rsa


def generate_rsa(bits: int = 2048):
    """Generate an RSA private/public pair; practical minimum is 2048 bits."""
    if bits < 2048:
        raise ValueError("use RSA 2048 bits or more")
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return private, private.public_key()


def rsa_pss_sign(message: bytes, private_key) -> bytes:
    """Sign with SHA-256 and randomized PSS padding.

    PSS encodes the hash with a random salt before the RSA private operation,
    so signing the same message twice normally produces different signatures.
    """
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )


def rsa_pss_verify(message: bytes, signature: bytes, public_key) -> bool:
    """Return False instead of raising when message/signature/key is wrong."""
    try:
        public_key.verify(
            signature, message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def rsa_pkcs1v15_sign(message: bytes, private_key) -> bytes:
    """Legacy RSA PKCS#1 v1.5 signature for comparison/interoperability."""
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def rsa_pkcs1v15_verify(message: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def generate_dsa(bits: int = 2048):
    """Generate DSA keys; cryptography accepts 1024, 2048 or 3072 bits."""
    if bits not in (1024, 2048, 3072):
        raise ValueError("DSA size must be 1024, 2048 or 3072")
    private = dsa.generate_private_key(key_size=bits)
    return private, private.public_key()


def dsa_sign(message: bytes, private_key) -> bytes:
    """Return a DER-encoded pair (r,s) using DSA with SHA-256."""
    return private_key.sign(message, hashes.SHA256())


def dsa_verify(message: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(signature, message, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def generate_ecdsa():
    """Generate a NIST P-256 (SECP256R1) ECDSA key pair."""
    private = ec.generate_private_key(ec.SECP256R1())
    return private, private.public_key()


def ecdsa_sign(message: bytes, private_key) -> bytes:
    """Return DER-encoded (r,s); both integers must verify with same message."""
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def ecdsa_verify(message: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def generate_ed25519():
    """Generate Ed25519 keys; public keys and signatures are each 32/64 bytes."""
    private = ed25519.Ed25519PrivateKey.generate()
    return private, private.public_key()


def ed25519_sign(message: bytes, private_key) -> bytes:
    """Sign directly: Ed25519 fixes its hash, curve and encoding choices."""
    return private_key.sign(message)


def ed25519_verify(message: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def private_key_to_pem(private_key, password: str | None = None) -> bytes:
    """Serialize PKCS#8 PEM; encrypt it when a password is supplied."""
    encryption = (serialization.BestAvailableEncryption(password.encode("utf-8"))
                  if password else serialization.NoEncryption())
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )


def public_key_to_pem(public_key) -> bytes:
    """Serialize a shareable SubjectPublicKeyInfo PEM public key."""
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem: bytes, password: str | None = None):
    return serialization.load_pem_private_key(
        pem, password.encode("utf-8") if password else None
    )


def load_public_key(pem: bytes):
    return serialization.load_pem_public_key(pem)


def create_signed_envelope(message: bytes, private_key) -> str:
    """Transport-safe JSON containing Base64 message and Ed25519 signature.

    Base64 is only binary-to-text encoding, NOT encryption.  Real protocols
    must also bind context such as sender, timestamp and protocol name to stop
    a valid signature being replayed in a different context.
    """
    signature = ed25519_sign(message, private_key)
    return json.dumps({
        "algorithm": "Ed25519",
        "message_b64": base64.b64encode(message).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }, separators=(",", ":"))


def verify_signed_envelope(envelope: str, public_key) -> tuple[bool, bytes]:
    """Strictly decode and verify an envelope; return (valid, message)."""
    try:
        item = json.loads(envelope)
        if item.get("algorithm") != "Ed25519":
            return False, b""
        message = base64.b64decode(item["message_b64"], validate=True)
        signature = base64.b64decode(item["signature_b64"], validate=True)
        return ed25519_verify(message, signature, public_key), message
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return False, b""


def sign_file(path: str | Path, private_key) -> bytes:
    """Simple detached Ed25519 signature.  Suitable for ordinary lab files."""
    return ed25519_sign(Path(path).read_bytes(), private_key)


def verify_file(path: str | Path, signature: bytes, public_key) -> bool:
    return ed25519_verify(Path(path).read_bytes(), signature, public_key)


ALGORITHMS = {
    "1": ("RSA-PSS", generate_rsa, rsa_pss_sign, rsa_pss_verify),
    "2": ("DSA", generate_dsa, dsa_sign, dsa_verify),
    "3": ("ECDSA P-256", generate_ecdsa, ecdsa_sign, ecdsa_verify),
    "4": ("Ed25519", generate_ed25519, ed25519_sign, ed25519_verify),
}


def menu() -> None:
    """Input skeleton: choose algorithm, type message, sign, tamper-test."""
    for number, (name, *_unused) in ALGORITHMS.items():
        print(f"{number}. {name}")
    choice = input("Choice: ").strip()
    if choice not in ALGORITHMS:
        raise ValueError("invalid menu choice")
    name, keygen, signer, verifier = ALGORITHMS[choice]
    message = input("Message: ").encode("utf-8")
    private_key, public_key = keygen()
    signature = signer(message, private_key)
    print("Algorithm:", name)
    print("Signature hex:", signature.hex())
    print("Valid:", verifier(message, signature, public_key))
    print("Tampered valid:", verifier(message + b"!", signature, public_key))


if __name__ == "__main__":
    menu()
