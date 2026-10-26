"""Small, readable cryptographic building blocks used by the solved PYQs.

This module intentionally keeps the examples self-contained.  It uses the
``cryptography`` package for AES and RSA, while Paillier and the educational
ElGamal signature are implemented directly so that the homomorphic equations
are visible in the source.

The functions are educational examples for a lab, not a replacement for a
reviewed production cryptographic protocol.  In particular, MD5 and the
small ElGamal group used by the demos must not be used for real systems.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------------------------------------------------------------------------
# Encoding, files, and canonical records
# ---------------------------------------------------------------------------


def b64_encode(value: bytes) -> str:
    """Encode bytes as text suitable for a JSON record."""

    return base64.b64encode(value).decode("ascii")


def b64_decode(value: str) -> bytes:
    """Decode a base64 JSON field and raise a useful error for bad input."""

    return base64.b64decode(value.encode("ascii"), validate=True)


def canonical_json(value: Any) -> bytes:
    """Serialize a value deterministically before hashing or signing it."""

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def load_json(path: Path, default: Any) -> Any:
    """Load JSON, returning ``default`` when a new store does not exist."""

    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"Could not read JSON store {path}: {exc}") from exc


def save_json(path: Path, value: Any) -> None:
    """Atomically save a JSON file so a partial write does not corrupt data."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True), encoding="utf-8"
    )
    temporary.replace(path)


def make_password_record(password: str) -> dict[str, Any]:
    """Create a salted PBKDF2-HMAC record for a local role password."""

    if not password:
        raise ValueError("Role password cannot be blank")
    salt = os.urandom(16)
    iterations = 200_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {
        "salt": b64_encode(salt),
        "digest": b64_encode(digest),
        "iterations": iterations,
    }


def verify_password_record(password: str, record: dict[str, Any]) -> bool:
    """Verify a role password with a constant-time digest comparison."""

    try:
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            b64_decode(str(record["salt"])),
            int(record["iterations"]),
        )
        return hmac.compare_digest(digest, b64_decode(str(record["digest"])))
    except (KeyError, TypeError, ValueError):
        return False


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp with a trailing ``Z``."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_timestamp(value: str) -> datetime:
    """Parse the timestamp format emitted by :func:`utc_now`."""

    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def hex_dump(data: bytes, width: int = 16) -> str:
    """Return a conventional offset/hex/ascii dump for a byte string."""

    lines: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        hex_part = f"{hex_part:<{width * 3 - 1}}"
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines) if lines else "<empty>"


# ---------------------------------------------------------------------------
# AES-CBC with PKCS#7 padding
# ---------------------------------------------------------------------------


def aes_cbc_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt with AES-CBC and return ``(iv, ciphertext)``.

    AES-192 therefore requires a 24-byte key and AES-256 requires a 32-byte
    key.  A fresh random IV is generated for every encryption.
    """

    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    iv = os.urandom(algorithms.AES.block_size // 8)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv, encryptor.update(padded) + encryptor.finalize()


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt and unpad an AES-CBC ciphertext."""

    if len(key) not in (16, 24, 32) or len(iv) != 16:
        raise ValueError("Invalid AES key or IV length")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---------------------------------------------------------------------------
# RSA encryption/signatures
# ---------------------------------------------------------------------------


def ensure_rsa_keypair(directory: Path, bits: int = 2048):
    """Load or create an RSA keypair in PEM files under ``directory``."""

    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / "rsa_private.pem"
    public_path = directory / "rsa_public.pem"
    if private_path.exists() and public_path.exists():
        private_key = serialization.load_pem_private_key(
            private_path.read_bytes(), password=None
        )
        public_key = serialization.load_pem_public_key(public_path.read_bytes())
        return private_key, public_key

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private_key, public_key


def rsa_encrypt(plaintext: bytes, public_key) -> bytes:
    """Encrypt a short key with RSA-OAEP-SHA256."""

    return public_key.encrypt(
        plaintext,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(ciphertext: bytes, private_key) -> bytes:
    """Decrypt an RSA-OAEP-SHA256 ciphertext."""

    return private_key.decrypt(
        ciphertext,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_sign(message: bytes, private_key) -> bytes:
    """Sign bytes using RSA-PSS with SHA-256."""

    return private_key.sign(
        message,
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_verify(message: bytes, signature: bytes, public_key) -> bool:
    """Return ``False`` instead of raising for an invalid RSA signature."""

    try:
        public_key.verify(
            signature,
            message,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Small-prime and Paillier helpers
# ---------------------------------------------------------------------------


def is_probable_prime(number: int, rounds: int = 24) -> bool:
    """Miller-Rabin primality test suitable for lab-sized generated keys."""

    if number < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if number % small == 0:
            return number == small
    odd_part, powers = number - 1, 0
    while odd_part % 2 == 0:
        odd_part //= 2
        powers += 1
    for _ in range(rounds):
        witness = secrets.randbelow(number - 3) + 2
        value = pow(witness, odd_part, number)
        if value in (1, number - 1):
            continue
        for _ in range(powers - 1):
            value = pow(value, 2, number)
            if value == number - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate an odd probable prime with the requested bit length."""

    if bits < 16:
        raise ValueError("Prime size must be at least 16 bits")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def _lcm(left: int, right: int) -> int:
    """Return the least common multiple without another dependency."""

    return left // math.gcd(left, right) * right


def paillier_generate(bits: int = 256) -> dict[str, int]:
    """Generate a Paillier keypair represented by JSON-friendly integers."""

    p = generate_prime(bits // 2)
    q = generate_prime(bits - bits // 2)
    while p == q:
        q = generate_prime(bits - bits // 2)
    n = p * q
    private_lambda = _lcm(p - 1, q - 1)
    # The standard convenient generator g=n+1 makes L(g^lambda) = lambda.
    mu = pow(private_lambda, -1, n)
    return {
        "n": n,
        "g": n + 1,
        "p": p,
        "q": q,
        "lambda": private_lambda,
        "mu": mu,
    }


def paillier_public(key: dict[str, int]) -> dict[str, int]:
    """Return only the public portion of a Paillier key."""

    return {"n": int(key["n"]), "g": int(key.get("g", key["n"] + 1))}


def paillier_encrypt(message: int, public_key: dict[str, int]) -> int:
    """Encrypt an integer using Paillier's additive homomorphism."""

    n = int(public_key["n"])
    if not 0 <= message < n:
        raise ValueError("Paillier plaintext must satisfy 0 <= m < n")
    modulus = n * n
    while True:
        randomizer = secrets.randbelow(n - 1) + 1
        if math.gcd(randomizer, n) == 1:
            break
    return (
        pow(int(public_key.get("g", n + 1)), message, modulus)
        * pow(randomizer, n, modulus)
    ) % modulus


def paillier_add(left: int, right: int, public_key: dict[str, int]) -> int:
    """Add two encrypted integers by multiplying ciphertexts modulo n²."""

    n = int(public_key["n"])
    return (left * right) % (n * n)


def paillier_decrypt(ciphertext: int, key: dict[str, int]) -> int:
    """Decrypt one Paillier ciphertext using its private key."""

    n = int(key["n"])
    modulus = n * n
    value = pow(int(ciphertext), int(key["lambda"]), modulus)
    l_value = (value - 1) // n
    return (l_value * int(key["mu"])) % n


def paillier_decrypt_with_private_parts(
    ciphertext: int, public_key: dict[str, int], private_lambda: int, private_mu: int
) -> int:
    """Decrypt with reconstructed threshold shares, without a full key dict."""

    n = int(public_key["n"])
    value = pow(int(ciphertext), int(private_lambda), n * n)
    return (((value - 1) // n) * int(private_mu)) % n


def make_additive_threshold_shares(
    key: dict[str, int], share_count: int = 2
) -> dict[str, Any]:
    """Split Paillier's two private values into additive shares.

    This is a deliberately clear 2-of-2 teaching model: every share is needed
    to reconstruct ``lambda`` and ``mu``.  It demonstrates the access-control
    property requested by the e-voting question; production threshold Paillier
    should use a reviewed threshold cryptography implementation.
    """

    if share_count != 2:
        raise ValueError("The teaching implementation supports exactly two shares")
    largest = max(int(key["lambda"]), int(key["mu"]))
    field = generate_prime(max(32, largest.bit_length() + 2))
    first_lambda = secrets.randbelow(field)
    first_mu = secrets.randbelow(field)
    return {
        "field": field,
        "shares": [
            {"lambda": first_lambda, "mu": first_mu},
            {
                "lambda": (int(key["lambda"]) - first_lambda) % field,
                "mu": (int(key["mu"]) - first_mu) % field,
            },
        ],
    }


def combine_threshold_shares(
    threshold: dict[str, Any], first: int = 0, second: int = 1
) -> tuple[int, int]:
    """Combine two separate shares, rejecting a missing or duplicate share."""

    shares = threshold["shares"]
    if first == second or not (0 <= first < len(shares)) or not (0 <= second < len(shares)):
        raise ValueError("Two distinct valid threshold shares are required")
    field = int(threshold["field"])
    lambda_value = (int(shares[first]["lambda"]) + int(shares[second]["lambda"])) % field
    mu_value = (int(shares[first]["mu"]) + int(shares[second]["mu"])) % field
    return lambda_value, mu_value


# ---------------------------------------------------------------------------
# Educational ElGamal signature and trusted timestamps
# ---------------------------------------------------------------------------


# 2^255 - 19 is a well-known prime.  The group is intentionally compact for
# a lab; real signature systems should use standardized modern parameters.
ELGAMAL_P = 2**255 - 19
ELGAMAL_G = 5


def elgamal_keygen(private: int | None = None) -> dict[str, int]:
    """Create an educational ElGamal signing keypair."""

    x = private if private is not None else secrets.randbelow(ELGAMAL_P - 2) + 1
    if not 1 <= x <= ELGAMAL_P - 2:
        raise ValueError("ElGamal private key is outside the valid range")
    return {"p": ELGAMAL_P, "g": ELGAMAL_G, "x": x, "y": pow(ELGAMAL_G, x, ELGAMAL_P)}


def _message_integer(message: bytes) -> int:
    """Hash a message into the exponent ring used by ElGamal."""

    return int.from_bytes(hashlib.sha512(message).digest(), "big") % (ELGAMAL_P - 1)


def elgamal_sign(message: bytes, private_key: dict[str, int]) -> tuple[int, int]:
    """Return ``(r, s)`` for the textbook ElGamal signature equation."""

    modulus_minus_one = int(private_key["p"]) - 1
    while True:
        nonce = secrets.randbelow(modulus_minus_one - 2) + 2
        if math.gcd(nonce, modulus_minus_one) == 1:
            break
    r = pow(int(private_key["g"]), nonce, int(private_key["p"]))
    digest = _message_integer(message)
    s = ((digest - int(private_key["x"]) * r) * pow(nonce, -1, modulus_minus_one)) % modulus_minus_one
    return r, s


def elgamal_verify(
    message: bytes, signature: Iterable[int], public_key: dict[str, int]
) -> bool:
    """Verify ``g^H(m) = y^r r^s (mod p)`` without leaking exceptions."""

    try:
        r, s = (int(value) for value in signature)
        p, g, y = (int(public_key[name]) for name in ("p", "g", "y"))
        if not (0 < r < p and 0 <= s < p - 1 and 0 < y < p):
            return False
        left = pow(g, _message_integer(message), p)
        right = pow(y, r, p) * pow(r, s, p) % p
        return left == right
    except (TypeError, ValueError, KeyError):
        return False


def timestamp_token(timestamp: str, message_hash: str, secret: bytes) -> str:
    """Create a trusted-authority MAC over a timestamp and ballot hash."""

    payload = f"{timestamp}|{message_hash}".encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def verify_timestamp_token(
    timestamp: str, message_hash: str, token: str, secret: bytes
) -> bool:
    """Verify a timestamp token using constant-time comparison."""

    expected = timestamp_token(timestamp, message_hash, secret)
    return hmac.compare_digest(expected, token)

