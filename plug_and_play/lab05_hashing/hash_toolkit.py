"""Exam-ready hashing toolkit: copy individual functions as required.

Important distinction
---------------------
* Hash: unkeyed fingerprint; gives integrity only (SHA-256, SHA-3, BLAKE2).
* HMAC: keyed hash; gives integrity AND source authentication.
* Password KDF: intentionally slow and salted (PBKDF2 here).  A fast SHA hash
  must not be used directly for storing passwords.

All functions accept ``bytes``.  At a prompt convert text with
``input("Message: ").encode("utf-8")`` and display binary output with ``.hex()``.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from pathlib import Path


# Common exam algorithms and their digest sizes.  MD5 and SHA-1 are included
# for comparison/legacy questions only because practical collisions exist.
DIGEST_BITS = {
    "md5": 128,
    "sha1": 160,
    "sha224": 224,
    "sha256": 256,
    "sha384": 384,
    "sha512": 512,
    "sha3_256": 256,
    "sha3_512": 512,
    "blake2s": 256,
    "blake2b": 512,
}


def hash_bytes(data: bytes, algorithm: str = "sha256") -> bytes:
    """Return the raw digest for any byte string, including empty input.

    ``hashlib.new`` makes the algorithm selectable from a menu.  A digest with
    n output bits has roughly 2^n preimage work but only 2^(n/2) collision work
    because of the birthday paradox.
    """
    name = algorithm.lower().replace("-", "")
    if name not in DIGEST_BITS:
        raise ValueError(f"choose one of: {', '.join(DIGEST_BITS)}")
    return hashlib.new(name, data, usedforsecurity=False).digest()


def hash_text(text: str, algorithm: str = "sha256") -> str:
    """UTF-8 encode text and return a hexadecimal digest for easy printing."""
    return hash_bytes(text.encode("utf-8"), algorithm).hex()


def hash_file(path: str | Path, algorithm: str = "sha256",
              chunk_size: int = 64 * 1024) -> str:
    """Hash a large file without loading the entire file into RAM.

    Repeated ``update`` calls are equivalent to hashing the concatenation.
    ``chunk_size`` affects speed/memory, never the final digest.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    name = algorithm.lower().replace("-", "")
    if name not in DIGEST_BITS:
        raise ValueError(f"choose one of: {', '.join(DIGEST_BITS)}")
    digest = hashlib.new(name, usedforsecurity=False)
    with Path(path).open("rb") as source:
        while chunk := source.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def hmac_generate(message: bytes, key: bytes,
                  algorithm: str = "sha256") -> bytes:
    """Generate HMAC_K(message); keys should be random and secret.

    HMAC conceptually combines a key with inner and outer padded hashes:
      H((K xor opad) || H((K xor ipad) || message))
    A 32-byte random key is a convenient choice for HMAC-SHA-256.
    """
    if not key:
        raise ValueError("HMAC key must not be empty")
    return hmac.new(key, message, algorithm).digest()


def hmac_verify(message: bytes, key: bytes, received_tag: bytes,
                algorithm: str = "sha256") -> bool:
    """Verify in constant-time; do not compare authentication tags with ==."""
    expected = hmac_generate(message, key, algorithm)
    return hmac.compare_digest(expected, received_tag)


def password_hash(password: str, iterations: int = 600_000,
                  salt: bytes | None = None) -> tuple[bytes, bytes, int]:
    """Return (salt, derived_key, iterations) using PBKDF2-HMAC-SHA256.

    Salt is public and unique; it defeats rainbow tables.  Iterations make each
    guess expensive.  Store all three returned fields, never the password.
    The output is 32 bytes (256 bits); password strength still depends on the
    user's password entropy, not merely the digest length.
    """
    if iterations < 100_000:
        raise ValueError("use at least 100,000 iterations for this lab example")
    actual_salt = salt if salt is not None else secrets.token_bytes(16)
    if len(actual_salt) < 16:
        raise ValueError("salt must be at least 16 bytes")
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), actual_salt, iterations, dklen=32
    )
    return actual_salt, derived, iterations


def password_verify(password: str, salt: bytes, expected: bytes,
                    iterations: int) -> bool:
    """Recompute the PBKDF2 result and compare it in constant time."""
    _, actual, _ = password_hash(password, iterations, salt)
    return hmac.compare_digest(actual, expected)


def bit_difference(left: bytes, right: bytes) -> int:
    """Count changed bits (Hamming distance); inputs must have equal length."""
    if len(left) != len(right):
        raise ValueError("digests must have equal length")
    return sum((a ^ b).bit_count() for a, b in zip(left, right))


def avalanche_demo(message: bytes, algorithm: str = "sha256") -> dict:
    """Flip one input bit and measure changed digest bits.

    A good cryptographic hash changes about half its output bits.  This is the
    avalanche effect, not by itself proof of collision resistance.
    """
    if not message:
        raise ValueError("message must contain at least one byte")
    changed = bytes([message[0] ^ 1]) + message[1:]
    first = hash_bytes(message, algorithm)
    second = hash_bytes(changed, algorithm)
    differing = bit_difference(first, second)
    return {
        "original_digest": first.hex(),
        "changed_digest": second.hex(),
        "changed_bits": differing,
        "total_bits": len(first) * 8,
        "percent": differing * 100 / (len(first) * 8),
    }


def truncated_collision(bits: int = 16, algorithm: str = "sha256",
                        limit: int = 100_000) -> tuple[bytes, bytes, str] | None:
    """Find a classroom collision after truncating a hash to ``bits``.

    Expected work is about 2^(bits/2), illustrating the birthday bound.  This
    does NOT break full SHA-256; only the deliberately shortened digest.
    """
    if not 8 <= bits <= 24 or bits % 8:
        raise ValueError("use a byte-aligned size from 8 to 24 bits")
    size = bits // 8
    seen: dict[bytes, bytes] = {}
    for counter in range(limit):
        message = counter.to_bytes(8, "big")
        short = hash_bytes(message, algorithm)[:size]
        if short in seen and seen[short] != message:
            return seen[short], message, short.hex()
        seen[short] = message
    return None


def merkle_root(items: list[bytes], algorithm: str = "sha256") -> bytes:
    """Return a binary Merkle-tree root for a non-empty list of records.

    Leaves use H(0x00 || item), parents use H(0x01 || left || right).  Prefixes
    provide domain separation.  An odd final node is duplicated at that level.
    Changing any record changes its path and therefore the root.
    """
    if not items:
        raise ValueError("Merkle tree needs at least one item")
    level = [hash_bytes(b"\x00" + item, algorithm) for item in items]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hash_bytes(b"\x01" + level[i] + level[i + 1], algorithm)
            for i in range(0, len(level), 2)
        ]
    return level[0]


def interactive_demo() -> None:
    """Minimal input example suitable for an exam menu option."""
    message = input("Message: ").encode("utf-8")
    algorithm = input("Algorithm [sha256]: ").strip() or "sha256"
    print("Digest:", hash_bytes(message, algorithm).hex())
    if message:
        print("Avalanche:", avalanche_demo(message, algorithm))
    key_text = input("HMAC key in hex [blank=random]: ").strip()
    key = bytes.fromhex(key_text) if key_text else secrets.token_bytes(32)
    tag = hmac_generate(message, key)
    print("HMAC key:", key.hex())
    print("HMAC tag:", tag.hex())


if __name__ == "__main__":
    # Written inline instead of calling interactive_demo so the blank/random
    # input path is completely clear during a practical examination.
    raw = input("Message: ").encode("utf-8")
    chosen = input("Algorithm [sha256]: ").strip() or "sha256"
    print("Digest:", hash_bytes(raw, chosen).hex())
    if raw:
        print("Avalanche:", avalanche_demo(raw, chosen))
    key_text = input("HMAC key as hex [blank = random 32 bytes]: ").strip()
    secret_key = bytes.fromhex(key_text) if key_text else secrets.token_bytes(32)
    tag = hmac_generate(raw, secret_key)
    print("HMAC key (save/share securely):", secret_key.hex())
    print("HMAC tag:", tag.hex())
    print("Verified:", hmac_verify(raw, secret_key, tag))
