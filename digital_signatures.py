"""Lab 6 plug-and-play digital-signature functions.

RSA-PSS is the practical library example.  ElGamal, Schnorr, and DSA below are
short educational implementations that expose the numerical equations.  The
small default groups make calculations readable and are NOT production keys.
"""
from __future__ import annotations

import hashlib
import math
import secrets


def hash_integer(message: bytes, modulus: int) -> int:
    """Interpret SHA-256(message) as an integer reduced to the required range."""
    return int.from_bytes(hashlib.sha256(message).digest(), "big") % modulus


def rsa_generate(bits: int = 2048):
    """Generate RSA keys.  PyCryptodome requires at least 1024 bits."""
    if bits < 1024:
        raise ValueError("RSA.generate requires at least 1024 bits; use 2048 normally")
    from Crypto.PublicKey import RSA
    private_key = RSA.generate(bits)
    return private_key, private_key.public_key()


def rsa_sign(message: bytes, private_key) -> bytes:
    """Sign SHA-256(message) with randomized RSA-PSS."""
    from Crypto.Hash import SHA256
    from Crypto.Signature import pss
    return pss.new(private_key).sign(SHA256.new(message))


def rsa_verify(message: bytes, signature: bytes, public_key) -> bool:
    """Return False for any altered message, signature, or wrong key."""
    from Crypto.Hash import SHA256
    from Crypto.Signature import pss
    try:
        pss.new(public_key).verify(SHA256.new(message), signature)
        return True
    except (ValueError, TypeError):
        return False


def elgamal_keygen(p: int = 467, g: int = 2, private: int | None = None):
    """Return private x and public y=g^x mod p.

    Requirements: p is prime; g generates a large subgroup; 1 <= x <= p-2.
    The defaults are deliberately tiny so the lab math is easy to inspect.
    """
    x = private if private is not None else secrets.randbelow(p - 2) + 1
    if not 1 <= x <= p - 2:
        raise ValueError("ElGamal private key must be in 1..p-2")
    return x, pow(g, x, p)


def elgamal_sign(message: bytes, private: int, p: int = 467, g: int = 2):
    """Return (r,s), where r=g^k and s=k^-1(H(m)-xr) mod (p-1).

    The nonce k must be random, secret, never reused, and coprime to p-1.
    Reusing k can reveal the private key.
    """
    hashed = hash_integer(message, p - 1)
    while True:
        k = secrets.randbelow(p - 2) + 1
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((hashed - private * r) * pow(k, -1, p - 1)) % (p - 1)
    return r, s


def elgamal_verify(message: bytes, signature, public: int, p: int = 467, g: int = 2) -> bool:
    """Check g^H(m) == y^r * r^s (mod p)."""
    r, s = signature
    if not (0 < r < p and 0 <= s < p - 1 and 0 < public < p):
        return False
    left = pow(g, hash_integer(message, p - 1), p)
    right = pow(public, r, p) * pow(r, s, p) % p
    return left == right


def schnorr_keygen(p: int = 23, q: int = 11, g: int = 2, private: int | None = None):
    """Return x and y=g^x mod p for a q-order subgroup.

    Requirements: q divides p-1 and g^q mod p = 1.  Real deployments use a
    standardized large group; (23,11,2) is only an exam-size demonstration.
    """
    if (p - 1) % q or pow(g, q, p) != 1 or g == 1:
        raise ValueError("Invalid Schnorr group")
    x = private if private is not None else secrets.randbelow(q - 1) + 1
    if not 1 <= x < q:
        raise ValueError("Schnorr private key must be in 1..q-1")
    return x, pow(g, x, p)


def schnorr_sign(message: bytes, private: int, p: int = 23, q: int = 11, g: int = 2):
    """Return (R,s): R=g^k, e=H(R||m), s=k+ex mod q."""
    k = secrets.randbelow(q - 1) + 1
    commitment = pow(g, k, p)
    challenge = hash_integer(commitment.to_bytes((p.bit_length() + 7) // 8, "big") + message, q)
    response = (k + challenge * private) % q
    return commitment, response


def schnorr_verify(message: bytes, signature, public: int, p: int = 23, q: int = 11, g: int = 2) -> bool:
    """Check g^s == R*y^e (mod p)."""
    commitment, response = signature
    if not (0 < commitment < p and 0 <= response < q and 0 < public < p):
        return False
    challenge = hash_integer(commitment.to_bytes((p.bit_length() + 7) // 8, "big") + message, q)
    return pow(g, response, p) == commitment * pow(public, challenge, p) % p


def dsa_keygen(p: int = 23, q: int = 11, g: int = 2, private: int | None = None):
    """DSA uses Diffie-Hellman-style discrete-log parameters (p,q,g)."""
    return schnorr_keygen(p, q, g, private)


def dsa_sign(message: bytes, private: int, p: int = 23, q: int = 11, g: int = 2):
    """Return (r,s): r=(g^k mod p) mod q; s=k^-1(H(m)+xr) mod q."""
    hashed = hash_integer(message, q)
    while True:
        k = secrets.randbelow(q - 1) + 1
        r = pow(g, k, p) % q
        s = pow(k, -1, q) * (hashed + private * r) % q
        if r and s:
            return r, s


def dsa_verify(message: bytes, signature, public: int, p: int = 23, q: int = 11, g: int = 2) -> bool:
    """Verify DSA.  Plain Diffie-Hellman itself is key agreement, not signing."""
    r, s = signature
    if not (0 < r < q and 0 < s < q):
        return False
    w = pow(s, -1, q)
    u1 = hash_integer(message, q) * w % q
    u2 = r * w % q
    return (pow(g, u1, p) * pow(public, u2, p) % p) % q == r

