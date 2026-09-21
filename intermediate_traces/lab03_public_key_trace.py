"""Lab 3 public-key algorithms with printable mathematical working."""
from __future__ import annotations

import hashlib
from math import gcd

from trace_utils import heading


def rsa_trace(message: bytes, p: int = 17, q: int = 19, e: int = 5) -> list[int]:
    """Textbook bytewise RSA trace. Tiny primes are for paper arithmetic only."""
    if p == q:
        raise ValueError("p and q must differ")
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1 or n <= 255:
        raise ValueError("need gcd(e,phi)=1 and n>255 for bytewise example")
    d = pow(e, -1, phi)
    print(f"p={p}, q={q}")
    print(f"n=p*q={p}*{q}={n}")
    print(f"phi(n)=(p-1)(q-1)={p-1}*{q-1}={phi}")
    print(f"e={e}; gcd(e,phi)=1")
    print(f"d=e^-1 mod phi={d}; check: ({e}*{d}) mod {phi}={(e*d)%phi}")
    print(f"public key=(n={n},e={e}); private key=(n={n},d={d})")
    ciphertext = []
    recovered = []
    for index, byte in enumerate(message, 1):
        cipher = pow(byte, e, n)
        plain = pow(cipher, d, n)
        print(f"{index:2}. m={byte:3} ({chr(byte)!r}); c=m^e mod n="
              f"{byte}^{e} mod {n}={cipher}; m'=c^d mod n={plain}")
        ciphertext.append(cipher)
        recovered.append(plain)
    print("ciphertext integers:", ciphertext)
    print("recovered bytes    :", bytes(recovered))
    return ciphertext


def square_and_multiply_trace(base: int, exponent: int, modulus: int) -> int:
    """Show the modular exponentiation steps used throughout Labs 3/4/6."""
    result = 1
    base %= modulus
    print(f"compute power: base={base}, exponent={exponent} ({exponent:b}), mod={modulus}")
    step = 0
    while exponent:
        bit = exponent & 1
        before = result
        if bit:
            result = result * base % modulus
        print(f"step {step}: bit={bit}, result {before}->{result}, base={base}")
        base = base * base % modulus
        exponent >>= 1
        step += 1
    print("power result:", result)
    return result


def diffie_hellman_trace(p: int = 23, g: int = 5,
                         alice_private: int = 6, bob_private: int = 15) -> int:
    """Print both public values and both equal shared-secret computations."""
    alice_public = pow(g, alice_private, p)
    bob_public = pow(g, bob_private, p)
    alice_shared = pow(bob_public, alice_private, p)
    bob_shared = pow(alice_public, bob_private, p)
    print(f"public parameters: prime p={p}, generator g={g}")
    print(f"Alice private a={alice_private}; A=g^a mod p={alice_public}")
    print(f"Bob   private b={bob_private}; B=g^b mod p={bob_public}")
    print(f"Alice computes B^a mod p={bob_public}^{alice_private} mod {p}={alice_shared}")
    print(f"Bob computes   A^b mod p={alice_public}^{bob_private} mod {p}={bob_shared}")
    print(f"reason equal: g^(ab) mod p; match={alice_shared == bob_shared}")
    encoded = alice_shared.to_bytes(max(1, (alice_shared.bit_length() + 7) // 8), "big")
    derived = hashlib.sha256(encoded).digest()
    print(f"SHA-256(shared-secret bytes {encoded.hex()})={derived.hex()}")
    return alice_shared


def elgamal_trace(message_integer: int, p: int = 467, g: int = 2,
                   private: int = 127, nonce: int = 53) -> tuple[int, int]:
    """Deterministic paper trace; real encryption requires a fresh random nonce."""
    if not 0 <= message_integer < p:
        raise ValueError("message integer must be in 0..p-1")
    public = pow(g, private, p)
    c1 = pow(g, nonce, p)
    shared_sender = pow(public, nonce, p)
    c2 = message_integer * shared_sender % p
    shared_receiver = pow(c1, private, p)
    inverse = pow(shared_receiver, -1, p)
    recovered = c2 * inverse % p
    print(f"p={p}, g={g}, private x={private}")
    print(f"public h=g^x mod p={g}^{private} mod {p}={public}")
    print(f"message m={message_integer}; one-time nonce k={nonce}")
    print(f"c1=g^k mod p={c1}")
    print(f"sender shared s=h^k mod p={shared_sender}")
    print(f"c2=m*s mod p={message_integer}*{shared_sender} mod {p}={c2}")
    print(f"receiver shared s'=c1^x mod p={shared_receiver}")
    print(f"s'^-1 mod p={inverse}")
    print(f"recovered m'=c2*s'^-1 mod p={recovered}")
    return c1, c2


def ecdh_aesgcm_trace(message: bytes, aad: bytes = b"lab3") -> bytes:
    """Print observable ECDH, HKDF and AES-GCM intermediate fields."""
    import os
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    alice = ec.generate_private_key(ec.SECP256R1())
    bob = ec.generate_private_key(ec.SECP256R1())
    a_numbers = alice.public_key().public_numbers()
    b_numbers = bob.public_key().public_numbers()
    print("curve=SECP256R1/P-256")
    print(f"Alice public point: x={a_numbers.x:X}, y={a_numbers.y:X}")
    print(f"Bob public point  : x={b_numbers.x:X}, y={b_numbers.y:X}")
    shared_a = alice.exchange(ec.ECDH(), bob.public_key())
    shared_b = bob.exchange(ec.ECDH(), alice.public_key())
    print("Alice raw ECDH shared:", shared_a.hex())
    print("Bob raw ECDH shared  :", shared_b.hex())
    print("shared values match  :", shared_a == shared_b)
    salt = os.urandom(16)
    info = b"ISLAB-ECDH-AESGCM"
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared_a)
    print("HKDF salt:", salt.hex())
    print("HKDF info:", info)
    print("derived AES-256 key:", key.hex())
    nonce = os.urandom(12)
    combined = AESGCM(key).encrypt(nonce, message, aad)
    print("GCM nonce (12 bytes):", nonce.hex())
    print("AAD (authenticated, visible):", aad)
    print("ciphertext:", combined[:-16].hex())
    print("GCM tag (last 16 bytes):", combined[-16:].hex())
    print("recovered:", AESGCM(key).decrypt(nonce, combined, aad))
    return combined


def demo() -> None:
    heading("LAB 3: RSA")
    rsa_trace(b"Hi")
    heading("LAB 3: SQUARE-AND-MULTIPLY")
    square_and_multiply_trace(5, 117, 19)
    heading("LAB 3: DIFFIE-HELLMAN")
    diffie_hellman_trace()
    heading("LAB 3: ELGAMAL")
    elgamal_trace(72)
    heading("LAB 3: ECC/ECDH + AES-GCM")
    ecdh_aesgcm_trace(b"ECC message")


if __name__ == "__main__":
    demo()
