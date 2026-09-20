"""Diffie-Hellman key agreement - standalone educational version.

Public parameters: prime p and generator g.  Alice selects secret a and sends
A=g^a mod p.  Bob selects b and sends B=g^b mod p.  Both calculate
B^a=A^b=g^(ab) mod p.  DH does not encrypt or sign by itself; authenticate A/B
to prevent a man-in-the-middle attack and feed the shared value through a KDF.
"""
import hashlib
import secrets


def create_keypair(p: int, g: int):
    private = secrets.randbelow(p - 3) + 2
    public = pow(g, private, p)
    return private, public


def shared_secret(peer_public: int, private: int, p: int) -> int:
    if not 2 <= peer_public <= p - 2:
        raise ValueError("invalid peer public value")
    return pow(peer_public, private, p)


def derive_aes_key(shared: int, length: int = 32) -> bytes:
    """Simple lab KDF.  HKDF should be preferred when the library is available."""
    raw = shared.to_bytes((shared.bit_length() + 7)//8, "big")
    return hashlib.sha256(raw).digest()[:length]


if __name__ == "__main__":
    p, g = 7919, 2
    alice_private, alice_public = create_keypair(p, g)
    bob_private, bob_public = create_keypair(p, g)
    left = shared_secret(bob_public, alice_private, p)
    right = shared_secret(alice_public, bob_private, p)
    print("shared equal:", left == right)
    print("AES key:", derive_aes_key(left).hex())

