"""ECC/ECDH + AES-GCM hybrid encryption using ``cryptography``.

ECC is point arithmetic, not direct string encryption.  On P-256, a private key
is a scalar d and public key is Q=dG.  ECDH computes d_A*Q_B=d_B*Q_A.  HKDF turns
the shared point-derived bytes into a uniform AES key, and AES-GCM encrypts data.

P-256 private/public keys provide roughly 128-bit security.  AES-GCM accepts any
message length, uses a 32-byte AES-256 key here, and requires a unique 12-byte
nonce for every encryption under that key.
"""
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_keypair():
    private = ec.generate_private_key(ec.SECP256R1())
    return private, private.public_key()


def derive_key(our_private, peer_public, salt: bytes, context: bytes = b"ISLAB-ECDH"):
    shared = our_private.exchange(ec.ECDH(), peer_public)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=context).derive(shared)


def encrypt_for_recipient(message: bytes, recipient_public, aad: bytes = b""):
    ephemeral_private, ephemeral_public = generate_keypair()
    salt, nonce = os.urandom(16), os.urandom(12)
    key = derive_key(ephemeral_private, recipient_public, salt)
    ciphertext = AESGCM(key).encrypt(nonce, message, aad)
    return ephemeral_public, salt, nonce, ciphertext


def decrypt_from_sender(package, recipient_private, aad: bytes = b""):
    ephemeral_public, salt, nonce, ciphertext = package
    key = derive_key(recipient_private, ephemeral_public, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


if __name__ == "__main__":
    private, public = generate_keypair()
    package = encrypt_for_recipient(b"Secure Transactions", public)
    print("ciphertext:", package[-1].hex())
    print("plaintext :", decrypt_from_sender(package, private).decode())

