"""RSA math plus safe library encryption/signing.

TEXTBOOK MATH
1. Choose distinct primes p,q; n=pq and phi=(p-1)(q-1).
2. Choose e with gcd(e,phi)=1; compute d=e^-1 mod phi.
3. Encrypt integer m<n: c=m^e mod n.  Decrypt: m=c^d mod n.

Textbook RSA is deterministic and insecure for real messages.  Use OAEP for
encryption and PSS for signatures.  RSA-OAEP can encrypt only short values:
with SHA-256, at most modulus_bytes-66 bytes.  Encrypt files with a random AES
key and encrypt only that key using RSA.
"""
from math import gcd


def textbook_keypair(p: int, q: int, e: int = 65537):
    if p == q:
        raise ValueError("p and q must differ")
    n, phi = p*q, (p-1)*(q-1)
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime to phi(n)")
    return (n, e), (n, pow(e, -1, phi))


def textbook_encrypt_bytes(message: bytes, public_key):
    n, e = public_key
    if n <= 255:
        raise ValueError("bytewise demo requires n > 255")
    return [pow(byte, e, n) for byte in message]


def textbook_decrypt_bytes(ciphertext: list[int], private_key):
    n, d = private_key
    return bytes(pow(value, d, n) for value in ciphertext)


def generate_rsa(bits: int = 2048):
    from Crypto.PublicKey import RSA
    private = RSA.generate(bits)
    return private, private.public_key()


def oaep_encrypt(message: bytes, public_key) -> bytes:
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    return PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(message)


def oaep_decrypt(ciphertext: bytes, private_key) -> bytes:
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(ciphertext)


if __name__ == "__main__":
    public, private = textbook_keypair(17, 19, e=5)
    encrypted = textbook_encrypt_bytes(b"Cryptographic Protocols", public)
    print("public/private:", public, private)  # d=173, matching the manual
    print("ciphertext:", encrypted)
    print("plaintext :", textbook_decrypt_bytes(encrypted, private).decode())

