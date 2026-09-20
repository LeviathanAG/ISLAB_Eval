"""ElGamal encryption over integers modulo a prime.

Key generation: private x; public h=g^x mod p.
Encryption of 0<=m<p with one-time random k:
    c1=g^k mod p, c2=m*h^k mod p
Decryption:
    m=c2*(c1^x)^-1 mod p
Never reuse k.  For strings, this lab version encrypts each UTF-8 byte; practical
systems use ElGamal to wrap a symmetric key rather than encrypting every byte.
"""
import secrets


def keygen(p: int = 7919, g: int = 2, private: int | None = None):
    x = private if private is not None else secrets.randbelow(p - 3) + 2
    return x, (p, g, pow(g, x, p))


def encrypt(message: bytes, public_key):
    p, g, h = public_key
    output = []
    for byte in message:
        k = secrets.randbelow(p - 3) + 2
        output.append((pow(g, k, p), byte * pow(h, k, p) % p))
    return output


def decrypt(ciphertext, p: int, private: int) -> bytes:
    output = []
    for c1, c2 in ciphertext:
        shared = pow(c1, private, p)
        output.append(c2 * pow(shared, -1, p) % p)
    return bytes(output)


if __name__ == "__main__":
    private, public = keygen(private=2999)
    print("The manual's h=6465 is inconsistent; correct h is", public[2])
    encrypted = encrypt(b"Asymmetric Algorithms", public)
    print("ciphertext:", encrypted)
    print("plaintext :", decrypt(encrypted, public[0], private).decode())

