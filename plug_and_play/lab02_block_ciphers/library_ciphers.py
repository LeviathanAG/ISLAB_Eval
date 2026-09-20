"""Short PyCryptodome AES, DES, and 3DES functions for exam use.

Install: ``pip install pycryptodome`` (import package name is ``Crypto``).

KEY/BLOCK SIZES
* AES: 16-byte block; 16/24/32-byte key.
* DES: 8-byte block; 8-byte stored key (56 effective key bits).
* 3DES: 8-byte block; 16 or 24-byte key.

MODE RULES
* ECB: no IV, leaks repeated-block patterns; PKCS#7 pad plaintext.
* CBC: random unpredictable IV of one block; PKCS#7 pad plaintext.
* CTR: unique nonce for every message under a key; no padding.
* GCM: unique nonce (normally 12 bytes), no padding, returns authentication tag.
Never reuse a CTR/GCM nonce with the same key.
"""
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes | None = None):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    iv = iv or get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return iv, cipher.encrypt(pad(plaintext, AES.block_size))


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes):
    return unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext), AES.block_size)


def aes_ctr_encrypt(plaintext: bytes, key: bytes, nonce: bytes | None = None):
    nonce = nonce or get_random_bytes(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return nonce, cipher.encrypt(plaintext)


def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes):
    return AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ciphertext)


def aes_gcm_encrypt(plaintext: bytes, key: bytes, associated_data: bytes = b""):
    """Preferred real-world example: confidentiality + integrity + authenticity."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag


def aes_gcm_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes,
                    associated_data: bytes = b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    return cipher.decrypt_and_verify(ciphertext, tag)


def des_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes | None = None):
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    iv = iv or get_random_bytes(8)
    return iv, DES.new(key, DES.MODE_CBC, iv).encrypt(pad(plaintext, 8))


def des_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes):
    return unpad(DES.new(key, DES.MODE_CBC, iv).decrypt(ciphertext), 8)


def triple_des_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes | None = None):
    """3DES uses E_K1(D_K2(E_K3(...))).  Distinct subkeys prevent collapse."""
    if len(key) not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes")
    key = DES3.adjust_key_parity(key)
    iv = iv or get_random_bytes(8)
    return iv, DES3.new(key, DES3.MODE_CBC, iv).encrypt(pad(plaintext, 8))


if __name__ == "__main__":
    message = b"Sensitive Information"
    key = bytes.fromhex("0123456789ABCDEF" * 2)  # 16 bytes = AES-128
    iv, encrypted = aes_cbc_encrypt(message, key)
    print("iv        :", iv.hex())
    print("ciphertext:", encrypted.hex())
    print("plaintext :", aes_cbc_decrypt(encrypted, key, iv))

