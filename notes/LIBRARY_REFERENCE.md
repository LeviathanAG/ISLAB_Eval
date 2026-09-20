# Crypto library reference

## PyCryptodome (`Crypto`)

Install with `pip install pycryptodome`. `Crypto.Cipher.AES`, `DES`, and `DES3`
provide block ciphers; `Crypto.Util.Padding.pad/unpad` supplies PKCS#7 padding;
`Crypto.PublicKey.RSA` creates/imports RSA keys; `Crypto.Cipher.PKCS1_OAEP`
provides safe RSA encryption; `Crypto.Signature.pss` supplies RSA-PSS signatures;
`Crypto.Hash.SHA256` creates the hash object expected by PSS/OAEP.

Do not install the obsolete package named `crypto`. The distribution is
`pycryptodome`, while its Python import path is `Crypto`.

## cryptography

Install with `pip install cryptography`. `ec.SECP256R1()` selects P-256;
`private.exchange(ec.ECDH(), public)` computes an ECDH secret; `HKDF` derives a
uniform key; `AESGCM` provides authenticated encryption; `Fernet` is a simple
high-level authenticated-encryption token and is used to demonstrate encrypting
private keys at rest.

## hashlib, hmac, secrets, socket (standard library)

`hashlib.new(name, bytes).hexdigest()` hashes bytes. `hmac.compare_digest`
compares authentication values without early-exit timing leakage. `secrets`
creates cryptographic random keys/nonces; do not use `random` for secrets.
`socket` is a byte stream: one `recv` need not equal one `send`, so prefix each
message with a fixed-width length or loop until all bytes arrive.

## sympy

Install with `pip install sympy`. Useful lab helpers include `mod_inverse(a,m)`,
`Matrix.det()`, `Matrix.adjugate()`, and classical cipher helpers in
`sympy.crypto.crypto`. The pure files show the math when library calls are not
allowed.
