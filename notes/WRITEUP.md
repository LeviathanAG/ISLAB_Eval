# How to explain the lab answers

## Classical ciphers

Use `A=0,...,Z=25`. Caesar/additive is `C=(P+k) mod 26`; decrypt with
`P=(C-k) mod 26`. Multiplicative is `C=aP mod 26`; `a` must have an inverse,
so `gcd(a,26)=1`. Affine combines both: `C=aP+b`, and decrypts with
`a^-1(C-b) mod 26`. Vigenere uses a repeating key: `C_i=P_i+K_i mod 26`.
Autokey starts with the short key, then appends plaintext. Playfair uses a 5x5
square, splits into digraphs, inserts X between repeated letters, and shifts a
row, column, or rectangle. Hill maps each block with `C=K P mod 26`; the key
must be invertible modulo 26. Transposition keeps letters but changes positions.

Known-plaintext and chosen-plaintext attacks reveal the mapping by supplying or
recognising plaintext. Brute force is appropriate when the key space is small;
frequency analysis ranks guesses, but is not proof on short text.

## Symmetric ciphers

DES has 64-bit blocks, a nominal 56-bit key, and 16 Feistel rounds. AES has
128-bit blocks and 128/192/256-bit keys; its rounds are SubBytes, ShiftRows,
MixColumns, and AddRoundKey (the final round omits MixColumns). ECB repeats
patterns. CBC XORs each plaintext block with the previous ciphertext and needs
an unpredictable IV. CTR encrypts a counter and XORs the keystream with data;
never reuse a nonce/key pair. PKCS#7 adds `n` bytes each equal to `n`, even when
the message already fits a block. DES is legacy; use authenticated AES-GCM in
real systems. The manual's AES-192 key is only 128 bits and its repeated 3DES
key collapses to single DES; state the correction explicitly.

## Public-key algorithms

RSA chooses primes `p,q`, computes `n=pq`, `phi=(p-1)(q-1)`, then `ed=1 mod
phi`. Textbook RSA is `m^e mod n`; exam demonstrations can use it, but real
messages need OAEP and signatures need PSS. Factoring `n`, shared primes,
close primes, low exponents, and raw small messages are classic failures.

ElGamal uses `h=g^x mod p`; encryption is `(g^k, m h^k)`, decryption multiplies
by `(g^kx)^-1`. Reusing `k` leaks relationships. Rabin squares `m mod n` and
decryption gives four roots, so redundancy is needed to identify the message.
Diffie-Hellman computes `A=g^a`, `B=g^b`, and shared `g^(ab)`; authenticate the
public values or a man-in-the-middle can create two secrets. ECC uses the same
idea with point multiplication and smaller keys. ECDH is key agreement, not
direct message encryption: derive a symmetric key with HKDF, then use an
authenticated cipher.

## Timing and scenarios

Time only the operation, repeat it, and report the average or median. Do not
compare different message sizes or include printing/key generation unless the
question asks. `exam_scripts/04_timing/time_it.py` is the copy-paste helper.
KMS answers should authenticate callers, enforce role/owner/expiry, encrypt
private keys at rest, audit every operation, and revoke active versions. A
customer who receives a master private key can keep an offline copy after API
revocation; the service must distribute per-content keys instead.

## Hashing

The manual's custom function is DJB2-style: `h=5381`, then
`h=((h<<5)+h)+character`, masked to 32 bits. It is a fast non-cryptographic
hash. A cryptographic hash maps arbitrary bytes to a fixed digest and should
resist preimages, second preimages, and collisions. MD5 and SHA-1 are retained
only for the required comparison; use SHA-256 or stronger in new designs. A
100-message experiment normally finds no collisions in any of them and does
not prove security: an ideal n-bit hash reaches the birthday collision scale
near `2^(n/2)` samples. A bare hash detects accidental changes only when the
expected digest arrives through a trusted channel; use HMAC or a signature
against an active attacker.

## Digital signatures

A signature hashes the message and applies private-key mathematics; verification
uses the public key. It gives integrity, origin authentication, and usually
non-repudiation, but no confidentiality. RSA-PSS is randomized and suitable for
new RSA signatures. ElGamal, Schnorr, and DSA require a fresh unpredictable
nonce for every signature; nonce reuse can expose the private key. Plain
Diffie-Hellman is key agreement rather than a signature. To authenticate DH,
sign the ephemeral public values or use a signature scheme such as DSA, which
uses related discrete-log group mathematics.
