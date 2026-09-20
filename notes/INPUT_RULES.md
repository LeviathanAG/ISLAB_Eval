# Input, key, IV, nonce, and padding rules

| Algorithm | Data unit | Key/parameter requirement | Extra rule |
|---|---:|---|---|
| Additive | letters | integer mod 26 | only 26 keys |
| Multiplicative | letters | gcd(key,26)=1 | modular inverse required |
| Affine | letters | gcd(a,26)=1; b any mod 26 | 312 valid `(a,b)` keys |
| Vigenere | letters | nonempty alphabetic keyword | repeats keyword |
| Autokey | letters | initial letter/word | extends key with plaintext |
| Playfair | digraph | keyword creates 5x5 square | I/J merged; filler X/Q |
| Hill 2x2 | 2 letters | gcd(det(K),26)=1 | pad odd plaintext |
| AES | 16-byte block | 16/24/32-byte key | 10/12/14 rounds |
| DES | 8-byte block | 8 stored bytes, 56 effective bits | obsolete |
| 3DES | 8-byte block | 16 or 24 bytes | avoid repeated subkeys |
| CBC | block multiples | one-block unpredictable IV | PKCS#7 padding |
| CTR | any length | unique nonce/counter per key | no padding |
| GCM | any length | normally 12-byte unique nonce | verifies tag before use |
| RSA textbook | integer `m<n` | primes p,q; gcd(e,phi)=1 | demonstration only |
| RSA-OAEP SHA-256 | up to k-66 bytes | normally >=2048-bit modulus | use hybrid for files |
| Diffie-Hellman | group elements | validated p,g and peer public | authenticate exchange |
| ElGamal | integer `m<p` | fresh random k each encryption | ciphertext doubles |
| P-256 ECDH | curve point | private scalar/public point | derive AES key with HKDF |
| Rabin | integer `m<n` | p,q distinct and 3 mod 4 | decryption gives 4 roots |
| Hash | any bytes | no key | fixed-size digest |
| Digital signature | any bytes | private signs, public verifies | sign a cryptographic hash |

Text strings must be encoded to bytes (`text.encode('utf-8')`) before modern
cryptography. Ciphertext and keys are printed with `.hex()` for safe display;
recover bytes with `bytes.fromhex(text)`. Never confuse hexadecimal characters
with raw bytes: 32 hex characters represent 16 bytes.
