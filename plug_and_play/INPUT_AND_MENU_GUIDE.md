# Taking input in crypto lab programs

Use this guide when the question is printed on paper and you must decide which
values are typed, generated, encoded, or displayed.

## The four conversions to remember

```python
plaintext_bytes = input("Plaintext: ").encode("utf-8")
key_bytes = bytes.fromhex(input("Key hex: ").strip())
ciphertext_bytes = bytes.fromhex(input("Ciphertext hex: ").strip())
print("Ciphertext hex:", ciphertext_bytes.hex())
```

Normal strings must become bytes before modern cryptography. Ciphertext is
arbitrary binary and may not be valid text, so display and accept it as hex.
Two hex characters represent one byte: 32 hex characters = 16 bytes = 128 bits.

## If the paper gives a text key

For `key = "A1B2C3D4"`, the eight characters themselves are eight bytes:

```python
key = input("8-character DES key: ").encode("utf-8")
if len(key) != 8:
    raise ValueError("DES key must encode to exactly 8 bytes")
```

For `key = "0123456789ABCDEF0123456789ABCDEF"`, the manual normally intends
hexadecimal, producing 16 bytes:

```python
key = bytes.fromhex(input("AES key hex: "))
if len(key) not in (16, 24, 32):
    raise ValueError("AES key must be 16, 24, or 32 bytes")
```

State your interpretation because 32 ASCII characters would instead be 32
bytes and therefore an AES-256 key.

## ECB

ECB requires no IV or nonce. ECB/CBC need padding for arbitrary-length text.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = bytes.fromhex(input("Key hex: "))
plaintext = input("Plaintext: ").encode()
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
print(ciphertext.hex())

ciphertext = bytes.fromhex(input("Ciphertext hex: "))
plaintext = unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), AES.block_size)
print(plaintext.decode())
```

## CBC and IV initialization

The IV is random/unpredictable, exactly one block, public, and different for
each encryption. AES IV = 16 bytes; DES/3DES IV = 8 bytes. Decryption must use
the exact IV produced during encryption.

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

key = bytes.fromhex(input("AES key hex: "))
iv = get_random_bytes(AES.block_size)       # initialize a new 16-byte IV
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
ciphertext = cipher.encrypt(pad(input("Plaintext: ").encode(), AES.block_size))
print("IV hex:", iv.hex())
print("Ciphertext hex:", ciphertext.hex())

# Values typed back during decryption:
iv = bytes.fromhex(input("IV hex: "))
ciphertext = bytes.fromhex(input("Ciphertext hex: "))
plaintext = unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext), 16)
print(plaintext.decode())
```

If the paper explicitly gives `IV="12345678"` for DES, use:

```python
iv = input("8-character IV: ").encode()      # b"12345678"
```

## CTR and nonce initialization

CTR needs no padding. Its nonce/counter combination must never repeat with the
same key. The nonce is public and must accompany ciphertext.

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = bytes.fromhex(input("AES key hex: "))
nonce = get_random_bytes(8)
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
ciphertext = cipher.encrypt(input("Plaintext: ").encode())
print("Nonce hex:", nonce.hex())
print("Ciphertext hex:", ciphertext.hex())

nonce = bytes.fromhex(input("Nonce hex: "))
ciphertext = bytes.fromhex(input("Ciphertext hex: "))
plaintext = AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ciphertext)
```

## GCM, nonce, and tag

GCM gives encryption plus tamper detection. Save the nonce and tag. Decryption
fails when the key, nonce, ciphertext, associated data, or tag is wrong.

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = bytes.fromhex(input("AES key hex: "))
nonce = get_random_bytes(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(input("Plaintext: ").encode())
print("Nonce:", nonce.hex(), "Ciphertext:", ciphertext.hex(), "Tag:", tag.hex())

nonce = bytes.fromhex(input("Nonce hex: "))
ciphertext = bytes.fromhex(input("Ciphertext hex: "))
tag = bytes.fromhex(input("Tag hex: "))
plaintext = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag)
```

## Classical-cipher input patterns

```python
text = input("Message: ")
integer_key = int(input("Additive/multiplicative key: "))
keyword = input("Vigenere/Playfair keyword: ").strip()
a = int(input("Affine a: "))
b = int(input("Affine b: "))
hill_key = [[int(x) for x in input("Row 1: ").split()],
            [int(x) for x in input("Row 2: ").split()]]
permutation = [int(x) for x in input("Permutation, space separated: ").split()]
```

Validate `gcd(multiplicative_key,26)==1`, `gcd(a,26)==1`, and
`gcd(det(Hill_key),26)==1` before encrypting.

## RSA, ElGamal, and Diffie-Hellman inputs

```python
n = int(input("RSA modulus n: "))
e = int(input("RSA public exponent e: "))
d = int(input("RSA private exponent d: "))
message_integer = int(input("Message integer (< n): "))

p = int(input("Prime p: "))
g = int(input("Generator g: "))
private = int(input("Private exponent: "))
peer_public = int(input("Peer public value: "))
```

For RSA-OAEP/library keys, generate or import key objects rather than asking for
large integers manually. For ElGamal require each message integer `< p`. For
Diffie-Hellman validate the peer's public value before computing the secret.

## File input

```python
from pathlib import Path
source = Path(input("Input filename: ").strip())
data = source.read_bytes()
Path(input("Output filename: ").strip()).write_bytes(ciphertext)
```

For large files, use hybrid encryption: encrypt file bytes with AES-GCM and
encrypt only the small AES key using RSA/ECC.

## What to print in the observation/output

Always label values clearly:

```python
print("Algorithm:", algorithm)
print("Mode:", mode)
print("Key size (bits):", len(key) * 8)
print("IV/nonce hex:", iv_or_nonce.hex())
print("Ciphertext hex:", ciphertext.hex())
print("Recovered plaintext:", recovered.decode())
print("Round trip successful:", recovered == plaintext)
```

Never print a private key in a real system. Printing demo keys is acceptable
only when the lab specifically asks you to show generated values.

