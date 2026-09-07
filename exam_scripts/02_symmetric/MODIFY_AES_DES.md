# AES/DES modification cheat sheet

Change these values near the top of a script:

```python
message = b'new plaintext'       # `b` means bytes
key = b'0123456789ABCDEF'        # AES: exactly 16, 24, or 32 bytes
des_key = b'12345678'            # DES: exactly 8 bytes
iv = b'1234567890ABCDEF'         # AES CBC/CFB/OFB: exactly 16 bytes
nonce = b'12345678'              # AES CTR: normally 8 bytes here
```

Use `bytes.fromhex('001122...')` when the question gives hexadecimal. Use
`'text'.encode()` to turn a string into bytes and `plaintext.decode()` to turn
bytes back into text.

| Mode | Extra input | Padding | Main property |
|---|---|---|---|
| ECB | none | yes | repeated blocks are visible |
| CBC | random/unpredictable IV | yes | blocks are chained |
| CFB | unique IV | no | stream-like |
| OFB | unique IV | no | stream-like |
| CTR | unique nonce/counter | no | parallel and stream-like |
| GCM | unique nonce | no | encryption plus authentication tag |

For a fixed lab answer, reuse the exact IV/nonce for decryption. In a real
program, generate a fresh IV/nonce for every encryption and store it beside the
ciphertext. Never reuse a GCM or CTR nonce with the same key.

`AES.MODE_ECB` can be replaced with `AES.MODE_CBC`, `AES.MODE_CFB`,
`AES.MODE_OFB`, `AES.MODE_CTR`, or `AES.MODE_GCM`, but constructor arguments
and padding must be changed as shown in `aes_all_modes_lib.py`.

DES has an 8-byte block and key. AES always has a 16-byte block regardless of
key size. 3DES uses a 16-byte or 24-byte key. DES and 3DES are for lab study;
choose AES-GCM for a new real application.
