# Intermediate-output runners for Labs 1-6

These are additive exam helpers. They do not replace the short reusable
functions in `plug_and_play/`. Each trace prints the working an examiner may
ask you to show: normalization, numeric conversion, generated keys/streams,
round inputs, modular equations, verification sides, and recovered output.

Run the common examples:

```bash
python intermediate_traces/trace_menu.py --all
python intermediate_traces/trace_menu.py --lab 2
python intermediate_traces/lab01_classical_trace.py
```

Import one function when the question supplies different values:

```python
from intermediate_traces.lab01_classical_trace import affine_trace
affine_trace("HELLO", a=5, b=8)

from intermediate_traces.lab02_block_trace import aes_trace
aes_trace(bytes.fromhex("00112233445566778899aabbccddeeff"),
          bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
```

## What each file prints

| Lab | File | Intermediate values |
|---|---|---|
| 1 | `lab01_classical_trace.py` | letter numbers, equations, key streams, Playfair pairs/rules, Hill vectors, transposition positions |
| 2 | `lab02_block_trace.py` | AES round keys/states, DES key schedule/E/XOR/S-box/P/L/R, 3DES stages, CBC XOR chain |
| 3 | `lab03_public_key_trace.py` | RSA `n,phi,d,m,c`, DH public/shared/KDF, ElGamal `k,c1,s,c2`, ECDH coordinates/KDF/AEAD fields |
| 4 | `lab04_key_management_trace.py` | Rabin four roots, Fermat attempts, lifecycle versions/status/audit hashes, envelope DEK wrapping stages |
| 5 | `lab05_hashing_trace.py` | manual-hash state per character, hash padding/blocks, complete SHA-256 schedule and 64 rounds, HMAC/PBKDF2/Merkle stages |
| 6 | `lab06_signature_trace.py` | message hash, nonce, `(r,s)`, both verification sides, RSA/DSA/ECDSA/Ed25519 signature structure |

The tiny parameters and fixed nonces in some demonstrations exist only so the
math is reproducible on paper. Never use fixed/reused signature or ElGamal
nonces in real software.
