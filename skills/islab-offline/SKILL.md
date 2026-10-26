---
name: islab-offline
description: Work on this Information Security lab using only local files, local Python documentation, and installed packages. Use for explaining or changing the lab scripts.
---

# IS Lab offline skill

Work from the repository root. Do not browse the web, call remote APIs, download packages, or invent undocumented library behavior. Treat the repository files, its tests, Python's local documentation, and installed package source as the available reference.

## Before changing code

1. Read the relevant script and its callers.
2. Search this repository with `rg` before changing a function or import.
3. Keep the scripts menu-driven, short, and runnable with ordinary Python.
4. Preserve existing behavior and output unless the user explicitly asks for a change.
5. Prefer standard-library functions and the existing dependencies in `requirements.txt`.
6. Run `python3 -m compileall -q .` on the changed Python files and the relevant tests.

## Offline documentation method

Use these commands instead of internet searches:

```bash
python3 -c 'import inspect, hashlib; print(inspect.signature(hashlib.pbkdf2_hmac)); help(hashlib.pbkdf2_hmac)'
python3 -m pydoc hashlib.pbkdf2_hmac
python3 -c 'import Crypto.Cipher.AES as x; print(x.__file__)'
python3 -c 'import cryptography; print(cryptography.__file__)'
rg -n "def |class |from |import " . --glob '*.py'
```

For an installed package, inspect its local source only after checking the public function signature. Do not claim a function exists until `python3 -c 'import ...'` or `pydoc` confirms it.

## Library quick reference

These are the libraries used by this lab. The exact installed version wins; use `help()` or `inspect.signature()` when a detail matters.

### Python standard library

| Library | Functions used here | Purpose |
|---|---|---|
| `hashlib` | `sha256`, `sha512`, `md5`, `pbkdf2_hmac`, `new` | Hashes and password-based key derivation |
| `hmac` | `new`, `compare_digest`, `digest`, `hexdigest` | Keyed hashes and constant-time comparison |
| `secrets` | `token_bytes`, `token_hex`, `randbelow`, `randbits`, `choice` | Cryptographically secure randomness |
| `math` | `gcd`, `isqrt`, `ceil`, `log2` | Number theory and size calculations |
| `os` | `urandom`, `environ`, `makedirs`, `replace` | OS randomness, environment, and files |
| `pathlib` | `Path`, `.read_bytes`, `.write_bytes`, `.exists`, `.mkdir` | Portable file paths |
| `json` | `dumps`, `loads`, `dump`, `load` | Key and message serialization |
| `base64` | `b64encode`, `b64decode` | Text-safe binary encoding |
| `struct` | `pack`, `unpack` | Fixed-size binary fields |
| `socket` | `socket`, `bind`, `listen`, `accept`, `connect`, `sendall`, `recv` | Hashing/integrity service demos |
| `threading` | `Thread`, `.start`, `.join` | Small concurrent service demos |
| `time` | `time`, `sleep`, `perf_counter` | Timing and benchmarks |
| `statistics` | `mean`, `median`, `stdev` | Benchmark summaries |
| `csv` | `writer`, `DictWriter` | Benchmark output |
| `datetime` | `datetime`, `timezone`, `timedelta` | Timestamps in solved questions |
| `getpass` | `getpass` | Password input without echo |
| `itertools` | `combinations`, `permutations`, `product` | Small exhaustive demonstrations |
| `string` | `ascii_lowercase`, `ascii_uppercase`, `digits` | Classical-cipher alphabets |
| `decimal` | `Decimal`, `InvalidOperation` | Exact amount handling |
| `unittest` | `TestCase`, `assertEqual`, `discover` | Repository tests |

### PyCryptodome

| Import | Functions/classes used | Purpose |
|---|---|---|
| `Crypto.Cipher.AES` | `AES.new`, `MODE_ECB`, `MODE_CBC`, `MODE_GCM` | AES encryption modes |
| `Crypto.Cipher.DES` | `DES.new`, `MODE_ECB`, `MODE_CBC` | DES lab demonstration |
| `Crypto.Cipher.DES3` | `DES3.new`, `MODE_ECB` | 3DES demonstration |
| `Crypto.Util.Padding` | `pad`, `unpad` | Block-cipher padding |
| `Crypto.Random` | `get_random_bytes` | Secure random bytes |
| `Crypto.PublicKey.RSA` | `generate`, `import_key`, `.publickey`, `.export_key` | RSA keys |
| `Crypto.Cipher.PKCS1_OAEP` | `new`, `.encrypt`, `.decrypt` | RSA-OAEP encryption |
| `Crypto.Signature.pss` | `new`, `.sign`, `.verify` | RSA-PSS signatures |
| `Crypto.Signature.pkcs1_15` | `new`, `.sign`, `.verify` | RSA PKCS#1 signatures |
| `Crypto.Hash.SHA256` | `new`, `.update`, `.digest` | Digest objects for RSA APIs |
| `Crypto.Hash.MD5` | `new` | Legacy lab comparison only; do not use for new security code |
| `Crypto.Util.number` | `getPrime`, `inverse` | Prime generation and modular inverse |
| `Crypto.PublicKey.ECC` | `EccPoint` | Elliptic-curve point arithmetic |

Typical patterns:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
ciphertext = cipher.encrypt(pad(message, AES.block_size))
plaintext = unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext), AES.block_size)
```

Never reuse a CBC IV with the same key. Never use ECB for real data; it is present only because the lab demonstrates it.

### `cryptography`

| Import | Functions/classes used | Purpose |
|---|---|---|
| `cryptography.hazmat.primitives.ciphers` | `Cipher`, `algorithms.AES`, `modes.CBC`, `modes.GCM` | Low-level symmetric encryption |
| `cryptography.hazmat.primitives.ciphers.aead` | `AESGCM` | Authenticated AES-GCM |
| `cryptography.hazmat.primitives.kdf.hkdf` | `HKDF` | Derive keys from shared secrets |
| `cryptography.hazmat.primitives.asymmetric.ec` | `SECP256R1`, `generate_private_key`, `.public_key`, `.exchange` | ECDH demonstrations |
| `cryptography.hazmat.primitives.asymmetric.dh` | `generate_parameters`, `generate_private_key`, `.exchange` | Finite-field DH demonstrations |
| `cryptography.hazmat.primitives.asymmetric.rsa` | `generate_private_key`, `public_key`, `padding.OAEP` | RSA demonstrations |
| `cryptography.hazmat.primitives` | `hashes.SHA256`, `serialization` | Hashes and key serialization |
| `cryptography.exceptions` | `InvalidSignature` | Expected signature-failure handling |
| `cryptography.fernet` | `Fernet.generate_key`, `encrypt`, `decrypt` | Simple authenticated encryption |

### `sympy`

| Import | Functions/classes used | Purpose |
|---|---|---|
| `sympy` | `mod_inverse`, `Matrix` | Modular arithmetic and Hill-cipher matrices |
| `sympy.crypto.crypto` | `encipher_affine`, `decipher_affine`, `encipher_vigenere`, `decipher_vigenere` | Classical-cipher reference implementations |

### Optional or source-only libraries

`matplotlib` is used only for optional benchmark plots. `flask`, `requests`, `schedule`, `numpy`, `phe`, and `matplotlib` appear in the copied source-material programs; check `requirements.txt` and the target file before importing them. Do not make the core lab depend on optional packages.

## Security rules for this lab

- Keep servers on `127.0.0.1` unless the user explicitly asks for network access.
- Do not print passwords, private keys, or raw secret material.
- Explain that MD5, DES, ECB, textbook RSA, and homemade cryptography are educational demonstrations, not production choices.
- Use `secrets`, not `random`, for keys, nonces, salts, and challenges.
- Validate authentication before returning plaintext or accepting a state change.

## Response style

Explain the result briefly, show the exact local command to run, and mention any package or hardware assumption. If a requested API is unavailable locally, say so and point to `pydoc` or the installed source; do not fill the gap with a web-based guess.
