# Plug-and-play function pack

This folder is the fastest route during the lab exam.  Each file contains the
requirements, input rules, mathematics, reusable functions, and a tiny demo.
Copy the function you need together with the helper functions listed directly
above it.

For paper-question input handling, IV/nonce initialization, ciphertext hex,
and complete menu examples, read `INPUT_AND_MENU_GUIDE.md`. Start a generic
menu question with `generic_menu_skeleton.py`; use the fully working
AES/DES/3DES version in `lab02_block_ciphers/symmetric_menu.py`.

## Navigation

| Need | File |
|---|---|
| Additive/Caesar | `lab01_classical/additive.py` |
| Multiplicative/Affine | `lab01_classical/affine.py` |
| Vigenere/Autokey | `lab01_classical/vigenere_autokey.py` |
| Playfair | `lab01_classical/playfair.py` |
| Hill | `lab01_classical/hill.py` |
| AES algorithm internals | `lab02_block_ciphers/aes_from_scratch.py` |
| DES algorithm internals | `lab02_block_ciphers/des_from_scratch.py` |
| AES/DES/3DES library calls and modes | `lab02_block_ciphers/library_ciphers.py` |
| Complete AES/DES/3DES input menu | `lab02_block_ciphers/symmetric_menu.py` |
| RSA | `lab03_public_key/rsa.py` |
| Diffie-Hellman | `lab03_public_key/diffie_hellman.py` |
| ElGamal | `lab03_public_key/elgamal.py` |
| ECC/ECDH + AES | `lab03_public_key/ecc_hybrid.py` |
| Key-manager scenario patterns | `lab04_key_management/key_manager_patterns.py` |
| Weak-RSA attack | `lab04_key_management/weak_rsa_attack.py` |
| Hashing | `lab05_hashing/` |
| Digital signatures | `lab06_signatures/` |

Run scripts from the repository root, for example:

```bash
python plug_and_play/lab02_block_ciphers/aes_from_scratch.py
```

The from-scratch code is for learning and written exams.  For real data, use
the library versions and an authenticated mode such as AES-GCM.
