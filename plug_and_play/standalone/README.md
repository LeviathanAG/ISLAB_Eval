# Standalone plug-and-play snippets

Each file is a small, commented, menu-driven script that can be copied into an
answer or run from the repository root.  The top comments explain the API,
accepted key sizes/modes, and a working usage example.

```bash
python3 plug_and_play/standalone/hashing_snippet.py
python3 plug_and_play/standalone/aes_cbc_snippet.py
python3 plug_and_play/standalone/rsa_signature_snippet.py
python3 plug_and_play/standalone/elgamal_signature_snippet.py
python3 plug_and_play/standalone/paillier_snippet.py
python3 plug_and_play/standalone/searchable_encryption_snippet.py
python3 plug_and_play/standalone/threshold_paillier_snippet.py
```

The snippets use only the Python standard library plus the `cryptography`
dependency already listed in `requirements.txt`.  `crypto_helpers.py` is the
shared implementation behind the two full PYQ programs.

