# Variation index

AES/DES editing guide: `02_symmetric/MODIFY_AES_DES.md`.

|---|---|
| Caesar/additive, changed key, decrypt | `01_classical/caesar.py` |
| Multiplicative or affine | `multiplicative_pure.py`, `affine.py`, `affine_lib.py` |
| Vigenere or autokey | `vigenere.py`, `autokey_pure.py` |
| Rail fence or columnar transposition | `rail_fence_*.py`, `columnar_pure.py` |
| Mix substitution ciphers | `05_variations/classical_pipeline_*.py` |
| AES modes or key sizes | `02_symmetric/aes_all_modes_lib.py`, `aes_modes_pure.py`, `aes_key_sizes_lib.py` |
| DES or 3DES | `des_*.py`, `triple_des_lib.py` |
| Authenticated encryption or files | `aes_gcm_lib.py`, `aes_file_lib.py` |
| RSA, signatures, or hybrid encryption | `03_asymmetric/rsa_*.py`, `rsa_aes_hybrid_*.py` |
| Sign then encrypt / encrypt then sign | `sign_then_encrypt_lib.py`, `encrypt_then_sign_lib.py` |
| DH/ECDH plus encryption | `dh_*.py`, `ecdh_aes_*.py` |
| RSA-authenticated DH | `signed_dh_lib.py` |
| ElGamal or Rabin | `elgamal_pure.py`, `rabin_pure.py` |
| Timing comparison | `04_timing/time_it.py`, `compare_aes_des.py` |
| Cipher attacks | `05_variations/` contains one attack per file |
| Access control, rotation, audit | `access_control.py`, `key_rotation.py`, `audit_log.py` |

For an unseen combination, copy the relevant small functions and apply them in
encryption order. Decryption always calls them in reverse order.
