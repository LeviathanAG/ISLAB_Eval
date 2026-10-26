# Lab 1-8 solution verification

Source checked: the three supplied Information Security Lab PDFs in
`source_material/Sem_5_Labs/Debrato_240911734_IS/IS/`.

Verification method:

- Extracted the complete PDF text with Poppler.
- Mapped every numbered lab and additional exercise to an implementation.
- Ran all 41 Lab 1-4 registry entries from `lab.py` with the default pure
  backend and one benchmark repeat.
- Ran the Lab 5-8 solution suites.
- Ran the repository test suite: 24 tests passed.
- Compiled the changed Python files successfully.

## Coverage matrix

| Manual | Questions covered | Implementation | Result |
|---|---|---|---|
| Lab 1 | 6 exercises + 3 additional | `lab.py` entries `L1Q1-L1Q6`, `L1A1-L1A3` | Verified: 9/9 |
| Lab 2 | 5 exercises + 5 additional | `lab.py` entries `L2Q1-L2Q5`, `L2A1-L2A5` | Verified: 10/10 |
| Lab 3 | 5 exercises + 5 additional | `lab.py` entries `L3Q1-L3Q5`, `L3A1-L3A5` | Verified: 10/10 |
| Lab 4 | 2 exercises + 2 additional | `lab.py` entries `L4Q1-L4Q2`, `L4A1-L4A2`; KMS code in `services.py` | Verified: 4/4 |
| Lab 5 | 3 exercises + 1 additional | `solved_labs/lab05_hashing/solutions.py` | Verified: 4/4 |
| Lab 6 | 3 exercises + 1 additional | `solved_labs/lab06_signatures/solutions.py` | Verified: 4/4 |
| Lab 7 | 2 exercises + 4 additional | `solved_labs/lab07_phe/solutions.py` | Verified: 6/6 |
| Lab 8 | 2 exercises + 2 additional | `solved_labs/lab08_searchable_encryption/solutions.py`, `gnupg_tools.py`, `snort_tools.py` | Verified: 4/4 |

Total: **51 numbered items covered**.

## Question-level mapping

### Lab 1

- Q1: additive, multiplicative, and affine encryption/decryption.
- Q2: Vigenere and autokey.
- Q3: Playfair with `GUIDANCE`.
- Q4: Hill cipher.
- Q5: known-plaintext shift attack and tablet plaintext.
- Q6: affine brute force constrained by `ab -> GL`.
- A1: birthday-near additive brute force.
- A2: chosen-plaintext transposition inference and key-size reasoning.
- A3: Vigenere with `HEALTH`.

### Lab 2

- Q1: DES round-trip.
- Q2: AES-128 round-trip.
- Q3: DES versus AES-256 timing.
- Q4: Triple DES repeated-key issue and corrected distinct-key comparison.
- Q5: AES-192 round trace and round-trip. The malformed 16-byte manual key is
  explicitly repaired to 24 bytes.
- A1: DES/AES key-size and mode benchmark with CSV/graph support.
- A2: DES block encryption/decryption.
- A3: AES-256 round-trip.
- A4: DES-CBC round-trip.
- A5: AES-CTR round-trip.

### Lab 3

- Q1: RSA encryption/decryption.
- Q2: ECC hybrid encryption/decryption.
- Q3: ElGamal encryption/decryption.
- Q4: RSA/ECC/EC-ElGamal file-size benchmark.
- Q5: Diffie-Hellman shared-secret and timing test.
- A1: inconsistent ElGamal public value corrected before use.
- A2: ECC repeat.
- A3: small textbook RSA example.
- A4: healthcare hybrid/EC-ElGamal performance scenario.
- A5: RSA versus EC-ElGamal versus ECC comparison.

### Lab 4

- Q1: SecureCorp authenticated RSA/DH communication, KMS, revocation, and
  enrollment of a new subsystem.
- Q2: Healthcare Rabin key generation, encrypted storage, access control,
  revocation, renewal, and audit logging, plus Rabin/RSA trade-off.
- A1: ElGamal DRM content encryption, time-limited grants, creator ownership,
  revocation, key renewal, and audit logging.
- A2: weak-RSA factorization attack using trial, Fermat, and Pollard-rho-style
  methods, with mitigation notes.

### Lab 5-8

The corresponding solution folders contain a menu entry for each row in the
coverage table. Lab 7 now includes secure encrypted data sharing and a small
Paillier-versus-ElGamal timing comparison in addition to the original four
demonstrations. Lab 8 documents the searchable-encryption leakage trade-off
instead of comparing randomized ciphertexts directly.

## Important scope notes

- The manual's website-based RSA signature activity is implemented as a local
  RSA-PSS sign/verify demonstration, so it is repeatable without a website.
- The manual asks for real Snort monitoring. The repository safely builds the
  commands and analyzes an alert log; it does not start privileged capture.
- The manual's sample Paillier and searchable-encryption snippets contain
  mathematical or equality-search issues. The solutions use correct small
  educational implementations and call out the limitations.
- This audit covers Labs 1-8 only. The supplied Information Security source
  repository does not include exact Information Security Lab 9-11 manuals.
