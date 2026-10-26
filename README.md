# Information Security Lab - complete midsem pack

This repository solves every exercise and additional exercise from Labs 1-6.
It also contains readable, reusable implementations for adapting to unseen exam
questions.

The additional source-backed solutions requested for the secure grant portal,
national e-voting, and Labs 5-8 are in [`solved_pyqs/`](solved_pyqs/),
[`solved_labs/`](solved_labs/), and [`plug_and_play/standalone/`](plug_and_play/standalone/).
The user-provided manuals and locally saved API references are in
[`source_material/`](source_material/) and [`docs/`](docs/).

Revision material and the complete question audit are in
[`STUDY_NOTES_LABS_1_TO_8.md`](STUDY_NOTES_LABS_1_TO_8.md) and
[`LAB_1_TO_8_AUDIT.md`](LAB_1_TO_8_AUDIT.md).

## Fastest way during the exam

Start `lab.py` and choose an exercise from the menu.  `Q` means Lab Exercise
and `A` means Additional Exercise.  The solved PYQs and standalone snippets
also start directly in their own menus; no flags or command-line options are
needed.

For an implementation question, open [`plug_and_play/README.md`](plug_and_play/README.md).
   AES and DES now have readable full implementations with individual round
   functions and known-answer tests.

4. For an unfamiliar variation, open [`question_bank/README.md`](question_bank/README.md).
   It contains ten examiner-style variations for every algorithm in all six labs.

## Repository map

| Path | Purpose |
|---|---|
| `lab.py` | One command runs any exact manual exercise |
| `plug_and_play/` | Copy-paste functions, formulas, constraints, and demos |
| `plug_and_play/INPUT_AND_MENU_GUIDE.md` | Taking input, IVs, nonces, ciphertext and menu patterns |
| `plug_and_play/generic_menu_skeleton.py` | Minimal reusable menu-driven program |
| `question_bank/` | Ten question variations for every algorithm |
| `notes/INPUT_RULES.md` | Key sizes, block sizes, IV/nonce and padding rules |
| `notes/LIBRARY_REFERENCE.md` | PyCryptodome, cryptography, hashlib, SymPy APIs |
| `notes/WRITEUP.md` | Short theory answers and trade-offs |
| `classical.py` | Complete classical-cipher engine |
| `symmetric.py` | Complete pure AES/DES/3DES engine and modes |
| `public_key.py` | RSA, ElGamal, DH, ECC and Rabin primitives |
| `services.py` | Lab 4 key-management and access-control scenarios |
| `hashing.py` | Lab 5 hashes, benchmarks, collision and socket helpers |
| `digital_signatures.py` | Lab 6 RSA-PSS, ElGamal, Schnorr and DSA signatures |

## Setup

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

All pure classical/hash code uses the standard library.  Library AES/DES/RSA
uses PyCryptodome.  ECC and encrypted key storage use `cryptography`.  SymPy is
optional for alternate classical-cipher arithmetic.  Matplotlib is needed only
for timing graphs.

## Manual errors already handled

- Lab 1 keyed-transposition sample changes `I` to `L`, which a transposition
  cannot do; the corrected sample is documented.
- Lab 2 calls a 16-byte hex key AES-192; the answer explicitly repairs it to
  24 bytes.
- Lab 2 repeats the same DES subkey three times, causing 3DES to collapse to
  single DES; the answer demonstrates both the literal and corrected key.
- Lab 3 gives ElGamal `(p=7919,g=2,h=6465,x=2999)`, but
  `2^2999 mod 7919 = 3868`; the answer reports and corrects the inconsistency.
- Lab 6 calls Diffie-Hellman an encryption/signature algorithm.  The answer
  explains that plain DH is key agreement and uses DSA/authenticated DH for the
  requested signing behavior.
