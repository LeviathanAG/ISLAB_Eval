# Information Security Lab - complete midsem pack

This repository solves every exercise and additional exercise from Labs 1-6.
It also contains readable, reusable implementations for adapting to unseen exam
questions.

## Fastest way during the exam

1. List every exact manual question:

   ```bash
   python lab.py --list
   ```

2. Run one answer, for example:

   ```bash
   python lab.py L1Q4
   python lab.py L2Q5
   python lab.py L5Q3
   python lab.py L6A1
   ```

   `Q` means Lab Exercise and `A` means Additional Exercise.  Use
   `--backend pure` for from-scratch implementations or `--backend lib` for
   library implementations where supported.

3. For an implementation question, open [`plug_and_play/README.md`](plug_and_play/README.md).
   AES and DES now have readable full implementations with individual round
   functions and known-answer tests.

4. For an unfamiliar variation, open [`question_bank/README.md`](question_bank/README.md).
   It contains ten examiner-style variations for every algorithm in all six labs.

## Repository map

| Path | Purpose |
|---|---|
| `lab.py` | One command runs any exact manual exercise |
| `plug_and_play/` | Copy-paste functions, formulas, constraints, and demos |
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

