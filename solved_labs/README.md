# Solved lab examples

The supplied `Sem_5_Labs` repository contains Information Security manuals for
Labs 1–8.  The exact source exercises used here are:

| Folder | Source exercise |
|---|---|
| `lab05_hashing/` | Manual 5: user hash, socket integrity, timing/collisions, multipart transfer |
| `lab06_signatures/` | Manual 6: RSA signatures, ElGamal/Schnorr, DH-style signing, client/server, CIA |
| `lab07_phe/` | Manual 7: Paillier addition, RSA multiplication, ElGamal multiplication, encrypted data sharing, thresholding, performance comparison |
| `lab08_searchable_encryption/` | Manual 8: SSE, Paillier-backed indexes, GnuPG, and Snort command/log helpers |

The source repository has no Lab 9, 10, or 11 PDF.  Folders for those numbers
are intentionally not represented as invented solutions: an exact solution
requires the missing questions.  The downloaded source tree and text extracts
are in `source_material/`.

The full Lab 1-8 revision sheet and question-by-question verification are in
[`../STUDY_NOTES_LABS_1_TO_8.md`](../STUDY_NOTES_LABS_1_TO_8.md) and
[`../LAB_1_TO_8_AUDIT.md`](../LAB_1_TO_8_AUDIT.md).

Run an exercise from the repository root and choose from its menu:

```bash
python3 solved_labs/lab05_hashing/solutions.py
python3 solved_labs/lab06_signatures/solutions.py
python3 solved_labs/lab07_phe/solutions.py
python3 solved_labs/lab08_searchable_encryption/solutions.py
```

Every script is deliberately verbose and commented so it can be copied into a
lab answer.  `standalone/` contains smaller plug-and-play versions of the
individual primitives.

