# Exam question bank

There are ten variations for every algorithm used across Labs 1-6.  The aim is
to recognize which parameter/function changes while keeping the core algorithm
unchanged.  Start with the exact manual question in `lab.py`, then use the file
for that lab:

- `lab01_classical.md`
- `lab02_block_ciphers.md`
- `lab03_public_key.md`
- `lab04_key_management.md`
- `lab05_hashing.md`
- `lab06_signatures.md`

For “combine algorithms” questions, encryption runs in the stated order and
decryption runs in reverse order.  For timing questions, do not include printing
or key generation unless requested.  For socket questions, TCP requires message
framing because `recv()` boundaries do not preserve `send()` boundaries.
