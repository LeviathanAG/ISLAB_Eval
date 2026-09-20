# IS lab exam pack

For the new fully explained functions, including from-scratch AES/DES and Labs
5-6, start at `../plug_and_play/README.md`.  For exact manual answers use
`python ../lab.py --list` from this directory, or `python lab.py --list` from
the repository root.

One concept per file. Run from this directory, for example:

    python 01_classical/caesar.py
    python 04_timing/compare_aes_des.py

The copied `all_*.py` files are the complete pure implementations. The small
files are the exam versions. Change the variables at the top. `time_it.py`
contains the timing function to copy into any answer.

For AES/DES changes, read `02_symmetric/MODIFY_AES_DES.md`. Every symmetric
script marks editable lines with `MODIFY`, explains its key/IV/nonce length,
and shows where padding is required.
