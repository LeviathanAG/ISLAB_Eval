"""Two-share threshold-style Paillier snippet.

Usage:
    python3 plug_and_play/standalone/threshold_paillier_snippet.py

The educational helper splits Paillier's private lambda and mu additively into
two shares.  Both shares are needed to decrypt the final aggregate.  This is a
clear 2-of-2 demonstration of the access-control idea; production systems
should use a reviewed threshold-Paillier construction.
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from solved_pyqs.crypto_helpers import (
    combine_threshold_shares,
    make_additive_threshold_shares,
    paillier_add,
    paillier_decrypt_with_private_parts,
    paillier_encrypt,
    paillier_generate,
    paillier_public,
)


def run_menu() -> None:
    """Decrypt only a final Paillier aggregate after combining two shares."""

    while True:
        print("\n=== Threshold Paillier menu ===")
        print("1. Decrypt the final aggregate with both shares")
        print("0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        if choice != "1":
            print("Invalid choice.")
            continue
        key = paillier_generate(128)
        public = paillier_public(key)
        aggregate = paillier_add(paillier_encrypt(10, public), paillier_encrypt(20, public), public)
        threshold = make_additive_threshold_shares(key)
        private_lambda, private_mu = combine_threshold_shares(threshold, 0, 1)
        print("Final aggregate:", paillier_decrypt_with_private_parts(
            aggregate, public, private_lambda, private_mu
        ))


if __name__ == "__main__":
    run_menu()

