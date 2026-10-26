"""One entry point for every lab's intermediate-output demonstration."""
from __future__ import annotations

import lab01_classical_trace
import lab02_block_trace
import lab03_public_key_trace
import lab04_key_management_trace
import lab05_hashing_trace
import lab06_signature_trace


LABS = {
    1: lab01_classical_trace.demo,
    2: lab02_block_trace.demo,
    3: lab03_public_key_trace.demo,
    4: lab04_key_management_trace.demo,
    5: lab05_hashing_trace.demo,
    6: lab06_signature_trace.demo,
}


def main() -> None:
    """Print one lab trace, or every trace, from a menu."""

    while True:
        print("\n=== Intermediate traces ===")
        for number in sorted(LABS):
            print(f"{number}. Lab {number}")
        print("7. Run every trace")
        print("0. Exit")
        choice = input("Choose a trace: ").strip()
        if choice == "0" or not choice:
            return
        if choice == "7":
            selected = sorted(LABS)
        elif choice.isdigit() and int(choice) in LABS:
            selected = [int(choice)]
        else:
            print("Invalid choice.")
            continue
        for number in selected:
            LABS[number]()


if __name__ == "__main__":
    main()
