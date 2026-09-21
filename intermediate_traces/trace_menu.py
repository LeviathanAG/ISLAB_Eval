"""One entry point for every lab's intermediate-output demonstration."""
from __future__ import annotations

import argparse

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
    parser = argparse.ArgumentParser(description="Print IS-lab intermediate steps")
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--lab", type=int, choices=LABS, help="trace one lab")
    choice.add_argument("--all", action="store_true", help="trace Labs 1 through 6")
    arguments = parser.parse_args()
    selected = sorted(LABS) if arguments.all else [arguments.lab]
    for number in selected:
        LABS[number]()


if __name__ == "__main__":
    main()
