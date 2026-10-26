"""Small symmetric searchable-encryption snippet.

Usage:
    python3 plug_and_play/standalone/searchable_encryption_snippet.py
    index = build_index(documents, secret); search(index, "word", secret)

The index uses HMAC-SHA256 tokens so only a holder of the shared secret can
query it.  Token equality leaks that the same word was searched repeatedly;
production SSE needs a reviewed leakage profile and key-management design.
"""

from __future__ import annotations

import hashlib
import hmac


def _token(word: str, secret: bytes) -> str:
    """Create a normalized keyed search token."""

    return hmac.new(secret, word.lower().encode(), hashlib.sha256).hexdigest()


def build_index(documents: dict[str, str], secret: bytes) -> dict[str, list[str]]:
    """Map keyed tokens to document IDs."""

    index: dict[str, list[str]] = {}
    for document_id, document in documents.items():
        for word in set(document.lower().split()):
            index.setdefault(_token(word, secret), []).append(document_id)
    return index


def search(index: dict[str, list[str]], query: str, secret: bytes) -> list[str]:
    """Search without placing the plaintext query in the index."""

    return index.get(_token(query, secret), [])


def run_menu() -> None:
    """Build a small protected index and search it interactively."""

    documents = {"doc1": "secure encrypted data", "doc2": "secure searchable data"}
    secret = b"shared search secret"
    index = build_index(documents, secret)
    while True:
        print("\n=== Searchable-encryption menu ===")
        print("1. Search the sample documents")
        print("0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        if choice == "1":
            query = input("Search word: ").strip()
            print("Matching document IDs:", search(index, query, secret))
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    run_menu()

