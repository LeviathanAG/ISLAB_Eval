"""Lab 8: readable SSE and Paillier-backed public-key-style search.

The manual's sample compares randomized encrypted keyword hashes for equality.
That cannot work with secure randomized AES or Paillier encryption: encrypting
the same word twice gives different ciphertexts.  This solution uses a
deterministic HMAC search token for SSE and a public SHA-256 token for the
PKSE-style index, while encrypting returned document IDs with Paillier.  The
limitation is called out in comments so the lab demonstrates both the desired
function and the security trade-off honestly.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from solved_pyqs.crypto_helpers import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    paillier_decrypt,
    paillier_encrypt,
    paillier_generate,
    paillier_public,
)


def words(document: str) -> set[str]:
    """Normalize a document into searchable lowercase word tokens."""

    return set(re.findall(r"[a-z0-9]+", document.lower()))


DOCUMENTS = {
    "doc01": "secure grant records need integrity and privacy",
    "doc02": "encrypted ballots preserve voter privacy",
    "doc03": "hashes detect document integrity changes",
    "doc04": "RSA signatures provide authenticity",
    "doc05": "Paillier supports homomorphic addition",
    "doc06": "AES protects confidential document content",
    "doc07": "searchable encryption balances privacy and utility",
    "doc08": "threshold decryption needs multiple authorities",
    "doc09": "network sockets can transfer integrity hashes",
    "doc10": "digital signatures support non repudiation",
}


class SSEIndex:
    """Symmetric searchable-encryption demo using HMAC search tokens."""

    def __init__(self, documents: dict[str, str]):
        self.key = os.urandom(32)
        self.index: dict[str, list[str]] = {}
        self.encrypted_documents: dict[str, tuple[bytes, bytes]] = {}
        for doc_id, document in documents.items():
            self.encrypted_documents[doc_id] = aes_cbc_encrypt(document.encode(), self.key)
            for word in words(document):
                token = self._token(word)
                self.index.setdefault(token, []).append(doc_id)

    def _token(self, query: str) -> str:
        """Create the deterministic keyed search token for a query word."""

        return hmac.new(self.key, query.lower().encode(), hashlib.sha256).hexdigest()

    def search(self, query: str) -> list[tuple[str, str]]:
        """Return matching IDs and decrypt their contents with the shared key."""

        matches = []
        for doc_id in self.index.get(self._token(query), []):
            ciphertext, iv = self.encrypted_documents[doc_id][1], self.encrypted_documents[doc_id][0]
            plaintext = aes_cbc_decrypt(ciphertext, self.key, iv).decode()
            matches.append((doc_id, plaintext))
        return matches


class PaillierSearchIndex:
    """Public-token index with Paillier-encrypted result identifiers."""

    def __init__(self, documents: dict[str, str]):
        self.paillier_key = paillier_generate(128)
        self.public_key = paillier_public(self.paillier_key)
        self.document_ids = {doc_id: number + 1 for number, doc_id in enumerate(documents)}
        self.documents = dict(documents)
        self.index: dict[str, list[int]] = {}
        for doc_id, document in documents.items():
            for word in words(document):
                # A deterministic public token makes equality search possible.
                # Paillier protects the returned numeric document identifiers.
                token = hashlib.sha256(word.encode()).hexdigest()
                encrypted_id = paillier_encrypt(self.document_ids[doc_id], self.public_key)
                self.index.setdefault(token, []).append(encrypted_id)

    def search(self, query: str) -> list[tuple[str, str]]:
        """Find encrypted IDs by token and decrypt only the result IDs."""

        token = hashlib.sha256(query.lower().encode()).hexdigest()
        output: list[tuple[str, str]] = []
        reverse = {number: doc_id for doc_id, number in self.document_ids.items()}
        for encrypted_id in self.index.get(token, []):
            number = paillier_decrypt(encrypted_id, self.paillier_key)
            doc_id = reverse[number]
            output.append((doc_id, self.documents[doc_id]))
        return output


def run_all() -> None:
    """Execute both manual Lab 8 exercises over ten documents."""

    print("=== Lab 8.1 symmetric searchable encryption ===")
    sse = SSEIndex(DOCUMENTS)
    print("SSE search for 'integrity':", sse.search("integrity"))
    print("=== Lab 8.2 Paillier-backed public-key-style search ===")
    pkse = PaillierSearchIndex(DOCUMENTS)
    print("PKSE search for 'encryption':", pkse.search("encryption"))
    print("Security note: the public token leaks equality/search patterns; real SE needs a reviewed scheme.")
    # The manual's additional exercises are system tools.  These demos build
    # safe commands and analyze a synthetic log without requiring root access.
    from solved_labs.lab08_searchable_encryption.gnupg_tools import demo as gpg_demo
    from solved_labs.lab08_searchable_encryption.snort_tools import demo as snort_demo

    print("=== Lab 8A.1 GnuPG command wrapper ===")
    gpg_demo()
    print("=== Lab 8A.2 Snort command/log wrapper ===")
    snort_demo()


def run_menu() -> None:
    """Run Lab 8's encryption and system-tool examples interactively."""

    from solved_labs.lab08_searchable_encryption.gnupg_tools import demo as gpg_demo
    from solved_labs.lab08_searchable_encryption.snort_tools import demo as snort_demo

    actions = {
        "1": ("Symmetric searchable encryption", lambda: print(SSEIndex(DOCUMENTS).search("integrity"))),
        "2": ("Paillier-backed searchable encryption", lambda: print(PaillierSearchIndex(DOCUMENTS).search("encryption"))),
        "3": ("GnuPG command wrapper", gpg_demo),
        "4": ("Snort command/log wrapper", snort_demo),
        "5": ("Run every example", run_all),
    }
    while True:
        print("\n=== Lab 8 menu ===")
        for number, (label, _action) in actions.items():
            print(f"{number}. {label}")
        print("0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        selected = actions.get(choice)
        if selected is None:
            print("Invalid choice.")
            continue
        try:
            selected[1]()
        except (OSError, ValueError) as exc:
            print(f"Example could not run: {exc}")


if __name__ == "__main__":  # pragma: no cover
    run_menu()

