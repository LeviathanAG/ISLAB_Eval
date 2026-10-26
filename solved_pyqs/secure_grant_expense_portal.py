"""Menu-driven solution for the Secure Grant Expense Portal question.

Roles
-----
* Researcher: submit grants and inspect the persistent encrypted records.
* Reviewer: verify hashes/signatures, search by Grant ID, and print a
  decrypted AES-192 description as a hexadecimal dump.
* Finance officer: verify selected records, homomorphically add their
  Paillier ciphertexts, and decrypt only the final sum.

Run it with::

    python3 solved_pyqs/secure_grant_expense_portal.py

The default data directory is ``solved_pyqs/data/grant_portal``.  The JSON
store and PEM key files are deliberately persistent so entries survive a
restart.  This is a teaching implementation; use reviewed libraries and
stronger hashes than MD5 in a real service.
"""

from __future__ import annotations

from getpass import getpass
import hashlib
import secrets
import sys
from pathlib import Path
from typing import Any

try:  # Allow both ``python -m solved_pyqs...`` and direct execution.
    from .crypto_helpers import (
        aes_cbc_decrypt,
        aes_cbc_encrypt,
        b64_decode,
        b64_encode,
        canonical_json,
        hex_dump,
        load_json,
        make_password_record,
        paillier_add,
        paillier_decrypt,
        paillier_encrypt,
        paillier_generate,
        paillier_public,
        rsa_sign,
        rsa_verify,
        save_json,
        verify_password_record,
    )
except ImportError:  # pragma: no cover - direct script convenience path.
    from crypto_helpers import (
        aes_cbc_decrypt,
        aes_cbc_encrypt,
        b64_decode,
        b64_encode,
        canonical_json,
        hex_dump,
        load_json,
        make_password_record,
        paillier_add,
        paillier_decrypt,
        paillier_encrypt,
        paillier_generate,
        paillier_public,
        rsa_sign,
        rsa_verify,
        save_json,
        verify_password_record,
    )
    from crypto_helpers import ensure_rsa_keypair


if "ensure_rsa_keypair" not in globals():
    # The relative-import branch keeps this name local without duplicating the
    # large import list above.
    from .crypto_helpers import ensure_rsa_keypair


DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "data" / "grant_portal"


class GrantPortal:
    """Persistent grant store with role-specific operations."""

    def __init__(self, data_dir: Path | str = DEFAULT_DATA_DIR, paillier_bits: int = 1024):
        self.data_dir = Path(data_dir)
        self.key_dir = self.data_dir / "keys"
        self.records_path = self.data_dir / "records.json"
        self.roles_path = self.data_dir / "roles.json"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # One persistent AES-192 key protects descriptions in this lab store.
        key_path = self.key_dir / "aes192.key"
        self.key_dir.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            self.aes_key = b64_decode(key_path.read_text(encoding="ascii").strip())
            if len(self.aes_key) != 24:
                raise ValueError("Stored AES key is not AES-192 length")
        else:
            self.aes_key = secrets.token_bytes(24)
            key_path.write_text(b64_encode(self.aes_key), encoding="ascii")

        # RSA signs the MD5 digest of each encrypted record.
        self.rsa_private, self.rsa_public = ensure_rsa_keypair(self.key_dir, bits=2048)

        # Paillier keys are stored as integers in JSON.  The public fields are
        # used for encryption, while the private fields are used only by the
        # finance operation after all signatures have been verified.
        self.paillier_path = self.key_dir / "paillier.json"
        self.paillier_key = load_json(self.paillier_path, None)
        if self.paillier_key is None:
            self.paillier_key = paillier_generate(paillier_bits)
            save_json(self.paillier_path, self.paillier_key)
        self.records: list[dict[str, Any]] = load_json(self.records_path, [])
        if not isinstance(self.records, list):
            raise ValueError("Grant record store must contain a JSON list")

    def authenticate_role(self, role: str, password: str | None = None) -> bool:
        """Authenticate or initialize one of the three local portal roles."""

        labels = {
            "researcher": "Researcher",
            "reviewer": "Reviewer",
            "finance": "Finance officer",
        }
        if role not in labels:
            raise ValueError(f"Unknown portal role: {role}")
        roles = load_json(self.roles_path, {})
        if not isinstance(roles, dict):
            raise ValueError("Role credential store is malformed")
        if role not in roles:
            if password is None:
                first = getpass(f"Set password for {labels[role]}: ")
                second = getpass("Repeat password: ")
                if first != second:
                    raise ValueError("Passwords do not match")
                password = first
            roles[role] = make_password_record(password)
            save_json(self.roles_path, roles)
            return True
        if password is None:
            password = getpass(f"Password for {labels[role]}: ")
        return verify_password_record(password, roles[role])

    @property
    def paillier_public_key(self) -> dict[str, int]:
        """Expose only Paillier public parameters to researcher operations."""

        return paillier_public(self.paillier_key)

    def _record_payload(self, record: dict[str, Any]) -> dict[str, Any]:
        """Return precisely the fields covered by the MD5 record hash."""

        return {
            "grant_id": record["grant_id"],
            "description_iv": record["description_iv"],
            "description_ciphertext": record["description_ciphertext"],
            "amount_ciphertext": record["amount_ciphertext"],
        }

    def _record_digest(self, record: dict[str, Any]) -> str:
        """Compute the required MD5 digest over the canonical encrypted record."""

        return hashlib.md5(canonical_json(self._record_payload(record))).hexdigest()

    def submit_grant(self, grant_id: str, description: str, amount: int) -> dict[str, Any]:
        """Encrypt, hash, sign, and persist one researcher grant."""

        grant_id = grant_id.strip()
        description = description.strip()
        if not grant_id:
            raise ValueError("Grant ID cannot be empty")
        if not description:
            raise ValueError("Grant description cannot be empty")
        if amount < 0:
            raise ValueError("Grant amount cannot be negative")
        if any(record.get("grant_id") == grant_id for record in self.records):
            raise ValueError(f"Grant ID already exists: {grant_id}")

        # AES-192 encrypts only the description; the random IV is stored next
        # to the ciphertext and is not secret.
        iv, description_ciphertext = aes_cbc_encrypt(description.encode("utf-8"), self.aes_key)
        amount_ciphertext = paillier_encrypt(amount, self.paillier_public_key)
        record: dict[str, Any] = {
            "grant_id": grant_id,
            "description_iv": b64_encode(iv),
            "description_ciphertext": b64_encode(description_ciphertext),
            "amount_ciphertext": str(amount_ciphertext),
        }

        # The question explicitly asks for MD5 and an RSA signature over the
        # hash, so both are retained as visible audit fields.
        record["record_hash_md5"] = self._record_digest(record)
        record["rsa_signature"] = b64_encode(
            rsa_sign(record["record_hash_md5"].encode("ascii"), self.rsa_private)
        )
        self.records.append(record)
        save_json(self.records_path, self.records)
        return record

    def verify_record(self, record: dict[str, Any]) -> dict[str, bool]:
        """Recompute the MD5 and verify the RSA signature safely."""

        try:
            recomputed = self._record_digest(record)
            hash_valid = secrets.compare_digest(recomputed, record["record_hash_md5"])
            signature_valid = rsa_verify(
                record["record_hash_md5"].encode("ascii"),
                b64_decode(record["rsa_signature"]),
                self.rsa_public,
            )
            return {
                "hash_valid": hash_valid,
                "signature_valid": signature_valid,
                "valid": hash_valid and signature_valid,
            }
        except (KeyError, TypeError, ValueError):
            # A malformed or tampered JSON record is reported, not fatal to the
            # reviewer menu or to verification of other records.
            return {"hash_valid": False, "signature_valid": False, "valid": False}

    def list_records(self) -> list[dict[str, Any]]:
        """Return a copy of records; plaintext amounts never appear here."""

        return [dict(record) for record in self.records]

    def search_by_grant_id(self, grant_id: str) -> dict[str, Any] | None:
        """Search the record index and return metadata without decrypting fields."""

        for record in self.records:
            if record.get("grant_id") == grant_id:
                status = self.verify_record(record)
                return {
                    "grant_id": grant_id,
                    "found": True,
                    "hash_valid": status["hash_valid"],
                    "signature_valid": status["signature_valid"],
                    # Do not expose either encrypted payload during an index search.
                    "encrypted_contents_hidden": True,
                }
        return {"grant_id": grant_id, "found": False}

    def description_hex_dump(self, grant_id: str) -> str:
        """Decrypt one description and return the requested hexadecimal dump."""

        record = next((item for item in self.records if item.get("grant_id") == grant_id), None)
        if record is None:
            raise KeyError(f"Unknown Grant ID: {grant_id}")
        if not self.verify_record(record)["valid"]:
            raise ValueError("Record hash/signature verification failed; description withheld")
        plaintext = aes_cbc_decrypt(
            b64_decode(record["description_ciphertext"]),
            self.aes_key,
            b64_decode(record["description_iv"]),
        )
        return hex_dump(plaintext)

    def finance_total(self, grant_ids: list[str]) -> int:
        """Verify selected records and decrypt only their final Paillier sum."""

        if not grant_ids:
            raise ValueError("Select at least one Grant ID")
        selected: list[dict[str, Any]] = []
        seen: set[str] = set()
        for grant_id in grant_ids:
            if grant_id in seen:
                continue
            seen.add(grant_id)
            record = next((item for item in self.records if item.get("grant_id") == grant_id), None)
            if record is None:
                raise KeyError(f"Unknown Grant ID: {grant_id}")
            status = self.verify_record(record)
            if not status["valid"]:
                raise ValueError(f"Integrity/signature check failed for {grant_id}")
            selected.append(record)

        # Paillier multiplication of ciphertexts adds the hidden amounts.
        aggregate = 1
        for record in selected:
            aggregate = paillier_add(
                aggregate, int(record["amount_ciphertext"]), self.paillier_public_key
            )

        # No individual Paillier ciphertext is decrypted.  Only this final
        # aggregate is passed to the private-key operation.
        return paillier_decrypt(aggregate, self.paillier_key)


def _read(prompt: str) -> str:
    """Read input while converting Ctrl-D into a clean menu exit."""

    try:
        return input(prompt).strip()
    except EOFError:
        print("\nInput ended; returning to the main menu.")
        return ""


def researcher_menu(portal: GrantPortal) -> None:
    """Interactive researcher role menu."""

    while True:
        print("\n--- Researcher menu ---")
        print("1. Submit grant")
        print("2. View all encrypted records")
        print("0. Back")
        choice = _read("Choose: ")
        if choice == "0" or not choice:
            return
        try:
            if choice == "1":
                grant_id = _read("Grant ID: ")
                description = _read("Grant description: ")
                amount = int(_read("Grant amount (whole number): "))
                record = portal.submit_grant(grant_id, description, amount)
                print(f"Submitted {record['grant_id']}; MD5={record['record_hash_md5']}")
            elif choice == "2":
                if not portal.records:
                    print("No records have been submitted.")
                for record in portal.list_records():
                    print(record)
            else:
                print("Invalid researcher option.")
        except (ValueError, KeyError) as exc:
            print(f"Could not complete operation: {exc}")


def reviewer_menu(portal: GrantPortal) -> None:
    """Interactive reviewer role menu."""

    while True:
        print("\n--- Reviewer menu ---")
        print("1. Verify every stored record")
        print("2. Search by Grant ID (encrypted fields hidden)")
        print("3. Show AES-192 description hexadecimal dump")
        print("0. Back")
        choice = _read("Choose: ")
        if choice == "0" or not choice:
            return
        try:
            if choice == "1":
                for record in portal.records:
                    print(record.get("grant_id", "<malformed>"), portal.verify_record(record))
            elif choice == "2":
                print(portal.search_by_grant_id(_read("Grant ID: ")))
            elif choice == "3":
                print(portal.description_hex_dump(_read("Grant ID: ")))
            else:
                print("Invalid reviewer option.")
        except (ValueError, KeyError) as exc:
            print(f"Could not complete operation: {exc}")


def finance_menu(portal: GrantPortal) -> None:
    """Interactive finance officer role menu."""

    while True:
        print("\n--- Finance officer menu ---")
        print("1. Homomorphically total selected grants")
        print("0. Back")
        choice = _read("Choose: ")
        if choice == "0" or not choice:
            return
        if choice != "1":
            print("Invalid finance option.")
            continue
        try:
            raw_ids = _read("Grant IDs separated by commas: ")
            grant_ids = [value.strip() for value in raw_ids.split(",") if value.strip()]
            total = portal.finance_total(grant_ids)
            print(f"Verified aggregate expenditure (individual amounts never decrypted): {total}")
        except (ValueError, KeyError) as exc:
            print(f"Could not compute total: {exc}")


def run_menu(portal: GrantPortal) -> None:
    """Run the top-level role-based menu required by the question."""

    while True:
        print("\n=== Secure Grant Expense Portal ===")
        print("1. Researcher")
        print("2. Reviewer")
        print("3. Finance officer")
        print("0. Exit")
        choice = _read("Choose role: ")
        if choice == "0" or not choice:
            print("Goodbye.")
            return
        if choice == "1":
            try:
                if portal.authenticate_role("researcher"):
                    researcher_menu(portal)
                else:
                    print("Access denied.")
            except (OSError, ValueError, EOFError) as exc:
                print(f"Authentication failed: {exc}")
        elif choice == "2":
            try:
                if portal.authenticate_role("reviewer"):
                    reviewer_menu(portal)
                else:
                    print("Access denied.")
            except (OSError, ValueError, EOFError) as exc:
                print(f"Authentication failed: {exc}")
        elif choice == "3":
            try:
                if portal.authenticate_role("finance"):
                    finance_menu(portal)
                else:
                    print("Access denied.")
            except (OSError, ValueError, EOFError) as exc:
                print(f"Authentication failed: {exc}")
        else:
            print("Invalid role. Choose 0, 1, 2, or 3.")


def main() -> None:
    """Start the program with its fixed local store and menu."""

    try:
        run_menu(GrantPortal())
    except (OSError, ValueError) as exc:
        print(f"Unable to start portal: {exc}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover - exercised by manual use.
    main()

