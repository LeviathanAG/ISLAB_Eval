"""Menu-driven solution for the national e-voting question.

The program separates the client and server responsibilities in one runnable
teaching application.  A voter creates a ballot, while the election server
stores only encrypted ballot data plus verification metadata.  The server can
verify a ballot and search its encrypted index without printing the candidate
choice.  Election-end tallying combines encrypted one-hot candidate counters
and decrypts only those final aggregates using two threshold shares.

Run with::

    python3 solved_pyqs/national_e_voting_system.py

The default store is persistent.  The default RSA key is 4096 bits as required
by the question; tests may pass a smaller ``rsa_bits`` value to keep unit tests
fast.  The threshold mechanism
is an explicit 2-of-2 additive-share teaching model, not a production
threshold-Paillier deployment.
"""

from __future__ import annotations

from getpass import getpass
import hashlib
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:  # Support package execution and direct script execution.
    from .crypto_helpers import (
        aes_cbc_decrypt,
        aes_cbc_encrypt,
        b64_decode,
        b64_encode,
        canonical_json,
        combine_threshold_shares,
        elgamal_keygen,
        elgamal_sign,
        elgamal_verify,
        ensure_rsa_keypair,
        load_json,
        make_password_record,
        make_additive_threshold_shares,
        paillier_add,
        paillier_decrypt_with_private_parts,
        paillier_encrypt,
        paillier_generate,
        paillier_public,
        parse_timestamp,
        rsa_decrypt,
        rsa_encrypt,
        rsa_sign,
        rsa_verify,
        save_json,
        timestamp_token,
        utc_now,
        verify_timestamp_token,
        verify_password_record,
    )
except ImportError:  # pragma: no cover - direct script convenience path.
    from crypto_helpers import (
        aes_cbc_decrypt,
        aes_cbc_encrypt,
        b64_decode,
        b64_encode,
        canonical_json,
        combine_threshold_shares,
        elgamal_keygen,
        elgamal_sign,
        elgamal_verify,
        ensure_rsa_keypair,
        load_json,
        make_password_record,
        make_additive_threshold_shares,
        paillier_add,
        paillier_decrypt_with_private_parts,
        paillier_encrypt,
        paillier_generate,
        paillier_public,
        parse_timestamp,
        rsa_decrypt,
        rsa_encrypt,
        rsa_sign,
        rsa_verify,
        save_json,
        timestamp_token,
        utc_now,
        verify_timestamp_token,
        verify_password_record,
    )


DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "data" / "e_voting"


class EVotingSystem:
    """Persistent client/server e-voting demonstration."""

    def __init__(
        self,
        data_dir: Path | str = DEFAULT_DATA_DIR,
        rsa_bits: int = 4096,
        paillier_bits: int = 1024,
        max_candidates: int = 5,
        voting_start: str | None = None,
        voting_end: str | None = None,
    ):
        if max_candidates < 2:
            raise ValueError("The demonstration needs at least two candidate IDs")
        self.data_dir = Path(data_dir)
        self.key_dir = self.data_dir / "keys"
        self.voters_dir = self.key_dir / "voters"
        self.records_path = self.data_dir / "ballots.json"
        self.threshold_path = self.key_dir / "paillier_threshold.json"
        self.paillier_path = self.key_dir / "paillier.json"
        self.timestamp_key_path = self.key_dir / "trusted_timestamp.key"
        self.timestamp_authority_dir = self.key_dir / "timestamp_authority"
        self.roles_path = self.data_dir / "roles.json"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.voters_dir.mkdir(parents=True, exist_ok=True)
        self.max_candidates = max_candidates

        # The Election Commission RSA key encrypts each voter's AES session key.
        self.rsa_private, self.rsa_public = ensure_rsa_keypair(self.key_dir, bits=rsa_bits)
        # A separate trusted-authority signing key binds the submission time to
        # the voter and ballot digest.  The Commission key never signs this
        # proof, keeping the two authorities conceptually distinct.
        self.tsa_private, self.tsa_public = ensure_rsa_keypair(
            self.timestamp_authority_dir, bits=2048
        )

        # Paillier public data is used by clients; its private values are split
        # into two separate additive shares for the election-end operation.
        self.paillier_key = load_json(self.paillier_path, None)
        if self.paillier_key is None:
            self.paillier_key = paillier_generate(paillier_bits)
            save_json(self.paillier_path, self.paillier_key)
        self.paillier_public_key = paillier_public(self.paillier_key)
        self.threshold = load_json(self.threshold_path, None)
        if self.threshold is None:
            self.threshold = make_additive_threshold_shares(self.paillier_key)
            save_json(self.threshold_path, self.threshold)

        if self.timestamp_key_path.exists():
            self.timestamp_secret = b64_decode(
                self.timestamp_key_path.read_text(encoding="ascii").strip()
            )
        else:
            self.timestamp_secret = secrets.token_bytes(32)
            self.timestamp_key_path.write_text(
                b64_encode(self.timestamp_secret), encoding="ascii"
            )

        # The default period is deliberately broad enough for a lab session.
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.voting_start = parse_timestamp(voting_start) if voting_start else now - timedelta(days=1)
        self.voting_end = parse_timestamp(voting_end) if voting_end else now + timedelta(days=1)
        self.records: list[dict[str, Any]] = load_json(self.records_path, [])
        if not isinstance(self.records, list):
            raise ValueError("Ballot store must contain a JSON list")

    def authenticate_role(self, role: str, password: str | None = None) -> bool:
        """Authenticate or initialize the voter/server menu roles."""

        labels = {"voter": "Voter/client", "server": "Election server"}
        if role not in labels:
            raise ValueError(f"Unknown e-voting role: {role}")
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

    def _voter_path(self, voter_id: str) -> Path:
        """Map a voter identifier to a safe filename."""

        cleaned = "".join(character if character.isalnum() or character in "-_" else "_" for character in voter_id)
        if not cleaned:
            raise ValueError("Voter ID must contain at least one usable character")
        return self.voters_dir / f"{cleaned}.json"

    def _voter_key(self, voter_id: str) -> dict[str, int]:
        """Load or create one voter ElGamal signing identity."""

        path = self._voter_path(voter_id)
        existing = load_json(path, None)
        if existing is not None:
            return {name: int(value) for name, value in existing.items()}
        key = elgamal_keygen()
        save_json(path, key)
        return key

    def _ballot_bytes(self, voter_id: str, candidate_id: int, constituency_id: str, submitted_at: str) -> bytes:
        """Build the canonical plaintext ballot file that gets hashed/encrypted."""

        return canonical_json(
            {
                "voter_id": voter_id,
                "candidate_id": candidate_id,
                "constituency_id": constituency_id,
                "submitted_at": submitted_at,
            }
        )

    def _index_token(self, constituency_id: str) -> str:
        """Create the server-side searchable token without storing plaintext."""

        return hashlib.sha256(f"constituency:{constituency_id}".encode("utf-8")).hexdigest()

    def cast_vote(
        self, voter_id: str, candidate_id: int, constituency_id: str, submitted_at: str | None = None
    ) -> dict[str, Any]:
        """Client-side ballot creation and secure submission."""

        voter_id = voter_id.strip()
        constituency_id = constituency_id.strip()
        if not voter_id or not constituency_id:
            raise ValueError("Voter ID and constituency ID cannot be empty")
        if not 1 <= candidate_id <= self.max_candidates:
            raise ValueError(f"Candidate ID must be between 1 and {self.max_candidates}")
        timestamp = submitted_at or utc_now()
        timestamp_value = parse_timestamp(timestamp)
        if not self.voting_start <= timestamp_value <= self.voting_end:
            raise ValueError("Vote timestamp is outside the configured voting period")

        ballot = self._ballot_bytes(voter_id, candidate_id, constituency_id, timestamp)
        ballot_hash = hashlib.sha512(ballot).hexdigest()
        voter_key = self._voter_key(voter_id)
        signature = elgamal_sign(ballot_hash.encode("ascii"), voter_key)

        # AES-256-CBC protects the full ballot file; the IV is public metadata.
        aes_key = secrets.token_bytes(32)
        iv, encrypted_ballot = aes_cbc_encrypt(ballot, aes_key)
        encrypted_session_key = rsa_encrypt(aes_key, self.rsa_public)

        # A one-hot Paillier vector supports encrypted candidate counts.  The
        # numerical candidate ID is also encrypted directly as required by the
        # question, and is used for an optional encrypted sum.
        encrypted_vote = paillier_encrypt(candidate_id, self.paillier_public_key)
        encrypted_counts = {
            str(candidate): paillier_encrypt(
                1 if candidate == candidate_id else 0, self.paillier_public_key
            )
            for candidate in range(1, self.max_candidates + 1)
        }

        token = timestamp_token(timestamp, ballot_hash, self.timestamp_secret)
        timestamp_proof = {
            "voter_id": voter_id,
            "timestamp": timestamp,
            "sha512": ballot_hash,
        }
        ballot_id = f"ballot-{len(self.records) + 1:06d}"
        record: dict[str, Any] = {
            "ballot_id": ballot_id,
            "voter_id": voter_id,
            "encrypted_ballot": b64_encode(encrypted_ballot),
            "ballot_iv": b64_encode(iv),
            "encrypted_session_key": b64_encode(encrypted_session_key),
            "sha512": ballot_hash,
            "elgamal_signature": [str(signature[0]), str(signature[1])],
            "elgamal_public_key": {name: str(value) for name, value in {"p": voter_key["p"], "g": voter_key["g"], "y": voter_key["y"]}.items()},
            "trusted_timestamp": timestamp,
            "trusted_timestamp_token": token,
            "trusted_timestamp_proof": timestamp_proof,
            "trusted_timestamp_signature": b64_encode(
                rsa_sign(canonical_json(timestamp_proof), self.tsa_private)
            ),
            "constituency_index": self._index_token(constituency_id),
            "day_index": timestamp[:10],
            "encrypted_vote": str(encrypted_vote),
            "encrypted_candidate_counts": encrypted_counts,
        }
        self.records.append(record)
        save_json(self.records_path, self.records)
        return record

    def _decrypt_ballot_for_verification(self, record: dict[str, Any]) -> bytes:
        """Server-side AES key recovery and ballot decryption."""

        aes_key = rsa_decrypt(b64_decode(record["encrypted_session_key"]), self.rsa_private)
        return aes_cbc_decrypt(
            b64_decode(record["encrypted_ballot"]),
            aes_key,
            b64_decode(record["ballot_iv"]),
        )

    def verify_ballot(self, record: dict[str, Any]) -> dict[str, Any]:
        """Verify hash, ElGamal signature, timestamp token, and deadline."""

        result: dict[str, Any] = {
            "ballot_id": record.get("ballot_id", "<malformed>"),
            "hash_valid": False,
            "signature_valid": False,
            "timestamp_signature_valid": False,
            "timestamp_valid": False,
            "valid": False,
            "error": "",
        }
        try:
            ballot = self._decrypt_ballot_for_verification(record)
            recomputed_hash = hashlib.sha512(ballot).hexdigest()
            result["hash_valid"] = secrets.compare_digest(recomputed_hash, record["sha512"])
            public_key = {name: int(value) for name, value in record["elgamal_public_key"].items()}
            signature = tuple(int(value) for value in record["elgamal_signature"])
            result["signature_valid"] = elgamal_verify(
                record["sha512"].encode("ascii"), signature, public_key
            )
            timestamp = parse_timestamp(record["trusted_timestamp"])
            timestamp_proof = record["trusted_timestamp_proof"]
            result["timestamp_signature_valid"] = rsa_verify(
                canonical_json(timestamp_proof),
                b64_decode(record["trusted_timestamp_signature"]),
                self.tsa_public,
            )
            result["timestamp_valid"] = (
                self.voting_start <= timestamp <= self.voting_end
                and timestamp_proof["voter_id"] == record["voter_id"]
                and timestamp_proof["timestamp"] == record["trusted_timestamp"]
                and timestamp_proof["sha512"] == record["sha512"]
                and result["timestamp_signature_valid"]
                and verify_timestamp_token(
                    record["trusted_timestamp"],
                    record["sha512"],
                    record["trusted_timestamp_token"],
                    self.timestamp_secret,
                )
            )
            result["valid"] = all(
                (
                    result["hash_valid"],
                    result["signature_valid"],
                    result["timestamp_signature_valid"],
                    result["timestamp_valid"],
                )
            )
        except (KeyError, TypeError, ValueError, OSError) as exc:
            result["error"] = str(exc)
        return result

    def search(
        self, constituency_id: str | None = None, start: str | None = None, end: str | None = None
    ) -> list[dict[str, Any]]:
        """Return ballot IDs from hashed indexes, never ballot contents."""

        constituency_token = self._index_token(constituency_id) if constituency_id else None
        start_time = parse_timestamp(start) if start else None
        end_time = parse_timestamp(end) if end else None
        matches = []
        for record in self.records:
            if constituency_token and record.get("constituency_index") != constituency_token:
                continue
            timestamp = parse_timestamp(record["trusted_timestamp"])
            if start_time and timestamp < start_time:
                continue
            if end_time and timestamp > end_time:
                continue
            matches.append(
                {
                    "ballot_id": record["ballot_id"],
                    "timestamp": record["trusted_timestamp"],
                    "contents_hidden": True,
                }
            )
        return matches

    def tally(self, ballot_ids: list[str] | None = None) -> dict[str, Any]:
        """Verify ballots, aggregate ciphertexts, then use both threshold shares."""

        wanted = set(ballot_ids or [record["ballot_id"] for record in self.records])
        selected = [record for record in self.records if record.get("ballot_id") in wanted]
        if not selected:
            raise ValueError("No ballots selected")
        verified = []
        rejected = []
        for record in selected:
            if self.verify_ballot(record)["valid"]:
                verified.append(record)
            else:
                rejected.append(record["ballot_id"])
        if not verified:
            raise ValueError("No valid ballots remain after verification")

        # Multiply ciphertexts: Paillier adds the underlying one-hot counters.
        aggregates = {str(candidate): 1 for candidate in range(1, self.max_candidates + 1)}
        encrypted_sum = 1
        for record in verified:
            encrypted_sum = paillier_add(
                encrypted_sum, int(record["encrypted_vote"]), self.paillier_public_key
            )
            for candidate in aggregates:
                aggregates[candidate] = paillier_add(
                    aggregates[candidate],
                    int(record["encrypted_candidate_counts"][candidate]),
                    self.paillier_public_key,
                )

        # Both independent authority shares are required.  One share alone is
        # insufficient to reconstruct lambda and mu.
        private_lambda, private_mu = combine_threshold_shares(self.threshold, 0, 1)
        counts = {
            candidate: paillier_decrypt_with_private_parts(
                ciphertext, self.paillier_public_key, private_lambda, private_mu
            )
            for candidate, ciphertext in aggregates.items()
        }
        candidate_id_sum = paillier_decrypt_with_private_parts(
            encrypted_sum, self.paillier_public_key, private_lambda, private_mu
        )
        return {
            "valid_ballots": [record["ballot_id"] for record in verified],
            "rejected_ballots": rejected,
            "candidate_counts": counts,
            "candidate_id_sum": candidate_id_sum,
            "threshold_shares_used": 2,
        }


def _read(prompt: str) -> str:
    """Read one menu value and make EOF a clean return."""

    try:
        return input(prompt).strip()
    except EOFError:
        print("\nInput ended; returning to the previous menu.")
        return ""


def client_menu(system: EVotingSystem) -> None:
    """Voter/client-side menu."""

    while True:
        print("\n--- Voter client ---")
        print("1. Cast encrypted ballot")
        print("0. Back")
        choice = _read("Choose: ")
        if choice == "0" or not choice:
            return
        if choice != "1":
            print("Invalid client option.")
            continue
        try:
            record = system.cast_vote(
                _read("Voter ID: "),
                int(_read("Candidate ID: ")),
                _read("Constituency ID: "),
            )
            print(f"Ballot submitted as {record['ballot_id']}; SHA-512={record['sha512']}")
        except (ValueError, OSError) as exc:
            print(f"Ballot rejected: {exc}")


def server_menu(system: EVotingSystem) -> None:
    """Election-server verification/search/tally menu."""

    while True:
        print("\n--- Election server ---")
        print("1. Verify all ballot records")
        print("2. Search encrypted index")
        print("3. Threshold tally final aggregates")
        print("0. Back")
        choice = _read("Choose: ")
        if choice == "0" or not choice:
            return
        try:
            if choice == "1":
                for record in system.records:
                    print(system.verify_ballot(record))
            elif choice == "2":
                constituency = _read("Constituency (blank for any): ") or None
                start = _read("Start ISO timestamp (blank for any): ") or None
                end = _read("End ISO timestamp (blank for any): ") or None
                print(system.search(constituency, start, end))
            elif choice == "3":
                raw = _read("Ballot IDs separated by commas (blank for all): ")
                ids = [value.strip() for value in raw.split(",") if value.strip()] or None
                print(system.tally(ids))
            else:
                print("Invalid server option.")
        except (ValueError, KeyError, OSError) as exc:
            print(f"Server operation failed: {exc}")


def run_menu(system: EVotingSystem) -> None:
    """Run the required role-based top-level menu."""

    while True:
        print("\n=== National E-Voting System ===")
        print("1. Voter/client")
        print("2. Election server")
        print("0. Exit")
        choice = _read("Choose role: ")
        if choice == "0" or not choice:
            print("Goodbye.")
            return
        if choice == "1":
            try:
                if system.authenticate_role("voter"):
                    client_menu(system)
                else:
                    print("Access denied.")
            except (OSError, ValueError, EOFError) as exc:
                print(f"Authentication failed: {exc}")
        elif choice == "2":
            try:
                if system.authenticate_role("server"):
                    server_menu(system)
                else:
                    print("Access denied.")
            except (OSError, ValueError, EOFError) as exc:
                print(f"Authentication failed: {exc}")
        else:
            print("Invalid role. Choose 0, 1, or 2.")


def main() -> None:
    """Start the program with its fixed local store and menu."""

    try:
        run_menu(EVotingSystem())
    except (OSError, ValueError) as exc:
        print(f"Unable to start e-voting system: {exc}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover - exercised by manual use.
    main()

