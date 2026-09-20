"""Small centralized key-manager pattern for Lab 4 scenario questions.

The class demonstrates generation, authenticated retrieval, versioning,
revocation, renewal, expiry, and audit logging.  It stores only keys encrypted
under a service master key.  The dictionary is for a lab demo; replace it with
a database/KMS/HSM in production.

The caller receives a key only with the matching API token.  Revocation changes
server policy, but cannot erase a private key that a client already copied.
Per-content/per-facility keys limit that unavoidable exposure.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA


@dataclass
class KeyRecord:
    public_pem: bytes
    encrypted_private_pem: bytes
    version: int
    expires_at: datetime
    revoked: bool = False


class KeyManager:
    def __init__(self):
        self._wrapping_key = Fernet.generate_key()
        self._cipher = Fernet(self._wrapping_key)
        self._records: dict[str, KeyRecord] = {}
        self._token_hashes: dict[str, str] = {}
        self.audit_log: list[dict] = []

    def _audit(self, action: str, owner: str):
        self.audit_log.append({"time": datetime.now(timezone.utc).isoformat(),
                               "action": action, "owner": owner})

    def register(self, owner: str, validity_days: int = 365, bits: int = 2048) -> str:
        """Create/rotate a key and return the API token exactly once."""
        key = RSA.generate(bits)
        version = self._records[owner].version + 1 if owner in self._records else 1
        self._records[owner] = KeyRecord(
            public_pem=key.public_key().export_key(),
            encrypted_private_pem=self._cipher.encrypt(key.export_key()),
            version=version,
            expires_at=datetime.now(timezone.utc) + timedelta(days=validity_days),
        )
        token = secrets.token_urlsafe(32)
        self._token_hashes[owner] = hashlib.sha256(token.encode()).hexdigest()
        self._audit("GENERATE_OR_RENEW", owner)
        return token

    def _authorize(self, owner: str, token: str) -> KeyRecord:
        expected = self._token_hashes.get(owner, "")
        supplied = hashlib.sha256(token.encode()).hexdigest()
        if not secrets.compare_digest(expected, supplied):
            raise PermissionError("invalid API token")
        record = self._records[owner]
        if record.revoked or record.expires_at <= datetime.now(timezone.utc):
            raise PermissionError("key revoked or expired")
        return record

    def get_public_key(self, owner: str) -> bytes:
        record = self._records[owner]
        if record.revoked:
            raise PermissionError("key revoked")
        self._audit("DISTRIBUTE_PUBLIC", owner)
        return record.public_pem

    def get_private_key(self, owner: str, token: str) -> bytes:
        record = self._authorize(owner, token)
        self._audit("DISTRIBUTE_PRIVATE", owner)
        return self._cipher.decrypt(record.encrypted_private_pem)

    def revoke(self, owner: str):
        self._records[owner].revoked = True
        self._audit("REVOKE", owner)


if __name__ == "__main__":
    manager = KeyManager()
    token = manager.register("Hospital-A", validity_days=365)
    print(manager.get_public_key("Hospital-A").decode().splitlines()[0])
    print(manager.get_private_key("Hospital-A", token).decode().splitlines()[0])
    manager.revoke("Hospital-A")
    print("audit:", manager.audit_log)

