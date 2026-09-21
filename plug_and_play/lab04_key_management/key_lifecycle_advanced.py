"""Central KMS model with RBAC, versions, expiry, rotation and audit chaining.

This is an exam-sized in-memory model, not a production KMS.  It demonstrates
the policy state machine clearly: ACTIVE -> RETIRED/REVOKED, with EXPIRED being
derived from time.  Encryption uses only ACTIVE keys; old RETIRED versions may
remain for decrypting old data.  REVOKED keys must not be used at all.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets


@dataclass
class ManagedKey:
    owner: str
    version: int
    key_bytes: bytes
    created_at: datetime
    expires_at: datetime
    status: str = "ACTIVE"


class LifecycleKMS:
    """Small centralized key manager with explicit authorization decisions."""

    ALLOWED = {
        "admin": {"create", "rotate", "revoke", "read", "audit"},
        "service": {"read"},
        "auditor": {"audit"},
    }

    def __init__(self):
        self._keys: dict[str, list[ManagedKey]] = {}
        self._roles: dict[str, str] = {}
        self.audit_log: list[dict] = []

    def assign_role(self, identity: str, role: str) -> None:
        if role not in self.ALLOWED:
            raise ValueError(f"role must be one of {sorted(self.ALLOWED)}")
        self._roles[identity] = role

    def _require(self, identity: str, action: str) -> None:
        role = self._roles.get(identity)
        allowed = self.ALLOWED.get(role, set())
        if action not in allowed:
            self._audit(identity, action, "DENIED", "-")
            raise PermissionError(f"{identity!r} may not perform {action!r}")

    def _audit(self, actor: str, action: str, outcome: str, owner: str) -> None:
        """Append a hash-chained entry so deletion/editing becomes detectable."""
        previous = self.audit_log[-1]["entry_hash"] if self.audit_log else "0" * 64
        entry = {
            "time": datetime.now(timezone.utc).isoformat(),
            "actor": actor, "action": action, "outcome": outcome,
            "owner": owner, "previous_hash": previous,
        }
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        entry["entry_hash"] = hashlib.sha256(canonical).hexdigest()
        self.audit_log.append(entry)

    def _new_version(self, owner: str, validity_days: int) -> ManagedKey:
        if validity_days <= 0:
            raise ValueError("validity_days must be positive")
        now = datetime.now(timezone.utc)
        versions = self._keys.setdefault(owner, [])
        key = ManagedKey(owner, len(versions) + 1, secrets.token_bytes(32),
                         now, now + timedelta(days=validity_days))
        versions.append(key)
        return key

    def create(self, actor: str, owner: str, validity_days: int = 90) -> ManagedKey:
        self._require(actor, "create")
        if owner in self._keys:
            raise ValueError("owner exists; use rotate")
        key = self._new_version(owner, validity_days)
        self._audit(actor, "create", "SUCCESS", owner)
        return key

    def rotate(self, actor: str, owner: str, validity_days: int = 90) -> ManagedKey:
        """Retire current encryption key and issue a fresh version."""
        self._require(actor, "rotate")
        current = self.current(owner)
        current.status = "RETIRED"
        key = self._new_version(owner, validity_days)
        self._audit(actor, "rotate", "SUCCESS", owner)
        return key

    def revoke(self, actor: str, owner: str, version: int | None = None) -> None:
        self._require(actor, "revoke")
        target = self.current(owner) if version is None else self._keys[owner][version - 1]
        target.status = "REVOKED"
        self._audit(actor, f"revoke:v{target.version}", "SUCCESS", owner)

    def current(self, owner: str) -> ManagedKey:
        if owner not in self._keys or not self._keys[owner]:
            raise KeyError(owner)
        return self._keys[owner][-1]

    def retrieve(self, actor: str, owner: str, version: int | None = None,
                 purpose: str = "encrypt") -> bytes:
        """Enforce status: only ACTIVE encrypts; ACTIVE/RETIRED can decrypt."""
        self._require(actor, "read")
        key = self.current(owner) if version is None else self._keys[owner][version - 1]
        if key.expires_at <= datetime.now(timezone.utc):
            decision = "EXPIRED"
        elif key.status == "REVOKED":
            decision = "REVOKED"
        elif purpose == "encrypt" and key.status != "ACTIVE":
            decision = "NOT_ACTIVE"
        elif purpose not in {"encrypt", "decrypt"}:
            decision = "BAD_PURPOSE"
        else:
            self._audit(actor, f"retrieve:{purpose}:v{key.version}", "SUCCESS", owner)
            return key.key_bytes
        self._audit(actor, f"retrieve:{purpose}:v{key.version}", decision, owner)
        raise PermissionError(decision)

    def verify_audit_chain(self) -> bool:
        previous = "0" * 64
        for stored in self.audit_log:
            entry = {key: value for key, value in stored.items() if key != "entry_hash"}
            if entry["previous_hash"] != previous:
                return False
            canonical = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
            calculated = hashlib.sha256(canonical).hexdigest()
            if not secrets.compare_digest(calculated, stored["entry_hash"]):
                return False
            previous = stored["entry_hash"]
        return True


if __name__ == "__main__":
    kms = LifecycleKMS()
    kms.assign_role("root-admin", "admin")
    kms.assign_role("billing-api", "service")
    first = kms.create("root-admin", "customer-records")
    print("created version", first.version)
    print("service key hex:", kms.retrieve("billing-api", "customer-records").hex())
    second = kms.rotate("root-admin", "customer-records")
    print("rotated to version", second.version)
    print("old key usable to decrypt:",
          bool(kms.retrieve("billing-api", "customer-records", 1, "decrypt")))
    print("audit chain valid:", kms.verify_audit_chain())
