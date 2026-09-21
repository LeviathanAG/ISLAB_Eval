"""Lab 4 KMS, Rabin, weak-RSA and envelope-encryption traces."""
from __future__ import annotations

import json
from math import isqrt

from trace_utils import heading, load_module


lifecycle = load_module(
    "trace_lifecycle", "plug_and_play/lab04_key_management/key_lifecycle_advanced.py"
)
envelope = load_module(
    "trace_envelope", "plug_and_play/lab04_key_management/envelope_encryption.py"
)


def rabin_trace(message: int = 42, p: int = 499, q: int = 547) -> list[int]:
    """Print Rabin encryption and CRT construction of all four square roots."""
    if p % 4 != 3 or q % 4 != 3 or p == q:
        raise ValueError("p and q must be distinct Blum primes (3 mod 4)")
    n = p * q
    if not 0 <= message < n:
        raise ValueError("message must be in 0..n-1")
    ciphertext = message * message % n
    root_p = pow(ciphertext, (p + 1) // 4, p)
    root_q = pow(ciphertext, (q + 1) // 4, q)
    inverse_q = pow(q, -1, p)
    inverse_p = pow(p, -1, q)
    print(f"p={p} (mod4={p%4}), q={q} (mod4={q%4}), n=pq={n}")
    print(f"encryption c=m^2 mod n={message}^2 mod {n}={ciphertext}")
    print(f"root mod p: c^((p+1)/4) mod p={root_p}; alternatives ±={root_p},{(-root_p)%p}")
    print(f"root mod q: c^((q+1)/4) mod q={root_q}; alternatives ±={root_q},{(-root_q)%q}")
    print(f"q^-1 mod p={inverse_q}; p^-1 mod q={inverse_p}")
    roots = []
    for sign_p, a in (("+", root_p), ("-", -root_p)):
        for sign_q, b in (("+", root_q), ("-", -root_q)):
            raw = a * q * inverse_q + b * p * inverse_p
            root = raw % n
            roots.append(root)
            print(f"CRT signs ({sign_p}rp,{sign_q}rq): raw={raw}; mod n={root}; "
                  f"check root^2 mod n={root*root%n}")
    answer = sorted(set(roots))
    print("four candidates:", answer)
    print("original selected using redundancy/encoding:", message in answer)
    return answer


def fermat_attack_trace(n: int, e: int = 65537, max_rows: int = 50):
    """Print each Fermat attempt until n=(a-b)(a+b)."""
    a = isqrt(n)
    if a * a < n:
        a += 1
    print(f"n={n}; start a=ceil(sqrt(n))={a}")
    attempts = 0
    while True:
        b_squared = a * a - n
        b = isqrt(b_squared)
        attempts += 1
        if attempts <= max_rows:
            print(f"attempt {attempts:2}: a={a}, a^2-n={b_squared}, "
                  f"is_square={b*b == b_squared}")
        if b * b == b_squared:
            p, q = a - b, a + b
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            print(f"found b={b}; p=a-b={p}; q=a+b={q}; p*q={p*q}")
            print(f"phi={phi}; recovered d=e^-1 mod phi={d}")
            return p, q, d
        a += 1


def lifecycle_trace() -> lifecycle.LifecycleKMS:
    """Print lifecycle state changes, access decisions and audit-chain links."""
    kms = lifecycle.LifecycleKMS()
    print("1. initialize centralized KMS")
    for identity, role in (("alice-admin", "admin"),
                           ("records-api", "service"),
                           ("compliance", "auditor")):
        kms.assign_role(identity, role)
        print(f"2. assign role: {identity} -> {role}; permissions={sorted(kms.ALLOWED[role])}")
    first = kms.create("alice-admin", "patient-records", validity_days=90)
    print(f"3. create: owner={first.owner}, version={first.version}, status={first.status}, "
          f"key_length={len(first.key_bytes)*8} bits, expires={first.expires_at.isoformat()}")
    obtained = kms.retrieve("records-api", "patient-records", purpose="encrypt")
    print(f"4. authorized retrieval: key fingerprint={__import__('hashlib').sha256(obtained).hexdigest()[:16]}")
    second = kms.rotate("alice-admin", "patient-records", validity_days=90)
    print(f"5. rotate: v1 status={first.status}; v2 status={second.status}; "
          f"new key differs={first.key_bytes != second.key_bytes}")
    old = kms.retrieve("records-api", "patient-records", version=1, purpose="decrypt")
    print(f"6. retired v1 allowed for old-data decryption={old == first.key_bytes}")
    kms.revoke("alice-admin", "patient-records", version=1)
    print(f"7. revoke v1: status={first.status}")
    try:
        kms.retrieve("records-api", "patient-records", version=1, purpose="decrypt")
    except PermissionError as error:
        print(f"8. later v1 request rejected: {error}")
    print("9. audit entries (secrets are never logged):")
    for index, entry in enumerate(kms.audit_log, 1):
        print(f"   {index}: action={entry['action']}, outcome={entry['outcome']}, "
              f"previous={entry['previous_hash'][:12]}, hash={entry['entry_hash'][:12]}")
    print("10. complete audit chain valid:", kms.verify_audit_chain())
    return kms


def envelope_trace(message: bytes = b"medical record", aad: bytes = b"patient=42") -> dict:
    """Print hybrid encryption stages and transport encoding."""
    private, public = envelope.generate_kek()
    print(f"1. RSA KEK generated: modulus={public.key_size} bits, exponent="
          f"{public.public_numbers().e}")
    package = envelope.envelope_encrypt(message, public, aad)
    print("2. plaintext bytes:", message.hex())
    print("3. AAD (visible but authenticated):", aad)
    print(f"4. random AES-256 DEK generated internally: 32 bytes")
    print(f"5. GCM nonce={package['nonce'].hex()} ({len(package['nonce'])} bytes)")
    print(f"6. ciphertext||tag={package['ciphertext'].hex()}")
    print(f"   encrypted data bytes={len(package['ciphertext'])-16}; GCM tag bytes=16")
    print(f"7. RSA-OAEP wrapped DEK length={len(package['wrapped_dek'])} bytes")
    wire = envelope.package_to_json(package)
    print("8. Base64 JSON transport:", wire)
    parsed = envelope.package_from_json(wire)
    recovered = envelope.envelope_decrypt(parsed, private)
    print("9. unwrap DEK -> authenticate GCM -> recovered:", recovered)
    return package


def demo() -> None:
    heading("LAB 4: RABIN FOUR ROOTS")
    rabin_trace()
    heading("LAB 4: WEAK RSA FERMAT ATTACK")
    fermat_attack_trace(1009 * 1013)
    heading("LAB 4: KEY LIFECYCLE")
    lifecycle_trace()
    heading("LAB 4: ENVELOPE ENCRYPTION")
    envelope_trace()


if __name__ == "__main__":
    demo()
