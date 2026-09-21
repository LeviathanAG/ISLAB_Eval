# Lab 4 beyond the manual: key-management exam map

Use `key_manager_patterns.py` for the original compact service,
`key_lifecycle_advanced.py` for lifecycle/RBAC/auditing, and
`envelope_encryption.py` for hybrid KMS encryption.

## Lifecycle and components

| Topic | Meaning | Implementation hook |
|---|---|---|
| Generation | Use a CSPRNG and approved size | `secrets`, library key generation |
| Distribution | Public keys may be shared; secret/private keys need protection | PEM/certificate or wrapped key |
| Storage | Encrypt keys at rest under a KEK/master key | Fernet/KMS/HSM concept |
| Use control | Identity + role + purpose checks | RBAC `retrieve()` |
| Rotation | New version for future encryption/signing | `rotate()` |
| Retirement | Stop new use; allow old decrypt/verify when policy permits | `RETIRED` status |
| Revocation | Compromised/untrusted; deny use | `REVOKED` status |
| Expiry | Time-based automatic rejection | `expires_at` |
| Destruction | Securely remove all recoverable key copies | policy/HSM operation |
| Audit | Record actor/action/result without secrets | hash-chained log |

## Ten realistic variations: key lifecycle and RBAC

1. Create roles for admin, application and auditor with least privilege.
2. Generate a versioned key and reject duplicate create requests.
3. Rotate a key; use the new version for encryption and old version for
   decrypting existing records.
4. Revoke one version after compromise and reject every later use.
5. Set a short expiry and explain renewal versus rotation.
6. Log successful and denied accesses without logging key bytes.
7. Tamper with one audit entry and detect the broken hash chain.
8. Separate key owner, key custodian and key user duties.
9. Cache a data key briefly and discuss invalidation after revocation.
10. Design per-tenant keys so one compromise does not expose every customer.

## Ten realistic variations: envelope/hybrid encryption

1. Generate AES-256 DEK, encrypt data with GCM, and wrap DEK with RSA-OAEP.
2. Accept plaintext and AAD from input; print Base64 transport fields.
3. Alter ciphertext, tag/combined ciphertext, nonce, AAD and wrapped DEK.
4. Explain why RSA should wrap a short key rather than encrypt a large file.
5. Encrypt several files with separate DEKs but one centrally managed KEK.
6. Rotate the KEK by rewrapping DEKs without decrypting every large file.
7. Put owner/version/algorithm identifiers into authenticated AAD.
8. Compare envelope encryption with directly distributing one AES key.
9. Store package fields in JSON and validate every required field/length.
10. Replace RSA wrapping with a cloud/HSM KMS call conceptually.

## Ten realistic variations: RSA/DH secure service

1. Use ephemeral DH to obtain a shared secret and HKDF to derive AES keys.
2. Authenticate the ephemeral DH public key with a long-term RSA signature.
3. Demonstrate a man-in-the-middle attack when DH is unauthenticated.
4. Validate group/curve public keys before deriving a secret.
5. Explain forward secrecy and why static RSA encryption lacks it.
6. Rotate long-term identity keys without losing old audit verification.
7. Use unique session keys for many clients instead of a global symmetric key.
8. Bind transcript, identities and protocol version into the KDF/signature.
9. Reject replayed handshake nonces.
10. Compare classical DH, ECDH and RSA key transport.

## Ten realistic variations: Rabin/RSA/ElGamal management and attacks

1. Validate Rabin Blum primes (`p mod 4 = q mod 4 = 3`).
2. Explain Rabin's four plaintext roots and add redundancy for disambiguation.
3. Factor a weak RSA modulus made from small primes and recover the private key.
4. Apply Fermat factorization to RSA primes chosen too close together.
5. Demonstrate failure from shared RSA primes using `gcd(n1,n2)`.
6. Explain why predictable RNG compromises RSA/ElGamal private keys.
7. Give each DRM title a content key and wrap it per authorized user/device.
8. Enforce entitlement expiry before releasing a content key.
9. Explain that revocation cannot erase keys already copied by a malicious
   client; limit damage with short validity and per-content keys.
10. Compare Rabin, RSA and ElGamal ciphertext expansion and operational
    complexity for a centralized KMS.

## Common traps

- Rotation is not immediate deletion: old ciphertext may still need its old key.
- Revoking a certificate/public key does not magically remove cached private
  keys or plaintext from endpoints.
- Never store plaintext secret keys or secrets inside audit logs.
- Encryption without authentication is insufficient; use an AEAD such as
  AES-GCM and protect metadata as AAD.
- A master key should be isolated in a KMS/HSM, not hard-coded beside data.
