# Lab 6 beyond the manual: digital-signature exam map

Use `signatures.py` for readable finite-field math and
`modern_signatures.py` for library-grade RSA, DSA, ECDSA and Ed25519.

## Algorithm comparison

| Algorithm | Mathematical idea | Typical key/input requirement | Important exam point |
|---|---|---|---|
| RSA-PSS | RSA trapdoor permutation + padded hash | RSA >= 2048 bits | Randomized; preferred RSA padding |
| RSA PKCS#1 v1.5 | RSA + deterministic encoding | RSA >= 2048 bits | Legacy interoperability |
| DSA | Discrete logarithm mod `p` | Approved `(p,q,g)`; unique nonce | Nonce reuse reveals private key |
| ElGamal signature | Discrete logarithm mod `p` | Prime group; `gcd(k,p-1)=1` | Large two-integer signature |
| Schnorr | Proof of discrete-log knowledge | Prime-order subgroup | Simple relation, basis of modern schemes |
| ECDSA P-256 | Elliptic-curve discrete log | Valid curve point; unique nonce | Small keys, DER `(r,s)` output |
| Ed25519 | Edwards-curve signature | 32-byte private seed/public key | Fixed choices, deterministic, 64-byte signature |

## Generic flow and security properties

1. Key generation returns private signing key `sk` and shareable public key
   `pk`.
2. Signing computes a scheme-specific signature over the exact message bytes.
3. Verification checks `(pk, message, signature)` and returns valid/invalid.
4. This supplies integrity, origin authentication and practical
   non-repudiation assumptions. It supplies no confidentiality.
5. To obtain confidentiality too: sign a well-defined plaintext/envelope and
   use authenticated encryption for transport. State the order and protocol.

## Ten realistic variations: RSA signatures

1. Generate a 2048-bit pair, sign typed input with PSS and verify it.
2. Export/import encrypted private PEM and public PEM before signing.
3. Compare two PSS signatures of the same message and explain why they differ.
4. Compare PSS with deterministic PKCS#1 v1.5 signatures.
5. Reject altered message, altered signature and unrelated public key.
6. Sign a large file by hashing/streaming, using a prehashed API where needed.
7. Transmit message/signature/public key using Base64 JSON and socket framing.
8. Compare RSA-OAEP encryption with RSA-PSS signing; do not swap paddings.
9. Time signing versus verification for 2048/3072-bit keys.
10. Explain certificate validation: a raw public key alone does not establish
    the owner's identity.

## Ten realistic variations: DSA / ElGamal / Schnorr

1. Calculate a complete signature with small supplied `p,q,g,x,k` values.
2. Verify by printing both sides of the verification congruence.
3. Reject a nonce outside range or not coprime where the scheme requires it.
4. Sign two messages with a reused nonce and explain private-key recovery.
5. Validate that `q | (p-1)` and that `g` lies in the expected subgroup.
6. Accept `(r,s)` as decimal input and perform range checks before arithmetic.
7. Alter each component of `(r,s)` and show verification failure.
8. Compare the ElGamal, DSA and Schnorr equations side-by-side.
9. Explain why plain Diffie-Hellman is key agreement, not a signature.
10. Replace small educational parameters with a library-generated DSA key and
    explain why handwritten parameters are unsafe in real use.

## Ten realistic variations: ECDSA

1. Generate P-256 keys, sign input and verify the DER signature.
2. Decode DER into `(r,s)` and print both integers.
3. Export/import keys and repeat verification after program restart.
4. Compare P-256 key/signature size with RSA-2048.
5. Use SHA-384 with P-384 and ensure both sides select the same hash/curve.
6. Demonstrate message, signature and wrong-key tampering.
7. Explain that an arbitrary `(x,y)` is not automatically a valid curve point.
8. Explain catastrophic private-key exposure from reused/predictable nonce `k`.
9. Sign a canonical transaction containing amount, sender and sequence number.
10. Explain signature malleability/canonicalization at a conceptual level.

## Ten realistic variations: Ed25519

1. Generate keys, sign arbitrary bytes and verify the 64-byte signature.
2. Show deterministic signing produces the same signature for the same input.
3. Serialize raw/public or PEM keys and load them again.
4. Build and verify the Base64 JSON envelope in `modern_signatures.py`.
5. Add sender ID, timestamp and nonce to the signed content to prevent replay.
6. Sign a file and store the detached `.sig` separately.
7. Verify a received file before opening or executing it.
8. Compare Ed25519's fixed API with ECDSA's curve/hash choices.
9. Explain why Base64 does not encrypt the message or signature.
10. Maintain a public-key registry and reject an unknown/revoked signer.

## Ten realistic variations: signed network/application protocols

1. Add a 4-byte length prefix so TCP message boundaries are unambiguous.
2. Sign metadata plus payload rather than payload alone.
3. Reject messages older than a time window.
4. Store seen nonces/sequence numbers to reject replay.
5. Associate public-key fingerprints with authenticated user identities.
6. Rotate signing keys while retaining old public keys for historical checks.
7. Revoke a compromised key and audit every rejected signature.
8. Verify before acting on a command, not afterward.
9. Canonically encode JSON or sign the exact transmitted bytes.
10. Combine encryption and signatures and explain what each primitive adds.

## Common traps

- Signing with a public key or verifying with a private key reverses the roles.
- “Encrypt with private key” is not a correct general definition of signing;
  signature encodings and verification rules are separate constructions.
- Hashing alone gives no sender authentication; HMAC is shared-secret
  authentication; signatures are public-key authentication.
- Never create a nonce using `random`, time, PID or a counter unless the exact
  scheme standard specifies a safe deterministic nonce derivation.
