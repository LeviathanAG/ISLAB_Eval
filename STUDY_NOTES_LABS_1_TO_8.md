# Information Security Lab Study Notes: Labs 1-8

These notes are a short revision sheet made from the supplied Information
Security Lab manuals. The runnable answers are in `lab.py` for Labs 1-4 and in
`solved_labs/` for Labs 5-8.

## Lab 1 - Basic symmetric ciphers

Symmetric encryption uses the same secret key to encrypt and decrypt.

- Additive/Caesar: `c = (m + k) mod 26`, `m = (c - k) mod 26`.
- Multiplicative: `c = m*k mod 26`. The key must have an inverse modulo 26.
- Affine: `c = (a*m + b) mod 26`. Require `gcd(a, 26) = 1`.
- Vigenere: use a repeating keyword; add each keyword letter modulo 26.
- Autokey: start with a short key, then extend it with plaintext or a fixed
  numeric seed.
- Playfair: make a 5 x 5 key square, combine I/J, split into digraphs, and
  apply the same-row, same-column, or rectangle rule.
- Hill: convert letters to numbers and multiply each block by an invertible
  key matrix modulo 26.
- Transposition changes positions; substitution changes symbols.

Attack reminders:

- Known plaintext: use a known plaintext/ciphertext pair to recover a key.
- Brute force: try every valid key and inspect plausible plaintext.
- Chosen plaintext: submit selected plaintext and observe the ciphertext
  permutation.

Manual answers covered: additive, multiplicative, affine, Vigenere, autokey,
Playfair, Hill, known-plaintext shift recovery, affine brute force, birthday-
near additive search, chosen-plaintext permutation inference, and Vigenere
with `HEALTH`.

## Lab 2 - DES and AES

DES and AES are block ciphers, but AES is the modern choice.

### DES

- Block size: 64 bits.
- Effective key size: 56 bits from a 64-bit input key.
- Structure: initial permutation, 16 Feistel rounds, final permutation.
- A round expands the right half, XORs a round key, applies S-boxes, applies
  a permutation, then XORs with the left half.
- Triple DES repeats DES with three keys or three stages. Repeated keys reduce
  its benefit and can collapse it toward single DES.

### AES

- Block size: 128 bits.
- Key sizes: 128, 192, and 256 bits.
- Rounds: 10, 12, and 14 respectively.
- Round operations: AddRoundKey, SubBytes, ShiftRows, MixColumns. The final
  round omits MixColumns.
- AES-192 requires 24 bytes, or 48 hexadecimal characters.

Modes to remember:

- ECB: simple but leaks equal blocks; avoid it for real data.
- CBC: needs a fresh unpredictable IV and padding; it does not authenticate.
- CFB/OFB/CTR: stream-like modes; use a fresh IV or nonce and add integrity.
- GCM: authenticated encryption; preferred when available.

The manual's AES-192 key is only 16 bytes as printed. The solution explicitly
repairs it to 24 bytes before running AES-192.

## Lab 3 - RSA, ElGamal, ECC, and DH

### RSA

1. Choose primes `p`, `q`.
2. Compute `n = p*q` and `phi = (p-1)*(q-1)`.
3. Choose `e` with `gcd(e, phi) = 1`.
4. Compute `d = e^(-1) mod phi`.
5. Public key: `(n, e)`. Private key: `(n, d)`.
6. Textbook equations are `c = m^e mod n` and `m = c^d mod n`.

Real systems must use padding such as RSA-OAEP for encryption and RSA-PSS for
signatures. Textbook RSA is used only for the small lab demonstration.

### ElGamal

- Public parameters: prime `p`, generator `g`.
- Private key: `x`; public value: `y = g^x mod p`.
- Encryption with random `k`: `c1 = g^k`, `c2 = m*y^k mod p`.
- Decryption: `m = c2 * (c1^x)^(-1) mod p`.

### ECC and DH

- ECC public key: `Q = d*G` on a chosen curve.
- ECC is normally used for key agreement or hybrid encryption, not direct
  arbitrary-size message encryption.
- DH: Alice sends `A = g^a`, Bob sends `B = g^b`, and both obtain
  `g^(ab)`. Plain DH provides key agreement, not authentication.
- Authenticate the transcript with a signature to prevent a man-in-the-middle
  attack.

The manual's additional ElGamal values are inconsistent: with `p=7919`,
`g=2`, and `x=2999`, the calculated public value is 3868, not 6465. The
solution reports and corrects this before decrypting.

## Lab 4 - advanced asymmetric systems, KMS, and access control

### Rabin

- Choose `p` and `q` such that both are 3 modulo 4.
- Public key: `n = p*q`; private key: `(p, q)`.
- Encryption: `c = m^2 mod n`.
- Decryption produces four possible square roots; the message needs a way to
  be identified or padded unambiguously.

### Key-management checklist

- Generate keys with strong randomness.
- Store private keys encrypted under a separate master key.
- Distribute only the minimum key material needed.
- Record generation, distribution, renewal, revocation, and access events.
- Rotate or expire keys and reject inactive or expired versions.
- Use a KDF with a salt and sufficient work factor for password-derived keys.
- Keep backups and audit logs protected from tampering.

### Access-control models

- RBAC: permissions come from the user's role.
- ABAC: a policy evaluates user, object, and environment attributes.
- MAC: a central policy compares clearance and classification.
- DAC: the object owner controls an access matrix.
- Bell-LaPadula: no read up and no write down.
- Time-based: access is valid only inside a time window.
- Probabilistic: access probability depends on trust and risk conditions.

The code demonstrates SecureCorp RSA plus authenticated DH, a Rabin KMS for
healthcare, ElGamal DRM with expiring grants, revocation, renewal, encrypted
storage, and audit logging. It also includes the RSA factorization attack and
mitigation discussion through the lab menu.

## Lab 5 - hashing

- A hash maps variable-length input to a fixed-length digest.
- Good cryptographic hashes are one-way and collision resistant.
- The manual's user hash starts at 5381, multiplies by 33, adds each character,
  mixes bits, and masks to 32 bits.
- For transmission integrity, hash the received bytes and compare them with a
  locally computed digest.
- MD5 and SHA-1 are useful for legacy comparisons but should not protect new
  security designs. Use SHA-256 or SHA-512 for an unkeyed digest and HMAC when
  an attacker could replace the digest.
- A zero collision count in 50-100 random strings is only an experiment result,
  not proof of collision resistance.

The multipart exercise needs framing, complete reads, reassembly, and one hash
comparison after the final part.

## Lab 6 - digital signatures

A signature provides authenticity and integrity, not secrecy.

1. Hash the message when the signature scheme requires it.
2. Sign with the sender's private key.
3. Verify with the sender's public key.
4. Reject any changed message, signature, or public-key identity.

The solution covers RSA-PSS exchange, ElGamal signatures, Schnorr signatures,
DSA-style authenticated DH, a client/server signed message, and the CIA triad
using RSA-OAEP, RSA-PSS, and SHA-256.

## Lab 7 - partial homomorphic encryption

- Paillier is additively homomorphic: multiplying ciphertexts gives an
  encryption of the sum.
- RSA textbook encryption is multiplicatively homomorphic:
  `E(a)*E(b) mod n = E(a*b)` when the values fit the message space.
- ElGamal is multiplicatively homomorphic by multiplying both ciphertext
  components.
- Homomorphic encryption means the server can calculate on ciphertexts, but
  decryption still reveals the result.
- Threshold decryption splits private material so multiple authorities must
  cooperate before the final aggregate is opened.

Important limitation: textbook RSA and the small educational ElGamal/PHE code
are for understanding algebraic properties, not production encryption.

## Lab 8 - searchable encryption

- Searchable encryption separates encrypted content from a searchable index.
- SSE uses one shared secret and is efficient, but key distribution and search
  leakage must be controlled.
- Public-key searchable encryption supports wider access control but costs more
  computation.
- Normalize words consistently before indexing.
- A secure deterministic search token can be made with HMAC-SHA256. It leaks
  equality and search patterns, so the leakage must be documented.
- Randomized AES-CBC or Paillier ciphertexts cannot be compared directly for
  equality. The solutions therefore use keyed HMAC/public SHA-256 tokens for
  lookup and protect returned IDs or documents separately.
- GnuPG examples cover encryption, decryption, detached signing, and verify.
- Snort examples cover safe command construction and existing alert-log
  analysis; live monitoring must be limited to an authorized interface.

## One-minute exam checklist

1. Identify the security goal: confidentiality, integrity, authenticity,
   availability, privacy, or computation on ciphertext.
2. Pick the primitive that matches the goal: AES for bulk data, RSA/ECC/DH for
   key exchange, signatures for authenticity, hashes/HMAC for integrity, and
   Paillier for additive aggregation.
3. Validate key size, IV/nonce rules, padding, and message-size limits.
4. Never decrypt individual values when the question asks for an aggregate.
5. Test the happy path and a tampered path.
6. Keep the program interactive, print descriptive results, and handle invalid
   input without crashing.
