# Lab 5 beyond the manual: hashing exam map

Use `hash_toolkit.py` for copy-paste functions. Every function takes bytes;
convert keyboard text with `input(...).encode("utf-8")` and print a digest with
`.hex()`.

## Which primitive answers which question?

| Asked for | Use | Key/salt | Output / central rule |
|---|---|---|---|
| File/message fingerprint | SHA-256 or SHA-3 | None | 256-bit fixed digest |
| Legacy comparison | MD5 / SHA-1 | None | Demonstrate only; collision-broken |
| Fast modern alternative | BLAKE2s/BLAKE2b | Optional modes exist | 256/512 bits here |
| Message authentication | HMAC-SHA-256 | Secret random key | Constant-time verification |
| Password storage | PBKDF2-HMAC-SHA-256 | Unique random salt | Slow, repeated derivation |
| Many-record integrity | Merkle root | None | One root commits to every leaf |
| Diffusion experiment | Avalanche test | None | Roughly half digest bits change |
| Collision experiment | Truncated digest | None | About `2^(n/2)` trials |

## Core math to write in an answer

- Preimage resistance: given `y`, finding `x` with `H(x)=y` should take about
  `2^n` work for an ideal `n`-bit hash.
- Second-preimage resistance: given `x`, finding another `x'` with the same
  digest should also take about `2^n` work.
- Collision resistance: finding *any* two different inputs with equal digest
  takes about `2^(n/2)` work because of the birthday paradox.
- A hash is not encryption: it has no decryption key and intentionally loses
  information. It also does not prove who sent a message.
- HMAC adds a shared secret and resists length-extension attacks that affect
  naive constructions such as `SHA256(key || message)`.
- Salt is public, unique and stored beside a password hash. A pepper is a
  separate server secret. Neither is an IV.

## Ten realistic variations: SHA family / MD5 / BLAKE2

1. Read a string and print MD5, SHA-1, SHA-256, SHA-512 and SHA3-256 in a table.
2. Hash a binary file in chunks and prove two chunk sizes give the same result.
3. Compare digest sizes, hex lengths and timings for five message sizes.
4. Modify one character and report the digest's Hamming distance.
5. Demonstrate why comparing only the first 16 hash bits causes collisions.
6. Verify a downloaded file against a supplied hexadecimal SHA-256 value.
7. Hash an empty string and compare it with a known-answer value.
8. Explain why MD5 and SHA-1 are unsuitable even when no collision appears in
   a dataset of 100 random values.
9. Build a menu that validates algorithm names and accepts text or hex input.
10. Stream received socket chunks into `digest.update()` without concatenating
    the whole file in memory.

## Ten realistic variations: HMAC

1. Generate a 32-byte HMAC key, authenticate user input and verify the tag.
2. Accept the key/tag in hex and reject malformed or altered input.
3. Send `message + tag` over a socket and verify before processing the message.
4. Show that two users with different keys get different tags for one message.
5. Tamper with the message, key and tag separately and print all outcomes.
6. Replace unsafe `==` with `hmac.compare_digest` and explain timing leakage.
7. Compare plain SHA-256 integrity with HMAC source authentication.
8. Authenticate JSON canonically; explain why whitespace/key order matters.
9. Derive separate encryption and MAC keys rather than reusing one key.
10. Explain why `SHA256(key || message)` is not a safe HMAC replacement.

## Ten realistic variations: PBKDF2 password hashing

1. Register a password by storing salt, iterations and derived key.
2. Implement login verification without ever decrypting a password.
3. Prove equal passwords with different salts produce different stored values.
4. Reject a wrong password with constant-time comparison.
5. Benchmark 100k, 300k and 600k iterations and discuss the trade-off.
6. Serialize the three stored fields in a delimiter-separated record.
7. Migrate an old record by rehashing after successful login at a higher cost.
8. Explain salt versus IV versus nonce versus pepper.
9. Explain why one fast SHA-256 call enables high-speed offline guessing.
10. Replace PBKDF2 with scrypt/Argon2 conceptually and compare memory hardness.

## Ten realistic variations: Merkle tree and avalanche/collision experiments

1. Compute a Merkle root for four transactions.
2. Change one transaction and demonstrate that the root changes.
3. Handle an odd leaf count by duplicating the final node.
4. Explain leaf/parent prefixes and the need for domain separation.
5. Construct and verify a Merkle inclusion path for one record.
6. Compare storing every digest against storing one trusted root.
7. Flip each input bit in turn and average the SHA-256 avalanche percentage.
8. Find collisions for 8-, 16- and 24-bit truncations and compare with the
   birthday estimate.
9. Explain why a truncated collision does not break full SHA-256.
10. Use the Merkle root as the value signed by a digital-signature algorithm.

## Common traps

- `str.digest()` does not exist: encode text and pass bytes to `hashlib`.
- Hex text has twice as many characters as digest bytes: SHA-256 is 32 bytes
  but 64 hex characters.
- Hash equality detects accidental/malicious changes only if the expected hash
  arrives through a trusted channel. An attacker can replace both otherwise.
- Never use Python's built-in `hash()` for security or persistent checks; it is
  process-dependent and not a cryptographic hash.
