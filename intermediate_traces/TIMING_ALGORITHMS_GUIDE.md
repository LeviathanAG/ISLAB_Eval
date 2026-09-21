# How to time cryptographic algorithms correctly

Use `timing_templates.py` when the question asks to compare execution time,
throughput, key generation, encryption/decryption, hashing, or signing.

## The short exam pattern

```python
from time import perf_counter_ns

start = perf_counter_ns()
output = algorithm(data, key)
elapsed_ns = perf_counter_ns() - start

print("output:", output)
print("time (ns):", elapsed_ns)
print("time (ms):", elapsed_ns / 1_000_000)
```

This is enough when the paper explicitly asks for one run. One run is noisy,
however, so use repeated measurements for a proper comparison.

## Reliable repeated timing

```python
from intermediate_traces.timing_templates import benchmark

# Prepare values outside the timed function.
message = b"Information Security"
key = bytes.fromhex("00112233445566778899aabbccddeeff")

# lambda has no arguments, which makes it convenient for benchmark().
ciphertext, stats = benchmark(
    lambda: encrypt(message, key),
    repeats=1000,
    warmups=10,
)

print("ciphertext:", ciphertext.hex())
print("median ms:", stats.median_ms)
print("mean ms:", stats.mean_ns / 1_000_000)
print("minimum ms:", stats.minimum_ns / 1_000_000)
```

Why median? A context switch or background process can make a few runs much
slower. The median is less distorted by those outliers. Also report the mean
when the question asks for “average time.”

## Time encryption and decryption separately

```python
encrypted, encryption_time = benchmark(
    lambda: encrypt(plaintext, key), repeats=1000
)

decrypted, decryption_time = benchmark(
    lambda: decrypt(encrypted, key), repeats=1000
)

assert decrypted == plaintext
print("encryption median ms:", encryption_time.median_ms)
print("decryption median ms:", decryption_time.median_ms)
```

Do not put decryption inside the encryption callable. Otherwise the number is
the combined round-trip time and cannot answer which operation is faster.

## Time key generation separately

```python
_, keygen_time = benchmark(lambda: generate_rsa(2048), repeats=20, warmups=1)

private_key, public_key = generate_rsa(2048)  # outside later timed regions
_, encrypt_time = benchmark(
    lambda: rsa_encrypt(message, public_key), repeats=200
)

print("key generation median ms:", keygen_time.median_ms)
print("public operation median ms:", encrypt_time.median_ms)
```

RSA/ECC key generation is a different operation from encryption or signing.
Including fresh key generation in each encryption trial makes the comparison
misleading unless the question explicitly asks for total setup cost.

## Hash comparison

```python
import hashlib
from intermediate_traces.timing_templates import compare_algorithms, throughput

message = b"A" * 1_000_000
rows = compare_algorithms({
    "MD5": lambda: hashlib.md5(message, usedforsecurity=False).digest(),
    "SHA-1": lambda: hashlib.sha1(message, usedforsecurity=False).digest(),
    "SHA-256": lambda: hashlib.sha256(message).digest(),
    "SHA-512": lambda: hashlib.sha512(message).digest(),
}, repeats=100)

for name, result in rows.items():
    print(name, throughput(len(message), result.median_ns), "MiB/s")
```

Speed does not mean security: MD5 may benchmark faster but is collision-broken.
Always state that MD5/SHA-1 results are for legacy comparison only.

## Throughput for many blocks

For total bytes `N` processed in `t` nanoseconds:

```text
seconds = t / 1,000,000,000
MiB     = N / (1024 * 1024)
MiB/s   = MiB / seconds
```

Time the whole batch when one operation is extremely fast:

```python
start = perf_counter_ns()
for block in blocks:
    encrypt_block(block, key)
elapsed = perf_counter_ns() - start

total_bytes = sum(map(len, blocks))
speed = throughput(total_bytes, elapsed)
```

This avoids the clock-call overhead dominating each tiny block measurement.

## File hashing timing

```python
from pathlib import Path
from time import perf_counter_ns
import hashlib

path = Path(input("File path: "))
digest = hashlib.sha256()
bytes_read = 0

start = perf_counter_ns()
with path.open("rb") as source:
    while chunk := source.read(64 * 1024):
        digest.update(chunk)
        bytes_read += len(chunk)
elapsed = perf_counter_ns() - start

print("digest:", digest.hexdigest())
print("time ms:", elapsed / 1e6)
print("throughput MiB/s:", throughput(bytes_read, elapsed))
```

This includes disk-read time. If asked for hash-algorithm speed rather than
end-to-end file processing, read the file before starting the clock.

## Signature timing

```python
private_key, public_key = generate_keys()  # not timed here

signature, sign_stats = benchmark(
    lambda: sign(message, private_key), repeats=200
)
valid, verify_stats = benchmark(
    lambda: verify(message, signature, public_key), repeats=1000
)

assert valid
print("sign median ms:", sign_stats.median_ms)
print("verify median ms:", verify_stats.median_ms)
```

Some signatures are randomized. Different signature bytes do not invalidate a
timing comparison; correctness is determined by verification.

## Network client/server timing

Choose and name what you measure:

- Algorithm time: time only hash/encrypt/sign on one side.
- Round-trip latency: start immediately before `sendall` and stop after the
  complete response arrives.
- End-to-end time: includes serialization, network, server work and parsing.

Never compare a local algorithm time against an end-to-end network time.

## Fair-comparison checklist

1. Use identical input bytes and equivalent security parameters.
2. Keep `input()`, `print()`, key generation and random dataset construction
   outside the timed region unless explicitly required.
3. Perform several warm-up calls before collecting samples.
4. Repeat enough times: often 1,000+ for hashes/block operations, but fewer for
   expensive RSA key generation or PBKDF2.
5. Verify output correctness outside the timer.
6. Report units, repetitions, message size, key size, mode and machine/library.
7. Prefer median; include mean/minimum when useful.
8. For randomized operations, reuse the same inputs but allow fresh internal
   randomness as required by the algorithm.
9. Do not include intermediate-output printing in benchmarks—console I/O is
   far slower and measures printing instead of cryptography.
10. State that classroom timings vary across machines and do not prove security.
