"""Standalone Lab 5 hash functions.

A hash accepts any number of bytes and returns a fixed-size digest.  MD5 gives
128 bits, SHA-1 gives 160, SHA-256 gives 256.  MD5/SHA-1 are legacy algorithms
included for the comparison experiment; use SHA-256 or stronger in new work.
"""
import hashlib
import random
import string
import time


def manual_hash(text: str) -> int:
    """h=5381; h=h*33+ASCII(character); mask to unsigned 32 bits."""
    h = 5381
    for character in text:
        h = (((h << 5) + h) + ord(character)) & 0xFFFFFFFF
    return h


def hash_hex(data: bytes, algorithm: str = "sha256") -> str:
    """algorithm may be md5, sha1, sha256, sha384, sha512, etc."""
    return hashlib.new(algorithm, data, usedforsecurity=False).hexdigest()


def compare_hashes(count: int = 100, length: int = 32):
    """Return timing and observed collisions for the manual's three hashes."""
    if not 50 <= count <= 100:
        raise ValueError("manual requires 50..100 samples")
    rng = random.Random(3132)
    alphabet = string.ascii_letters + string.digits
    dataset = ["".join(rng.choice(alphabet) for _ in range(length)).encode()
               for _ in range(count)]
    rows = []
    for algorithm in ("md5", "sha1", "sha256"):
        start = time.perf_counter_ns()
        values = [hash_hex(item, algorithm) for item in dataset]
        elapsed = (time.perf_counter_ns() - start) / 1_000_000
        rows.append((algorithm, elapsed, len(values)-len(set(values))))
    return rows


if __name__ == "__main__":
    print("manual hash:", f"{manual_hash('Information Security'):08x}")
    for row in compare_hashes():
        print("algorithm=%s time_ms=%.6f collisions=%d" % row)
