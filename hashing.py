"""Lab 5 reusable hashing and socket helpers.

Every function accepts bytes unless its name says ``text``.  Hash functions can
read any input length.  MD5 returns 128 bits, SHA-1 160 bits, and SHA-256 256
bits.  MD5 and SHA-1 are included because the manual asks for them; neither
should be used to protect security-sensitive data in a new system.
"""
from __future__ import annotations

import hashlib
import json
import random
import socket
import string
import time
from collections.abc import Iterable


def manual_hash(text: str) -> int:
    """Return the manual's 32-bit DJB2-style hash.

    Start with h=5381.  ``(h << 5) + h`` is exactly ``h * 33``; the shift is
    the bitwise operation requested by the question.  ``& 0xffffffff`` keeps
    only the least-significant 32 bits, so the answer is always 0..2^32-1.

    This is useful for hash tables and the lab demonstration, not passwords,
    signatures, or adversarial integrity checks.
    """
    value = 5381
    for character in text:
        value = (((value << 5) + value) + ord(character)) & 0xFFFFFFFF
    return value


def digest(data: bytes, algorithm: str = "sha256") -> str:
    """Return a lowercase hexadecimal digest.

    ``algorithm`` may be md5, sha1, sha224, sha256, sha384, sha512, or another
    algorithm exposed by hashlib.  Input is bytes, so encode text first with
    ``message.encode('utf-8')``.  ``usedforsecurity=False`` keeps the MD5 lab
    experiment usable on systems that mark MD5 as legacy.
    """
    try:
        obj = hashlib.new(algorithm.lower(), usedforsecurity=False)
    except TypeError:  # Older Python versions do not expose usedforsecurity.
        obj = hashlib.new(algorithm.lower())
    obj.update(data)
    return obj.hexdigest()


def random_dataset(count: int = 100, length: int = 32, seed: int = 3132) -> list[str]:
    """Create reproducible printable inputs for timing/collision experiments."""
    if not 50 <= count <= 100:
        raise ValueError("The manual asks for 50 to 100 strings")
    if length < 1:
        raise ValueError("String length must be positive")
    rng = random.Random(seed)
    alphabet = string.ascii_letters + string.digits
    return ["".join(rng.choice(alphabet) for _ in range(length)) for _ in range(count)]


def find_collisions(values: Iterable[str], algorithm: str) -> dict[str, list[str]]:
    """Map each repeated digest to the distinct inputs that produced it."""
    buckets: dict[str, list[str]] = {}
    for value in values:
        buckets.setdefault(digest(value.encode(), algorithm), []).append(value)
    return {key: items for key, items in buckets.items() if len(set(items)) > 1}


def benchmark_hashes(values: list[str], algorithms=("md5", "sha1", "sha256")) -> list[dict]:
    """Time complete dataset hashing and count observed collisions.

    Collision *resistance* cannot be proved with 100 samples.  The expected
    birthday bound is roughly 2^(n/2) samples for an n-bit ideal digest, so this
    experiment normally observes zero collisions for all three algorithms.
    """
    rows = []
    for algorithm in algorithms:
        start = time.perf_counter_ns()
        hashes = [digest(value.encode(), algorithm) for value in values]
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
        rows.append({
            "algorithm": algorithm.upper(),
            "samples": len(values),
            "digest_bits": len(hashes[0]) * 4 if hashes else 0,
            "milliseconds": elapsed_ms,
            "collisions": len(hashes) - len(set(hashes)),
        })
    return rows


def send_packet(connection: socket.socket, payload: dict) -> None:
    """Send one length-prefixed JSON object; handles TCP's lack of messages."""
    raw = json.dumps(payload).encode("utf-8")
    connection.sendall(len(raw).to_bytes(4, "big") + raw)


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise ConnectionError("Peer closed the connection early")
        data.extend(part)
    return bytes(data)


def receive_packet(connection: socket.socket) -> dict:
    """Receive one object written by :func:`send_packet`."""
    size = int.from_bytes(_receive_exact(connection, 4), "big")
    if size > 10_000_000:
        raise ValueError("Refusing an unexpectedly large packet")
    return json.loads(_receive_exact(connection, size))

