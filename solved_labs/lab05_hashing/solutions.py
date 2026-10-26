"""Lab 5 solutions: hashing, socket integrity, timing, and multipart data.

The menu runs all four manual exercises.  The socket demonstrations use a
local ``socketpair`` so they are deterministic and do not require a network
service running in another terminal.
"""

from __future__ import annotations

import hashlib
import random
import socket
import string
import time
from collections.abc import Iterable


def user_hash(text: str) -> int:
    """Implement the manual's 5381 / multiply-by-33 32-bit hash."""

    value = 5381
    for character in text:
        # XOR after the addition mixes high and low bits while the mask keeps
        # the result in the requested unsigned 32-bit range.
        value = ((value * 33) + ord(character)) & 0xFFFFFFFF
        value ^= (value >> 16)
        value &= 0xFFFFFFFF
    return value


def digest(data: bytes, algorithm: str = "sha256") -> str:
    """Return a hexadecimal digest for any hashlib-supported algorithm."""

    return hashlib.new(algorithm, data).hexdigest()


def _send_frame(connection: socket.socket, payload: bytes) -> None:
    """Send a length-prefixed frame so a receive cannot truncate data."""

    connection.sendall(len(payload).to_bytes(8, "big") + payload)


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    """Read exactly ``size`` bytes from a stream socket."""

    parts: list[bytes] = []
    remaining = size
    while remaining:
        part = connection.recv(remaining)
        if not part:
            raise ConnectionError("Peer closed before the complete frame arrived")
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)


def _receive_frame(connection: socket.socket) -> bytes:
    """Receive the frame produced by :func:`_send_frame`."""

    size = int.from_bytes(_receive_exact(connection, 8), "big")
    return _receive_exact(connection, size)


def socket_integrity_demo(corrupt: bool = False) -> bool:
    """Demonstrate server hash verification and optional tamper detection."""

    client, server = socket.socketpair()
    try:
        original = b"Integrity checked message from the client"
        transmitted = original[:-1] + b"!" if corrupt else original
        _send_frame(client, transmitted)
        received = _receive_frame(server)
        server_hash = digest(received, "sha256")
        _send_frame(server, server_hash.encode("ascii"))
        received_hash = _receive_frame(client).decode("ascii")
        local_hash = digest(original, "sha256")
        verified = received_hash == local_hash
        print(f"Server SHA-256: {server_hash}")
        print(f"Client SHA-256: {local_hash}")
        print(f"Integrity verified: {verified}")
        return verified
    finally:
        client.close()
        server.close()


def multipart_integrity_demo(parts: int = 4) -> bool:
    """Send a message in multiple frames, reassemble, and verify its hash."""

    if parts < 2:
        raise ValueError("Use at least two message parts")
    original = b"A multipart Information Security lab message." * 3
    chunk_size = (len(original) + parts - 1) // parts
    chunks = [original[index : index + chunk_size] for index in range(0, len(original), chunk_size)]
    client, server = socket.socketpair()
    try:
        for chunk in chunks:
            _send_frame(client, chunk)
        _send_frame(client, b"")  # Empty frame is the end-of-message marker.
        received_parts: list[bytes] = []
        while True:
            chunk = _receive_frame(server)
            if not chunk:
                break
            received_parts.append(chunk)
        reassembled = b"".join(received_parts)
        server_hash = digest(reassembled)
        _send_frame(server, server_hash.encode("ascii"))
        client_hash = digest(original)
        received_hash = _receive_frame(client).decode("ascii")
        verified = received_hash == client_hash and reassembled == original
        print(f"Multipart parts received: {len(received_parts)}")
        print(f"Reassembled hash verified: {verified}")
        return verified
    finally:
        client.close()
        server.close()


def collision_experiment(count: int = 75) -> list[dict[str, object]]:
    """Time MD5/SHA-1/SHA-256 and report collisions in random samples."""

    if not 50 <= count <= 100:
        raise ValueError("The manual asks for a dataset between 50 and 100 strings")
    randomizer = random.Random(2026)
    values = ["".join(randomizer.choice(string.ascii_letters) for _ in range(32)) for _ in range(count)]
    results: list[dict[str, object]] = []
    for algorithm in ("md5", "sha1", "sha256"):
        start = time.perf_counter()
        digests = [digest(value.encode("utf-8"), algorithm) for value in values]
        elapsed = time.perf_counter() - start
        collisions = len(digests) - len(set(digests))
        result = {"algorithm": algorithm, "seconds": elapsed, "collisions": collisions}
        results.append(result)
        print(result)
    print("Collision note: no collision in a small random sample is not a proof of collision resistance.")
    return results


def run_all() -> None:
    """Display outputs for every Lab 5 requirement."""

    print("=== Lab 5.1 user-defined hash ===")
    print("hash('Information Security') =", hex(user_hash("Information Security")))
    print("=== Lab 5.2 socket integrity ===")
    socket_integrity_demo(False)
    socket_integrity_demo(True)
    print("=== Lab 5.3 timing/collision experiment ===")
    collision_experiment()
    print("=== Lab 5A.1 multipart transfer ===")
    multipart_integrity_demo()


def run_menu() -> None:
    """Run one Lab 5 example at a time from a simple interactive menu."""

    actions = {
        "1": ("User-defined hash", lambda: print(hex(user_hash("Information Security")))),
        "2": ("Socket integrity", lambda: socket_integrity_demo(False)),
        "3": ("Tamper detection", lambda: socket_integrity_demo(True)),
        "4": ("Timing and collision experiment", collision_experiment),
        "5": ("Multipart integrity", multipart_integrity_demo),
        "6": ("Run every example", run_all),
    }
    while True:
        print("\n=== Lab 5 menu ===")
        for number, (label, _action) in actions.items():
            print(f"{number}. {label}")
        print("0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        selected = actions.get(choice)
        if selected is None:
            print("Invalid choice.")
            continue
        try:
            selected[1]()
        except (ConnectionError, ValueError) as exc:
            print(f"Example could not run: {exc}")


if __name__ == "__main__":  # pragma: no cover - manual entry point.
    run_menu()

