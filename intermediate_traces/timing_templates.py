"""Copy-paste timing helpers for cryptography lab experiments.

Timing rules:
1. Use perf_counter_ns(), a high-resolution monotonic clock.
2. Keep input(), print(), file/network setup and key generation outside the
   timed region unless the question explicitly asks to measure them.
3. Warm up, repeat many times, and report median as well as average.
4. Check correctness outside the timed loop.
"""
from __future__ import annotations

from dataclasses import dataclass
import statistics
import time
from typing import Callable, TypeVar


T = TypeVar("T")


@dataclass
class TimingResult:
    repeats: int
    median_ns: float
    mean_ns: float
    minimum_ns: int
    maximum_ns: int

    @property
    def median_ms(self) -> float:
        return self.median_ns / 1_000_000


def benchmark(function: Callable[[], T], repeats: int = 1000,
              warmups: int = 10) -> tuple[T, TimingResult]:
    """Time a zero-argument callable and return its last result plus statistics."""
    if repeats <= 0 or warmups < 0:
        raise ValueError("repeats must be positive and warmups non-negative")
    for _ in range(warmups):
        function()
    samples = []
    result = None
    for _ in range(repeats):
        start = time.perf_counter_ns()
        result = function()
        end = time.perf_counter_ns()
        samples.append(end - start)
    stats = TimingResult(
        repeats=repeats,
        median_ns=statistics.median(samples),
        mean_ns=statistics.fmean(samples),
        minimum_ns=min(samples),
        maximum_ns=max(samples),
    )
    return result, stats


def throughput(bytes_processed: int, elapsed_ns: float) -> float:
    """Return MiB/s for one operation or an aggregate timed batch."""
    if bytes_processed < 0 or elapsed_ns <= 0:
        raise ValueError("bytes must be non-negative and elapsed time positive")
    return (bytes_processed / (1024 * 1024)) / (elapsed_ns / 1_000_000_000)


def compare_algorithms(operations: dict[str, Callable[[], object]],
                       repeats: int = 1000) -> dict[str, TimingResult]:
    """Benchmark several equivalent zero-argument operations."""
    rows = {}
    print(f"{'algorithm':20} {'median ms':>12} {'mean ms':>12} {'min ms':>12}")
    for name, operation in operations.items():
        _, result = benchmark(operation, repeats=repeats)
        rows[name] = result
        print(f"{name:20} {result.median_ms:12.6f} "
              f"{result.mean_ns/1e6:12.6f} {result.minimum_ns/1e6:12.6f}")
    return rows


def demo() -> None:
    import hashlib
    message = b"A" * 4096
    operations = {
        "SHA-256": lambda: hashlib.sha256(message).digest(),
        "SHA-512": lambda: hashlib.sha512(message).digest(),
        "SHA3-256": lambda: hashlib.sha3_256(message).digest(),
        "BLAKE2b": lambda: hashlib.blake2b(message).digest(),
    }
    results = compare_algorithms(operations, repeats=1000)
    for name, result in results.items():
        print(f"{name:20} throughput={throughput(len(message), result.median_ns):.2f} MiB/s")


if __name__ == "__main__":
    demo()
