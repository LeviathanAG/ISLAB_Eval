"""Correctness checks for trace functions; output itself remains human-readable."""
from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
TRACE = ROOT / "intermediate_traces"
sys.path.insert(0, str(TRACE))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, TRACE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


lab1 = load("test_trace_lab1", "lab01_classical_trace.py")
lab2 = load("test_trace_lab2", "lab02_block_trace.py")
lab3 = load("test_trace_lab3", "lab03_public_key_trace.py")
lab4 = load("test_trace_lab4", "lab04_key_management_trace.py")
lab5 = load("test_trace_lab5", "lab05_hashing_trace.py")
lab6 = load("test_trace_lab6", "lab06_signature_trace.py")
timing = load("test_timing_templates", "timing_templates.py")


class TraceTests(unittest.TestCase):
    def quiet(self, function, *args, **kwargs):
        with redirect_stdout(io.StringIO()):
            return function(*args, **kwargs)

    def test_lab1_round_trips(self):
        encrypted = self.quiet(lab1.affine_trace, "HELLO", 5, 8)
        self.assertEqual(self.quiet(lab1.affine_trace, encrypted, 5, 8, True), "HELLO")
        encrypted = self.quiet(lab1.hill_trace, "HELP", [[3, 3], [2, 5]])
        self.assertEqual(self.quiet(lab1.hill_trace, encrypted, [[3, 3], [2, 5]], True), "HELP")

    def test_lab2_known_vectors(self):
        aes_result = self.quiet(
            lab2.aes_trace,
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        )
        self.assertEqual(aes_result.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")
        des_result = self.quiet(
            lab2.des_trace,
            bytes.fromhex("0123456789ABCDEF"),
            bytes.fromhex("133457799BBCDFF1"),
        )
        self.assertEqual(des_result.hex(), "85e813540f0ab405")

    def test_lab3_and_lab4_math(self):
        self.assertEqual(self.quiet(lab3.diffie_hellman_trace), 2)
        self.assertIn(42, self.quiet(lab4.rabin_trace))
        self.assertEqual(self.quiet(lab4.fermat_attack_trace, 1009 * 1013)[:2],
                         (1009, 1013))

    def test_lab5_sha256(self):
        self.assertEqual(self.quiet(lab5.sha256_trace, b"abc", False),
                         __import__("hashlib").sha256(b"abc").digest())

    def test_lab6_equations(self):
        self.assertEqual(len(self.quiet(lab6.elgamal_signature_trace, b"exam")), 2)
        self.assertEqual(len(self.quiet(lab6.schnorr_signature_trace, b"exam")), 2)
        self.assertEqual(len(self.quiet(lab6.dsa_signature_trace, b"exam")), 2)

    def test_timing_helper(self):
        result, stats = timing.benchmark(lambda: 2 + 2, repeats=5, warmups=1)
        self.assertEqual(result, 4)
        self.assertEqual(stats.repeats, 5)
        self.assertGreaterEqual(stats.minimum_ns, 0)


if __name__ == "__main__":
    unittest.main()
