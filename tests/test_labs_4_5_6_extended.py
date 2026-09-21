"""Round-trip and tamper tests for additive beyond-manual modules."""
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


hashes = load("extended_hashes", "plug_and_play/lab05_hashing/hash_toolkit.py")
signatures = load("modern_signatures", "plug_and_play/lab06_signatures/modern_signatures.py")
envelope = load("envelope_encryption", "plug_and_play/lab04_key_management/envelope_encryption.py")
lifecycle = load("key_lifecycle_advanced", "plug_and_play/lab04_key_management/key_lifecycle_advanced.py")


class TestExtendedHashing(unittest.TestCase):
    def test_known_sha256_and_hmac_tamper(self):
        self.assertEqual(
            hashes.hash_text("abc"),
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad",
        )
        key = b"K" * 32
        tag = hashes.hmac_generate(b"message", key)
        self.assertTrue(hashes.hmac_verify(b"message", key, tag))
        self.assertFalse(hashes.hmac_verify(b"tampered", key, tag))

    def test_password_merkle_and_collision(self):
        salt, result, rounds = hashes.password_hash("correct horse")
        self.assertTrue(hashes.password_verify("correct horse", salt, result, rounds))
        self.assertFalse(hashes.password_verify("wrong", salt, result, rounds))
        self.assertNotEqual(hashes.merkle_root([b"a", b"b"]),
                            hashes.merkle_root([b"a", b"c"]))
        self.assertIsNotNone(hashes.truncated_collision(bits=8))


class TestModernSignatures(unittest.TestCase):
    def test_all_signature_families(self):
        cases = (
            (signatures.generate_rsa, signatures.rsa_pss_sign, signatures.rsa_pss_verify),
            (signatures.generate_dsa, signatures.dsa_sign, signatures.dsa_verify),
            (signatures.generate_ecdsa, signatures.ecdsa_sign, signatures.ecdsa_verify),
            (signatures.generate_ed25519, signatures.ed25519_sign, signatures.ed25519_verify),
        )
        for generate, sign, verify in cases:
            with self.subTest(generate=generate.__name__):
                private, public = generate()
                signature = sign(b"exam answer", private)
                self.assertTrue(verify(b"exam answer", signature, public))
                self.assertFalse(verify(b"changed", signature, public))

    def test_ed25519_envelope(self):
        private, public = signatures.generate_ed25519()
        wire = signatures.create_signed_envelope(b"hello", private)
        self.assertEqual(signatures.verify_signed_envelope(wire, public),
                         (True, b"hello"))


class TestKeyManagement(unittest.TestCase):
    def test_envelope_round_trip_and_aad(self):
        private, public = envelope.generate_kek()
        package = envelope.envelope_encrypt(b"record", public, b"owner=7")
        wire = envelope.package_to_json(package)
        self.assertEqual(envelope.envelope_decrypt(
            envelope.package_from_json(wire), private), b"record")

    def test_lifecycle_and_audit_chain(self):
        kms = lifecycle.LifecycleKMS()
        kms.assign_role("admin", "admin")
        kms.assign_role("app", "service")
        kms.create("admin", "records")
        first = kms.retrieve("app", "records")
        kms.rotate("admin", "records")
        self.assertNotEqual(first, kms.retrieve("app", "records"))
        self.assertEqual(first, kms.retrieve("app", "records", 1, "decrypt"))
        self.assertTrue(kms.verify_audit_chain())
        kms.audit_log[0]["actor"] = "attacker"
        self.assertFalse(kms.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
