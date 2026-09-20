"""Meaningful known-answer and round-trip checks for the exam implementations."""
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


aes = load("aes_explained", "plug_and_play/lab02_block_ciphers/aes_from_scratch.py")
des = load("des_explained", "plug_and_play/lab02_block_ciphers/des_from_scratch.py")
additive = load("additive_explained", "plug_and_play/lab01_classical/additive.py")
affine = load("affine_explained", "plug_and_play/lab01_classical/affine.py")
vig = load("vig_explained", "plug_and_play/lab01_classical/vigenere_autokey.py")
hill = load("hill_explained", "plug_and_play/lab01_classical/hill.py")
elgamal = load("elgamal_explained", "plug_and_play/lab03_public_key/elgamal.py")
dh = load("dh_explained", "plug_and_play/lab03_public_key/diffie_hellman.py")


class TestKnownVectors(unittest.TestCase):
    def test_aes_128_nist_vector(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        encrypted = aes.aes_encrypt_block(plain, key)
        self.assertEqual(encrypted.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(aes.aes_decrypt_block(encrypted, key), plain)

    def test_des_vector(self):
        key = bytes.fromhex("133457799BBCDFF1")
        plain = bytes.fromhex("0123456789ABCDEF")
        encrypted = des.des_encrypt_block(plain, key)
        self.assertEqual(encrypted.hex(), "85e813540f0ab405")
        self.assertEqual(des.des_decrypt_block(encrypted, key), plain)


class TestRoundTrips(unittest.TestCase):
    def test_classical(self):
        text = "INFORMATIONSECURITY"
        self.assertEqual(additive.additive_decrypt(additive.additive_encrypt(text, 20), 20), text)
        self.assertEqual(affine.affine_decrypt(affine.affine_encrypt(text, 15, 20), 15, 20), text)
        self.assertEqual(vig.vigenere_decrypt(vig.vigenere_encrypt(text, "HEALTH"), "HEALTH"), text)
        self.assertEqual(vig.autokey_decrypt(vig.autokey_encrypt(text, 7), 7), text)
        expected_hill = text + ("X" if len(text) % 2 else "")
        self.assertEqual(hill.hill(hill.hill(text, [[3, 3], [2, 7]]), [[3, 3], [2, 7]], True), expected_hill)

    def test_public_key(self):
        private, public = elgamal.keygen(private=2999)
        message = b"ElGamal"
        self.assertEqual(elgamal.decrypt(elgamal.encrypt(message, public), public[0], private), message)
        p, g = 7919, 2
        a_private, a_public = dh.create_keypair(p, g)
        b_private, b_public = dh.create_keypair(p, g)
        self.assertEqual(dh.shared_secret(b_public, a_private, p),
                         dh.shared_secret(a_public, b_private, p))


if __name__ == "__main__":
    unittest.main()
