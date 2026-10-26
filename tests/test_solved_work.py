"""Regression tests for the newly added PYQ and manual solutions."""

from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from solved_labs.lab05_hashing.solutions import (
    collision_experiment,
    multipart_integrity_demo,
    socket_integrity_demo,
    user_hash,
)
from solved_labs.lab07_phe.solutions import (
    elgamal_multiplication_demo,
    paillier_addition_demo,
    performance_demo,
    rsa_multiplication_demo,
    secure_data_sharing_demo,
    threshold_demo,
)
from solved_labs.lab08_searchable_encryption.solutions import (
    DOCUMENTS,
    PaillierSearchIndex,
    SSEIndex,
)
from solved_labs.lab08_searchable_encryption.gnupg_tools import (
    decrypt_command,
    encrypt_command,
    sign_command,
    verify_command,
)
from solved_labs.lab08_searchable_encryption.snort_tools import (
    analyze_alert_log,
    live_command,
    pcap_command,
    test_config_command,
)
from solved_pyqs.crypto_helpers import combine_threshold_shares
from solved_pyqs.national_e_voting_system import EVotingSystem
from solved_pyqs.secure_grant_expense_portal import GrantPortal


class TestSolvedPyqs(unittest.TestCase):
    """Exercise persistence, tamper handling, and aggregate-only decryption."""

    def test_grant_portal_persists_and_aggregates(self):
        with tempfile.TemporaryDirectory() as directory:
            location = Path(directory) / "portal"
            first = GrantPortal(location, paillier_bits=128)
            first.submit_grant("G1", "Microscope", 15)
            first.submit_grant("G2", "Transport", 25)
            self.assertEqual(first.finance_total(["G1", "G2"]), 40)

            # A new object sees the earlier entries after a restart.
            second = GrantPortal(location, paillier_bits=128)
            self.assertEqual(len(second.list_records()), 2)
            self.assertTrue(second.verify_record(second.records[0])["valid"])
            self.assertIn("4d 69 63 72 6f 73 63 6f 70 65", second.description_hex_dump("G1"))

            self.assertTrue(second.authenticate_role("researcher", "lab-password"))
            self.assertTrue(second.authenticate_role("researcher", "lab-password"))
            self.assertFalse(second.authenticate_role("researcher", "wrong-password"))

            # A record edit is reported as invalid and cannot be included in a total.
            second.records[0]["amount_ciphertext"] = "1"
            self.assertFalse(second.verify_record(second.records[0])["valid"])
            with self.assertRaises(ValueError):
                second.description_hex_dump("G1")
            with self.assertRaises(ValueError):
                second.finance_total(["G1", "G2"])

    def test_evoting_verify_search_tally_and_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            system = EVotingSystem(Path(directory) / "votes", rsa_bits=2048, paillier_bits=128)
            system.cast_vote("alice", 1, "C1")
            system.cast_vote("bob", 2, "C1")
            self.assertTrue(all(system.verify_ballot(item)["valid"] for item in system.records))
            self.assertEqual(len(system.search("C1")), 2)
            result = system.tally()
            self.assertEqual(result["candidate_counts"], {"1": 1, "2": 1, "3": 0, "4": 0, "5": 0})
            self.assertTrue(system.authenticate_role("server", "lab-password"))
            self.assertFalse(system.authenticate_role("server", "wrong-password"))

            system.records[0]["sha512"] = "0" * 128
            self.assertFalse(system.verify_ballot(system.records[0])["valid"])
            self.assertEqual(system.tally()["rejected_ballots"], ["ballot-000001"])


class TestManualSolutions(unittest.TestCase):
    """Check representative outputs from the exact Lab 5, 7, and 8 exercises."""

    def test_lab5(self):
        self.assertEqual(user_hash(""), 5381)
        self.assertTrue(socket_integrity_demo(False))
        self.assertFalse(socket_integrity_demo(True))
        self.assertTrue(multipart_integrity_demo())
        self.assertEqual(sum(int(row["collisions"]) for row in collision_experiment(50)), 0)

    def test_lab7(self):
        self.assertTrue(paillier_addition_demo())
        self.assertTrue(rsa_multiplication_demo())
        self.assertTrue(elgamal_multiplication_demo())
        self.assertTrue(secure_data_sharing_demo())
        self.assertTrue(threshold_demo())
        self.assertTrue(performance_demo())

    def test_lab8(self):
        sse = SSEIndex(DOCUMENTS)
        self.assertEqual({row[0] for row in sse.search("integrity")}, {"doc01", "doc03", "doc09"})
        pkse = PaillierSearchIndex(DOCUMENTS)
        self.assertEqual([row[0] for row in pkse.search("encryption")], ["doc07"])

    def test_lab8_system_tool_helpers(self):
        self.assertEqual(
            encrypt_command("alice", "plain.txt", "plain.gpg"),
            ["gpg", "--output", "plain.gpg", "--encrypt", "--recipient", "alice", "plain.txt"],
        )
        self.assertEqual(decrypt_command("plain.gpg", "plain.txt")[0], "gpg")
        self.assertEqual(sign_command("alice", "plain.txt", "plain.sig")[0], "gpg")
        self.assertEqual(verify_command("plain.sig", "plain.txt"), ["gpg", "--verify", "plain.sig", "plain.txt"])
        self.assertEqual(test_config_command("snort.lua", "local.rules")[-1], "-T")
        self.assertEqual(pcap_command("snort.lua", "local.rules", "traffic.pcap")[-2:], ["-A", "alert_fast"])
        self.assertEqual(live_command("snort.lua", "local.rules", "lo")[0], "snort")
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "alerts.log"
            log.write_text("icmp alert\nicmp alert\ntcp alert\n", encoding="utf-8")
            report = analyze_alert_log(log, "icmp")
            self.assertEqual(report["total_lines"], 3)
            self.assertEqual(report["matching_lines"], ["icmp alert", "icmp alert"])

    def test_threshold_requires_two_distinct_shares(self):
        with self.assertRaises(ValueError):
            combine_threshold_shares({"field": 101, "shares": [{"lambda": 1, "mu": 1}, {"lambda": 2, "mu": 2}]}, 0, 0)

