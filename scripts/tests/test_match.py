#!/usr/bin/env python3
"""Tests for vulncheck.match plus light inventory/state checks.

The dpkg truth table below combines dpkg 1.21.1's own test vectors
(lib/dpkg/t/t-version.c), our recorded probe results against the live
`dpkg --compare-versions`, and the official deb-version(7) rules.
"""

import os
import random
import subprocess
import sys
import tempfile
import unittest
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulncheck import inventory, match, state  # noqa: E402

DPKG = "/usr/bin/dpkg"

# (a, b, expected_sign) or (a, None, "ERR") for hard parse errors
TRUTHS = [
    ("0", "0", 0), ("0", "00", 0), ("00", "0", 0), ("0:0", "0", 0),
    ("0:0-0", "0-0", 0), ("0:0.0-0.0", "0.0-0.0", 0), ("1:0", "0:0", 1),
    ("5:1", "1:1", 1), ("0:0-0-0", "0-0-0", 0),
    ("0:0:0-0", "0:0-0", 1), ("0:0:0:0-0", "0:0:0-0", 1),
    ("0:0:0-0-0", "0:0-0-0", 1), ("0:0-0:0-0", "0:0-0:0-0", 0),
    ("0:09azAZ.-+~:-0", "0:09azAZ.-+~:-0", 0),
    ("1:09azAZ.-+~:-0", "0:09azAZ.-+~:-0", 1),
    ("0:0-azAZ09.+~", "0-azAZ09.+~", 0),
    ("  \t0:0-1", "0:0-1", 0), ("0:0-1  \t", "0:0-1", 0),
    ("a", "b", -1), ("2", "10", -1), ("10", "010", 0), ("1.10", "1.9", 1),
    ("1.2-10", "1.2-9", 1), ("100-2", "0100-2", 0), ("2:1", "1:9", 1),
    ("1:100", "0:9", 1), ("2:0", "2:0-0", 0), ("1.2", "1.2-0", 0),
    ("5.1-6ubuntu1", "5.1-6ubuntu1.1", -1),
    ("1-0ubuntu1.30", "1-0ubuntu1.2", 1),
    ("3.0.2-0ubuntu1.30", "3.0.2-0ubuntu1.29", 1),
    ("1.0", "1.0~", 1), ("1.0~~", "1.0~", -1), ("~b", "~a", 1),
    ("1.0a", "1.0~~beta1", 1), ("1.2.10a", "1.2.10b", -1), ("0", "a", -1),
    ("a1", "ab", -1), ("1", "1a", -1), ("1", "11", -1), ("1", "1.a", -1),
    ("1.0", "1.0.0", -1), ("1~a", "10", -1),
    ("1-0ubuntu1.2", "1-0ubuntu1.10", -1), ("1.2-9", "1.2-9.1", -1),
    ("0:1", "1", 0), ("2:1-2", "2:1", 1), ("1-1", "0-2", 1),
    ("1.0-1", "1.0-01", 0), ("49", "a", -1), ("1000", "b", -1),
    ("1a", "a", -1), ("09", "a", -1), ("1.0", "1.o", -1), ("1", "~", 1),
    ("0~", "0", -1), ("18446744073709551615", "18446744073709551616", -1),
    ("a.b", "ab", 1), ("a+b", "ab", 1), ("a~b", "ab", -1),
    ("1_a", "1ab", 1), ("1+a", "1.a", -1), ("1.a", "1aa", 1),
    ("1.a", "1Za", 1), ("1a", "1.b", -1), ("a1", "ab1", -1),
    ("ab", "a1c", 1), ("1a", "11", -1), ("aa", "a1a", 1),
    ("1..0", "1.0", 1), ("0-0", "0", 0), ("01:1", "1:1", 0),
    ("1:2:3", "1:2:4", -1), (".5", "1", 1), ("+", "1", 1),
    ("99999999999999999998", "99999999999999999999", -1),
    ("18446744073709551616", "18446744073709551617", -1),
    ("1.0~~beta1", "1.0~rc1", -1), ("2147483647:1", "2147483646:1", 1),
    ("+1:2", "1:2", 0), ("1-a-b", "1-a-b", 0), ("1-0-1", "1-0-1", 0),
]

PARSE_ERRORS = [
    "1 2", " ", "-1", ":1", "1:", "1-", "1--", "a:1", "2147483648:1",
    "18446744073709551615:1", "99999999999999999999:1",
    "09azAZ.-+~:-0", "0-0:0-0",
]

# Versions dpkg accepts with only warnings (non-fatal).
PARSE_WARNINGS_OK = ["1_a", "a", "+", ".5", "abc3", "1..0", "0:abc3-0",
                     "0:0-0:0", "-i-2~08X6rg"]

CVSS_VECTORS = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "9.8"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "10.0"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "5.5"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "6.1"),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "9.8"),
]

PYPI_PAIRS = [
    ("1.0", "1.1", -1), ("1.0rc1", "1.0", -1), ("1.0", "1.0.post1", -1),
    ("1.0a1", "1.0b1", -1), ("1.0b1", "1.0rc1", -1), ("1.0.dev1", "1.0", -1),
    ("2!1.0", "1.0", 1), ("1.0+local", "1.0", 0), ("V1.2", "1.2", 0),
    ("1.0-alpha1", "1.0a1", 0), ("1.0", "1.0a", 1), ("0.9.9", "1.0", -1),
]


def sgn(value):
    return (value > 0) - (value < 0)


class TestDpkgComparator(unittest.TestCase):
    def test_truths(self):
        for a, b, expected in TRUTHS:
            with self.subTest(a=a, b=b):
                self.assertEqual(sgn(match.dpkg_compare_strings(a, b)),
                                 expected)

    def test_parse_errors(self):
        for version in PARSE_ERRORS:
            with self.subTest(version=version):
                self.assertRaises(match.DpkgParseError,
                                  match.parse_dpkg_version, version)

    def test_warnings_are_accepted(self):
        for version in PARSE_WARNINGS_OK:
            with self.subTest(version=version):
                match.parse_dpkg_version(version)  # must not raise

    def test_relate_operators(self):
        self.assertTrue(match.dpkg_relate("1.0", "lt", "2.0"))
        self.assertTrue(match.dpkg_relate("1.0", "<=", "1.0"))
        self.assertTrue(match.dpkg_relate("1.0", "=", "1.0"))
        self.assertTrue(match.dpkg_relate("2.0", "ge", "2.0"))
        self.assertFalse(match.dpkg_relate("1.0", "gt", "2.0"))
        self.assertRaises(ValueError, match.dpkg_relate, "1", "~=", "2")


@unittest.skipUnless(os.path.exists(DPKG), "dpkg not available")
class TestDpkgLiveFuzz(unittest.TestCase):
    """Cross-check the port against the live dpkg binary (small fuzz)."""

    ALPHABET = ("0123456789" * 4 + "abcdefghijklmnopqrstuvwxyz" * 2
                + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + ".+~" * 4 + ":--_" + "! @")

    @staticmethod
    def cli(a, op, b):
        proc = subprocess.run(
            [DPKG, "--compare-versions", "--", a, op, b],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc.returncode

    def test_fuzz_agreement(self):
        rng = random.Random(20261030)

        def rand_version():
            length = rng.randint(1, 14)
            return "".join(rng.choice(self.ALPHABET) for _ in range(length))

        pairs = [(rand_version(), rand_version()) for _ in range(150)]
        for a, b in pairs:
            with self.subTest(a=a, b=b):
                try:
                    ours = sgn(match.dpkg_compare_strings(a, b))
                    parsed = True
                except match.DpkgParseError:
                    ours, parsed = None, False
                rc_lt = self.cli(a, "lt", b)
                rc_gt = self.cli(a, "gt", b)
                if 2 in (rc_lt, rc_gt):
                    self.assertEqual(rc_lt, rc_gt)
                    self.assertFalse(parsed)
                    continue
                self.assertTrue(parsed)
                if rc_lt == 0:
                    expected = -1
                elif rc_gt == 0:
                    expected = 1
                else:
                    expected = 0  # neither lt nor gt holds
                self.assertEqual(ours, expected)


class TestCvss(unittest.TestCase):
    def test_spec_vectors(self):
        for vector, expected in CVSS_VECTORS:
            with self.subTest(vector=vector):
                self.assertEqual(match.cvss3_base_score(vector),
                                 Decimal(expected))

    def test_rejects(self):
        for vector in ("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
                       "not a vector", "",
                       "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H"):
            with self.subTest(vector=vector):
                self.assertIsNone(match.cvss3_base_score(vector))


class TestSeverity(unittest.TestCase):
    def test_rank_from_score(self):
        self.assertEqual(match.severity_rank_from_score(9.8), 4)
        self.assertEqual(match.severity_rank_from_score("7.5"), 3)
        self.assertEqual(match.severity_rank_from_score(4.0), 2)
        self.assertEqual(match.severity_rank_from_score(0.5), 1)
        self.assertEqual(match.severity_rank_from_score(0), 0)
        self.assertEqual(match.severity_rank_from_score("bogus"), 0)

    def test_labels(self):
        self.assertEqual(match.severity_rank_from_label("HIGH"), 3)
        self.assertEqual(match.severity_rank_from_label("moderate"), 2)
        self.assertEqual(match.severity_rank_from_label("negligible"), 0)
        self.assertEqual(match.severity_label(4), "critical")
        self.assertEqual(match.severity_label(0), "none")

    def test_extract(self):
        record = {"severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "database_specific": {"severity": "LOW"}}
        rank, detail = match.extract_severity(record)
        self.assertEqual(rank, 4)
        self.assertIn("9.8", detail)
        rank, _ = match.extract_severity(
            {"database_specific": {"severity": "HIGH"}})
        self.assertEqual(rank, 3)
        rank, detail = match.extract_severity({})
        self.assertEqual(rank, 0)
        self.assertTrue(detail)


class TestPypiComparator(unittest.TestCase):
    def test_pairs(self):
        comparator = match.PypiComparator()
        for a, b, expected in PYPI_PAIRS:
            with self.subTest(a=a, b=b):
                self.assertEqual(comparator.compare(a, b), expected)

    def test_undecidable(self):
        comparator = match.PypiComparator()
        self.assertIsNone(comparator.compare("junk!!", "1.0"))
        self.assertIsNone(comparator.compare("1.0", ""))


class TestEcosystem(unittest.TestCase):
    def test_matches(self):
        self.assertTrue(match.ecosystem_matches("Ubuntu:22.04",
                                                "Ubuntu:22.04:LTS"))
        self.assertTrue(match.ecosystem_matches("Ubuntu:22.04",
                                                "Ubuntu:22.04"))
        self.assertFalse(match.ecosystem_matches("Ubuntu:22.04",
                                                 "Ubuntu:20.04"))
        self.assertTrue(match.ecosystem_matches("PyPI", "pypi"))
        self.assertFalse(match.ecosystem_matches("Ubuntu:22.04", "Debian:11"))


class TestOsvMatching(unittest.TestCase):
    CURL_RECORD = {
        "affected": [{
            "package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "curl"},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "0"},
                                   {"fixed": "7.81.0-6ubuntu1.5"}]}],
        }],
    }

    def test_ubuntu_range(self):
        fn = match.osv_record_matches_asset
        self.assertIs(fn(self.CURL_RECORD, "Ubuntu:22.04", "curl",
                         "7.81.0-6ubuntu1.4"), True)
        self.assertIs(fn(self.CURL_RECORD, "Ubuntu:22.04", "curl",
                         "7.81.0-6ubuntu1.5"), False)
        self.assertIs(fn(self.CURL_RECORD, "Ubuntu:20.04", "curl",
                         "7.81.0-6ubuntu1.4"), False)
        self.assertIs(fn(self.CURL_RECORD, "Ubuntu:22.04", "wget",
                         "7.81.0-6ubuntu1.4"), False)

    def test_explicit_versions_win(self):
        record = {"affected": [{
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "versions": ["2.28.0"],
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}]}],
        }]}
        fn = match.osv_record_matches_asset
        self.assertIs(fn(record, "PyPI", "requests", "2.28.0"), True)
        self.assertIs(fn(record, "PyPI", "requests", "2.31.0"), False)


class TestState(unittest.TestCase):
    def _finding(self, version="1.0"):
        return {"vuln_id": "CVE-TEST-1", "asset_key": "os:curl",
                "severity_rank": 3, "severity_detail": "x",
                "summary": "", "description": "", "references": []}

    def test_lifecycle(self):
        st = state.load_state(os.path.join(tempfile.gettempdir(),
                                           "vulncheck-no-such-state"),
                              [])
        asset = {"layer": "os", "ecosystem": "Ubuntu:22.04",
                 "name": "curl", "version": "1.0"}
        deltas = state.update_state(st, [asset], [])
        self.assertEqual(deltas["assets"]["os:curl"], "new")

        deltas = state.update_state(st, [asset], [self._finding()])
        self.assertEqual(deltas["findings"]["CVE-TEST-1|os:curl"], "new")

        deltas = state.update_state(st, [asset], [self._finding()])
        self.assertEqual(deltas["findings"]["CVE-TEST-1|os:curl"], "unchanged")

        deltas = state.update_state(st, [asset], [])
        self.assertEqual(deltas["findings"]["CVE-TEST-1|os:curl"], "resolved")

        asset2 = dict(asset, version="2.0")
        deltas = state.update_state(st, [asset2], [])
        self.assertEqual(deltas["assets"]["os:curl"], "version_changed")

        deltas = state.update_state(st, [], [])
        self.assertEqual(deltas["assets"]["os:curl"], "gone")
        # The finding was already resolved while the asset existed, so the
        # asset's disappearance must NOT re-report it as gone.
        self.assertNotIn("CVE-TEST-1|os:curl", deltas["findings"])

        deltas = state.update_state(st, [asset], [])
        self.assertEqual(deltas["assets"]["os:curl"], "reappeared")

        # A finding that is active when its asset vanishes becomes "gone".
        deltas = state.update_state(st, [asset], [self._finding()])
        self.assertEqual(deltas["findings"]["CVE-TEST-1|os:curl"], "reopened")
        deltas = state.update_state(st, [], [])
        self.assertEqual(deltas["assets"]["os:curl"], "gone")
        self.assertEqual(deltas["findings"]["CVE-TEST-1|os:curl"], "gone")

    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            st = state.load_state(path, [])
            asset = {"layer": "os", "ecosystem": "Ubuntu:22.04",
                     "name": "curl", "version": "1.0"}
            state.update_state(st, [asset], [self._finding()])
            state.save_state(path, st)
            loaded = state.load_state(path, [])
            self.assertIn("os:curl", loaded["assets"])
            self.assertIn("CVE-TEST-1|os:curl", loaded["findings"])


class TestInventoryHelpers(unittest.TestCase):
    def test_source_field(self):
        self.assertEqual(inventory.parse_source_field("openssl (1:1.2.3-4)"),
                         ("openssl", "1:1.2.3-4"))
        self.assertEqual(inventory.parse_source_field("curl"), ("curl", None))

    def test_ecosystem(self):
        self.assertEqual(
            inventory.osv_ecosystem_from_os_release(
                {"ID": "ubuntu", "VERSION_ID": "22.04"}),
            "Ubuntu:22.04")
        self.assertIsNone(inventory.osv_ecosystem_from_os_release(
            {"ID": "debian", "VERSION_ID": "11"}))

    def test_asset_key(self):
        self.assertEqual(inventory.asset_key(
            {"layer": "python", "name": "Flask_Cors", "version": "1"}),
            "python:flask-cors")
        self.assertEqual(inventory.asset_key(
            {"layer": "os", "name": "Curl", "version": "1"}), "os:curl")


if __name__ == "__main__":
    unittest.main(verbosity=2)
