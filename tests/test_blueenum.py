"""Unit tests for blueenum's pure helper logic.

These tests import the module (which is safe thanks to the __main__ guard) and
exercise the functions that do not shell out to nmap/nikto.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import blueenum  # noqa: E402


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="http" tunnel="ssl"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed"/>
        <service name="mysql"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class ExpandTargetsTests(unittest.TestCase):
    def test_single_host(self):
        self.assertEqual(blueenum.expand_targets("10.0.0.5"), ["10.0.0.5"])

    def test_small_block(self):
        # /30 has two usable hosts.
        self.assertEqual(
            blueenum.expand_targets("192.168.1.0/30"),
            ["192.168.1.1", "192.168.1.2"],
        )

    def test_invalid_and_empty(self):
        self.assertEqual(blueenum.expand_targets("not-an-ip"), [])
        self.assertEqual(blueenum.expand_targets(""), [])
        self.assertEqual(blueenum.expand_targets(None), [])


class MergeAddressesTests(unittest.TestCase):
    def test_drops_none_sentinel_and_dedupes(self):
        result = blueenum.merge_addresses([None], ["10.0.0.1", "10.0.0.1", "10.0.0.2"])
        self.assertEqual(result, ["10.0.0.1", "10.0.0.2"])

    def test_empty_returns_sentinel(self):
        self.assertEqual(blueenum.merge_addresses([None], []), [None])


class MatchIpFilesTests(unittest.TestCase):
    def test_boundary_is_respected(self):
        files = [
            "10.0.0.1.xml",
            "nikto_10.0.0.1_80.xml",
            "10.0.0.10.xml",       # must NOT match 10.0.0.1
            "10.0.0.100.xml",      # must NOT match 10.0.0.1
            "192.168.1.1.xml",
        ]
        matched = blueenum.match_ip_files("10.0.0.1", files)
        self.assertEqual(
            sorted(matched),
            sorted(["10.0.0.1.xml", "nikto_10.0.0.1_80.xml"]),
        )


class ReportTests(unittest.TestCase):
    def test_open_ports_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "10.0.0.1.xml"), "w") as handle:
                handle.write(SAMPLE_NMAP_XML)
            report = blueenum.build_report(["10.0.0.1"], output_dir=tmp)
        self.assertIn("22/tcp ssh", report)
        self.assertIn("80/tcp http", report)
        self.assertIn("443/tcp http", report)
        self.assertNotIn("mysql", report)  # closed port excluded

    def test_missing_scan_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = blueenum.build_report(["10.0.0.9"], output_dir=tmp)
        self.assertIn("(no scan data)", report)


class FollowUpWebTests(unittest.TestCase):
    def test_detects_http_and_https_ports(self):
        import xml.etree.ElementTree as ET

        root = ET.fromstring(SAMPLE_NMAP_XML)
        seen = []
        original = blueenum.niktoscan
        blueenum.niktoscan = lambda ip, port="80", use_ssl=False, output_dir=None: \
            seen.append((port, use_ssl))
        try:
            blueenum.follow_up_web(root, "10.0.0.1", output_dir=".")
        finally:
            blueenum.niktoscan = original
        self.assertIn(("80", False), seen)
        self.assertIn(("443", True), seen)
        # ssh (22) and closed mysql (3306) should not trigger nikto.
        self.assertEqual(len(seen), 2)


if __name__ == "__main__":
    unittest.main()
