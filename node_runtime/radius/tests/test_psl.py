"""A12 site key: the Python matcher agrees with the agent's (shared vectors)."""

from __future__ import annotations

import json
import os
import unittest

import rtest  # noqa: F401  (sys.path)

import psl

HERE = os.path.dirname(os.path.abspath(__file__))


class SiteKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.psl = psl.Psl.load()

    def test_vendored_list_loads(self):
        self.assertGreater(self.psl.size, 5000)

    def test_shared_vectors(self):
        with open(os.path.join(HERE, "psl_vectors.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["format"], "netrun-pergb-psl-v1")
        for v in data["vectors"]:
            self.assertEqual(psl.site_key(v.get("host"), v.get("dst"), self.psl), v["site"], v)

    def test_bytes_and_packed_inputs(self):
        import ipaddress

        dst = ipaddress.IPv6Address("2606:4700:10::6814:1").packed
        self.assertEqual(psl.site_key(b"www.example.co.uk", dst, self.psl), "example.co.uk")
        self.assertEqual(psl.site_key(None, dst, self.psl), "v6:2606:4700:10::/48")
        self.assertEqual(psl.site_key(b"\xff\xfe", dst, self.psl), "v6:2606:4700:10::/48")
        self.assertIsNone(psl.site_key(None, None, self.psl))
        self.assertEqual(psl.site_key("1.2.3.4", None, self.psl), "v4:1.2.3.0/24")

    def test_missing_list_still_works(self):
        p = psl.Psl.load("/nonexistent/psl.dat")
        self.assertEqual(p.size, 0)
        self.assertEqual(psl.site_key("a.b.example.com", None, p), "example.com")  # the default rule *


if __name__ == "__main__":
    unittest.main()
