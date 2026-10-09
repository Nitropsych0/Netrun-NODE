from __future__ import annotations

import base64
import ipaddress
import json
import os
import random
import unittest

import rtest  # noqa: F401  (sys.path)
import gen_feistel_vectors as ref
import tag

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feistel_vectors.json")


class SharedVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VECTORS) as fh:
            cls.data = json.load(fh)

    def test_fixture_is_current(self):
        self.assertEqual(self.data, json.loads(json.dumps(ref.build())), "regenerate with gen_feistel_vectors.py")

    def test_encrypt_matches_vectors(self):
        for v in self.data["vectors"]:
            k = base64.b64decode(v["keyB64"])
            self.assertEqual(tag.mac16(k, v["listId"], v["r16"]), v["mac16"])
            iid = tag.encrypt(k, v["listId"], v["r16"])
            self.assertEqual("%016x" % iid, v["iid"])
            self.assertEqual(iid >= tag.IID_MIN, v["iidAccepted"])
            self.assertEqual(tag.decrypt(k, iid), (v["listId"], v["r16"], True))

    def test_addresses(self):
        for a in self.data["addresses"]:
            k = base64.b64decode(a["keyB64"])
            net = ipaddress.IPv6Network(a["prefix"])
            iid = tag.encrypt(k, a["listId"], a["r16"])
            addr = int(net.network_address) | (a["subnet"] << 64) | iid
            self.assertEqual(str(ipaddress.IPv6Address(addr)), a["addr"])
            self.assertEqual(
                tag.Tagger(k).list_of(int(ipaddress.IPv6Address(a["addr"])) & ((1 << 64) - 1)), a["listId"]
            )

    def test_invalid(self):
        for v in self.data["invalid"]:
            k = base64.b64decode(v["keyB64"])
            lid, r16, ok = tag.decrypt(k, int(v["iid"], 16))
            self.assertEqual((lid, r16, ok), (v["listId"], v["r16"], False))


class Properties(unittest.TestCase):
    def test_round_trip_and_host_floor(self):
        rng = random.Random(5)
        t = tag.Tagger(os.urandom(32))
        for _ in range(2000):
            lid = rng.getrandbits(32)
            iid = t.make_iid(lid, rng.getrandbits)
            self.assertGreaterEqual(iid, 1 << 32)
            self.assertLess(iid, 1 << 64)
            got, _r16, ok = t.decode(iid)
            self.assertTrue(ok)
            self.assertEqual(got, lid)

    def test_random_iids_fail_the_mac(self):
        rng = random.Random(6)
        k = os.urandom(32)
        n = 20000
        passed = sum(tag.decrypt(k, rng.getrandbits(64))[2] for _ in range(n))
        # 2^-16 per guess: ~0.3 expected in 20k; 5 would be ~1e-5 likely
        self.assertLess(passed, 5)

    def test_wrong_key_fails_the_mac(self):
        rng = random.Random(7)
        k1, k2 = os.urandom(32), os.urandom(32)
        iids = [tag.Tagger(k1).make_iid(42, rng.getrandbits) for _ in range(500)]
        self.assertLess(sum(tag.decrypt(k2, i)[2] for i in iids), 3)

    def test_redraw_below_2_32(self):
        calls = []

        def fake_randbits(n):
            calls.append(n)
            return len(calls) - 1

        t = tag.Tagger(bytes(32))
        orig = tag.encrypt
        try:
            tag.encrypt = lambda k, lid, r16: 5 if r16 == 0 else orig(k, lid, r16)
            iid = t.make_iid(1, fake_randbits)
        finally:
            tag.encrypt = orig
        self.assertGreaterEqual(iid, 1 << 32)
        self.assertEqual(len(calls), 2)

    def test_bad_inputs(self):
        with self.assertRaises(ValueError):
            tag.Tagger(b"short")
        with self.assertRaises(ValueError):
            tag.encrypt(bytes(32), 1 << 32, 0)
        with self.assertRaises(ValueError):
            tag.decrypt(bytes(32), 1 << 64)


if __name__ == "__main__":
    unittest.main()
