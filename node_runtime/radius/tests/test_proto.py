from __future__ import annotations

import hmac
import ipaddress
import json
import os
import struct
import unittest

import rtest  # noqa: F401  (sys.path)
import proto

# RFC 2865 §7.1: "nemo" / "arctangent", shared secret "xyzzy5461"
RFC_REQ = bytes.fromhex(
    "01000038 0f403f9473978057bd83d5cb98f4227a 01066e656d6f 02120dbe708d93d413ce3196e43f782a0aee 0406c0a80110 050600000003".replace(
        " ", ""
    )
)
RFC_ACCEPT = bytes.fromhex(
    "02000026 86fe220e7624ba2a1005f6bf9b55e0b2 060600000001 0f0600000000 0e06c0a80103".replace(" ", "")
)
RFC_SECRET = b"xyzzy5461"
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class RfcVectors(unittest.TestCase):
    def test_rfc2865_access_request(self):
        r = proto.decode_request(RFC_REQ)
        self.assertEqual(r.code, proto.ACCESS_REQUEST)
        self.assertEqual(r.ident, 0)
        self.assertEqual(r.username, b"nemo")
        self.assertEqual(r.nas_port, 3)
        self.assertEqual(proto.decode_password(r.password_enc, RFC_SECRET, r.authenticator), b"arctangent")
        self.assertEqual(proto.encode_password(b"arctangent", RFC_SECRET, r.authenticator), r.password_enc)

    def test_rfc2865_response_authenticator(self):
        r = proto.decode_request(RFC_REQ)
        self.assertTrue(proto.verify_reply(RFC_ACCEPT, r.authenticator, RFC_SECRET))
        attrs = RFC_ACCEPT[20:]
        self.assertEqual(proto.encode_reply(proto.ACCESS_ACCEPT, 0, r.authenticator, attrs, RFC_SECRET), RFC_ACCEPT)
        self.assertFalse(proto.verify_reply(RFC_ACCEPT, r.authenticator, b"wrong"))


class ThreeProxyLayout(unittest.TestCase):
    def build(self, **kw):
        ra = os.urandom(16)
        args = dict(username=b"netrun-abcdefg-session-x1", password=b"Passw0rdPassw0rd", nas_port=31005, dst=rtest.DST6)
        args.update(kw)
        return proto.build_3proxy_request(9, ra, rtest.SECRET, **args), ra

    def test_attributes_of_a_socks_request(self):
        pkt, ra = self.build(hostname=b"example.com", dst_port=8443)
        r = proto.decode_request(pkt)
        self.assertEqual(r.ident, 9)
        self.assertEqual(r.authenticator, ra)
        self.assertEqual(r.username, b"netrun-abcdefg-session-x1")
        self.assertEqual(r.nas_port, 31005)
        self.assertEqual((r.dst_family, r.dst_addr, r.dst_port), (6, rtest.DST6, 8443))
        self.assertEqual(r.login_service, 1001)  # 2-byte value in a length-4 attribute
        self.assertEqual(r.called_station, b"example.com")
        self.assertEqual(r.nas_identifier, b"SOCKS")
        self.assertEqual(proto.decode_password(r.password_enc, rtest.SECRET, ra), b"Passw0rdPassw0rd")

    def test_non_rfc_length_4_attributes_are_accepted(self):
        pkt, _ = self.build()
        # Login-Service (15) and Login-TCP-Port (16) are length 4 in 3proxy 0.9.3
        self.assertIn(bytes((15, 4)), pkt)
        self.assertIn(bytes((16, 4)) + struct.pack("!H", 443), pkt)
        proto.decode_request(pkt)

    def test_ipv4_destination(self):
        pkt, _ = self.build(dst=rtest.DST4, dst_port=80)
        r = proto.decode_request(pkt)
        self.assertEqual((r.dst_family, r.dst_addr, r.dst_port), (4, rtest.DST4, 80))

    def test_no_destination_is_reported_as_none(self):
        pkt, _ = self.build(dst=None)
        r = proto.decode_request(pkt)
        self.assertEqual((r.dst_family, r.dst_addr), (0, None))
        pkt, _ = self.build(dst=bytes(16))
        self.assertEqual(proto.decode_request(pkt).dst_family, 0)

    def test_password_lengths(self):
        for n in (1, 15, 16, 17, 31, 32, 33, 100, 128):
            pw = (b"Ab3" * 50)[:n]
            pkt, ra = self.build(password=pw)
            r = proto.decode_request(pkt)
            self.assertEqual(len(r.password_enc) % 16, 0)
            self.assertEqual(proto.decode_password(r.password_enc, rtest.SECRET, ra), pw, n)

    def test_empty_password_attribute(self):
        # 3proxy sends User-Password with length 2 for an empty password
        pkt, ra = self.build(password=b"")
        r = proto.decode_request(pkt)
        self.assertEqual(r.password_enc, b"")
        self.assertEqual(proto.decode_password(r.password_enc, rtest.SECRET, ra), b"")

    def test_username_is_truncated_like_3proxy(self):
        pkt, _ = self.build(username=b"x" * 200)
        self.assertEqual(len(proto.decode_request(pkt).username), 128)

    def test_ipv6_nas_and_client(self):
        pkt, _ = self.build(nas_addr=bytes(15) + b"\x01", client_addr=bytes(15) + b"\x02")
        proto.decode_request(pkt)


class Malformed(unittest.TestCase):
    def good(self):
        return proto.build_3proxy_request(1, bytes(16), b"s", username=b"u", password=b"p", nas_port=1, dst=None)

    def test_short(self):
        with self.assertRaises(proto.ProtoError):
            proto.decode_request(b"\x01\x00\x00\x14")

    def test_length_beyond_datagram(self):
        p = bytearray(self.good())
        p[2:4] = struct.pack("!H", len(p) + 1)
        with self.assertRaises(proto.ProtoError):
            proto.decode_request(bytes(p))

    def test_trailing_padding_is_ignored(self):
        p = self.good()
        self.assertEqual(proto.decode_request(p + b"\0\0\0").username, b"u")

    def test_attribute_overflow(self):
        p = bytearray(self.good())
        p[21] = 250  # first attribute claims to run past the end
        with self.assertRaises(proto.ProtoError):
            proto.decode_request(bytes(p))

    def test_attribute_length_below_two(self):
        p = bytearray(self.good())
        p[21] = 1
        with self.assertRaises(proto.ProtoError):
            proto.decode_request(bytes(p))

    def test_bad_password_length(self):
        with self.assertRaises(proto.ProtoError):
            proto.decode_password(b"x" * 15, b"s", bytes(16))
        with self.assertRaises(proto.ProtoError):
            proto.decode_password(b"x" * 144, b"s", bytes(16))


class Replies(unittest.TestCase):
    def setUp(self):
        self.ra = os.urandom(16)
        self.pkt = proto.build_3proxy_request(
            33, self.ra, rtest.SECRET, username=b"u", password=b"p", nas_port=1, dst=None
        )
        self.req = proto.decode_request(self.pkt)

    def test_accept_v6_carries_exactly_one_framed_ipv6(self):
        a = ipaddress.IPv6Address("2001:db8:aa:1::5").packed
        out = proto.accept_v6(self.req, rtest.SECRET, a)
        self.assertEqual(out[:2], b"\x02\x21")
        self.assertEqual(struct.unpack("!H", out[2:4])[0], len(out))
        self.assertEqual(proto.reply_attrs(out), [(168, a)])
        self.assertTrue(proto.verify_reply(out, self.ra, rtest.SECRET))

    def test_accept_v4_carries_exactly_one_framed_ip(self):
        a = ipaddress.IPv4Address("192.0.2.10").packed
        out = proto.accept_v4(self.req, rtest.SECRET, a)
        self.assertEqual(proto.reply_attrs(out), [(8, a)])
        self.assertTrue(proto.verify_reply(out, self.ra, rtest.SECRET))

    def test_reject_has_no_attributes(self):
        out = proto.reject(self.req, rtest.SECRET)
        self.assertEqual(len(out), 20)
        self.assertEqual(out[0], proto.ACCESS_REJECT)
        self.assertTrue(proto.verify_reply(out, self.ra, rtest.SECRET))
        self.assertFalse(proto.verify_reply(out, bytes(16), rtest.SECRET))

    def test_message_authenticator(self):
        body = proto.attr(1, b"u") + bytes((80, 18)) + bytes(16)
        hdr = struct.pack("!BBH", 1, 1, 20 + len(body))
        ra = os.urandom(16)
        pkt = bytearray(hdr + ra + body)
        mac = hmac.new(b"s", bytes(pkt), "md5").digest()
        pkt[-16:] = mac
        r = proto.decode_request(bytes(pkt))
        self.assertTrue(proto.message_authenticator_ok(r, b"s"))
        self.assertFalse(proto.message_authenticator_ok(r, b"t"))
        self.assertTrue(proto.message_authenticator_ok(proto.decode_request(RFC_REQ), b"x"))


class CapturedPackets(unittest.TestCase):
    """Access-Requests captured from a real 3proxy 0.9.3 by scripts/test_pergb_radius_e2e.sh."""

    def test_captured(self):
        path = os.path.join(FIXTURES, "3proxy_captured.json")
        if not os.path.exists(path):
            self.skipTest("no captured packets")
        with open(path) as fh:
            cap = json.load(fh)
        secret = cap["secret"].encode()
        self.assertGreater(len(cap["packets"]), 0)
        for p in cap["packets"]:
            raw = bytes.fromhex(p["hex"])
            r = proto.decode_request(raw)
            self.assertEqual(r.code, proto.ACCESS_REQUEST)
            self.assertEqual(r.msg_auth_offset, -1)
            self.assertEqual(r.username.decode(), p["username"])
            self.assertEqual(proto.decode_password(r.password_enc, secret, r.authenticator).decode(), p["password"])
            self.assertEqual(r.nas_port, p["nasPort"])
            if p.get("dst"):
                self.assertEqual(str(ipaddress.ip_address(r.dst_addr)), p["dst"])
                self.assertEqual(r.dst_port, p["dstPort"])
            out = proto.accept_v6(r, secret, ipaddress.IPv6Address("2001:db8::1").packed)
            self.assertTrue(proto.verify_reply(out, r.authenticator, secret))


if __name__ == "__main__":
    unittest.main()
