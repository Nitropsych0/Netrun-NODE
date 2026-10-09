from __future__ import annotations

import unittest

import rtest  # noqa: F401  (sys.path)
import username as U

BASE = 31000


def p(name, geo="us"):
    return U.parse(name, geo)


class Grammar(unittest.TestCase):
    def test_valid(self):
        cases = {
            "netrun-7k2f9ab": dict(session=None, ttl=None, static=False, rotate=False),
            "NETRUN-7K2F9AB": dict(session=None),
            "netrun-7k2f9ab-session-job1-ttl-30m": dict(session="job1", ttl=1800),
            "netrun-7k2f9ab-ttl-30m-session-job1": dict(session="job1", ttl=1800),
            "netrun-7k2f9ab-static": dict(static=True),
            "netrun-7k2f9ab-rotate": dict(rotate=True),
            "netrun-7k2f9ab-session-a_b-static": dict(session="a_b", static=True),
            "netrun-7k2f9ab-country-us-rotate": dict(country="us", rotate=True),
            "netrun-7k2f9ab-ttl-60s": dict(ttl=60),
            "netrun-7k2f9ab-ttl-1440m": dict(ttl=86400),
            "netrun-7k2f9ab-ttl-24h": dict(ttl=86400),
            "netrun-abcde": dict(),
            "netrun-abcdefghijkl": dict(),
            "netrun-7k2f9ab-session-" + "s" * 32: dict(session="s" * 32),
            "netrun-7k2f9ab-session-static": dict(session="static"),
        }
        for name, want in cases.items():
            got = p(name)
            self.assertEqual(got.base, name.lower().split("-")[0] + "-" + name.lower().split("-")[1], name)
            for k, v in want.items():
                self.assertEqual(getattr(got, k), v, (name, k))

    def test_bytes_input(self):
        self.assertEqual(p(b"netrun-7k2f9ab-static").static, True)

    def test_bad_login(self):
        for name in [
            "",
            "netrun",
            "netrun-",
            "netrun-abcd",  # id too short
            "netrun-abcdefghijklm",  # id too long
            "proxy-7k2f9ab",
            "netrun_7k2f9ab",
            "netrun-7k2f9a!",
            "netrun-svcabcd",  # reserved prefix
            "netrun-7k2f9ab\xe9",
            b"netrun-7k2f\xff9ab",
        ]:
            with self.assertRaises(U.LoginError, msg=repr(name)) as cm:
                p(name)
            self.assertEqual(cm.exception.reason, "bad_login", name)

    def test_bad_params(self):
        for name in [
            "netrun-7k2f9ab-",
            "netrun-7k2f9ab--static",
            "netrun-7k2f9ab-foo",
            "netrun-7k2f9ab-session",
            "netrun-7k2f9ab-session-",
            "netrun-7k2f9ab-session-" + "s" * 33,
            "netrun-7k2f9ab-session-a.b",
            "netrun-7k2f9ab-static-static",
            "netrun-7k2f9ab-session-a-session-b",
            "netrun-7k2f9ab-ttl-59s",
            "netrun-7k2f9ab-ttl-86401s",
            "netrun-7k2f9ab-ttl-25h",
            "netrun-7k2f9ab-ttl-0m",
            "netrun-7k2f9ab-ttl-10",
            "netrun-7k2f9ab-ttl-10d",
            "netrun-7k2f9ab-ttl-9999999s",
            "netrun-7k2f9ab-rotate-session-x",
            "netrun-7k2f9ab-rotate-ttl-1h",
            "netrun-7k2f9ab-rotate-static",
            "netrun-7k2f9ab-static-ttl-1h",
            "netrun-7k2f9ab-country-de",
            "netrun-7k2f9ab-country-usa",
            "netrun-7k2f9ab-country-u1",
            "netrun-7k2f9ab-session-" + "a" * 32 + "-ttl-30m-country-us-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ]:
            with self.assertRaises(U.LoginError, msg=name) as cm:
                p(name)
            self.assertEqual(cm.exception.reason, "bad_params", name)
            self.assertEqual(cm.exception.base, "netrun-7k2f9ab", name)

    def test_length_limit(self):
        ok = "netrun-7k2f9ab-session-" + "a" * 32 + "-ttl-30m-country-us"
        self.assertLess(len(ok), U.MAX_BYTES)
        p(ok)
        name = "netrun-abcdefghijkl-session-" + "a" * 32 + "-ttl-86400s-country-us-static"
        self.assertLess(len(name), U.MAX_BYTES)
        with self.assertRaises(U.LoginError):
            p(name)  # static+ttl
        long_name = ("netrun-7k2f9ab-session-" + "a" * 32).ljust(U.MAX_BYTES, "x")
        with self.assertRaises(U.LoginError) as cm:
            p(long_name)
        self.assertEqual(cm.exception.reason, "bad_params")

    def test_country_without_node_geo(self):
        with self.assertRaises(U.LoginError):
            U.parse("netrun-7k2f9ab-country-us", None)
        self.assertEqual(U.parse("netrun-7k2f9ab-country-us", "US").country, "us")

    def test_probe(self):
        self.assertTrue(p("netrun-svcprobe").probe)
        self.assertFalse(p("netrun-7k2f9ab").probe)
        with self.assertRaises(U.LoginError) as cm:
            p("netrun-svcproba1")
        self.assertEqual(cm.exception.reason, "bad_login")
        with self.assertRaises(U.LoginError) as cm:
            p("netrun-svcprobe-rotate")
        self.assertEqual(cm.exception.reason, "bad_params")


class ModeTable(unittest.TestCase):
    """I1 mode resolution, first match wins."""

    def r(self, name, port, mode, ttl=None):
        return U.resolve(p(name), port, BASE, mode, ttl)

    def test_explicit_params_win_everywhere(self):
        for list_mode, list_ttl in (("rotate", None), ("sticky", 1800), ("static", None)):
            for port in (BASE, BASE + 1, BASE + 999):
                self.assertEqual(self.r("netrun-7k2f9ab-rotate", port, list_mode, list_ttl), ("rotate", 0, None))
                self.assertEqual(
                    self.r("netrun-7k2f9ab-static", port, list_mode, list_ttl), ("static", None, "p%d" % (port - BASE))
                )
                self.assertEqual(
                    self.r("netrun-7k2f9ab-ttl-2h", port, list_mode, list_ttl), ("sticky", 7200, "p%d" % (port - BASE))
                )
                self.assertEqual(
                    self.r("netrun-7k2f9ab-session-q-ttl-5m", port, list_mode, list_ttl), ("sticky", 300, "s:q")
                )
                self.assertEqual(
                    self.r("netrun-7k2f9ab-session-q-static", port, list_mode, list_ttl), ("static", None, "s:q")
                )

    def test_base_port_static_param_is_slot_p0(self):
        self.assertEqual(self.r("netrun-7k2f9ab-static", BASE, "rotate"), ("static", None, "p0"))

    def test_session_alone_follows_the_list(self):
        self.assertEqual(self.r("netrun-7k2f9ab-session-s00042", BASE, "static"), ("static", None, "s:s00042"))
        self.assertEqual(self.r("netrun-7k2f9ab-session-s00042", BASE, "sticky", 1800), ("sticky", 1800, "s:s00042"))
        self.assertEqual(self.r("netrun-7k2f9ab-session-s00042", BASE + 3, "rotate"), ("sticky", 600, "s:s00042"))

    def test_bare_login_rotates_on_the_base_port(self):
        for list_mode, ttl in (("rotate", None), ("sticky", 1800), ("static", None)):
            self.assertEqual(self.r("netrun-7k2f9ab", BASE, list_mode, ttl), ("rotate", 0, None))

    def test_bare_login_follows_the_list_mode_elsewhere(self):
        self.assertEqual(self.r("netrun-7k2f9ab", BASE + 7, "rotate"), ("rotate", 0, None))
        self.assertEqual(self.r("netrun-7k2f9ab", BASE + 7, "sticky", 1800), ("sticky", 1800, "p7"))
        self.assertEqual(self.r("netrun-7k2f9ab", BASE + 7, "sticky", None), ("sticky", 600, "p7"))
        self.assertEqual(self.r("netrun-7k2f9ab", BASE + 999, "static"), ("static", None, "p999"))

    def test_country_does_not_change_the_mode(self):
        self.assertEqual(self.r("netrun-7k2f9ab-country-us", BASE + 2, "static"), ("static", None, "p2"))

    def test_format_ttl(self):
        self.assertEqual(U.format_ttl(3600), "1h")
        self.assertEqual(U.format_ttl(86400), "24h")
        self.assertEqual(U.format_ttl(1800), "30m")
        self.assertEqual(U.format_ttl(90), "90s")
        for sec in (60, 61, 90, 600, 3599, 3600, 5400, 86400):
            self.assertEqual(p("netrun-7k2f9ab-ttl-" + U.format_ttl(sec)).ttl, sec)


if __name__ == "__main__":
    unittest.main()
