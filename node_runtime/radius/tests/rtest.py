"""Shared helpers for the netrun-radius tests (run with python3 -I -m unittest discover)."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import random
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
RADIUS_DIR = os.path.dirname(HERE)
if RADIUS_DIR not in sys.path:
    sys.path.insert(0, RADIUS_DIR)

import engine  # noqa: E402
import proto  # noqa: E402
import state  # noqa: E402

SECRET = b"T3stSecretT3stSecretT3stSecretT3stSecre1"  # 40 chars like the real one
PREFIX = "2001:db8:aa::/48"
PREFIX_INT = int(ipaddress.IPv6Network(PREFIX).network_address)
KEY = bytes(range(32))
BASE = 31000
COUNT = 1000
DST6 = ipaddress.IPv6Address("2001:db8:ffff::1").packed
DST4 = ipaddress.IPv4Address("198.51.100.7").packed
EGRESS4 = "192.0.2.10"


class FakeClock:
    def __init__(self, t: float = 1_800_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float):
        self.t += dt


def tmpdir(case) -> str:
    d = tempfile.mkdtemp(prefix="nr-")
    case.addCleanup(shutil.rmtree, d, True)
    return d


def facts(**over) -> dict:
    f = {
        "base": BASE,
        "count": COUNT,
        "geo": "us",
        "family": "dualstack",
        "egressIpv4": EGRESS4,
        "prefix": PREFIX,
        "subnets": [0, 0xFFFE],
        "addrKey": base64.b64encode(KEY).decode(),
        "reserves": {"staticPct": 5, "stickyPct": 15},
        "logdumpBytes": 262144,
    }
    f.update(over)
    return f


def pw_fields(password: str, salt: bytes | None = None) -> dict:
    salt = salt if salt is not None else os.urandom(16)
    return {"pwSalt": salt.hex(), "pwHash": hashlib.sha256(salt + password.encode()).hexdigest()}


def account(aid: int, **over) -> dict:
    a = {
        "id": aid,
        "state": "active",
        "expiresAt": 4_000_000_000,
        "limit": {"epoch": 1, "bytes": 10 << 30, "allowance": 10 << 30, "full": True},
        "staticCap": 100,
        "stickyExclCap": 2000,
        "trial": False,
    }
    a.update(over)
    return a


def plist(lid: int, login_id: str, aid: int, password: str = "Passw0rdPassw0rd", **over) -> dict:
    d = {
        "id": lid,
        "login": "netrun-" + login_id,
        "accountId": aid,
        "pwRev": 1,
        "status": "active",
        "mode": "rotate",
        "ttlSec": None,
    }
    d.update(pw_fields(password))
    d.update(over)
    return d


def make_engine(case, clock=None, seed=1, path=None, secret=SECRET, env=None, with_facts=True, **fact_over):
    d = path or tmpdir(case)
    st = state.Store(os.path.join(d, "radius.db"))
    eng = engine.Engine(st, secret=secret, clock=clock or FakeClock(), rng=random.Random(seed), env=env or {})
    eng.load()
    case.addCleanup(st.close)
    if with_facts:
        r = eng.dispatch({"op": "facts", "facts": facts(**fact_over)})
        case.assertEqual(r, {"ok": True})
    eng._test_dir = d
    return eng


def request(
    user: str,
    password: str = "Passw0rdPassw0rd",
    port: int = BASE,
    dst: bytes | None = DST6,
    dst_port: int = 443,
    secret: bytes = SECRET,
    ident: int = 7,
):
    ra = os.urandom(16)
    pkt = proto.build_3proxy_request(
        ident,
        ra,
        secret,
        username=user.encode(),
        password=password.encode(),
        nas_port=port,
        dst=dst,
        dst_port=dst_port,
    )
    return pkt, ra


class Reply:
    def __init__(self, raw: bytes, ra: bytes, secret: bytes = SECRET):
        self.raw = raw
        self.valid = raw is not None and proto.verify_reply(raw, ra, secret)
        self.code = raw[0] if raw else None
        self.attrs = proto.reply_attrs(raw) if raw else []

    @property
    def accepted(self) -> bool:
        return self.code == proto.ACCESS_ACCEPT

    @property
    def addr(self):
        for t, v in self.attrs:
            if t in (proto.A_FRAMED_IPV6_ADDRESS, proto.A_FRAMED_IP_ADDRESS):
                return ipaddress.ip_address(v)
        return None

    @property
    def net(self):
        a = self.addr
        return (int(a) >> 64) & 0xFFFF if a is not None and a.version == 6 else None


def ask(eng, user, password="Passw0rdPassw0rd", port=BASE, dst=DST6, dst_port=443, secret=SECRET) -> Reply:
    pkt, ra = request(user, password, port, dst, dst_port, secret)
    return Reply(eng.handle(pkt), ra, secret)
