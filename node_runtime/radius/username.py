"""Per-GB username grammar (frozen interface I1).

    netrun-<id>[-session-<s>][-ttl-<N>(s|m|h)][-static][-rotate][-country-<cc>]

- lowercased before parsing; the whole name must be < 120 bytes;
- <id> = [a-z0-9]{5,12}; ids starting with "svc" are reserved
  ("netrun-svcprobe" is the service probe);
- params in any order, each at most once:
  session-[a-z0-9_]{1,32} | ttl-<N>(s|m|h) with 60 <= seconds <= 86400 |
  static | rotate | country-[a-z]{2} (must equal the node's geo);
- refused combinations: rotate+session, rotate+ttl, rotate+static, static+ttl.

Errors: bad_login (the base login itself is unusable) or bad_params.
"""

from __future__ import annotations

import re

PROBE_LOGIN = "netrun-svcprobe"
MAX_BYTES = 120  # the name must be shorter than this (3proxy truncates at 128)
DEFAULT_STICKY_TTL = 600
TTL_MIN = 60
TTL_MAX = 86400

_ID_RE = re.compile(r"[a-z0-9]{5,12}\Z")
_SESSION_RE = re.compile(r"[a-z0-9_]{1,32}\Z")
_TTL_RE = re.compile(r"([0-9]{1,6})([smh])\Z")
_CC_RE = re.compile(r"[a-z]{2}\Z")
_MULT = {"s": 1, "m": 60, "h": 3600}


class LoginError(Exception):
    def __init__(self, reason: str, base: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.base = base  # the base login when it parsed, for per-list reject records


class Login:
    __slots__ = ("base", "login_id", "session", "ttl", "static", "rotate", "country", "probe")

    def __init__(self, base: str, login_id: str):
        self.base = base
        self.login_id = login_id
        self.session = None
        self.ttl = None
        self.static = False
        self.rotate = False
        self.country = None
        self.probe = base == PROBE_LOGIN

    def __repr__(self):
        return (
            f"Login({self.base!r}, session={self.session!r}, ttl={self.ttl!r}, "
            f"static={self.static}, rotate={self.rotate}, country={self.country!r})"
        )


def parse(raw, geo: str | None = None) -> Login:
    """Parse a username (bytes or str). Raises LoginError(reason, base)."""
    if isinstance(raw, (bytes, bytearray)):
        try:
            name = bytes(raw).decode("ascii")
        except UnicodeDecodeError:
            raise LoginError("bad_login") from None
    else:
        name = raw
        try:
            name.encode("ascii")
        except UnicodeEncodeError:
            raise LoginError("bad_login") from None
    name = name.lower()
    tokens = name.split("-")
    if len(tokens) < 2 or tokens[0] != "netrun" or not _ID_RE.match(tokens[1]):
        raise LoginError("bad_login")
    login_id = tokens[1]
    base = "netrun-" + login_id
    if login_id.startswith("svc") and base != PROBE_LOGIN:
        raise LoginError("bad_login")
    if len(name) >= MAX_BYTES:
        raise LoginError("bad_params", base)
    out = Login(base, login_id)
    if out.probe and len(tokens) > 2:
        raise LoginError("bad_params", base)
    seen = set()
    i, n = 2, len(tokens)
    while i < n:
        key = tokens[i]
        if key in seen:
            raise LoginError("bad_params", base)
        seen.add(key)
        if key == "static":
            out.static = True
            i += 1
        elif key == "rotate":
            out.rotate = True
            i += 1
        elif key in ("session", "ttl", "country"):
            if i + 1 >= n:
                raise LoginError("bad_params", base)
            val = tokens[i + 1]
            if key == "session":
                if not _SESSION_RE.match(val):
                    raise LoginError("bad_params", base)
                out.session = val
            elif key == "ttl":
                m = _TTL_RE.match(val)
                if not m:
                    raise LoginError("bad_params", base)
                sec = int(m.group(1)) * _MULT[m.group(2)]
                if not TTL_MIN <= sec <= TTL_MAX:
                    raise LoginError("bad_params", base)
                out.ttl = sec
            else:
                if not _CC_RE.match(val):
                    raise LoginError("bad_params", base)
                if not geo or val != geo.lower():
                    raise LoginError("bad_params", base)
                out.country = val
            i += 2
        else:
            raise LoginError("bad_params", base)
    if out.rotate and (out.session is not None or out.ttl is not None or out.static):
        raise LoginError("bad_params", base)
    if out.static and out.ttl is not None:
        raise LoginError("bad_params", base)
    return out


def resolve(login: Login, port: int, base_port: int, list_mode: str, list_ttl: int | None):
    """Mode and slot per the I1 table: returns (mode, ttl_sec, slot).

    mode: "rotate" (ttl 0, slot None), "sticky" (ttl > 0) or "static" (ttl None).
    Slot: "s:<session>" when a session is given, else "p<port - base>".
    """
    if login.rotate:
        return "rotate", 0, None
    slot = ("s:" + login.session) if login.session is not None else "p%d" % (port - base_port)
    if login.static:
        return "static", None, slot
    if login.ttl is not None:
        return "sticky", login.ttl, slot
    if login.session is not None:
        if list_mode == "static":
            return "static", None, slot
        ttl = list_ttl if (list_mode == "sticky" and list_ttl) else DEFAULT_STICKY_TTL
        return "sticky", ttl, slot
    if port == base_port:
        return "rotate", 0, None
    if list_mode == "static":
        return "static", None, slot
    if list_mode == "sticky":
        return "sticky", list_ttl or DEFAULT_STICKY_TTL, slot
    return "rotate", 0, None


def format_ttl(sec: int) -> str:
    """Canonical ttl token (I2): <h>h, else <m>m, else <s>s."""
    if sec % 3600 == 0:
        return "%dh" % (sec // 3600)
    if sec % 60 == 0:
        return "%dm" % (sec // 60)
    return "%ds" % sec
