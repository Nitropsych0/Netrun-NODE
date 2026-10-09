"""Per-GB username grammar (frozen interface I1, with amendment A10).

    netrun-<id>[-session-<s>][-ttl-<N>(s|m|h)][-static][-rotate][-country-<cc>]

- lowercased before parsing; the whole name must be < 120 bytes;
- <id> = [a-z0-9]{5,12}; ids starting with "svc" are reserved
  ("netrun-svcprobe" is the service probe);
- params in any order, each at most once:
  session-[a-z0-9_]{1,32} | ttl-<N>(s|m|h) with 30 <= seconds <= 86400 (A10) |
  static | rotate | country-[a-z]{2} (must equal the node's geo);
- refused combinations: rotate+session, rotate+ttl, rotate+static, static+ttl.

Errors: bad_login (the base login itself is unusable) or bad_params.

Mode resolution (A10: every port is a line slot that follows the list's
«Смена IP» mode; the base port no longer means rotation), first match wins:
  1. rotate                       -> a fresh address for this connection;
  2. static                       -> the slot's static address;
  3. a session that is not a line slot (anything but s<5 digits>)
                                  -> a sticky session for ttl (default 600 s),
                                     whatever the list's mode;
  4. otherwise the slot (p<port - base>, or s:sNNNNN for lines 1000+) follows
     the list mode: per_request -> per_request (ttl given: sticky for ttl);
     timer -> timer windows of ttl (the param) or the list ttl; link -> link
     (ttl given: sticky); static -> static (ttl given: sticky).
The legacy list modes map: rotate -> per_request, sticky -> timer.

A per-piece login (A13-I, a list of kind "piece") takes only -country-<cc>:
-session, -ttl, -static and -rotate are bad_params for it (piece_params_ok);
its address is fixed, whatever the port.
"""

from __future__ import annotations

import re

PROBE_LOGIN = "netrun-svcprobe"
MAX_BYTES = 120  # the name must be shorter than this (3proxy truncates at 128)
DEFAULT_STICKY_TTL = 600
TTL_MIN = 30  # A10: custom TTL 30 s .. 24 h
TTL_MAX = 86400

_ID_RE = re.compile(r"[a-z0-9]{5,12}\Z")
_SESSION_RE = re.compile(r"[a-z0-9_]{1,32}\Z")
_TTL_RE = re.compile(r"([0-9]{1,6})([smh])\Z")
_CC_RE = re.compile(r"[a-z]{2}\Z")
_LINE_SESSION_RE = re.compile(r"s[0-9]{5}\Z")  # I2: the slot of line 1000+ (s01000 .. s10000)
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


# list modes after A10 (the legacy names map onto them)
PER_REQUEST = "per_request"
TIMER = "timer"
LINK = "link"
STATIC = "static"
LIST_MODES = (PER_REQUEST, TIMER, LINK, STATIC)
LEGACY_MODES = {"rotate": PER_REQUEST, "sticky": TIMER}

# resolved per-connection modes
FRESH = "fresh"  # a new random address for this one connection (the rotate param)
STICKY = "sticky"  # a remembered address for ttl from its first connection


def list_mode(mode: str) -> str:
    """Normalise a list mode (legacy rotate/sticky accepted)."""
    m = LEGACY_MODES.get(mode, mode)
    if m not in LIST_MODES:
        raise ValueError("unknown list mode %r" % mode)
    return m


def piece_params_ok(login: Login) -> bool:
    """A13-I: a per-piece login may carry -country-<cc> only."""
    return login.session is None and login.ttl is None and not login.static and not login.rotate


def is_line_session(session: str | None) -> bool:
    return session is not None and _LINE_SESSION_RE.match(session) is not None


def resolve(login: Login, port: int, base_port: int, mode: str, list_ttl: int | None):
    """Per-connection mode and slot (see the module doc): returns (mode, ttl_sec, slot).

    mode: fresh (slot None), per_request, timer (ttl = the window), link, static or
    sticky (ttl = the session TTL). Slot: "s:<session>" when a session is given,
    else "p<port - base>" (the base port is slot p0).
    """
    if login.rotate:
        return FRESH, 0, None
    mode = LEGACY_MODES.get(mode, mode)
    slot = ("s:" + login.session) if login.session is not None else "p%d" % (port - base_port)
    if login.static:
        return STATIC, None, slot
    if login.session is not None and not is_line_session(login.session):
        return STICKY, login.ttl or DEFAULT_STICKY_TTL, slot
    if mode == TIMER:
        return TIMER, login.ttl or list_ttl or DEFAULT_STICKY_TTL, slot
    if login.ttl is not None:
        return STICKY, login.ttl, slot
    if mode == STATIC:
        return STATIC, None, slot
    if mode == LINK:
        return LINK, None, slot
    return PER_REQUEST, None, slot


def format_ttl(sec: int) -> str:
    """Canonical ttl token (I2): <h>h, else <m>m, else <s>s."""
    if sec % 3600 == 0:
        return "%dh" % (sec // 3600)
    if sec % 60 == 0:
        return "%dm" % (sec // 60)
    return "%ds" % sec
