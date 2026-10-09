"""Site key of a destination for smart rotation (amendment A12).

The site of a connection is the registrable domain (eTLD+1, punycode, lowercase,
no trailing dot) of its host name by the vendored Public Suffix List
(public_suffix_list.dat next to this file; ICANN and private sections, the
longest rule wins, an exception rule !x beats a wildcard *.y, the default rule
is *). Without a host name (an IP literal, empty, "-", or a public suffix
itself) the key is the destination network: "v4:a.b.c.0/24" or
"v6:<the /48, RFC 5952>/48".

The node agent computes the same key from the 3proxy log (pergb_psl.js); both
sides are checked against tests/psl_vectors.json. stdlib only.
"""

from __future__ import annotations

import ipaddress
import os

DEFAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public_suffix_list.dat")


def to_ascii(name) -> str:
    """Lowercase punycode form of a host name ('' when it cannot be converted)."""
    if isinstance(name, (bytes, bytearray)):
        try:
            name = bytes(name).decode("utf-8")
        except UnicodeDecodeError:
            return ""
    s = str(name or "").strip().lower()
    if s.endswith("."):
        s = s[:-1]
    if not s:
        return ""
    if s.isascii():
        return s
    try:
        return s.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return ""


class Psl:
    __slots__ = ("rules", "wild", "exc", "size")

    def __init__(self, text: str = ""):
        self.rules = set()
        self.wild = set()
        self.exc = set()
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            tok = line.split()[0]
            if tok.startswith("!"):
                n = to_ascii(tok[1:])
                if n:
                    self.exc.add(n)
            elif tok.startswith("*."):
                n = to_ascii(tok[2:])
                if n:
                    self.wild.add(n)
            else:
                n = to_ascii(tok)
                if n:
                    self.rules.add(n)
        self.size = len(self.rules) + len(self.wild) + len(self.exc)

    @classmethod
    def load(cls, path: str = DEFAULT_FILE) -> Psl:
        try:
            with open(path, encoding="utf-8") as fh:
                return cls(fh.read())
        except OSError:
            return cls("")

    def registrable(self, host) -> str | None:
        """The eTLD+1 of host, or None (IP literal, empty, invalid, a public suffix)."""
        if isinstance(host, (bytes, bytearray)):
            try:
                host = bytes(host).decode("utf-8")
            except UnicodeDecodeError:
                return None
        h = str(host or "").strip()
        if h.startswith("[") and h.endswith("]"):
            h = h[1:-1]
        if not h or h == "-" or _is_ip(h):
            return None
        a = to_ascii(h)
        if not a or len(a) > 253:
            return None
        labels = a.split(".")
        if any(not lab or len(lab) > 63 for lab in labels):
            return None
        n = len(labels)
        suffix = 1  # the default rule "*"
        for i in range(n):
            cand = ".".join(labels[i:])
            if cand in self.exc:
                suffix = n - i - 1
                break
            if cand in self.rules:
                suffix = n - i
                break
            if i + 1 < n and ".".join(labels[i + 1 :]) in self.wild:
                suffix = n - i
                break
        if n <= suffix:
            return None
        return ".".join(labels[n - suffix - 1 :])


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def address_site(ip) -> str | None:
    """The destination /24 (IPv4) or /48 (IPv6) as a site key; ip is text or packed bytes."""
    try:
        if isinstance(ip, (bytes, bytearray)):
            a = ipaddress.ip_address(bytes(ip))
        else:
            a = ipaddress.ip_address(str(ip or "").strip().strip("[]"))
    except ValueError:
        return None
    if a.version == 4:
        if int(a) == 0:
            return None
        o = str(a).split(".")
        return "v4:%s.%s.%s.0/24" % (o[0], o[1], o[2])
    if int(a) == 0:
        return None
    return "v6:%s/48" % ipaddress.IPv6Address((int(a) >> 80) << 80)


def site_key(host, dst, psl: Psl) -> str | None:
    """eTLD+1 of the host name, else the destination network (else an IP-literal host's network)."""
    r = psl.registrable(host)
    if r:
        return r
    r = address_site(dst) if dst else None
    if r:
        return r
    if isinstance(host, (bytes, bytearray)):
        try:
            host = bytes(host).decode("utf-8")
        except UnicodeDecodeError:
            return None
    h = str(host or "").strip().strip("[]")
    return address_site(h) if h and _is_ip(h) else None
