"""RADIUS codec (RFC 2865) for the Access-Requests of 3proxy 0.9.3.

What 3proxy sends (authradius.c radsend(), auth=1), in this order:
  Service-Type(6)=Authenticate-Only, Acct-Session-Id(44), NAS-Port-Type(61)=Virtual,
  NAS-Port(5) = the service's listen port, NAS-IP-Address(4) or NAS-IPv6-Address(95)
  (the accepting address), NAS-Identifier(32) (service name), Framed-IP-Address(8)
  or Framed-IPv6-Address(168) (the client), Called-Station-Id(30) (the requested
  host name, when there is one), Login-Service(15) and Login-TCP-Port(16) with a
  NON-RFC attribute length of 4 (2-byte values), Login-IP-Host(14) or
  Login-IPv6-Host(98) (the resolved destination), User-Name(1) (<= 128 bytes),
  User-Password(2) (PAP, <= 128 bytes, zero padded to 16).
No Message-Authenticator. The reply must carry a valid Response Authenticator;
3proxy reads Framed-IP-Address / Framed-IPv6-Address from an Accept and never
needs anything else from us.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3

A_USER_NAME = 1
A_USER_PASSWORD = 2
A_NAS_IP_ADDRESS = 4
A_NAS_PORT = 5
A_SERVICE_TYPE = 6
A_FRAMED_IP_ADDRESS = 8
A_LOGIN_IP_HOST = 14
A_LOGIN_SERVICE = 15
A_LOGIN_TCP_PORT = 16
A_REPLY_MESSAGE = 18
A_CALLED_STATION_ID = 30
A_NAS_IDENTIFIER = 32
A_ACCT_SESSION_ID = 44
A_NAS_PORT_TYPE = 61
A_MESSAGE_AUTHENTICATOR = 80
A_NAS_IPV6_ADDRESS = 95
A_LOGIN_IPV6_HOST = 98
A_FRAMED_IPV6_ADDRESS = 168

MAX_PACKET = 4096
MAX_PASSWORD = 128
_HDR = struct.Struct("!BBH")
_U32 = struct.Struct("!I")
_U16 = struct.Struct("!H")


class ProtoError(ValueError):
    """A packet that must be silently discarded (RFC 2865 §3)."""


def md5(data: bytes) -> bytes:
    return hashlib.md5(data, usedforsecurity=False).digest()


class Request:
    __slots__ = (
        "code",
        "ident",
        "authenticator",
        "username",
        "password_enc",
        "nas_port",
        "dst_family",
        "dst_addr",
        "dst_port",
        "login_service",
        "called_station",
        "nas_identifier",
        "session_id",
        "msg_auth_offset",
        "raw",
    )

    def __init__(self):
        self.code = 0
        self.ident = 0
        self.authenticator = b""
        self.username = None  # bytes | None
        self.password_enc = None  # bytes | None
        self.nas_port = None  # int | None
        self.dst_family = 0  # 4, 6 or 0 (none)
        self.dst_addr = None  # bytes (4 or 16) | None
        self.dst_port = None  # int | None
        self.login_service = None
        self.called_station = None
        self.nas_identifier = None
        self.session_id = None
        self.msg_auth_offset = -1
        self.raw = b""


def _uint(v: bytes) -> int | None:
    if len(v) == 4:
        return _U32.unpack(v)[0]
    if len(v) == 2:  # 3proxy's length-4 attributes carry a 16-bit value
        return _U16.unpack(v)[0]
    return None


def decode_request(data: bytes) -> Request:
    """Parse an Access-Request. Raises ProtoError for anything malformed."""
    n = len(data)
    if n < 20:
        raise ProtoError("short packet")
    code, ident, length = _HDR.unpack_from(data, 0)
    if length < 20 or length > n or length > MAX_PACKET:
        raise ProtoError("bad length")
    req = Request()
    req.code = code
    req.ident = ident
    req.authenticator = bytes(data[4:20])
    req.raw = bytes(data[:length])
    pos = 20
    seen = set()
    while pos < length:
        if pos + 2 > length:
            raise ProtoError("truncated attribute")
        t = data[pos]
        alen = data[pos + 1]
        if alen < 2 or pos + alen > length:
            raise ProtoError("bad attribute length")
        if t not in seen:  # the first occurrence wins
            seen.add(t)
            v = data[pos + 2 : pos + alen]
            if t == A_USER_NAME:
                req.username = bytes(v)
            elif t == A_USER_PASSWORD:
                req.password_enc = bytes(v)
            elif t == A_NAS_PORT:
                req.nas_port = _uint(v)
            elif t == A_LOGIN_IP_HOST:
                if len(v) == 4 and req.dst_family != 6:
                    req.dst_family, req.dst_addr = 4, bytes(v)
            elif t == A_LOGIN_IPV6_HOST:
                if len(v) == 16:
                    req.dst_family, req.dst_addr = 6, bytes(v)
            elif t == A_LOGIN_TCP_PORT:
                req.dst_port = _uint(v)
            elif t == A_LOGIN_SERVICE:
                req.login_service = _uint(v)
            elif t == A_CALLED_STATION_ID:
                req.called_station = bytes(v)
            elif t == A_NAS_IDENTIFIER:
                req.nas_identifier = bytes(v)
            elif t == A_ACCT_SESSION_ID:
                req.session_id = bytes(v)
            elif t == A_MESSAGE_AUTHENTICATOR:
                if alen != 18:
                    raise ProtoError("bad Message-Authenticator")
                req.msg_auth_offset = pos + 2
        pos += alen
    # 3proxy sends 0.0.0.0 / :: when it has no destination yet
    if req.dst_addr is not None and not any(req.dst_addr):
        req.dst_family, req.dst_addr = 0, None
    return req


def message_authenticator_ok(req: Request, secret: bytes) -> bool:
    """True when there is no Message-Authenticator or it verifies."""
    off = req.msg_auth_offset
    if off < 0:
        return True
    raw = req.raw
    zeroed = raw[:off] + b"\0" * 16 + raw[off + 16 :]
    want = hmac.new(secret, zeroed, "md5").digest()
    return hmac.compare_digest(want, raw[off : off + 16])


def decode_password(enc: bytes | None, secret: bytes, authenticator: bytes) -> bytes:
    """PAP User-Password (RFC 2865 §5.2). Trailing NUL padding is removed."""
    if not enc:
        return b""
    if len(enc) % 16 or len(enc) > MAX_PASSWORD:
        raise ProtoError("bad User-Password length")
    out = []
    last = authenticator
    for i in range(0, len(enc), 16):
        c = enc[i : i + 16]
        b = md5(secret + last)
        out.append((int.from_bytes(c, "big") ^ int.from_bytes(b, "big")).to_bytes(16, "big"))
        last = c
    return b"".join(out).rstrip(b"\0")


def encode_password(password: bytes, secret: bytes, authenticator: bytes) -> bytes:
    """PAP encoding (for clients and tests)."""
    password = password[:MAX_PASSWORD]
    if not password:
        return b""
    pad = (-len(password)) % 16
    p = password + b"\0" * pad
    out = []
    last = authenticator
    for i in range(0, len(p), 16):
        b = md5(secret + last)
        c = (int.from_bytes(p[i : i + 16], "big") ^ int.from_bytes(b, "big")).to_bytes(16, "big")
        out.append(c)
        last = c
    return b"".join(out)


def encode_reply(code: int, ident: int, req_auth: bytes, attrs: bytes, secret: bytes) -> bytes:
    hdr = _HDR.pack(code, ident, 20 + len(attrs))
    return hdr + md5(hdr + req_auth + attrs + secret) + attrs


def accept_v6(req: Request, secret: bytes, addr16: bytes) -> bytes:
    """Access-Accept with exactly one Framed-IPv6-Address (168)."""
    if len(addr16) != 16:
        raise ValueError("IPv6 address must be 16 bytes")
    return encode_reply(ACCESS_ACCEPT, req.ident, req.authenticator, b"\xa8\x12" + addr16, secret)


def accept_v4(req: Request, secret: bytes, addr4: bytes) -> bytes:
    """Access-Accept with exactly one Framed-IP-Address (8)."""
    if len(addr4) != 4:
        raise ValueError("IPv4 address must be 4 bytes")
    return encode_reply(ACCESS_ACCEPT, req.ident, req.authenticator, b"\x08\x06" + addr4, secret)


def reject(req: Request, secret: bytes) -> bytes:
    """Access-Reject without attributes (reasons are recorded, never signalled)."""
    return encode_reply(ACCESS_REJECT, req.ident, req.authenticator, b"", secret)


# ---- client side (tests, the e2e driver, operators) -------------------------------


def attr(t: int, value: bytes) -> bytes:
    if len(value) > 253:
        raise ValueError("attribute too long")
    return bytes((t, 2 + len(value))) + value


def build_3proxy_request(
    ident: int,
    authenticator: bytes,
    secret: bytes,
    *,
    username: bytes | None,
    password: bytes | None,
    nas_port: int,
    dst: bytes | None,
    dst_port: int = 443,
    nas_addr: bytes = b"\x7f\x00\x00\x04",
    client_addr: bytes = b"\x7f\x00\x00\x01",
    service: bytes = b"SOCKS",
    hostname: bytes | None = None,
    operation_bits: int = 1,
    session_id: bytes = b"1760000000.123.140000000000001",
) -> bytes:
    """An Access-Request laid out byte for byte like 3proxy 0.9.3 radsend(auth=1).

    dst: 4 or 16 bytes (destination), or None for 3proxy's "no destination yet"
    (it then sends Login-IP-Host 0.0.0.0).
    """
    a = []
    a.append(bytes((A_SERVICE_TYPE, 6)) + _U32.pack(8))  # Authenticate-Only
    a.append(attr(A_ACCT_SESSION_ID, session_id))
    a.append(bytes((A_NAS_PORT_TYPE, 6)) + _U32.pack(5))  # Virtual
    a.append(bytes((A_NAS_PORT, 6)) + _U32.pack(nas_port))
    if len(nas_addr) == 16:
        a.append(bytes((A_NAS_IPV6_ADDRESS, 18)) + nas_addr)
    else:
        a.append(bytes((A_NAS_IP_ADDRESS, 6)) + nas_addr)
    a.append(attr(A_NAS_IDENTIFIER, service))
    if len(client_addr) == 16:
        a.append(bytes((A_FRAMED_IPV6_ADDRESS, 18)) + client_addr)
    else:
        a.append(bytes((A_FRAMED_IP_ADDRESS, 6)) + client_addr)
    if hostname:
        a.append(attr(A_CALLED_STATION_ID, hostname))
    op, nbits = operation_bits, 0
    while op:
        nbits += 1
        op >>= 1
    a.append(bytes((A_LOGIN_SERVICE, 4)) + _U16.pack(nbits + 1000))
    a.append(bytes((A_LOGIN_TCP_PORT, 4)) + _U16.pack(dst_port))
    if dst is not None and len(dst) == 16:
        a.append(bytes((A_LOGIN_IPV6_HOST, 18)) + dst)
    else:
        a.append(bytes((A_LOGIN_IP_HOST, 6)) + (dst if dst is not None else b"\0\0\0\0"))
    if username is not None:
        a.append(attr(A_USER_NAME, username[:128]))
    if password is not None:
        a.append(attr(A_USER_PASSWORD, encode_password(password, secret, authenticator)))
    body = b"".join(a)
    return _HDR.pack(ACCESS_REQUEST, ident, 20 + len(body)) + authenticator + body


def verify_reply(reply: bytes, req_auth: bytes, secret: bytes) -> bool:
    if len(reply) < 20:
        return False
    length = _HDR.unpack_from(reply, 0)[2]
    if length != len(reply):
        return False
    want = md5(reply[:4] + req_auth + reply[20:length] + secret)
    return hmac.compare_digest(want, reply[4:20])


def reply_attrs(reply: bytes) -> list[tuple[int, bytes]]:
    out = []
    pos, length = 20, _HDR.unpack_from(reply, 0)[2]
    while pos + 2 <= length:
        t, alen = reply[pos], reply[pos + 1]
        if alen < 2:
            break
        out.append((t, reply[pos + 2 : pos + alen]))
        pos += alen
    return out
