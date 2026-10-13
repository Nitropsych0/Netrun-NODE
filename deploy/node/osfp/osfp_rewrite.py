"""netrun OS-fingerprint SYN rewriter (phase 2 core).

Given a client SYN that our 3proxy sends (Linux stack), rewrite its TCP options,
window and (hop limit via phase-1 setsockopt already) so the on-the-wire SYN
matches a Windows or macOS fingerprint. Used by the NFQUEUE daemon; this module
is the pure rewrite so it can be unit-tested without netfilter.

Profiles (p0f-style, the values real stacks send):
  windows: win 64240, opts [MSS, NOP, WS(8), NOP, NOP, SACK], no timestamps, ttl 128
  macos:   win 65535, opts [MSS, NOP, WS(6), NOP, NOP, TS, SACK, EOL], ttl 64
Linux (what we start from): win 64240, opts [MSS, SACK, TS, NOP, WS(7)], ttl 64
"""
from __future__ import annotations

from scapy.all import IP, IPv6, TCP  # type: ignore

# option list builders. scapy TCP.options is a list of (name, value) / strings.
# MSS value is taken from the incoming SYN (path MTU), not forced.


def _mss(opts):
    for o in opts:
        if o[0] == "MSS":
            return o[1]
    return 1460


def _ts(opts):
    for o in opts:
        if o[0] == "Timestamp":
            return o[1]
    return (0, 0)


def windows_opts(src_opts):
    # MSS, NOP, WScale 8, NOP, NOP, SAckOK  (no Timestamp)
    return [("MSS", _mss(src_opts)), ("NOP", None), ("WScale", 8), ("NOP", None), ("NOP", None), ("SAckOK", b"")]


def macos_opts(src_opts):
    # MSS, NOP, WScale 6, NOP, NOP, Timestamp, SAckOK, EOL
    return [
        ("MSS", _mss(src_opts)),
        ("NOP", None),
        ("WScale", 6),
        ("NOP", None),
        ("NOP", None),
        ("Timestamp", _ts(src_opts)),
        ("SAckOK", b""),
        ("EOL", None),
    ]


PROFILES = {
    1: ("windows", windows_opts, 64240),
    2: ("macos", macos_opts, 65535),
}


def rewrite(pkt, profile_id: int):
    """Return the rewritten packet (new bytes) for a SYN, or pkt unchanged.
    profile_id: 1 windows, 2 macos. Only touches SYN (not SYN-ACK)."""
    prof = PROFILES.get(profile_id)
    if prof is None:
        return pkt
    name, optf, win = prof
    if TCP not in pkt:
        return pkt
    tcp = pkt[TCP]
    # SYN only, not SYN-ACK
    if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
        return pkt
    tcp.options = optf(tcp.options)
    tcp.window = win
    # force scapy to recompute length + checksums (and IP len/csum)
    del tcp.chksum
    del tcp.dataofs
    if IP in pkt:
        del pkt[IP].len
        del pkt[IP].chksum
    if IPv6 in pkt:
        del pkt[IPv6].plen
    return pkt.__class__(bytes(pkt))  # rebuild so lengths/checksums are filled
