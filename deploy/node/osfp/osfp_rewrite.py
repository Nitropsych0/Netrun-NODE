"""netrun OS-fingerprint SYN rewriter (#4 phase 2, v2: p0f-signature driven).

The daemon marks each -os-<name> connection with SO_MARK = osfp_mark(name)
(set by the patched 3proxy, same FNV formula as here and as the orchestrator).
A synced table (signatures.json) maps that mark to a p0f-v3 TCP SYN signature;
this module parses the signature and rewrites the client's (Linux) SYN to match,
so the on-the-wire fingerprint reads as the chosen OS. IPv4 and IPv6.

p0f v3 SYN signature: `ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass`
  ittl   initial TTL/hop-limit (64/128/255; a trailing -N distance is ignored; * keeps it)
  mss    MSS to force, or * to keep the SYN's own (path-dependent)
  wsize  window: a literal, mss*N, mtu*N, %N, or * (keep original)
  scale  window scale value, or * (keep original)
  olayout  option order: mss, sok, ts, nop, ws, eol+N
  quirks   df (set DF), ... (others best-effort/ignored for generation)
"""
from __future__ import annotations

from scapy.all import IP, IPv6, TCP  # type: ignore

FNV_OFFSET = 2166136261
FNV_PRIME = 16777619


def osfp_mark(name: str) -> int:
    """Stable 0x1xxxxxxx fwmark for a profile name. MUST match the 3proxy C
    (netrun-pergb.patch) and the orchestrator byte for byte: FNV-1a 32, then
    the low 28 bits with the 0x10000000 prefix (non-zero, distinctive range)."""
    h = FNV_OFFSET
    for b in name.encode("ascii", "ignore").lower():
        h = ((h ^ b) * FNV_PRIME) & 0xFFFFFFFF
    return 0x10000000 | (h & 0x0FFFFFFF)


# ── p0f parsing ──────────────────────────────────────────────────────────────


def _mss_of(opts):
    for o in opts:
        if o[0] == "MSS":
            return int(o[1])
    return 1460


def _ws_of(opts):
    for o in opts:
        if o[0] == "WScale":
            return int(o[1])
    return 0


def _ts_of(opts):
    for o in opts:
        if o[0] == "Timestamp":
            return o[1]
    return (0, 0)


def parse_p0f(sig: str) -> dict:
    """p0f SYN signature string -> a dict the applier uses. Raises ValueError."""
    f = sig.strip().split(":")
    if len(f) != 8:
        raise ValueError(f"p0f sig needs 8 fields, got {len(f)}: {sig!r}")
    _ver, ittl, _olen, mss, winscale, olayout, quirks, _pclass = f
    win, _, scale = winscale.partition(",")
    return {
        "ittl": None if ittl in ("", "*") else int(ittl.split("-")[0]),
        "mss": None if mss in ("", "*") else int(mss),
        "win": win.strip(),  # literal | mss*N | mtu*N | %N | *
        "scale": None if scale in ("", "*") else int(scale),
        "olayout": [t for t in olayout.split(",") if t],
        "quirks": set(q for q in quirks.split(",") if q),
    }


def _window(win_spec: str, mss: int, orig_win: int) -> int:
    s = win_spec.strip()
    if s in ("", "*"):
        return orig_win
    if s.startswith("mss*"):
        return mss * int(s[4:])
    if s.startswith("mtu*"):
        return (mss + 40) * int(s[4:])
    if s.startswith("%"):
        m = int(s[1:])
        return (orig_win // m) * m if m else orig_win
    return int(s)


def _options(layout, mss, scale, ts):
    out = []
    for tok in layout:
        if tok == "mss":
            out.append(("MSS", mss))
        elif tok == "sok":
            out.append(("SAckOK", b""))
        elif tok == "ts":
            out.append(("Timestamp", ts))
        elif tok == "nop":
            out.append(("NOP", None))
        elif tok == "ws":
            out.append(("WScale", scale))
        elif tok.startswith("eol"):
            out.append(("EOL", None))
        # unknown tokens are skipped
    return out


def apply_p0f(pkt, sig: str):
    """Rewrite a SYN (only; SYN-ACK left as is) to the p0f signature. Returns
    the rebuilt packet with lengths/checksums recomputed, or pkt unchanged."""
    if TCP not in pkt:
        return pkt
    tcp = pkt[TCP]
    if not (tcp.flags & 0x02) or (tcp.flags & 0x10):  # SYN only, not SYN-ACK
        return pkt
    p = parse_p0f(sig)
    mss = p["mss"] if p["mss"] is not None else _mss_of(tcp.options)
    scale = p["scale"] if p["scale"] is not None else _ws_of(tcp.options)
    tcp.options = _options(p["olayout"], mss, scale, _ts_of(tcp.options))
    tcp.window = _window(p["win"], mss, int(tcp.window))
    del tcp.chksum
    del tcp.dataofs
    if IP in pkt:
        ip = pkt[IP]
        if p["ittl"] is not None:
            ip.ttl = p["ittl"]
        ip.flags = "DF" if "df" in p["quirks"] else 0
        del ip.len
        del ip.chksum
    if IPv6 in pkt:
        if p["ittl"] is not None:
            pkt[IPv6].hlim = p["ittl"]
        del pkt[IPv6].plen
    return pkt.__class__(bytes(pkt))


# built-in fallback signatures (used only if signatures.json is missing a mark);
# concrete values, no "*", so generation is unambiguous.
DEFAULT_SIGNATURES = {
    "windows": "*:128:0:*:64240,8:mss,nop,ws,nop,nop,sok:df,id+:0",
    "macos": "*:64:0:*:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0",
}


def rewrite(pkt, sig: str):
    """Entry point: apply a p0f signature string to a SYN."""
    try:
        return apply_p0f(pkt, sig)
    except Exception:
        return pkt
