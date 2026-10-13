"""netrun OS-fingerprint NFQUEUE daemon (#4 phase 2, v2: signature table).

Reads marked SYNs from an NFQUEUE and rewrites each to the p0f signature its
fwmark selects. The signature table (/opt/netrun/osfp/signatures.json, synced
from the orchestrator) maps a profile NAME to a p0f-v3 signature; the daemon
derives each name's fwmark with the same FNV formula as the patched 3proxy and
the orchestrator, so mark -> signature with no id handshake. The file is
re-read when its mtime changes.

A dead daemon must NOT break egress: the nft rule uses `queue ... bypass`, so
with no daemon marked SYNs pass unmodified.
"""
from __future__ import annotations

import json
import os
import sys

from netfilterqueue import NetfilterQueue  # type: ignore
from scapy.all import IP, IPv6  # type: ignore

import osfp_rewrite as R

QUEUE = int(sys.argv[1]) if len(sys.argv) > 1 else 0
SIG_FILE = os.environ.get("OSFP_SIGNATURES", "/opt/netrun/osfp/signatures.json")

_table: dict[int, str] = {}  # fwmark -> p0f signature
_mtime: float = -1.0


def _load() -> None:
    """(Re)build {mark: sig} from the name->sig file; fall back to the built-ins."""
    global _table, _mtime
    table: dict[int, str] = {R.osfp_mark(n): s for n, s in R.DEFAULT_SIGNATURES.items()}
    try:
        st = os.stat(SIG_FILE)
        if st.st_mtime != _mtime:
            with open(SIG_FILE) as fh:
                data = json.load(fh)
            # accept {name: sig} or {name: {sig, enabled}}
            for name, v in data.items():
                sig = v.get("sig") if isinstance(v, dict) else v
                if isinstance(v, dict) and v.get("enabled") is False:
                    table.pop(R.osfp_mark(name), None)
                    continue
                if sig:
                    table[R.osfp_mark(name)] = str(sig)
            _mtime = st.st_mtime
            sys.stderr.write(f"osfp: loaded {len(data)} signatures from {SIG_FILE}\n")
            sys.stderr.flush()
    except FileNotFoundError:
        if _mtime != -2.0:
            _mtime = -2.0
            sys.stderr.write(f"osfp: {SIG_FILE} missing, using {len(table)} built-ins\n")
    except Exception as e:  # keep the last good table on a bad file
        sys.stderr.write(f"osfp: signatures reload error: {e}\n")
    _table = table


def handle(pkt):
    try:
        _load()
        sig = _table.get(pkt.get_mark())
        if sig:
            raw = pkt.get_payload()
            base = IPv6(raw) if (raw and (raw[0] >> 4) == 6) else IP(raw)
            pkt.set_payload(bytes(R.rewrite(base, sig)))
    except Exception as e:  # never drop on error — accept unmodified
        sys.stderr.write(f"osfp rewrite error: {e}\n")
    pkt.accept()


def main() -> None:
    _load()
    nfq = NetfilterQueue()
    nfq.bind(QUEUE, handle)
    try:
        nfq.run()
    finally:
        nfq.unbind()


if __name__ == "__main__":
    main()
