"""netrun OS-fingerprint NFQUEUE daemon (phase 2). Reads marked SYNs from an
NFQUEUE, rewrites the TCP fingerprint to the profile named by the packet mark
(1 windows, 2 macos), reinjects. A dead daemon must NOT break egress: the nft
rule uses `queue ... bypass`, so with no daemon the packet passes unmodified."""
from __future__ import annotations
import sys
from netfilterqueue import NetfilterQueue  # type: ignore
from scapy.all import IP, IPv6  # type: ignore
import osfp_rewrite as R

QUEUE = int(sys.argv[1]) if len(sys.argv) > 1 else 0

def handle(pkt):
    mark = pkt.get_mark()
    try:
        raw = pkt.get_payload()
        base = IPv6(raw) if (raw and (raw[0] >> 4) == 6) else IP(raw)
        new = R.rewrite(base, mark)
        pkt.set_payload(bytes(new))
    except Exception as e:  # never drop on error — accept unmodified
        sys.stderr.write(f"osfp rewrite error: {e}\n")
    pkt.accept()

nfq = NetfilterQueue()
nfq.bind(QUEUE, handle)
try:
    nfq.run()
finally:
    nfq.unbind()
