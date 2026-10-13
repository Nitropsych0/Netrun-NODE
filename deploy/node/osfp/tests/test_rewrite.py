import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
"""Self-test: craft a Linux SYN, rewrite to windows/macos, assert the wire bytes
parse back to the target fingerprint with valid checksums."""
from scapy.all import IP, IPv6, TCP, checksum  # type: ignore
import osfp_rewrite as R

def linux_syn_v4():
    return IP(src="203.0.113.5", dst="1.1.1.1", ttl=64)/TCP(sport=40000, dport=443, flags="S",
        window=64240, options=[("MSS",1460),("SAckOK",b""),("Timestamp",(12345,0)),("NOP",None),("WScale",7)])

def linux_syn_v6():
    return IPv6(src="2001:db8::5", dst="2606:4700:4700::1111", hlim=64)/TCP(sport=40000, dport=443, flags="S",
        window=64240, options=[("MSS",1440),("SAckOK",b""),("Timestamp",(12345,0)),("NOP",None),("WScale",7)])

def optnames(tcp): return [o[0] for o in tcp.options]

def check(pkt, profile, want_win, want_optnames, want_ws, want_ts):
    out = R.rewrite(pkt, profile)
    raw = bytes(out)
    # reparse from the wire
    p = out.__class__(raw)
    tcp = p[TCP]
    names = optnames(tcp)
    ws = dict((o[0], o[1]) for o in tcp.options).get("WScale")
    has_ts = "Timestamp" in names
    # verify TCP checksum by recomputing (scapy sets it; reparse keeps it)
    chk = tcp.chksum
    tcp.chksum = None
    reco = p.__class__(bytes(p))[TCP].chksum
    ok_csum = (chk == reco)
    print(f"  {R.PROFILES[profile][0]}: win={tcp.window} opts={names} ws={ws} ts={has_ts} csum_ok={ok_csum}")
    assert tcp.window == want_win, tcp.window
    assert names == want_optnames, names
    assert ws == want_ws, ws
    assert has_ts == want_ts
    assert ok_csum
    assert tcp.flags & 0x02 and not (tcp.flags & 0x10)

print("IPv4:")
check(linux_syn_v4(), 1, 64240, ["MSS","NOP","WScale","NOP","NOP","SAckOK"], 8, False)
check(linux_syn_v4(), 2, 65535, ["MSS","NOP","WScale","NOP","NOP","Timestamp","SAckOK","EOL"], 6, True)
print("IPv6:")
check(linux_syn_v6(), 1, 64240, ["MSS","NOP","WScale","NOP","NOP","SAckOK"], 8, False)
check(linux_syn_v6(), 2, 65535, ["MSS","NOP","WScale","NOP","NOP","Timestamp","SAckOK","EOL"], 6, True)
# SYN-ACK must be left untouched
sa = IP()/TCP(flags="SA", options=[("MSS",1460)])
assert R.rewrite(sa,1)[TCP].flags == sa[TCP].flags and "Timestamp" not in optnames(R.rewrite(sa,1)[TCP])
print("SYN-ACK untouched: ok")
print("ALL REWRITE TESTS PASSED")
