import os,sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scapy.all import IP, IPv6, TCP  # type: ignore
import osfp_rewrite as R

PANEL = {  # name: (p0f sig, expect window class, expect has_ts, expect ttl)
 "winxp":  ("*:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0", 16384, False, 128),
 "win7_8": ("*:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0", 8192, False, 128),
 "macosx": ("*:64:0:*:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0", 65535, True, 64),
 "linux311":("*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0", None, True, 64),
 "win10":  ("*:128:0:*:64240,8:mss,nop,ws,nop,nop,sok:df,id+:0", 64240, False, 128),
}
def linux_syn(v6=False, mss=1460):
    L4=TCP(sport=40000,dport=443,flags="S",window=64240,
        options=[("MSS",mss),("SAckOK",b""),("Timestamp",(999,0)),("NOP",None),("WScale",7)])
    return (IPv6(src="2001:db8::5",dst="2606:4700::1",hlim=64) if v6 else IP(src="203.0.113.5",dst="1.1.1.1",ttl=64))/L4

ok=True
for name,(sig,win,ts,ttl) in PANEL.items():
    for v6 in (False,True):
        pkt=linux_syn(v6)
        out=R.rewrite(pkt,sig); raw=bytes(out); p=out.__class__(raw); tcp=p[TCP]
        names=[o[0] for o in tcp.options]
        has_ts="Timestamp" in names
        # checksum valid?
        c=tcp.chksum; tcp.chksum=None; reco=p.__class__(bytes(p))[TCP].chksum
        obs_ttl = p[IP].ttl if IP in p else p[IPv6].hlim
        wok = (win is None) or (tcp.window==win)
        good = wok and has_ts==ts and (obs_ttl==ttl) and c==reco and (tcp.flags&2) and not (tcp.flags&16)
        ok=ok and good
        if not v6:
            print(f"  {name:9} win={tcp.window} ttl={obs_ttl} ts={has_ts} opts={names} csum={'ok' if c==reco else 'BAD'} {'' if good else '<<FAIL'}")
# unknown mark passthrough + SYN-ACK untouched
sa=IP()/TCP(flags="SA",options=[("MSS",1460)]); assert R.rewrite(sa,PANEL['win10'][0])[TCP].flags==sa[TCP].flags
# fnv mark determinism sample (must match the C / orchestrator)
print("  marks:", {n:hex(R.osfp_mark(n)) for n in ("windows","macos","win7","android","iphone")})
print("ALL P0F TESTS", "PASSED" if ok else "FAILED"); sys.exit(0 if ok else 1)
