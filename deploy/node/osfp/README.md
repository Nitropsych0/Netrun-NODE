# netrun OS-fingerprint egress rewriter (#4 phase 2)

Make a per-GB client's outbound TCP/IP fingerprint look like Windows or macOS
instead of Linux, chosen per connection with the `-os-<profile>` login suffix.

## Why a rewriter (not per-socket setsockopt)
TTL/hop limit is per-socket (phase 1, in 3proxy). But the TCP **window scale**,
**option order** and **timestamps** are fixed by the kernel and cannot be set
per-socket. A partial spoof (only TTL) is INCOHERENT — TTL says Windows while
window/scale/options still say Linux — and is MORE detectable than honest
Linux. So the full fingerprint needs the SYN rewritten on egress.

## How
1. 3proxy (patched, netrun-pergb.patch) parses `-os-windows|-os-macos` from the
   login and sets `SO_MARK` on the outbound socket (1 windows, 2 macos) plus the
   hop limit (phase 1). SO_MARK needs `CAP_NET_ADMIN` (install grants it).
2. nft (`netrun-osfp.nft`) sends only our marked, pure SYNs to NFQUEUE 0 with
   `bypass` — a stopped/crashed daemon lets them pass UNMODIFIED (egress never
   breaks).
3. `netrun-osfp-daemon.py` (NFQUEUE 0) rewrites each SYN to the profile named by
   the mark via `osfp_rewrite.py` and reinjects. Checksums/lengths recomputed.

Profiles (the values real stacks send):
| | window | wscale | options | timestamps | ttl (phase 1) |
|---|---|---|---|---|---|
| windows | 64240 | 8 | mss,nop,ws,nop,nop,sackOK | no | 128 |
| macos | 65535 | 6 | mss,nop,ws,nop,nop,TS,sackOK,eol | yes | 64 |
| linux (start) | 64240 | 7 | mss,sackOK,TS,nop,ws | yes | 64 |

## Validated (2026-10-13, isolated netns on the orchestrator host, Docker)
End-to-end SO_MARK -> nft -> NFQUEUE -> daemon -> reinject, captured on the wire:
- unmarked -> Linux (unchanged, bypassed the queue);
- mark 1 -> `win 64240, [mss 1460,nop,wscale 8,nop,nop,sackOK]`, no TS, cksum correct;
- mark 2 -> `win 65535, [mss 1460,nop,wscale 6,nop,nop,TS,sackOK,eol]`, cksum correct.
`tests/test_rewrite.py` checks the rewrite (IPv4+IPv6, both profiles, SYN-ACK
untouched, checksums) with scapy.

## NOT yet on prod — needs owner review
- `install-osfp.sh` touches the node's egress (nft output hook) and grants the
  per-GB 3proxy `CAP_NET_ADMIN`. Security trade-off: a 3proxy RCE would then
  have CAP_NET_ADMIN. Mitigations: our reproducible pinned binary, the slice,
  NoNewPrivileges, tight nft match (our mark + SYN only). The owner approves
  before enabling. `install-osfp.sh --off` fully reverts.
- Ship `-os-` to customers (bot/site UI «🖥 ОС») only with this phase 2 live —
  phase 1 alone is incoherent.

## Performance
Only `-os-` connections are marked, so only their SYNs are queued; all other
egress is untouched. SYNs are low-rate (one per new connection). If `-os-`
volume grows, replace the Python daemon with an eBPF tc-egress program (same
rewrite) — the mark/nft plumbing stays.
