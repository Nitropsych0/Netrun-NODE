#!/usr/bin/python3 -I
"""Send 3proxy-shaped Access-Requests to netrun-radius and report the answers.

    python3 -I radclient.py --secret-file /etc/netrun-pergb/radius.secret \
        --user netrun-svcprobe --password-file /root/probe.pw --nas-port 31000 \
        --dst 2001:db8::1 --dst-port 443 --count 10

Load mode: --duration S --rate R sends R requests/s for S seconds (one socket per
request, like 3proxy) and fails when any request goes unanswered within --timeout.
Prints one JSON line: {sent, accepts, rejects, lost, badAuth, p50Ms, p99Ms, maxMs, addrs}.
Exit status: 0 when every request got a valid answer (and --expect matched), else 1.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import selectors
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import proto  # noqa: E402


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--server", default="127.0.0.1:1812")
    p.add_argument("--secret-file", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--password", default=None)
    p.add_argument("--password-file", default=None)
    p.add_argument("--nas-port", type=int, required=True)
    p.add_argument("--dst", default=None, help="destination IP (Login-IP(v6)-Host); none = 0.0.0.0")
    p.add_argument("--dst-port", type=int, default=443)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--duration", type=float, default=0.0)
    p.add_argument("--rate", type=float, default=100.0)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--expect", choices=("accept", "reject", "any"), default="any")
    a = p.parse_args(argv)
    with open(a.secret_file, "rb") as fh:
        secret = fh.read().strip()
    if a.password_file:
        with open(a.password_file, "rb") as fh:
            password = fh.read().strip()
    else:
        password = (a.password or "").encode()
    host, _, port = a.server.rpartition(":")
    server = (host.strip("[]"), int(port))
    dst = ipaddress.ip_address(a.dst).packed if a.dst else None
    total = int(a.duration * a.rate) if a.duration else a.count
    interval = 1.0 / a.rate if a.duration else 0.0
    inflight = {}  # sock -> (ra, t0)
    sel = selectors.DefaultSelector()
    res = {"sent": 0, "accepts": 0, "rejects": 0, "lost": 0, "badAuth": 0}
    lat = []
    addrs = set()
    t_start = time.monotonic()

    def drain(block: float):
        if not inflight:
            return
        ready = [key.fileobj for key, _ in sel.select(block)]
        now = time.monotonic()
        for s in ready:
            ra, t0 = inflight.pop(s)
            sel.unregister(s)
            try:
                data = s.recv(4096)
            except OSError:
                res["lost"] += 1
                s.close()
                continue
            s.close()
            if not proto.verify_reply(data, ra, secret):
                res["badAuth"] += 1
                continue
            lat.append(now - t0)
            if data[0] == proto.ACCESS_ACCEPT:
                res["accepts"] += 1
                for _t, v in proto.reply_attrs(data):
                    addrs.add(str(ipaddress.ip_address(v)))
            else:
                res["rejects"] += 1
        for s, (_ra, t0) in list(inflight.items()):
            if now - t0 > a.timeout:
                del inflight[s]
                sel.unregister(s)
                s.close()
                res["lost"] += 1

    for i in range(total):
        due = t_start + i * interval
        while True:
            wait = due - time.monotonic()
            if wait <= 0:
                break
            if inflight:
                drain(min(wait, 0.05))
            else:
                time.sleep(wait)
        s = socket.socket(socket.AF_INET6 if ":" in server[0] else socket.AF_INET, socket.SOCK_DGRAM)
        ra = os.urandom(16)
        pkt = proto.build_3proxy_request(
            i % 256,
            ra,
            secret,
            username=a.user.encode(),
            password=password,
            nas_port=a.nas_port,
            dst=dst,
            dst_port=a.dst_port,
        )
        s.sendto(pkt, server)
        inflight[s] = (ra, time.monotonic())
        sel.register(s, selectors.EVENT_READ)
        res["sent"] += 1
        drain(0)
    deadline = time.monotonic() + a.timeout + 0.5
    while inflight and time.monotonic() < deadline:
        drain(0.1)
    for s in list(inflight):
        sel.unregister(s)
        s.close()
        res["lost"] += 1
    inflight.clear()
    lat.sort()
    if lat:
        res["p50Ms"] = round(lat[len(lat) // 2] * 1000, 3)
        res["p99Ms"] = round(lat[min(len(lat) - 1, int(len(lat) * 0.99))] * 1000, 3)
        res["maxMs"] = round(lat[-1] * 1000, 3)
    res["addrs"] = len(addrs)
    print(json.dumps(res))
    ok = res["lost"] == 0 and res["badAuth"] == 0
    if a.expect == "accept":
        ok = ok and res["accepts"] == res["sent"]
    elif a.expect == "reject":
        ok = ok and res["rejects"] == res["sent"]
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
