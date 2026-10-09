"""A stand-in for 3proxy's RADIUS side, to dry-run e2e_driver.py where 3proxy and
network namespaces are unavailable (macOS). NOT a proxy: after the RADIUS answer
it writes the Framed address back as if the target had seen it.

Like 3proxy 0.9.3: one Access-Request per connection from a fresh UDP socket,
NAS-Port = the listen port, the destination in Login-IP(v6)-Host, a 3 s timeout
(SINGLEBYTE_L), SOCKS reply 2 / HTTP 407 on refusal.

    python3 -I fake3proxy.py --secret-file F --base 31000 --count 4 --socks-host 127.0.0.1 \
        --http-host 127.0.0.1 --http-offset 100 [--radius 127.0.0.1:1812]
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import os
import socket
import struct
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import proto  # noqa: E402

TIMEOUT = 3.0


def radius(args, secret, nas_port, user, password, dst, dst_port, service):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        ra = os.urandom(16)
        pkt = proto.build_3proxy_request(
            1,
            ra,
            secret,
            username=user,
            password=password,
            nas_port=nas_port,
            dst=dst,
            dst_port=dst_port,
            service=service,
        )
        s.sendto(pkt, args.radius_addr)
        data = s.recv(4096)
    except OSError:
        return None
    finally:
        s.close()
    if not proto.verify_reply(data, ra, secret) or data[0] != proto.ACCESS_ACCEPT:
        return None
    for t, v in proto.reply_attrs(data):
        if t in (proto.A_FRAMED_IPV6_ADDRESS, proto.A_FRAMED_IP_ADDRESS):
            return str(ipaddress.ip_address(v))
    return None


def recv_exact(c, n):
    b = b""
    while len(b) < n:
        x = c.recv(n - len(b))
        if not x:
            raise OSError("closed")
        b += x
    return b


def socks_conn(args, secret, port, c):
    try:
        c.settimeout(30)
        _ver, nmethods = recv_exact(c, 2)
        recv_exact(c, nmethods)
        c.sendall(b"\x05\x02")
        recv_exact(c, 1)
        user = recv_exact(c, recv_exact(c, 1)[0])
        pw = recv_exact(c, recv_exact(c, 1)[0])
        c.sendall(b"\x01\x00")
        head = recv_exact(c, 4)
        dst = recv_exact(c, 16 if head[3] == 4 else 4)
        dport = struct.unpack("!H", recv_exact(c, 2))[0]
        framed = radius(args, secret, port, user, pw, dst, dport, b"SOCKS")
        if framed is None:
            c.sendall(b"\x05\x02\x00\x01" + bytes(6))
            return
        c.sendall(b"\x05\x00\x00\x01" + bytes(6))
        c.sendall((framed + "\n").encode())
    except OSError:
        pass
    finally:
        c.close()


def http_conn(args, secret, port, c):
    try:
        c.settimeout(30)
        head = b""
        while b"\r\n\r\n" not in head:
            x = c.recv(1)
            if not x:
                return
            head += x
        lines = head.decode().split("\r\n")
        target = lines[0].split()[1]
        host, _, dport = target.rpartition(":")
        auth = [x for x in lines if x.lower().startswith("proxy-authorization: basic ")]
        user, _, pw = base64.b64decode(auth[0].split()[-1]).decode().partition(":") if auth else ("", "", "")
        dst = ipaddress.ip_address(host.strip("[]")).packed
        framed = radius(args, secret, port, user.encode(), pw.encode(), dst, int(dport), b"PROXY")
        if framed is None:
            c.sendall(b"HTTP/1.0 407 Proxy Authentication Required\r\n\r\n")
            return
        c.sendall(b"HTTP/1.0 200 Connection established\r\n\r\n" + (framed + "\n").encode())
    except OSError:
        pass
    finally:
        c.close()


def listen(host, port, handler, args, secret, nas_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(512)

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handler, args=(args, secret, nas_port, c), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--secret-file", required=True)
    p.add_argument("--base", type=int, default=31000)
    p.add_argument("--count", type=int, default=4)
    p.add_argument("--socks-host", default="127.0.0.1")
    p.add_argument("--http-host", default="127.0.0.1")
    p.add_argument("--http-offset", type=int, default=100)
    p.add_argument("--radius", default="127.0.0.1:1812")
    args = p.parse_args()
    host, _, port = args.radius.rpartition(":")
    args.radius_addr = (host, int(port))
    secret = open(args.secret_file, "rb").read().strip()
    for i in range(args.count):
        listen(args.socks_host, args.base + i, socks_conn, args, secret, args.base + i)
        listen(args.http_host, args.base + args.http_offset + i, http_conn, args, secret, args.base + i)
    print("fake3proxy ready", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
