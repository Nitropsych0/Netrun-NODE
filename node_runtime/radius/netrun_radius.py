#!/usr/bin/python3 -I
"""netrun-radius: the per-GB RADIUS server of a NETRUN node (plan §3.1-§3.4).

    /usr/bin/python3 -I /opt/netrun/radius/netrun_radius.py

One process, four threads:
  A  UDP loop on the socket-activated fd 3 (LISTEN_FDS; --listen for tests),
     select() with a 1 s timeout; never touches the disk;
  B  ctl server on /run/netrun-radius/ctl.sock (newline-delimited JSON);
  C  sqlite writer: binding changes committed in batches every 100 ms;
  D  sweeper: sticky expiry, cool-downs, event pruning, secret reload, and
     sd_notify WATCHDOG=1 only while thread A's heartbeat is < 3 s old.
READY=1 is sent once the state is loaded (target: < 1 s with cap-sized state).
The RADIUS secret is read from /etc/netrun-pergb/radius.secret (never argv).
stdlib only; Python >= 3.10 (3.9 works).
"""

from __future__ import annotations

import argparse
import os
import select
import signal
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ctl import DEFAULT_PATH as DEFAULT_CTL  # noqa: E402
from ctl import CtlServer  # noqa: E402
from engine import Engine  # noqa: E402
from state import Store, log  # noqa: E402

VERSION = "1"
DEFAULT_SECRET = "/etc/netrun-pergb/radius.secret"
DEFAULT_STATE_DIR = "/var/lib/netrun-radius"
WRITER_INTERVAL = 0.1
SWEEP_INTERVAL = 5.0
PRUNE_INTERVAL = 3600.0
UDP_STALE = 3.0
DRAIN_MAX = 512


def sd_notify(msg: str) -> bool:
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr[0] == "@":
        addr = "\0" + addr[1:]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.connect(addr)
        s.sendall(msg.encode())
        return True
    except OSError as e:
        log("sd_notify failed: %s" % e)
        return False
    finally:
        s.close()


def listen_fds() -> list:
    """sd_listen_fds(): the fds passed by systemd (or a test harness), from 3 up."""
    n = os.environ.get("LISTEN_FDS")
    if not n:
        return []
    pid = os.environ.get("LISTEN_PID")
    if pid and pid.isdigit() and int(pid) != os.getpid():
        return []
    for k in ("LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES"):
        os.environ.pop(k, None)
    try:
        count = int(n)
    except ValueError:
        return []
    return list(range(3, 3 + count))


def open_udp(listen: str | None) -> socket.socket:
    fds = listen_fds()
    if fds:
        s = socket.socket(fileno=fds[0])
        if s.type != socket.SOCK_DGRAM:
            raise SystemExit("fd 3 is not a datagram socket")
        for extra in fds[1:]:
            os.close(extra)
    else:
        if not listen:
            raise SystemExit("no socket from systemd (LISTEN_FDS) and no --listen")
        host, _, port = listen.rpartition(":")
        host = host.strip("[]") or "127.0.0.1"
        fam = socket.AF_INET6 if ":" in host else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 << 20)
        except OSError:
            pass
        s.bind((host, int(port)))
    s.setblocking(False)
    return s


def read_secret(path: str) -> tuple[bytes | None, float | None]:
    try:
        st = os.stat(path)
        with open(path, "rb") as fh:
            secret = fh.read().strip()
    except OSError as e:
        log("no RADIUS secret at %s (%s): requests are dropped" % (path, e))
        return None, None
    if not secret or len(secret) > 63:  # 3proxy keeps at most 63 bytes
        log("RADIUS secret at %s is empty or longer than 63 bytes: requests are dropped" % path)
        return None, st.st_mtime
    return secret, st.st_mtime


class Server:
    def __init__(self, args):
        self.args = args
        self.stop = threading.Event()
        self.secret_path = args.secret_file
        secret, self.secret_mtime = read_secret(self.secret_path)
        self.store = Store(os.path.join(args.state_dir, "radius.db"))
        self.engine = Engine(self.store, secret=secret)
        self.ctl = None
        self.sock = None
        self.watchdog = bool(os.environ.get("WATCHDOG_USEC")) and not args.no_watchdog

    def start(self):
        t0 = time.monotonic()
        self.sock = open_udp(self.args.listen)
        self.engine.load()
        self.ctl = CtlServer(self.args.ctl_socket, self.engine)
        self.ctl.start()
        for name, target in (("writer", self._writer), ("sweeper", self._sweeper)):
            threading.Thread(target=target, name=name, daemon=True).start()
        ms = (time.monotonic() - t0) * 1000
        st = self.engine.op_status({})
        log(
            "ready in %.0f ms: epoch %d seq %d, %d lists, %d accounts, %d static, %d sticky%s"
            % (
                ms,
                st["epoch"],
                st["seq"],
                st["counts"]["lists"],
                st["counts"]["accounts"],
                st["counts"]["static"],
                st["counts"]["sticky"],
                " (DB recovered)" if st["dbRecovered"] else "",
            )
        )
        sd_notify("READY=1\nSTATUS=serving, epoch %d" % st["epoch"])

    def serve(self):
        eng = self.engine
        sock = self.sock
        handle = eng.handle
        while not self.stop.is_set():
            eng.udp_alive = time.monotonic()
            try:
                ready, _, _ = select.select([sock], [], [], 1.0)
            except InterruptedError:
                continue
            except OSError as e:
                log("select failed: %s" % e)
                time.sleep(0.1)
                continue
            if not ready:
                continue
            for _ in range(DRAIN_MAX):
                try:
                    data, peer = sock.recvfrom(4096)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    break
                try:
                    out = handle(data)
                except Exception as e:  # a bad packet must never stop the loop
                    log("request failed: %s: %s" % (type(e).__name__, e))
                    continue
                if out is not None:
                    try:
                        sock.sendto(out, peer)
                    except OSError:
                        eng.counters["sendErrors"] += 1
            eng.udp_alive = time.monotonic()

    def _writer(self):
        eng = self.engine
        while not self.stop.wait(WRITER_INTERVAL):
            try:
                eng.flush()
            except Exception as e:
                log("writer: %s: %s" % (type(e).__name__, e))
            if self.store.corrupt:
                log("state DB is corrupt: exiting so that the restart recovers it")
                sd_notify("STATUS=state DB corrupt, restarting")
                os._exit(70)

    def _sweeper(self):
        eng = self.engine
        last_sweep = last_prune = 0.0
        while not self.stop.wait(1.0):
            mono = time.monotonic()
            if self.watchdog and mono - eng.udp_alive < UDP_STALE:
                sd_notify("WATCHDOG=1")
            if mono - last_sweep >= SWEEP_INTERVAL:
                last_sweep = mono
                try:
                    eng.sweep()
                    self._reload_secret()
                except Exception as e:
                    log("sweeper: %s: %s" % (type(e).__name__, e))
            if mono - last_prune >= PRUNE_INTERVAL:
                last_prune = mono
                try:
                    eng.prune_events()
                except Exception as e:
                    log("prune: %s: %s" % (type(e).__name__, e))

    def _reload_secret(self):
        try:
            mtime = os.stat(self.secret_path).st_mtime
        except OSError:
            mtime = None
        if mtime != self.secret_mtime:
            secret, self.secret_mtime = read_secret(self.secret_path)
            self.engine.secret = secret
            log("RADIUS secret %s" % ("reloaded" if secret else "unavailable"))

    def shutdown(self):
        self.stop.set()
        sd_notify("STOPPING=1")
        try:
            self.engine.flush()
        except Exception as e:
            log("final flush failed: %s" % e)
        if self.ctl is not None:
            self.ctl.stop()
        self.store.close()


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="NETRUN per-GB RADIUS server")
    p.add_argument("--listen", help="host:port to bind when not socket-activated (tests)")
    p.add_argument("--state-dir", default=os.environ.get("STATE_DIRECTORY", DEFAULT_STATE_DIR).split(":")[0])
    p.add_argument("--secret-file", default=os.environ.get("NETRUN_RADIUS_SECRET_FILE", DEFAULT_SECRET))
    p.add_argument("--ctl-socket", default=os.environ.get("NETRUN_RADIUS_CTL", DEFAULT_CTL))
    p.add_argument("--no-watchdog", action="store_true")
    p.add_argument("--version", action="version", version="netrun-radius " + VERSION)
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    srv = Server(args)

    def on_term(signum, frame):
        srv.stop.set()

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    srv.start()
    try:
        srv.serve()
    finally:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
