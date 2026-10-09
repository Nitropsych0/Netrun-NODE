"""A tiny stand-in for systemd socket activation (tests and the Linux e2e only).

It holds the UDP socket, so datagrams queue in the kernel while netrun-radius is
down, and runs the server with the socket as fd 3 (LISTEN_FDS=1, LISTEN_PID).

    python3 -I sockact.py --listen 127.0.0.1:1812 --pidfile /run/x.pid -- \
        python3 -I netrun_radius.py --state-dir ... --secret-file ... --ctl-socket ... --no-watchdog

Signals to the supervisor:
  SIGHUP   graceful restart (SIGTERM the server, start a new one)
  SIGUSR1  crash restart (SIGKILL the server, start a new one)
  SIGUSR2  stop the server and keep the socket (requests queue unanswered)
  SIGTERM  stop the server and exit (the socket closes)
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import sys
import time


def bind_udp(listen: str) -> socket.socket:
    host, _, port = listen.rpartition(":")
    host = host.strip("[]") or "127.0.0.1"
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 << 20)
    except OSError:
        pass
    s.bind((host, int(port)))
    return s


def spawn(sock: socket.socket, argv: list, env: dict | None = None, **popen_kw) -> subprocess.Popen:
    """Start argv with sock as fd 3, LISTEN_FDS=1 and LISTEN_PID = the child's pid."""
    env = dict(os.environ if env is None else env)
    env["LISTEN_FDS"] = "1"
    env.pop("LISTEN_PID", None)
    fd = sock.fileno()

    def child_setup():
        if fd != 3:
            os.dup2(fd, 3)
            os.close(fd)
        os.set_inheritable(3, True)  # dup2(3, 3) would keep FD_CLOEXEC

    wrapper = ["/bin/sh", "-c", 'LISTEN_PID=$$; export LISTEN_PID; exec "$0" "$@"'] + list(argv)
    return subprocess.Popen(wrapper, env=env, close_fds=False, preexec_fn=child_setup, **popen_kw)


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--listen", required=True)
    p.add_argument("--pidfile")
    p.add_argument("cmd", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        p.error("no command")
    sock = bind_udp(a.listen)
    state = {"child": None, "want": "run", "exit": False}

    def start():
        state["child"] = spawn(sock, cmd)
        print("sockact: started pid %d" % state["child"].pid, file=sys.stderr, flush=True)

    def stop(sig):
        c = state["child"]
        if c is not None and c.poll() is None:
            c.send_signal(sig)
            try:
                c.wait(10)
            except subprocess.TimeoutExpired:
                c.kill()
                c.wait()
        state["child"] = None

    def on_signal(signum, frame):
        state["pending"] = signum

    for s in (signal.SIGHUP, signal.SIGUSR1, signal.SIGUSR2, signal.SIGTERM, signal.SIGINT):
        signal.signal(s, on_signal)
    if a.pidfile:
        with open(a.pidfile, "w") as fh:
            fh.write(str(os.getpid()))
    start()
    while True:
        sig = state.pop("pending", None)
        if sig in (signal.SIGTERM, signal.SIGINT):
            stop(signal.SIGTERM)
            return 0
        if sig == signal.SIGHUP:
            stop(signal.SIGTERM)
            start()
        elif sig == signal.SIGUSR1:
            stop(signal.SIGKILL)
            start()
        elif sig == signal.SIGUSR2:
            stop(signal.SIGTERM)
            print("sockact: server stopped, socket kept", file=sys.stderr, flush=True)
        c = state["child"]
        if c is not None and c.poll() is not None:
            print("sockact: server exited with %s; restarting in 1 s" % c.returncode, file=sys.stderr, flush=True)
            time.sleep(1)
            start()
        time.sleep(0.05)


if __name__ == "__main__":
    sys.exit(main())
