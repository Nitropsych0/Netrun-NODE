"""netrun-radius control socket (frozen interface I5).

Unix stream socket /run/netrun-radius/ctl.sock (0600). One JSON request line and
one JSON response line per connection; errors are {"error": code, ...}.
The node agent is the only client. Ops: status, facts, excluded, snapshot, apply,
heartbeat, near_stats, local_block, admission, ipv4_admission, bindings, logins,
accounts, rejects, reserve_nets, release_nets (amendment A1), avoid (A12), reserved (A13-I).
"""

from __future__ import annotations

import json
import os
import socket
import stat
import threading
import traceback

from state import log

DEFAULT_PATH = "/run/netrun-radius/ctl.sock"
MAX_REQUEST = 64 << 20  # a full snapshot of 50k lists is ~15 MB
CONN_TIMEOUT = 30.0


def _read_line(conn: socket.socket) -> bytes:
    chunks = []
    total = 0
    while True:
        buf = conn.recv(1 << 20)
        if not buf:
            break
        nl = buf.find(b"\n")
        if nl >= 0:
            chunks.append(buf[:nl])
            break
        chunks.append(buf)
        total += len(buf)
        if total > MAX_REQUEST:
            raise ValueError("request too large")
    return b"".join(chunks)


class CtlServer:
    def __init__(self, path: str, engine):
        self.path = path
        self.engine = engine
        self.sock = None
        self.thread = None
        self.stopping = False
        self.served = 0
        self.errors = 0

    def bind(self):
        d = os.path.dirname(self.path)
        if d and not os.path.isdir(d):
            os.makedirs(d, mode=0o750, exist_ok=True)
        try:
            st = os.lstat(self.path)
            if stat.S_ISSOCK(st.st_mode):
                os.unlink(self.path)
            else:
                raise RuntimeError("%s exists and is not a socket" % self.path)
        except FileNotFoundError:
            pass
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            s.bind(self.path)
        finally:
            os.umask(old)
        os.chmod(self.path, 0o600)
        s.listen(64)
        self.sock = s

    def start(self):
        if self.sock is None:
            self.bind()
        self.thread = threading.Thread(target=self._accept_loop, name="ctl", daemon=True)
        self.thread.start()

    def _accept_loop(self):
        while not self.stopping:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                if self.stopping:
                    return
                continue
            threading.Thread(target=self._serve, args=(conn,), name="ctl-conn", daemon=True).start()

    def _serve(self, conn: socket.socket):
        try:
            conn.settimeout(CONN_TIMEOUT)
            try:
                line = _read_line(conn)
                req = json.loads(line.decode("utf-8")) if line.strip() else None
            except (ValueError, UnicodeDecodeError) as e:
                reply = {"error": "bad_request", "detail": str(e)[:200]}
            else:
                try:
                    reply = self.engine.dispatch(req)
                except Exception as e:  # never let one request kill the ctl thread
                    self.errors += 1
                    log(
                        "ctl %s failed: %s\n%s"
                        % (req.get("op") if isinstance(req, dict) else "?", e, traceback.format_exc())
                    )
                    reply = {"error": "internal", "detail": "%s: %s" % (type(e).__name__, str(e)[:200])}
            conn.sendall(json.dumps(reply, separators=(",", ":")).encode() + b"\n")
            self.served += 1
        except OSError:
            self.errors += 1
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self.stopping = True
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        try:
            if stat.S_ISSOCK(os.lstat(self.path).st_mode):
                os.unlink(self.path)
        except OSError:
            pass


def call(path: str, req: dict, timeout: float = 30.0) -> dict:
    """One ctl round trip (for radctl, tests and the e2e driver)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        s.sendall(json.dumps(req, separators=(",", ":")).encode() + b"\n")
        chunks = []
        while True:
            b = s.recv(1 << 20)
            if not b:
                break
            chunks.append(b)
            if b.endswith(b"\n"):
                break
        return json.loads(b"".join(chunks).decode())
    finally:
        s.close()
