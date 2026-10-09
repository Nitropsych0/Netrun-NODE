"""Dry run of the Linux e2e driver against fake3proxy.py (any OS, no root).

The real run is scripts/test_pergb_radius_e2e.sh (3proxy in a network namespace).
This one exercises the same driver, the socket-activation stand-in and every
restart/timeout path of netrun-radius; only 3proxy itself is simulated.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
import unittest

import rtest

HERE = rtest.HERE


def free_ports(n, step=1):
    for base in range(32000, 60000, 7):
        socks = []
        try:
            for i in range(n):
                for p in (base + i, base + 100 + i):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.bind(("127.0.0.1", p))
                    socks.append(s)
            return base
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()
    raise RuntimeError("no free ports")


class DryRun(unittest.TestCase):
    def test_e2e_driver_against_fake_3proxy(self):
        d = rtest.tmpdir(self)
        secret = os.path.join(d, "radius.secret")
        with open(secret, "wb") as fh:
            fh.write(b"DryRunSecretDryRunSecretDryRunSecretDry1\n")
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind(("127.0.0.1", 0))
        rport = u.getsockname()[1]
        u.close()
        base = free_ports(4)
        ctl_path = os.path.join(d, "ctl.sock")
        pidfile = os.path.join(d, "sockact.pid")
        log = open(os.path.join(d, "radius.log"), "wb")
        self.addCleanup(log.close)
        sa = subprocess.Popen(
            [
                sys.executable,
                "-I",
                os.path.join(HERE, "sockact.py"),
                "--listen",
                "127.0.0.1:%d" % rport,
                "--pidfile",
                pidfile,
                "--",
                sys.executable,
                "-I",
                os.path.join(rtest.RADIUS_DIR, "netrun_radius.py"),
                "--state-dir",
                os.path.join(d, "state"),
                "--secret-file",
                secret,
                "--ctl-socket",
                ctl_path,
                "--no-watchdog",
            ],
            stdout=log,
            stderr=log,
        )
        self.addCleanup(lambda: (sa.poll() is None and sa.send_signal(signal.SIGTERM), sa.wait(15)))
        fake = subprocess.Popen(
            [
                sys.executable,
                "-I",
                os.path.join(HERE, "fake3proxy.py"),
                "--secret-file",
                secret,
                "--base",
                str(base),
                "--count",
                "4",
                "--http-offset",
                "100",
                "--radius",
                "127.0.0.1:%d" % rport,
            ],
            stdout=subprocess.DEVNULL,
        )
        self.addCleanup(lambda: (fake.kill(), fake.wait()))
        for _ in range(100):
            if os.path.exists(pidfile) and os.path.getsize(pidfile) and os.path.exists(ctl_path):
                break
            time.sleep(0.1)
        with open(pidfile) as fh:
            sa_pid = int(fh.read())
        out = os.path.join(d, "out")
        r = subprocess.run(
            [
                sys.executable,
                "-I",
                os.path.join(HERE, "e2e_driver.py"),
                "--ctl",
                ctl_path,
                "--sockact-pid",
                str(sa_pid),
                "--secret-file",
                secret,
                "--base",
                str(base),
                "--count",
                "4",
                "--out",
                out,
                "--no-target",
                "--socks-host",
                "127.0.0.1",
                "--http-host",
                "127.0.0.1",
                "--http-offset",
                "100",
                "--radius",
                "127.0.0.1:%d" % rport,
            ],
            capture_output=True,
            text=True,
            timeout=240,
        )
        sys.stderr.write("\n" + "\n".join("  " + x for x in r.stdout.splitlines() if not x.startswith("ok ")) + "\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(os.path.exists(os.path.join(out, "3proxy_captured.json")))


if __name__ == "__main__":
    unittest.main()
