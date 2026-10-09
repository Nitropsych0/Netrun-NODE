#!/usr/bin/python3 -I
"""Operator CLI for the netrun-radius ctl socket.

    python3 -I /opt/netrun/radius/radctl.py status
    python3 -I /opt/netrun/radius/radctl.py rejects
    python3 -I /opt/netrun/radius/radctl.py bindings '{"after": 0, "limit": 20}'
    python3 -I /opt/netrun/radius/radctl.py --socket /run/netrun-radius/ctl.sock raw '{"op": "logins"}'

Read-only ops are safe at any time. State-changing ops (facts, snapshot, apply,
excluded, reserve_nets, release_nets, local_block, admission) belong to the node
agent; use them by hand only in a runbook.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ctl import DEFAULT_PATH, call  # noqa: E402


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--socket", default=os.environ.get("NETRUN_RADIUS_CTL", DEFAULT_PATH))
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("op", help="ctl op name, or 'raw' to send the JSON argument as is")
    p.add_argument("args", nargs="?", default="{}", help="JSON object with the op arguments")
    a = p.parse_args(argv)
    try:
        extra = json.loads(a.args)
    except ValueError as e:
        print("bad JSON: %s" % e, file=sys.stderr)
        return 2
    if not isinstance(extra, dict):
        print("arguments must be a JSON object", file=sys.stderr)
        return 2
    req = extra if a.op == "raw" else dict(extra, op=a.op)
    try:
        reply = call(a.socket, req, a.timeout)
    except OSError as e:
        print("cannot reach %s: %s" % (a.socket, e), file=sys.stderr)
        return 3
    json.dump(reply, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 1 if isinstance(reply, dict) and "error" in reply else 0


if __name__ == "__main__":
    sys.exit(main())
