"""Regenerate feistel_vectors.json (the I3 shared fixture) from an independent
reference implementation written straight from the interface text.

    python3 -I node_runtime/radius/tests/gen_feistel_vectors.py > node_runtime/radius/tests/feistel_vectors.json

Consumers: node_runtime/radius (python), the node agent (JS, L3), the orchestrator
(python, L5/L6). Do not edit the JSON by hand.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import random
import sys


def ref_mac16(k: bytes, L: int, r16: int) -> int:
    h = hmac.new(k, b"netrun-pergb-mac" + L.to_bytes(4, "big") + r16.to_bytes(2, "big"), hashlib.sha256).digest()
    return int.from_bytes(h[:2], "big")


def ref_F(k: bytes, i: int, R: int) -> int:
    h = hmac.new(k, b"netrun-pergb-tag" + bytes([i]) + R.to_bytes(4, "big"), hashlib.sha256).digest()
    return int.from_bytes(h[:4], "big")


def ref_encrypt(k: bytes, list_id: int, r16: int) -> int:
    L = list_id
    R = (r16 << 16) | ref_mac16(k, list_id, r16)
    for i in range(8):
        L, R = R, L ^ ref_F(k, i, R)
    return (L << 32) | R


def ref_decrypt(k: bytes, iid: int):
    L, R = iid >> 32, iid & 0xFFFFFFFF
    for i in reversed(range(8)):
        R_prev = L
        L_prev = R ^ ref_F(k, i, R_prev)
        L, R = L_prev, R_prev
    list_id, r16, mac = L, R >> 16, R & 0xFFFF
    return list_id, r16, mac == ref_mac16(k, list_id, r16)


def build() -> dict:
    keys = [bytes(range(32)), hashlib.sha256(b"netrun-pergb test key 2").digest()]
    list_ids = [0, 1, 42, 900000001 & 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 123456789]
    r16s = [0, 1, 0x1234, 0xBEEF, 0xFFFF]
    vectors = []
    for k in keys:
        for lid in list_ids:
            for r16 in r16s:
                iid = ref_encrypt(k, lid, r16)
                assert ref_decrypt(k, iid) == (lid, r16, True)
                vectors.append(
                    {
                        "keyB64": base64.b64encode(k).decode(),
                        "keyHex": k.hex(),
                        "listId": lid,
                        "r16": r16,
                        "mac16": ref_mac16(k, lid, r16),
                        "iid": "%016x" % iid,
                        "iidAccepted": iid >= (1 << 32),
                    }
                )
    rng = random.Random(20261009)
    prefix = ipaddress.IPv6Network("2001:db8:aa::/48")
    addresses = []
    for k in keys:
        for lid, r16, subnet in [
            (42, 0x1234, 0x0000),
            (42, 0x0001, 0x8000),
            (7, 0xFFFF, 0xFFFE),
            (0xFFFFFFFF, 0x00AA, 0x1F2E),
        ]:
            iid = ref_encrypt(k, lid, r16)
            addr = ipaddress.IPv6Address(int(prefix.network_address) | (subnet << 64) | iid)
            addresses.append(
                {
                    "keyB64": base64.b64encode(k).decode(),
                    "prefix": str(prefix),
                    "subnet": subnet,
                    "subnetHex": "%04x" % subnet,
                    "listId": lid,
                    "r16": r16,
                    "iid": "%016x" % iid,
                    "addr": str(addr),
                }
            )
    invalid = []
    for k in keys:
        while len([v for v in invalid if v["keyB64"] == base64.b64encode(k).decode()]) < 8:
            iid = rng.getrandbits(64)
            lid, r16, ok = ref_decrypt(k, iid)
            if ok:
                continue
            invalid.append(
                {
                    "keyB64": base64.b64encode(k).decode(),
                    "iid": "%016x" % iid,
                    "listId": lid,
                    "r16": r16,
                    "tagValid": False,
                }
            )
    return {
        "format": "netrun-pergb-feistel-v1",
        "spec": (
            "I3: plain = listId(32) || r16(16) || mac16(16); mac16 = HMAC_SHA256(k, 'netrun-pergb-mac' || listId(4,BE) || "
            "r16(2,BE))[0:2]; 8 rounds i=0..7: (L,R) = (R, L xor F(i,R)), F(i,R) = HMAC_SHA256(k, 'netrun-pergb-tag' || "
            "byte(i) || R(4,BE))[0:4] as BE uint32; iid = L<<32 | R; r16 is redrawn while iid < 2^32 (iidAccepted=false); "
            "addr = prefix48 | subnet<<64 | iid; decrypt runs the rounds backwards, tagValid = recomputed mac16 matches."
        ),
        "vectors": vectors,
        "addresses": addresses,
        "invalid": invalid,
    }


if __name__ == "__main__":
    json.dump(build(), sys.stdout, indent=1)
    sys.stdout.write("\n")
