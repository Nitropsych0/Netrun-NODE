"""Print the shared per-piece address vectors (A13-I) as JSON.

    python3 -I node_runtime/radius/tests/gen_piece_vectors.py > node_runtime/radius/tests/piece_vectors.json

A piece list's address = prefix48 | (pieceNet << 64) | iid, where iid is the I3
tag of the list id with r16 from
    HMAC_SHA256(k, b"netrun-pergb-pick-r\\0" + b"piece\\0" + list_id(4, big) + b"\\0" + b"\\0" + j(4, big))[0:2]
for the first j = 0, 1, ... whose iid is >= 2^32. The node agent (pergb_tag.js) and
the orchestrator compute the same address from these vectors.
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from tag import IID_MIN, decrypt, encrypt  # noqa: E402

LABEL = b"netrun-pergb-pick-r\x00"
DERIVATION = [
    "addr = prefix48 | (pieceNet << 64) | iid",
    "iid = I3 tag (tag.encrypt) of (listId, r16), the first j = 0, 1, ... with iid >= 2^32",
    "r16 = HMAC_SHA256(key, 'netrun-pergb-pick-r' 00 'piece' 00 listId(4 bytes, big) 00 00 j(4 bytes, big))[0:2]",
]


def piece_iid(key: bytes, list_id: int) -> tuple[int, int, int]:
    """(iid, r16, j) of a piece list."""
    seed = LABEL + b"piece\x00" + list_id.to_bytes(4, "big") + b"\x00" + b"\x00"
    for j in range(64):
        d = hmac.digest(key, seed + j.to_bytes(4, "big"), "sha256")
        r16 = (d[0] << 8) | d[1]
        iid = encrypt(key, list_id, r16)
        if iid >= IID_MIN:
            return iid, r16, j
    raise RuntimeError("no interface id >= 2^32 in 64 draws")


def main():
    cases = []
    for key, prefix in (
        (bytes(range(32)), "2001:db8:aa::/48"),
        (bytes([7]) * 32, "2602:f2dc:a9::/48"),
    ):
        net = ipaddress.IPv6Network(prefix)
        vectors = []
        for list_id, piece_net in (
            (1, 0),
            (2, 1),
            (77, 0x8A3F),
            (4096, 0xFFFE),
            (0xFFFFFFFF, 0x1234),
            (123456, 0x0042),
        ):
            iid, r16, j = piece_iid(key, list_id)
            got, r, ok = decrypt(key, iid)
            assert ok and got == list_id and r == r16
            addr = int(net.network_address) | (piece_net << 64) | iid
            vectors.append(
                {
                    "listId": list_id,
                    "pieceNet": piece_net,
                    "j": j,
                    "r16": r16,
                    "iid": "%016x" % iid,
                    "addr": str(ipaddress.IPv6Address(addr)),
                }
            )
        cases.append({"key": base64.b64encode(key).decode(), "prefix": prefix, "vectors": vectors})
    json.dump({"version": 1, "derivation": DERIVATION, "cases": cases}, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
