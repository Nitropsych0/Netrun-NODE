"""Per-GB address tag (frozen interface I3).

The interface id (low 64 bits) of every per-GB source address is a keyed
8-round Feistel permutation of a 64-bit plain block:

    plain = L ‖ R,  L = list_id (32 bits),  R = r16 (16 bits) ‖ mac16 (16 bits)
    mac16 = HMAC_SHA256(k, b"netrun-pergb-mac" + L(4, big) + r16(2, big))[0:2]
    round i = 0..7:  (L, R) = (R, L XOR F(i, R))
    F(i, R) = HMAC_SHA256(k, b"netrun-pergb-tag" + bytes([i]) + R(4, big))[0:4], big-endian
    iid = (L << 32) | R   -- r16 is redrawn while iid < 2**32

Decryption runs the rounds backwards; the tag is valid when the recomputed
mac16 matches, so a random interface id passes with probability 2**-16.
Address = prefix48 | (subnet_id << 64) | iid.

Shared vectors: tests/feistel_vectors.json (also read by the node agent's JS
and by the orchestrator).
"""

from __future__ import annotations

import hmac

MAC_LABEL = b"netrun-pergb-mac"
ROUND_LABEL = b"netrun-pergb-tag"
ROUNDS = 8
IID_MIN = 1 << 32
MASK32 = 0xFFFFFFFF
_ROUND_PREFIX = tuple(ROUND_LABEL + bytes((i,)) for i in range(ROUNDS))


def mac16(key: bytes, list_id: int, r16: int) -> int:
    d = hmac.digest(key, MAC_LABEL + list_id.to_bytes(4, "big") + r16.to_bytes(2, "big"), "sha256")
    return (d[0] << 8) | d[1]


def _f(key: bytes, i: int, r: int) -> int:
    d = hmac.digest(key, _ROUND_PREFIX[i] + r.to_bytes(4, "big"), "sha256")
    return int.from_bytes(d[:4], "big")


def encrypt(key: bytes, list_id: int, r16: int) -> int:
    """Raw Feistel output for (list_id, r16); may be < 2**32 (the caller redraws)."""
    if not 0 <= list_id <= MASK32:
        raise ValueError("list_id out of range")
    if not 0 <= r16 <= 0xFFFF:
        raise ValueError("r16 out of range")
    left = list_id
    right = (r16 << 16) | mac16(key, list_id, r16)
    for i in range(ROUNDS):
        left, right = right, left ^ _f(key, i, right)
    return (left << 32) | right


def decrypt(key: bytes, iid: int) -> tuple[int, int, bool]:
    """Return (list_id, r16, tag_valid) for a 64-bit interface id."""
    if not 0 <= iid < (1 << 64):
        raise ValueError("iid out of range")
    left, right = iid >> 32, iid & MASK32
    for i in range(ROUNDS - 1, -1, -1):
        # forward step: left' = right, right' = left ^ F(i, right)
        left, right = right ^ _f(key, i, left), left
    list_id = left
    r16 = right >> 16
    return list_id, r16, (right & 0xFFFF) == mac16(key, list_id, r16)


class Tagger:
    """Key holder with the hot-path helpers used by the allocator."""

    __slots__ = ("key",)

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError("address key must be 32 bytes")
        self.key = bytes(key)

    def make_iid(self, list_id: int, randbits) -> int:
        """A fresh tagged interface id >= 2**32 for list_id (randbits(16) -> int)."""
        key = self.key
        while True:
            iid = encrypt(key, list_id, randbits(16))
            if iid >= IID_MIN:
                return iid

    def decode(self, iid: int) -> tuple[int, int, bool]:
        return decrypt(self.key, iid)

    def list_of(self, iid: int) -> int | None:
        """list_id when the tag is valid, else None."""
        list_id, _r16, ok = decrypt(self.key, iid)
        return list_id if ok else None
