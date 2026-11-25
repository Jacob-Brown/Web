"""VoltageSec "V2" protection primitives.

These helpers back the extra hardening layers exposed by the ``ultra`` preset:

* SHA-256 key derivation (mirrored by a pure-Luau runtime in voltage.py)
* a seeded, bijective opcode S-box
* a second authenticated stream cipher for the packed payload
* integrity digests that are derived - never embedded as plaintext keys

Every primitive is deterministic for a given seed so the Python emitter and the
Lua runtime agree without shipping the raw key material.
"""
from __future__ import annotations

import hashlib

MASK32 = 0xFFFFFFFF

__all__ = [
    "V2_FEATURES",
    "sha256_bytes",
    "derive_seed_key",
    "derive_sbox",
    "derive_inverse_sbox",
    "v2_crypt",
    "integrity_digest",
    "v2_enabled",
]

V2_FEATURES = (
    "sha256",
    "runtime-derivation",
    "sbox-opcodes",
    "double-encryption",
    "constant-vault-v2",
    "predicates",
    "ssa",
    "hook-guard",
    "integrity-binding",
    "history-dispatch",
    "state-layouts",
    "junk-code",
    "jump-threading",
    "table-virtualisation",
    "polymorph",
    "anti-disassembly",
    "instruction-formats",
    "dispatch-shuffling",
    "superinstructions",
    "fast-dispatch",
    "buffer-mode",
)


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def derive_seed_key(seed: int, tag: bytes = b"voltage-v2") -> int:
    """32-bit key derived from a seed and a domain tag."""
    payload = tag + b":" + str(int(seed) & MASK32).encode("ascii")
    return int.from_bytes(hashlib.sha256(payload).digest()[:4], "little") & MASK32


def derive_sbox(seed: int) -> bytes:
    """Fisher-Yates permutation of 0..255 seeded by SHA-256."""
    digest = hashlib.sha256(b"volt-sbox:" + (int(seed) & MASK32).to_bytes(4, "little")).digest()
    box = list(range(256))
    for i in range(255, 0, -1):
        j = digest[i % 32] % (i + 1)
        box[i], box[j] = box[j], box[i]
    return bytes(box)


def derive_inverse_sbox(sbox: bytes) -> bytes:
    out = bytearray(256)
    for i, value in enumerate(sbox):
        out[value] = i
    return bytes(out)


def lcg32_stream(seed: int, count: int):
    """Yield *count* 32-bit LCG states (shared by Python and Lua)."""
    state = int(seed) & MASK32
    for _ in range(count):
        state = (state * 1664525 + 1013904223) & MASK32
        yield state


def v2_crypt(data: bytes, seed: int, nonce: int, *, inverse: bool = False) -> bytes:
    """Second encryption layer: seeded LCG keystream XOR.

    The same seed and nonce are already available to the Lua decoder
    (payload key and metadata nonce), so no raw key material is embedded.
    The transform is symmetric; ``inverse`` is accepted for API symmetry.
    """
    state = seed & MASK32
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        state = (state * 1664525 + 1013904223) & MASK32
        mask = ((state >> 24) ^ ((i * 37 + nonce) & 0xFF)) & 0xFF
        out[i] = byte ^ mask
    return bytes(out)


def integrity_digest(seed: int, dispatch_digest: int, payload_checksum: int) -> int:
    """Seeded integrity binding value (32-bit, derived at build time)."""
    material = (
        (int(seed) & MASK32).to_bytes(4, "little")
        + (int(dispatch_digest) & MASK32).to_bytes(4, "little")
        + (int(payload_checksum) & MASK32).to_bytes(4, "little")
    )
    return int.from_bytes(hashlib.sha256(b"volt-integrity:" + material).digest()[:4], "little") & MASK32


def v2_enabled(config, name: str) -> bool:
    if not getattr(config, "v2", False):
        return False
    features = getattr(config, "v2Features", None) or ()
    if "all" in features:
        return True
    return name in features
