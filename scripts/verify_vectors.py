#!/usr/bin/env python3
"""Independent check of docs/test-vectors/*.json against docs/envelope-v0.md and docs/policy-v1.md.

Uses only the Python `cryptography` package (Ed25519, ChaCha20-Poly1305) and a local
HChaCha20 for XChaCha20; shares no code with the Rust implementation.
Usage: python3 scripts/verify_vectors.py [path]
"""
import base64
import hashlib
import json
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def h(person, data):
    return hashlib.blake2b(data, digest_size=32, person=person).digest()


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def hchacha20(key, nonce16):
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))

    def qr(a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def xchacha_open(key, sealed, aad):
    nonce = sealed[:24]
    return ChaCha20Poly1305(hchacha20(key, nonce[:16])).decrypt(b"\0" * 4 + nonce[16:], sealed[24:], aad)


def main(path):
    v = json.load(open(path))
    net = v["network"]
    key = bytes.fromhex(v["envelope_key"])
    assert h(b"zecret-v1-sessid", v["session_secret_utf8"].encode()).hex() == v["session_id"]
    seed = bytes.fromhex(v["signing_key_seed"])
    assert Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw().hex() == v["signing_public_key"]
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(v["signing_public_key"]))
    codes = {"Heartbeat": 1, "Panic": 2, "Rotate": 3, "Cancel": 4, "Recover": 5}
    for c in v["cases"]:
        rec, sealed = bytes.fromhex(c["record"]), bytes.fromhex(c["sealed"])
        assert rec[0] == 1 and rec[1] == net and rec[2] == codes[c["type"]]
        assert rec[3:35].hex() == v["session_id"]
        assert rec[83:115].hex() == v["policy_hash"] and rec[115:147] == b"\0" * 32
        body = len(rec) - 147 - 64
        assert body == (64 if c["type"] in ("Rotate", "Recover") else 0)
        if body:
            assert rec[147:179].hex() == v["new_main_public_key"]
            assert rec[179:211].hex() == v["new_duress_public_key"]
        msg = b"zecret/v1\0" + rec[:-64]
        assert msg.hex() == c["signed_message"]
        pk.verify(rec[-64:], msg)
        assert strict_verify(bytes.fromhex(v["signing_public_key"]), msg, rec[-64:])
        assert h(b"zecret-v1-record", rec).hex() == c["rid"]
        assert len(sealed) == 384 and sealed[:24].hex() == v["nonce"]
        pt = xchacha_open(key, sealed, b"zecret/v1" + bytes([net]))
        assert len(pt) == 344 and pt[: len(rec)] == rec and pt[len(rec):] == b"\0" * (344 - len(rec))
        assert len(c["memo_text"]) == 512 and base64.b64decode(c["memo_text"]) == sealed
        print(f"{c['type']}: layout, signature, rid, XChaCha20-Poly1305, Base64 ok")


# --- Strict Ed25519 (RFC 8032 arithmetic, pure Python) -------------------------------
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
G_Y = 4 * pow(5, P - 2, P) % P


def recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def decode_point(b):
    """Returns (x, y) or None; rejects y >= p and x = 0 with the sign bit (non-canonical)."""
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    return None if x is None else (x, y)


def encode_point(pt):
    x, y = pt
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def add(p1, p2):
    (x1, y1), (x2, y2) = p1, p2
    t = D * x1 * x2 * y1 * y2 % P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, P - 2, P) % P, (y1 * y2 + x1 * x2) * pow(1 - t, P - 2, P) % P)


def mul(k, pt):
    q = (0, 1)
    while k:
        if k & 1:
            q = add(q, pt)
        pt = add(pt, pt)
        k >>= 1
    return q


BASE = (recover_x(G_Y, 0), G_Y)


def small_order(pt):
    return mul(8, pt) == (0, 1)


def strict_verify(pk, msg, sig):
    a = decode_point(pk)
    if a is None or encode_point(a) != pk or small_order(a):
        return False
    r_bytes, s = sig[:32], int.from_bytes(sig[32:], "little")
    r = decode_point(r_bytes)
    if r is None or encode_point(r) != r_bytes or small_order(r) or s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + pk + msg).digest(), "little") % L
    return mul(s, BASE) == add(r, mul(k, a))


def check_strict(path):
    v = json.load(open(path))
    for c in v["cases"]:
        got = strict_verify(bytes.fromhex(c["public_key"]), bytes.fromhex(c["message"]), bytes.fromhex(c["signature"]))
        assert got == c["accept"], f"{c['name']}: expected accept={c['accept']}, got {got}"
        print(f"ed25519 {c['name']}: {'accept' if got else 'reject'} as expected")


# --- PolicyV1 / SetupV1 (docs/policy-v1.md) -------------------------------------------
def x25519_small_order(u):
    """[8]P via the Montgomery ladder; works for points on the curve and on the twist."""
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(4)):
        bit = (8 >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3, z3 = (da + cb) ** 2 % P, x1 * (da - cb) ** 2 % P
        x2, z2 = aa * bb % P, e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return z2 == 0 or x2 * pow(z2, P - 2, P) % P == 0


def check_recipient(k):
    u = int.from_bytes(k, "little")
    assert not (k[31] & 0x80), "bit 255 set"
    assert u < P, "u not reduced"
    assert not x25519_small_order(u), "small order"


def parse_policy(b):
    i = 0
    def take(n):
        nonlocal i
        assert i + n <= len(b), "truncated"
        out = b[i:i + n]; i += n
        return out
    pol = {}
    pol["version"], pol["network"], pol["threshold"], n = take(4)
    assert pol["version"] == 1 and pol["network"] <= 2
    pol["guardians"] = [take(32) for _ in range(n)]
    pol["timeout"], pol["warning"], pol["grace"], pol["max_delay"] = struct.unpack(">4I", take(16))
    pol["confirmations"] = take(1)[0]
    (pol["hard_end"],) = struct.unpack(">I", take(4))
    m = take(1)[0]
    pol["recipients"] = [take(32) for _ in range(m)]
    pol["payload_hash"] = take(32)
    assert 1 <= n <= 16 and 1 <= pol["threshold"] <= n and 1 <= m <= 16
    for keys in (pol["guardians"], pol["recipients"]):
        assert all(a < b_ for a, b_ in zip(keys, keys[1:])), "not strictly ascending"
    for g in pol["guardians"]:
        pt = decode_point(g)
        assert pt and encode_point(pt) == g and not small_order(pt)
    for r in pol["recipients"]:
        check_recipient(r)
    assert min(pol["timeout"], pol["warning"], pol["grace"], pol["max_delay"]) > 0
    assert pol["max_delay"] < pol["timeout"] and pol["confirmations"] >= 1
    pol["w_hard"] = pol["hard_end"] - pol["grace"] - pol["warning"]
    assert pol["w_hard"] >= 0
    return pol, i


def check_policy(path):
    v = json.load(open(path))
    pb = bytes.fromhex(v["policy"])
    pol, used = parse_policy(pb)
    assert used == len(pb), "trailing bytes"
    assert h(b"zecret-v1-policy", pb).hex() == v["policy_hash"]
    assert pol["w_hard"] == v["w_hard"] and pol["hard_end"] - pol["grace"] == v["g_hard"]
    guardians = sorted(
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)).public_key().public_bytes_raw()
        for s in v["guardian_key_seeds"]
    )
    assert pol["guardians"] == guardians

    sb = bytes.fromhex(v["setup"])
    assert sb[0] == 1
    assert sb[1:33] == h(b"zecret-v1-sessid", v["session_secret_utf8"].encode())
    assert sb[33:33 + len(pb)] == pb
    keys = [sb[33 + len(pb) + 32 * k: 33 + len(pb) + 32 * (k + 1)] for k in range(3)]
    assert 33 + len(pb) + 96 == len(sb), "trailing bytes"
    owners = [
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)).public_key().public_bytes_raw()
        for s in v["owner_key_seeds"]
    ]
    assert keys == owners and len(set(keys)) == 3
    for k in keys:
        pt = decode_point(k)
        assert pt and encode_point(pt) == k and not small_order(pt)
    assert h(b"zecret-v1-setup_", sb).hex() == v["setup_id"]
    print(f"policy: layout, profiles, H_pol, W_hard; setup: layout, keys, setup_id ok ({len(pb)} / {len(sb)} bytes)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "docs/test-vectors/envelope-v0.json")
    check_strict(sys.argv[2] if len(sys.argv) > 2 else "docs/test-vectors/ed25519-strict.json")
    check_policy(sys.argv[3] if len(sys.argv) > 3 else "docs/test-vectors/policy-v1.json")
