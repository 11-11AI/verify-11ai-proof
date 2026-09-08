#!/usr/bin/env python3
"""Cross-check the bundled RFC 8032 verifier against the cryptography library.

The bundled implementation is only reached when cryptography is absent, which
is exactly when nobody is watching. So it is checked here over valid
signatures, tampered signatures, tampered messages, wrong keys, truncated
input, and the RFC 8032 section 7.1 test vectors.

A single disagreement is a failure. A pure-Python verifier that says VERIFIED
where the reference library says INVALID is worse than no verifier at all.
"""
import importlib.util, os, secrets, sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "v", os.path.join(HERE, "..", "verify.py"))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

assert v.Ed25519PublicKey is not None, "cryptography must be present to cross-check"


def lib_verify(pub, msg, sig):
    try:
        v.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except Exception:
        return False


def flip(b, i):
    a = bytearray(b)
    a[i % len(a)] ^= 0x01
    return bytes(a)


disagreements = []
counts = {"valid": 0, "tampered_sig": 0, "tampered_msg": 0, "wrong_key": 0,
          "truncated": 0}

for n in range(300):
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw)
    msg = secrets.token_bytes(1 + (n % 200))
    sig = sk.sign(msg)

    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    cases = [
        ("valid", pub, msg, sig),
        ("tampered_sig", pub, msg, flip(sig, n)),
        ("tampered_msg", pub, flip(msg, n), sig),
        ("wrong_key", other, msg, sig),
        ("truncated", pub, msg, sig[:63]),
    ]
    for label, p, m, s in cases:
        a = lib_verify(p, m, s)
        b = v._ed25519_verify_pure(p, m, s)
        counts[label] += 1
        if a != b:
            disagreements.append((n, label, a, b))
        # sanity: the outcome must be what the case name says
        if label == "valid" and not a:
            disagreements.append((n, "valid-but-library-rejected", a, b))
        if label != "valid" and a:
            disagreements.append((n, label + "-but-library-accepted", a, b))

# RFC 8032 section 7.1 test vectors (public key, message, signature), hex.
VECTORS = [
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]
for pk_h, msg_h, sig_h in VECTORS:
    p, m, s = bytes.fromhex(pk_h), bytes.fromhex(msg_h), bytes.fromhex(sig_h)
    if not v._ed25519_verify_pure(p, m, s):
        disagreements.append(("rfc8032", pk_h[:16], True, False))
    if not lib_verify(p, m, s):
        disagreements.append(("rfc8032-lib", pk_h[:16], True, False))
    if v._ed25519_verify_pure(p, m, flip(s, 40)):
        disagreements.append(("rfc8032-tampered-accepted", pk_h[:16], False, True))

print("cases run:", counts, "+", len(VECTORS), "RFC 8032 vectors")
if disagreements:
    print("DISAGREEMENTS:", len(disagreements))
    for d in disagreements[:20]:
        print("   ", d)
    sys.exit(1)
print("the two implementations agree on every case, and both accept the RFC 8032 vectors")
