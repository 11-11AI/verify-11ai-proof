#!/usr/bin/env python3
"""Check the Ed25519 implementation bundled in verify.py.

verify.py falls back to an RFC 8032 reference implementation when the
cryptography package is absent, which is exactly when nobody is watching. A
pure-Python verifier that says VERIFIED where a real library says INVALID is
worse than no verifier at all, so it is checked here.

Runs in two modes, and says which one it used:

  Without cryptography (no installs needed)
      The RFC 8032 section 7.1 test vectors must be ACCEPTED, and several
      hundred mutations of them, plus cross-vector key and signature swaps,
      must be REJECTED.

  With cryptography installed
      Everything above, plus a differential test: 300 freshly generated
      keypairs over valid signatures, tampered signatures, tampered messages,
      wrong keys and truncated input. Any single disagreement is a failure.

    python3 tests/test_ed25519_reference.py
    python3 -m venv .venv && source .venv/bin/activate && pip install cryptography
    python3 tests/test_ed25519_reference.py     # now also differential
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("v", os.path.join(HERE, "..", "verify.py"))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

pure = v._ed25519_verify_pure
failures = []


def check(condition, label):
    if not condition:
        failures.append(label)


def flip(b, i):
    a = bytearray(b)
    a[i % len(a)] ^= 0x01
    return bytes(a)


# --- RFC 8032 section 7.1 test vectors. No dependencies. --------------------

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
V = [(bytes.fromhex(a), bytes.fromhex(b), bytes.fromhex(c)) for a, b, c in VECTORS]

vector_cases = 0
for n, (pub, msg, sig) in enumerate(V):
    check(pure(pub, msg, sig), f"vector {n}: a known-good RFC 8032 signature was REJECTED")
    vector_cases += 1

    # Every single-bit mutation of the signature must be rejected.
    for i in range(len(sig)):
        check(not pure(pub, msg, flip(sig, i)),
              f"vector {n}: signature with bit {i} flipped was ACCEPTED")
        vector_cases += 1

    # Every single-bit mutation of the public key must be rejected.
    for i in range(len(pub)):
        check(not pure(flip(pub, i), msg, sig),
              f"vector {n}: public key with bit {i} flipped was ACCEPTED")
        vector_cases += 1

    # Mutating the message must be rejected (the empty-message vector has no
    # byte to flip, so append instead).
    check(not pure(pub, flip(msg, 0) if msg else b"\x00", sig),
          f"vector {n}: altered message was ACCEPTED")
    vector_cases += 1

    # Truncated and over-long signatures must be rejected, not crash.
    check(not pure(pub, msg, sig[:63]), f"vector {n}: truncated signature ACCEPTED")
    check(not pure(pub, msg, sig + b"\x00"), f"vector {n}: over-long signature ACCEPTED")
    check(not pure(pub[:31], msg, sig), f"vector {n}: truncated public key ACCEPTED")
    vector_cases += 3

# Malleability. A signature is (R, s) with s reduced mod the group order q.
# Adding q to s leaves the verification equation satisfied unless the verifier
# explicitly rejects s >= q, so a verifier missing that one line accepts a
# second, different signature for the same message and key. Random testing
# never produces this input, so it is constructed here.
#
# This case was added after deliberately deleting the s >= q check from
# verify.py and finding that every other test in this file still passed.
Q = 2 ** 252 + 27742317777372353535851937790883648493
for n, (pub, msg, sig) in enumerate(V):
    s_int = int.from_bytes(sig[32:], "little")
    for k in (1, 2):
        mall = sig[:32] + (s_int + k * Q).to_bytes(32, "little")
        check(not pure(pub, msg, mall),
              f"vector {n}: malleated signature with s+{k}q was ACCEPTED "
              "(the s >= q canonicality check is missing)")
        vector_cases += 1

# Cross-vector swaps: right key, wrong signature, and the reverse.
for a in range(len(V)):
    for b in range(len(V)):
        if a == b:
            continue
        check(not pure(V[a][0], V[a][1], V[b][2]),
              f"vectors {a}/{b}: another vector's signature was ACCEPTED")
        check(not pure(V[b][0], V[a][1], V[a][2]),
              f"vectors {a}/{b}: another vector's public key was ACCEPTED")
        vector_cases += 2

print(f"RFC 8032 vectors: {vector_cases} cases, no installs required")

# --- Differential test against cryptography, when it is available ----------

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    print("differential test  : SKIPPED, the cryptography package is not installed.")
    print("                     Install it to compare the two implementations directly:")
    print("                     python3 -m venv .venv && source .venv/bin/activate")
    print("                     pip install cryptography")
    if failures:
        print(f"\nFAILURES: {len(failures)}")
        for f in failures[:20]:
            print("   ", f)
        sys.exit(1)
    print("\nthe bundled implementation accepts every RFC 8032 vector and rejects "
          "every mutation of them")
    sys.exit(0)


def lib_verify(pub, msg, sig):
    try:
        v.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except Exception:
        return False


import secrets  # noqa: E402  (only needed on this path)

for pub, msg, sig in V:
    check(lib_verify(pub, msg, sig), "cryptography rejected an RFC 8032 vector")

counts = {"valid": 0, "tampered_sig": 0, "tampered_msg": 0, "wrong_key": 0,
          "truncated": 0}
disagreements = []

for n in range(300):
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw)
    msg = secrets.token_bytes(1 + (n % 200))
    sig = sk.sign(msg)
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    for label, p, m, s in [
        ("valid", pub, msg, sig),
        ("tampered_sig", pub, msg, flip(sig, n)),
        ("tampered_msg", pub, flip(msg, n), sig),
        ("wrong_key", other, msg, sig),
        ("truncated", pub, msg, sig[:63]),
    ]:
        counts[label] += 1
        a, b = lib_verify(p, m, s), pure(p, m, s)
        if a != b:
            disagreements.append((n, label, "cryptography=" + str(a), "bundled=" + str(b)))
        if label == "valid" and not a:
            disagreements.append((n, "valid signature rejected by cryptography", a, b))
        if label != "valid" and a:
            disagreements.append((n, label + " accepted by cryptography", a, b))

print("differential test  :", counts)

if failures or disagreements:
    print(f"\nFAILURES: {len(failures)} vector, {len(disagreements)} differential")
    for f in failures[:10]:
        print("   ", f)
    for d in disagreements[:10]:
        print("   ", d)
    sys.exit(1)

print("\nthe two implementations agree on every case, and both accept the "
      "RFC 8032 vectors")
