#!/usr/bin/env python3
"""verify-11ai-proof -- independently verify a live 11/11 AI governance decision.

Fetches the public Ed25519 verification key (JWKS) and a signed evidence
record from the live control plane, then verifies the signature locally.
No API key. No trust in the server's own "VALID" labels -- the check is done
on your machine.

What is verified:
  1. JWKS key fetched from /.well-known/jwks.json (the trust anchor).
  2. The hybrid signature envelope's Ed25519 signature over the
     EA-11 evidence root (ASCII hex string of `ea11_evidence_root`).
  3. Envelope key id (kid) matches the JWKS key.
  4. Structural checks: decision, proof_id, execution_id, EA-11 component
     hashes present.
  5. Best-effort: ML-DSA-87 and SLH-DSA (SPHINCS+) signatures if the `oqs`
     (liboqs) bindings are installed. Skipped otherwise -- Ed25519 remains
     the classical trust anchor.

Usage:
  pip install cryptography requests
  python verify.py            # human-readable output
  python verify.py --json     # machine-readable, for CI

Exit code 0 = all required checks passed, 1 = failure.
"""

# Keeps `str | None` style annotations from being evaluated at import time, so
# this runs on Python 3.9 (what macOS ships) and not only on 3.10+. Without it
# the module raised TypeError on import before doing any work, which is the
# worst possible failure for a tool whose entire purpose is that a stranger can
# run it on the machine they already have.
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request

# requests is a convenience, not a requirement. A reviewer who runs this on a
# fresh machine and skips the pip line should get a verification result, not a
# traceback about a missing HTTP library. urllib does the same three GETs.
try:
    import requests
except ImportError:
    requests = None

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    ED25519_BACKEND = "cryptography"
except ImportError:
    Ed25519PublicKey = None
    ED25519_BACKEND = "the bundled RFC 8032 reference implementation"


# --- Ed25519 verification with no dependencies ------------------------------
#
# Added 8 September 2026. A reviewer on Homebrew Python could not run this at
# all: PEP 668 refuses `pip install` outside a virtual environment, so the first
# command of a five minute ask failed before any verification happened. A
# verifier nobody can start verifies nothing.
#
# This is the RFC 8032 section 6 reference implementation, verification only.
# It is used ONLY when the cryptography package is absent, and the output always
# names which implementation checked the signature. There are no secrets here
# and nothing to leak through timing: every input is public, published data.
#
# The two implementations are cross-checked against each other in tests/, over
# valid signatures, tampered signatures, tampered messages and wrong keys.

_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _modp_inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _modp_inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _modp_inv(_D * y * y + 1)
    if x2 % _P == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _modp_inv(5) % _P
_G = (_recover_x(_GY, 0), _GY, 1, _recover_x(_GY, 0) * _GY % _P)


def _pt_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _P
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _P
    C = 2 * P[3] * Q[3] * _D % _P
    D = 2 * P[2] * Q[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _pt_mul(s, P):
    R = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            R = _pt_add(R, P)
        P = _pt_add(P, P)
        s >>= 1
    return R


def _pt_equal(P, Q):
    return ((P[0] * Q[2] - Q[0] * P[2]) % _P == 0
            and (P[1] * Q[2] - Q[1] * P[2]) % _P == 0)


def _pt_decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _ed25519_verify_pure(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _pt_decompress(public)
    if A is None:
        return False
    R = _pt_decompress(sig[:32])
    if R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _Q
    return _pt_equal(_pt_mul(s, _G), _pt_add(R, _pt_mul(h, A)))


def ed25519_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify an Ed25519 signature, preferring the cryptography library."""
    if Ed25519PublicKey is not None:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
            return True
        except Exception:
            return False
    return _ed25519_verify_pure(public, msg, sig)

BASE = "https://control.11aiblockchain.com"
JWKS_URL = f"{BASE}/.well-known/jwks.json"
EVIDENCE_URL = f"{BASE}/v1/public/evidence"
PQ_KEYS_URL = f"{BASE}/v1/public/keys"


# --- EA-11 arithmetic -------------------------------------------------------
#
# Added 8 September 2026 after an independent reviewer pointed out that this
# script checked the Ed25519 signature over ea11_evidence_root and nothing else.
# That proves the server signed *a* value. It does not prove the value describes
# the decision printed above it. The component hashes were decorative.
#
# These functions recompute the evidence from published content, so a signature
# over a root that does not match the record now fails instead of passing.
#
# The canonical form is a port of the JavaScript implementation the records were
# built under: recursive key sort, compact separators, SHA-512 throughout. It is
# not RFC 8785 JCS and it is not json.dumps(sort_keys=True) on numbers. Floats
# are refused rather than guessed, because JavaScript renders 1.0 as "1" and
# Python renders it as "1.0", which would silently fork the chain.

LEAF_ORDER = ("decision_hash", "artifact_hash", "execution_hash",
              "audit_hash", "lineage_root")


class NonCanonical(ValueError):
    """A value whose JSON form differs between JavaScript and Python."""


def canonical_ea11(v):
    if isinstance(v, float):
        raise NonCanonical("float encountered; JavaScript and Python disagree on float JSON")
    if v is None or isinstance(v, (str, int, bool)):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(canonical_ea11(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonical_ea11(v[k])
            for k in sorted(v)) + "}"
    raise NonCanonical("unsupported type " + type(v).__name__)


def _sha512(text: str) -> str:
    return hashlib.sha512(text.encode("utf-8")).hexdigest()


def hash_state(o) -> str:
    return _sha512(canonical_ea11(o))


def merkle_root(leaves: list) -> str:
    if not leaves:
        return _sha512("")
    lvl = list(leaves)
    while len(lvl) > 1:
        lvl = [_sha512(lvl[i] + ":" + (lvl[i + 1] if i + 1 < len(lvl) else lvl[i]))
               for i in range(0, len(lvl), 2)]
    return lvl[0]


def key_bytes(s: str) -> bytes:
    """Decode a key or signature as published.

    The hybrid envelope publishes Ed25519 material base64url encoded and the
    post-quantum material hex encoded. Decoding hex as base64url silently
    yields the wrong bytes at the wrong length (a 2592 byte ML-DSA-87 key
    reads as 3888), so detect rather than assume.
    """
    t = s.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0:
        return bytes.fromhex(t)
    return b64u(t)


# liboqs parameter set names for the algorithms the envelope declares. Keyed on
# the declared algorithm rather than hardcoded, so a profile change cannot leave
# the verifier checking against a parameter set that is no longer deployed.
# Two naming eras. liboqs used "SPHINCS+-SHA2-128f-simple" before SLH-DSA was
# standardised and "SLH_DSA_PURE_SHA2_128F" after, so a verifier hardcoding
# either one silently degrades to SKIP against the other. Both are listed and
# the first one this build actually enables is used.
OQS_NAMES = {
    "ML-DSA-44": ["ML-DSA-44"],
    "ML-DSA-65": ["ML-DSA-65"],
    "ML-DSA-87": ["ML-DSA-87"],
    "SLH-DSA-SHA2-128F": ["SLH_DSA_PURE_SHA2_128F", "SPHINCS+-SHA2-128f-simple"],
    "SLH-DSA-SHA2-128S": ["SLH_DSA_PURE_SHA2_128S", "SPHINCS+-SHA2-128s-simple"],
    "SLH-DSA-SHA2-192F": ["SLH_DSA_PURE_SHA2_192F", "SPHINCS+-SHA2-192f-simple"],
    "SLH-DSA-SHA2-256F": ["SLH_DSA_PURE_SHA2_256F", "SPHINCS+-SHA2-256f-simple"],
    "SLH-DSA-SHA2-256S": ["SLH_DSA_PURE_SHA2_256S", "SPHINCS+-SHA2-256s-simple"],
}


def _enabled_name(candidates: list) -> str | None:
    """The first candidate this liboqs build actually offers."""
    try:
        import oqs  # type: ignore

        available = set(oqs.get_enabled_sig_mechanisms())
    except Exception:
        return candidates[0] if candidates else None
    for c in candidates:
        if c in available:
            return c
    return None


def b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


TIMESTAMP_FIELDS = ("attested_at", "timestamp", "created_at", "decided_at", "issued_at")


def parse_ts(s):
    """Parse an ISO 8601 timestamp, returning None rather than raising."""
    if not isinstance(s, str) or len(s) < 10:
        return None
    try:
        t = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=datetime.timezone.utc)
    return t


def record_age_days(*docs):
    """Age of the record in days, computed here from its own timestamp.

    Searches the record and its nested states for the first parseable
    timestamp, so freshness does not depend on the server volunteering a
    record_age_days field it could simply omit. Returns (days, source).
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    def walk(node, path, depth):
        if depth > 4 or not isinstance(node, dict):
            return None
        for k in TIMESTAMP_FIELDS:
            t = parse_ts(node.get(k))
            if t is not None:
                where = (path + "." + k) if path else k
                return (now - t).total_seconds() / 86400.0, "the record's own " + where
        for k, v in node.items():
            if isinstance(v, dict):
                found = walk(v, (path + "." + k) if path else k, depth + 1)
                if found:
                    return found
        return None

    for d in docs:
        found = walk(d, "", 0)
        if found:
            return found
    return None, None


class Unavailable(Exception):
    """Input could not be retrieved or parsed. Reported, never raised at the user."""


def fetch(url: str) -> dict:
    try:
        if requests is not None:
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            return r.json()
        req = urllib.request.Request(url, headers={"accept": "application/json",
                                                   "user-agent": "verify-11ai-proof"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        raise Unavailable("could not fetch " + url + ": " + str(e)) from e


def load_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise Unavailable("could not read " + path + ": " + str(e)) from e


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--evidence-file", help="verify a saved evidence JSON instead of fetching")
    ap.add_argument("--jwks-file", help="use a saved JWKS JSON instead of fetching")
    ap.add_argument("--pq-keys-file", help="use a saved /v1/public/keys JSON instead of fetching")
    ap.add_argument("--max-age-days", type=float, default=None,
                    help="fail if the record is older than this many days. Freshness is "
                         "otherwise reported but not enforced, because the endpoint serves "
                         "the most recent ATTESTED record, which is not the most recent decision.")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero if ANY check was skipped, not only on failure. "
                         "Use this in CI: without it a green build means the required "
                         "checks passed, not that the full hybrid proof was verified.")
    args = ap.parse_args()

    results = {"endpoint": args.evidence_file or EVIDENCE_URL, "checks": {}, "ok": False,
        "skipped": [],
        "verified": [],
    }
    ok = True

    # 1. Trust anchor: public key from JWKS
    jwks = load_json(args.jwks_file) if args.jwks_file else fetch(JWKS_URL)
    ed_keys = {
        k["kid"]: k for k in jwks.get("keys", [])
        if k.get("kty") == "OKP" and k.get("crv") == "Ed25519"
    }
    if not ed_keys:
        results["checks"]["jwks"] = "FAIL: no Ed25519 key in JWKS"
        _emit(results, args)
        return 1
    results["checks"]["jwks"] = f"OK: {len(ed_keys)} Ed25519 key(s): {', '.join(ed_keys)}"

    # 2. Signed evidence record
    doc = load_json(args.evidence_file) if args.evidence_file else fetch(EVIDENCE_URL)
    ev = doc.get("ea11_evidence") or doc
    envelope = (
        ev.get("hybrid_signature_envelope")
        or doc.get("hybrid_signature_envelope")
        or {}
    )
    evidence_root = ev.get("ea11_evidence_root") or doc.get("ea11_evidence_root") or ""

    # 3. Fields present. A presence check and nothing more. The arithmetic
    #    that actually ties these together is section 3b.
    decision = (ev.get("decision_state") or {}).get("decision") or doc.get("decision")
    lineage = ev.get("lineage_state", {})
    hashes = ev.get("ea11_component_hashes", {})
    structural = {
        "decision": decision,
        "proof_id": lineage.get("proof_id") or doc.get("proof_id"),
        "execution_id": lineage.get("execution_id") or doc.get("execution_id"),
        "evidence_root": evidence_root[:16] + "..." if evidence_root else None,
        "component_hashes": sorted(hashes.keys()),
    }
    missing = [k for k, v in structural.items() if not v]
    if missing:
        ok = False
        results["checks"]["fields_present"] = "FAIL: missing " + str(missing)
    else:
        results["checks"]["fields_present"] = (
            "OK (presence only, not verification): " + str(structural))

    # 3b. The arithmetic. Recompute the evidence from published content so the
    #     signature checked in step 4 is a signature over something this script
    #     has independently reconstructed, not a value taken on trust.
    pairs = [("decision_hash", "decision_state"), ("artifact_hash", "artifact_state"),
             ("execution_hash", "execution_state"), ("audit_hash", "audit_state"),
             ("lineage_root", "lineage_state")]
    try:
        for h, st in pairs:
            claimed, state = hashes.get(h), ev.get(st)
            if not claimed or state is None:
                ok = False
                results["checks"][h] = "FAIL: " + h + " or " + st + " absent"
                continue
            if hash_state(state) == claimed:
                results["checks"][h] = "OK: recomputes from published " + st + " under SHA-512"
            else:
                ok = False
                results["checks"][h] = (
                    "FAIL: " + h + " does NOT match SHA-512 over the published " + st)

        leaves = [hashes.get(k) for k in LEAF_ORDER]
        claimed_mr = ev.get("ea11_merkle_root")
        if all(leaves) and claimed_mr:
            if merkle_root(leaves) == claimed_mr:
                results["checks"]["merkle_root"] = "OK: recomputes from the five component hashes"
            else:
                ok = False
                results["checks"]["merkle_root"] = "FAIL: Merkle root does NOT recompute"
        else:
            ok = False
            results["checks"]["merkle_root"] = "FAIL: leaves or Merkle root absent"

        state_hash = ev.get("ea11_state_hash")
        if not state_hash:
            results["skipped"].append("evidence_root")
            results["checks"]["evidence_root"] = (
                "SKIP: ea11_state_hash is not published on this record, so the evidence "
                "root cannot be recomputed by any party including the issuer. Records "
                "minted before the state hash was retained cannot be backfilled. The "
                "component hashes and Merkle root above DO verify.")
        else:
            rebuilt = hash_state({"ea11_state_hash": state_hash,
                                  "ea11_merkle_root": claimed_mr,
                                  "ea11_component_hashes": hashes})
            if rebuilt == evidence_root:
                results["checks"]["evidence_root"] = (
                    "OK: the signed root recomputes from the published state hash, "
                    "Merkle root and component hashes")
                results["verified"].append("evidence_root")
            else:
                ok = False
                results["checks"]["evidence_root"] = (
                    "FAIL: the signed root does NOT match the published evidence")
    except NonCanonical as e:
        ok = False
        results["checks"]["arithmetic"] = "FAIL: cannot canonicalise (" + str(e) + ")"

    # 3c. Freshness.
    #
    # An independent reviewer noted that a correct signature over an old record
    # verifies exactly like a correct signature over a current one, so a replayed
    # historical record passes. Age is now computed here from the record's own
    # timestamp where one is present, rather than read from the server's
    # record_age_days field, and --max-age-days turns it into a failure.
    #
    # Stated plainly: that timestamp is asserted by the same server that signed
    # the record. Enforcing it detects a stale endpoint, not a lying one. The
    # only third-party freshness anchor in this system is the RFC 3161 timestamp
    # token, which this script does not check.
    sel = doc.get("selection") or {}
    age, age_source = record_age_days(doc, ev)
    if age is None:
        rep = sel.get("record_age_days")
        if isinstance(rep, (int, float)):
            age, age_source = float(rep), "the endpoint's own record_age_days field"

    if age is None:
        results["skipped"].append("freshness")
        results["checks"]["freshness"] = "SKIP: no usable timestamp in the record"
        if args.max_age_days is not None:
            ok = False
            results["checks"]["freshness"] = (
                "FAIL: --max-age-days was given but this record carries no usable "
                "timestamp, so its age cannot be checked. Refusing to pass a "
                "freshness check that was not performed.")
    else:
        results["record_age_days"] = round(age, 2)
        results["record_age_source"] = age_source
        note = "" if sel.get("is_most_recent_record", True) else (
            " NOT the newest record: newer governed decisions exist that carry no "
            "EA-11 evidence. See /v1/public/proof-ledger evidence_coverage.")
        if args.max_age_days is not None and age > args.max_age_days:
            ok = False
            results["checks"]["freshness"] = (
                "FAIL: record is " + str(round(age, 2)) + " day(s) old, older than the "
                + str(args.max_age_days) + " day limit you set. A valid signature over a "
                "historical record is not evidence that the system is deciding "
                "anything today." + note)
        else:
            results["checks"]["freshness"] = (
                ("OK: record is " if age <= 7 else "NOTE: record is ")
                + str(round(age, 2)) + " day(s) old (from " + age_source + ")."
                + (" Within the " + str(args.max_age_days) + " day limit you set."
                   if args.max_age_days is not None else "")
                + note)

    # 4. Ed25519 signature over the evidence root (ASCII hex)
    ed = (envelope.get("ed25519") or {}).get("signature") or {}
    kid = ed.get("kid", "")
    sig_b64 = ed.get("signature", "")
    if kid not in ed_keys:
        ok = False
        results["checks"]["ed25519"] = f"FAIL: envelope kid {kid!r} not in JWKS"
    elif not sig_b64 or not evidence_root:
        ok = False
        results["checks"]["ed25519"] = "FAIL: signature or evidence root absent"
    else:
        if ed25519_verify(b64u(ed_keys[kid]["x"]),
                          evidence_root.encode("ascii"),
                          b64u(sig_b64)):
            results["checks"]["ed25519"] = (
                "OK: signature by " + kid + " verifies over ea11_evidence_root"
                " (checked by " + ED25519_BACKEND + ")"
            )
        else:
            ok = False
            results["checks"]["ed25519"] = "FAIL: Ed25519 signature INVALID"
    results["ed25519_backend"] = ED25519_BACKEND

    # 4b. The published post-quantum keys.
    #
    # Added 8 September 2026 after an independent security review found that the
    # PQ algorithm, signature AND public key all arrive inside the same unsigned
    # envelope. Verifying a signature against a key supplied by whoever supplied
    # the signature proves internal consistency and nothing about who signed.
    # With liboqs installed, an altered document carrying a matching
    # attacker-generated pair produced a full VERIFIED headline.
    #
    # 11/11 AI's own doctrine 05 already states the rule this script was not
    # following: pin from the published endpoint, never from the document.
    pq_published = None
    pq_source = None
    try:
        pq_published = load_json(args.pq_keys_file) if args.pq_keys_file else fetch(PQ_KEYS_URL)
        pq_source = args.pq_keys_file or PQ_KEYS_URL
        results["checks"]["pq_key_source"] = "OK: published PQ keys retrieved from " + pq_source
    except Unavailable as e:
        results["checks"]["pq_key_source"] = (
            "SKIP: could not retrieve the published PQ keys (" + str(e) + "). "
            "Post-quantum signatures will NOT be checked, because verifying them "
            "against keys from the same document proves nothing about the signer.")
        results["skipped"].append("pq_key_source")
    pq_published_text = json.dumps(pq_published) if pq_published else ""

    # 5. Post-quantum verification. Skipped unless liboqs bindings are present.
    #    A skip is recorded as a skip and is never folded into the headline
    #    result: the point of this tool is to check, not to relay the server's
    #    own labels.
    for name in ("ml_dsa", "sphincs_plus"):
        blk = (envelope.get(name) or {}).get("signature") or {}
        pq_sig, pq_pub = blk.get("signature"), blk.get("public_key")
        declared = str(blk.get("algorithm") or "").strip()
        if not (pq_sig and pq_pub):
            results["skipped"].append(name)
            results["checks"][name] = "SKIP: not present in envelope"
            continue

        # The key must appear at the published endpoint. An unanchored key can
        # only ever demonstrate that the document agrees with itself.
        if not pq_published_text:
            results["skipped"].append(name)
            results["checks"][name] = (
                "SKIP: " + declared + " NOT CHECKED. The published key endpoint was "
                "unavailable, and the public key in this envelope cannot authenticate "
                "the signature beside it.")
            continue
        if pq_pub not in pq_published_text:
            ok = False
            results["checks"][name] = (
                "FAIL: the " + declared + " public key in this record does NOT appear at "
                + str(pq_source) + ". Refusing to verify a signature against a key supplied "
                "by the same document. This is what an attacker-substituted key pair looks like.")
            continue

        candidates = OQS_NAMES.get(declared.upper())
        alg = _enabled_name(candidates) if candidates else None
        if alg is None:
            results["skipped"].append(name)
            results["checks"][name] = (
                f"SKIP: envelope declares {declared!r}, which this verifier "
                "does not know how to check"
            )
            continue

        try:
            import oqs  # type: ignore
        except ImportError:
            results["skipped"].append(name)
            results["checks"][name] = (
                f"SKIP: {declared} NOT CHECKED here. The envelope reports "
                f"{blk.get('status')}, which is the server's own claim and is "
                "not evidence. Install liboqs-python to verify it locally."
            )
            continue

        try:
            with oqs.Signature(alg) as v:
                valid = v.verify(
                    evidence_root.encode("ascii"),
                    key_bytes(pq_sig),
                    key_bytes(pq_pub),
                )
            if valid:
                results["checks"][name] = (
                    "OK: " + declared + " verifies over ea11_evidence_root, against the key "
                    "published at " + str(pq_source) + " (not the copy embedded in this record)"
                )
                results["verified"].append(declared)
            else:
                ok = False
                results["checks"][name] = f"FAIL: {declared} signature INVALID"
        except Exception as e:  # unknown parameter set, bad encoding, etc.
            results["skipped"].append(name)
            results["checks"][name] = f"SKIP: could not verify locally ({e})"

    # "ok" means every REQUIRED check passed. It does not mean everything was
    # checked. A reviewer pointed out that a green CI badge on a PARTIAL result
    # reads as "the hybrid proof verified", which it does not. "complete" is the
    # field that answers that, and --strict makes the exit code answer it too.
    results["ok"] = ok
    results["complete"] = ok and not results["skipped"]
    results["skipped_count"] = len(results["skipped"])
    _emit(results, args)
    if not ok:
        return 1
    if args.strict and results["skipped"]:
        return 2
    return 0


def _emit(results: dict, args) -> None:
    if args.json:
        print(json.dumps(results, indent=2))
        return
    print(f"\n  verify-11ai-proof -- {results['endpoint']}\n")
    for name, outcome in results["checks"].items():
        print(f"  [{name}] {outcome}")
    if not results["ok"]:
        print("\n  RESULT: FAILED\n")
        return

    checked = ["Ed25519", "component hashes", "Merkle root"] + list(results.get("verified", []))
    skipped = results.get("skipped", [])
    if skipped:
        # Never a bare VERIFIED while something went unchecked. The point of
        # this tool is that it does the math rather than relaying the server's
        # labels, so it must say which math it actually did.
        tail = (
            "\n  Exit code is 2 because you passed --strict and the run was not"
            "\n  complete. Every required check passed; these were not performed."
            if args.strict else
            "\n  Exit code is 0 because every required check passed. It is NOT a"
            "\n  statement that the full hybrid proof verified. Run with --strict"
            "\n  to make an unchecked item exit non-zero, which is what you want"
            "\n  behind a CI badge."
        )
        print(
            "\n  RESULT: PARTIAL"
            "\n    verified    : " + ", ".join(checked) +
            "\n    NOT CHECKED : " + ", ".join(skipped) +
            "\n" + tail + "\n"
        )
    else:
        print("\n  RESULT: VERIFIED -- " + ", ".join(checked) + "\n")


if __name__ == "__main__":
    # Fail closed and legibly. A verifier that answers a network blip with a
    # Python traceback has told the reader nothing about the thing being verified.
    try:
        sys.exit(main())
    except Unavailable as e:
        print("\n  RESULT: FAILED -- " + str(e) + "\n")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print("\n  RESULT: FAILED -- unexpected error: "
              + type(e).__name__ + ": " + str(e) + "\n")
        sys.exit(1)
