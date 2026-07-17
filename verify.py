#!/usr/bin/env python3
"""verify-11ai-proof — independently verify a live 11/11 AI governance decision.

Fetches the public Ed25519 verification key (JWKS) and a signed evidence
record from the live control plane, then verifies the signature locally.
No API key. No trust in the server's own "VALID" labels — the check is done
on your machine.

What is verified:
  1. JWKS key fetched from /.well-known/jwks.json (the trust anchor).
  2. The hybrid signature envelope's Ed25519 signature over the
     EA-11 evidence root (ASCII hex string of `ea11_evidence_root`).
  3. Envelope key id (kid) matches the JWKS key.
  4. Structural checks: decision, proof_id, execution_id, EA-11 component
     hashes present.
  5. Best-effort: ML-DSA-65 and SLH-DSA (SPHINCS+) signatures if the `oqs`
     (liboqs) bindings are installed. Skipped otherwise — Ed25519 remains
     the classical trust anchor.

Usage:
  pip install cryptography requests
  python verify.py            # human-readable output
  python verify.py --json     # machine-readable, for CI

Exit code 0 = all required checks passed, 1 = failure.
"""

import argparse
import base64
import json
import sys

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE = "https://control.11aiblockchain.com"
JWKS_URL = f"{BASE}/.well-known/jwks.json"
EVIDENCE_URL = f"{BASE}/v1/public/evidence"


def b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def fetch(url: str) -> dict:
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.json()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--evidence-file", help="verify a saved evidence JSON instead of fetching")
    ap.add_argument("--jwks-file", help="use a saved JWKS JSON instead of fetching")
    args = ap.parse_args()

    results = {"endpoint": args.evidence_file or EVIDENCE_URL, "checks": {}, "ok": False}
    ok = True

    # 1. Trust anchor: public key from JWKS
    if args.jwks_file:
        with open(args.jwks_file) as f:
            jwks = json.load(f)
    else:
        jwks = fetch(JWKS_URL)
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
    if args.evidence_file:
        with open(args.evidence_file) as f:
            doc = json.load(f)
    else:
        doc = fetch(EVIDENCE_URL)
    ev = doc.get("ea11_evidence") or doc
    envelope = (
        ev.get("hybrid_signature_envelope")
        or doc.get("hybrid_signature_envelope")
        or {}
    )
    evidence_root = ev.get("ea11_evidence_root") or doc.get("ea11_evidence_root") or ""

    # 3. Structural checks
    decision = (ev.get("decision_state") or {}).get("decision") or doc.get("decision")
    lineage = ev.get("lineage_state", {})
    hashes = ev.get("ea11_component_hashes", {})
    structural = {
        "decision": decision,
        "proof_id": lineage.get("proof_id") or doc.get("proof_id"),
        "execution_id": lineage.get("execution_id") or doc.get("execution_id"),
        "evidence_root": evidence_root[:16] + "…" if evidence_root else None,
        "component_hashes": sorted(hashes.keys()),
    }
    missing = [k for k, v in structural.items() if not v]
    if missing:
        ok = False
        results["checks"]["structure"] = f"FAIL: missing {missing}"
    else:
        results["checks"]["structure"] = f"OK: {structural}"

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
        pub = Ed25519PublicKey.from_public_bytes(b64u(ed_keys[kid]["x"]))
        try:
            pub.verify(b64u(sig_b64), evidence_root.encode("ascii"))
            results["checks"]["ed25519"] = (
                f"OK: signature by {kid} verifies over ea11_evidence_root"
            )
        except InvalidSignature:
            ok = False
            results["checks"]["ed25519"] = "FAIL: Ed25519 signature INVALID"

    # 5. Best-effort post-quantum verification (requires liboqs bindings)
    for name, alg in (("ml_dsa", "ML-DSA-65"), ("sphincs_plus", "SPHINCS+-SHA2-256s-simple")):
        blk = (envelope.get(name) or {}).get("signature") or {}
        pq_sig, pq_pub = blk.get("signature"), blk.get("public_key")
        if not (pq_sig and pq_pub):
            results["checks"][name] = "SKIP: not present in envelope"
            continue
        try:
            import oqs  # type: ignore
        except ImportError:
            results["checks"][name] = (
                f"SKIP: envelope reports {blk.get('status')}; "
                "install liboqs-python to verify locally"
            )
            continue
        try:
            with oqs.Signature(alg) as v:
                valid = v.verify(
                    evidence_root.encode("ascii"), b64u(pq_sig), b64u(pq_pub)
                )
            if valid:
                results["checks"][name] = f"OK: {alg} verifies over ea11_evidence_root"
            else:
                ok = False
                results["checks"][name] = f"FAIL: {alg} signature INVALID"
        except Exception as e:  # unknown parameter set, etc.
            results["checks"][name] = f"SKIP: could not verify locally ({e})"

    results["ok"] = ok
    _emit(results, args)
    return 0 if ok else 1


def _emit(results: dict, args) -> None:
    if args.json:
        print(json.dumps(results, indent=2))
        return
    print(f"\n  verify-11ai-proof — {results['endpoint']}\n")
    for name, outcome in results["checks"].items():
        print(f"  [{name}] {outcome}")
    print(f"\n  RESULT: {'VERIFIED' if results['ok'] else 'FAILED'}\n")


if __name__ == "__main__":
    sys.exit(main())
