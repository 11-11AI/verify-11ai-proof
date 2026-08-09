# verify-11ai-proof

[![verify-live-proof](https://github.com/11-11AI/verify-11ai-proof/actions/workflows/verify.yml/badge.svg)](https://github.com/11-11AI/verify-11ai-proof/actions/workflows/verify.yml)

**Don't trust the claim. Run the check.**

This repository verifies, on *your* machine, that the [11/11 AI](https://11aiblockchain.com) control plane serves a cryptographically signed governance decision record, with no API key.

**What the endpoint serves.** `/v1/public/evidence` returns the most recent record that carries EA-11 evidence, which is not necessarily the most recent decision. Check `selection.record_age_days` in the response for how old it is. The signature is generated at request time over the stored evidence root, so it attests that the control plane vouches for that root now — not that the decision was signed when it was made.

**What the badge means.** The badge re-runs this script hourly. Green means the Ed25519 signature verified within the last hour. It does **not** mean the post-quantum signatures were checked; by default they are not (see below).

## Run it yourself (30 seconds)

```bash
git clone https://github.com/11-11AI/verify-11ai-proof
cd verify-11ai-proof
pip install -r requirements.txt
python verify.py
```

Expected output:

```
  [jwks]      OK: 1 Ed25519 key(s): ea11-ed25519-public-2026
  [structure] OK: decision, proof_id, execution_id, evidence_root, component hashes
  [ed25519]   OK: signature by ea11-ed25519-public-2026 verifies over ea11_evidence_root
  [ml_dsa]    SKIP: ML-DSA-87 NOT CHECKED here. The envelope reports VALID, which is
              the server's own claim and is not evidence. Install liboqs-python to
              verify it locally.
  [sphincs_plus] SKIP: SLH-DSA-SHA2-128f NOT CHECKED here. ...

  RESULT: PARTIAL — verified Ed25519; NOT CHECKED: ml_dsa, sphincs_plus
```

To check all three, install the post-quantum bindings and re-run:

```bash
pip install liboqs-python
python verify.py
#   RESULT: VERIFIED — Ed25519, ML-DSA-87, SLH-DSA-SHA2-128f
```

## What is actually verified

1. The public **Ed25519** verification key is fetched from the standard JWKS location:
   [`/.well-known/jwks.json`](https://control.11aiblockchain.com/.well-known/jwks.json)
2. A signed **EA-11 evidence record** is fetched from the public, unauthenticated endpoint:
   [`/v1/public/evidence`](https://control.11aiblockchain.com/v1/public/evidence)
3. The Ed25519 signature in the hybrid signature envelope is verified **locally** over the
   EA-11 evidence root (`ea11_evidence_root`, ASCII hex). For this signature the server's
   own `"VALID"` label is ignored — the math is done on your machine.
4. Structural checks: decision, proof id, execution id, and the EA-11 component hashes
   (decision / artifact / execution / audit / lineage root) are present.
5. **Post-quantum — not checked by default.** The envelope also carries ML-DSA and
   SLH-DSA (SPHINCS+) signatures over the same evidence root. Without
   [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) installed, this
   script **does not verify them** and says so; the result is reported as `PARTIAL`.
   The parameter sets are read from the envelope rather than assumed, so the verifier
   cannot drift out of step with a profile change.

## What is NOT verified

Stated plainly, because a verification tool that overstates its coverage is worse than none:

- **The post-quantum signatures, unless you install liboqs-python.** By default they are
  skipped and the result is `PARTIAL`.
- **The post-quantum public keys are not anchored.** They arrive inside the same document
  as the signatures they verify, so they establish internal consistency, not authenticity.
  Only the Ed25519 key is published out of band, in JWKS.
- **The evidence root is not independently derivable.** The rule for deriving
  `ea11_evidence_root` from the published component hashes is not documented, so this
  script cannot confirm the signed root commits to the published decision.
- **Freshness.** The record served may be older than the most recent decision. See
  `selection.record_age_days`.

## Why this exists

Most "AI governance" claims are slideware. This is a live enforcement gateway with a
public verification surface. Every homepage claim at [11aiblockchain.com](https://11aiblockchain.com)
is reproducible against the running control plane — this repo is the reproduction.

- Live proof viewer: <https://control.11aiblockchain.com/proof>
- System status: <https://control.11aiblockchain.com/health>
- Research corpus (54+ DOIs): <https://zenodo.org/communities/11-11-ai/records>
- Doctrine: <https://github.com/11-11AI/execution-governance-doctrine>

## License

MIT (verification tooling only). The 11/11 AI control plane, EA-11 evidence
architecture, and related systems are protected by patent-pending intellectual
property (USPTO Customer No. 229939). Execution Governance™, EA-11™,
Execution Evidence State™.
