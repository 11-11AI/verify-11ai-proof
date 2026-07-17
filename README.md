# verify-11ai-proof

[![verify-live-proof](https://github.com/AtlasQuantumProtocol/verify-11ai-proof/actions/workflows/verify.yml/badge.svg)](https://github.com/AtlasQuantumProtocol/verify-11ai-proof/actions/workflows/verify.yml)

**Don't trust the claim. Run the check.**

This repository verifies, on *your* machine, that the [11/11 AI](https://11aiblockchain.com) control plane is issuing cryptographically signed governance decisions — live, right now, with no API key.

The badge above re-runs the verification against the production endpoint **every hour**. If it is green, the signatures verified within the last hour.

## Run it yourself (30 seconds)

```bash
git clone https://github.com/AtlasQuantumProtocol/verify-11ai-proof
cd verify-11ai-proof
pip install -r requirements.txt
python verify.py
```

Expected output:

```
  [jwks]      OK: 1 Ed25519 key(s): ea11-ed25519-public-2026
  [structure] OK: decision, proof_id, execution_id, evidence_root, component hashes
  [ed25519]   OK: signature by ea11-ed25519-public-2026 verifies over ea11_evidence_root
  [ml_dsa]    SKIP: envelope reports VALID; install liboqs-python to verify locally
  [sphincs_plus] SKIP: envelope reports VALID; install liboqs-python to verify locally

  RESULT: VERIFIED
```

## What is actually verified

1. The public **Ed25519** verification key is fetched from the standard JWKS location:
   [`/.well-known/jwks.json`](https://control.11aiblockchain.com/.well-known/jwks.json)
2. A signed **EA-11 evidence record** is fetched from the public, unauthenticated endpoint:
   [`/v1/public/evidence`](https://control.11aiblockchain.com/v1/public/evidence)
3. The Ed25519 signature in the hybrid signature envelope is verified **locally** over the
   EA-11 evidence root (`ea11_evidence_root`, ASCII hex). The server's own `"VALID"` labels
   are ignored — the math is done on your machine.
4. Structural checks: decision, proof id, execution id, and the EA-11 component hashes
   (decision / artifact / execution / audit / lineage root) are present.
5. **Post-quantum (optional):** the envelope also carries ML-DSA-65 and SLH-DSA (SPHINCS+)
   signatures over the same evidence root. With [liboqs-python](https://github.com/open-quantum-safe/liboqs-python)
   installed, the script verifies those locally too.

## Why this exists

Most "AI governance" claims are slideware. This is a live enforcement gateway with a
public verification surface. Every homepage claim at [11aiblockchain.com](https://11aiblockchain.com)
is reproducible against the running control plane — this repo is the reproduction.

- Live proof viewer: <https://control.11aiblockchain.com/proof>
- System status: <https://control.11aiblockchain.com/health>
- Research corpus (54+ DOIs): <https://zenodo.org/communities/11-11-ai/records>
- Doctrine: <https://github.com/AtlasQuantumProtocol/execution-governance-doctrine>

## License

MIT (verification tooling only). The 11/11 AI control plane, EA-11 evidence
architecture, and related systems are protected by patent-pending intellectual
property (USPTO Customer No. 229939). Execution Governance™, EA-11™,
Execution Evidence State™.
