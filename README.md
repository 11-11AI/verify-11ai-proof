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
python3 verify.py
```

**No `pip install`.** Nothing to install, no virtual environment, no `sudo`.
Python 3.9 or newer, which includes the `python3` already on macOS. Tested on
3.9, 3.12 and 3.13, on macOS, Linux and Windows.

That is deliberate. An earlier version required `cryptography` and `requests`,
and a reviewer on Homebrew Python could not get past the first command, because
PEP 668 refuses system-wide installs. HTTP now uses the standard library, and
Ed25519 verification falls back to the RFC 8032 reference implementation
bundled in `verify.py`. The output always names which implementation checked
the signature.

If you would rather the signature were checked by a library you already trust,
install `cryptography` and it will be preferred automatically:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 verify.py
```

The bundled implementation is cross-checked against `cryptography` over 1500
cases and the RFC 8032 section 7.1 test vectors. Run that yourself:

```bash
python3 tests/test_ed25519_reference.py
```

Two flags matter if you are running this in CI rather than reading it:

```bash
python3 verify.py --strict --max-age-days 7
```

`--strict` exits non-zero when any check was **skipped**, not only when one
failed, so a green build means the full proof was checked rather than the
subset your machine could reach. `--max-age-days` fails when the served record
is older than the limit, because a valid signature over a historical record is
not evidence that the system is deciding anything today.

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
python3 -m venv .venv && source .venv/bin/activate
pip install liboqs-python
python3 verify.py
#   RESULT: VERIFIED: Ed25519, ML-DSA-87, SLH-DSA-SHA2-128f
```

The virtual environment is needed here because `liboqs-python` builds native
code and most current Python installations refuse system-wide installs. This is
the only part of the tool that asks you to install anything, and skipping it
costs you the two post-quantum checks, not the whole verification.

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
- **The identity of the signer.** JWKS is served from the same origin as the evidence,
  so whoever controls that origin controls both the record and the key that validates
  it. This script proves the record is internally consistent and signed by the key that
  domain publishes. It does not prove that key belongs to 11/11 AI. Pin the key
  fingerprint from a channel that is not `control.11aiblockchain.com` if that matters
  to you, and it should.
- **Independent freshness.** Age is computed from the record's own timestamp, which is
  asserted by the same server that signed the record. `--max-age-days` detects a stale
  endpoint, not a lying one. The RFC 3161 timestamp token is the third-party anchor and
  this script does not check it.
- **Records minted before 5 September 2026.** Seven of them do not carry
  `ea11_state_hash`, so their evidence root cannot be recomputed by anyone, including
  11/11 AI. The script reports this as a skip and never as a pass.

Three items previously listed here were fixed on 8 September 2026 after an independent
review: the component hashes and Merkle root are now recomputed rather than displayed,
the evidence root is derived from published content, and post-quantum public keys are
checked against `/v1/public/keys` instead of the copy embedded in the record.

## Why this exists

Most "AI governance" claims are slideware. This is a live enforcement gateway with a
public verification surface. Every homepage claim at [11aiblockchain.com](https://11aiblockchain.com)
is reproducible against the running control plane — this repo is the reproduction.

- Live proof viewer: <https://control.11aiblockchain.com/proof>
- System status: <https://control.11aiblockchain.com/health>
- Research corpus: <https://zenodo.org/communities/11-11-ai/records>
- Doctrine: <https://github.com/11-11AI/execution-governance-doctrine>

## License

MIT (verification tooling only). The 11/11 AI control plane, EA-11 evidence
architecture, and related systems are protected by patent-pending intellectual
property. Execution Governance™, EA-11™,
Execution Evidence State™.
