# darkmatter-l3-example

**A reproducible, offline-verifiable example of DarkMatter L3 non-repudiation.**

Run this yourself. Verify the output without trusting DarkMatter.

---

## What this proves

DarkMatter L3 means every commit is signed with a key **only you hold**, before it reaches DarkMatter's servers.

This repo shows that:

1. The signature was produced by a customer private key
2. DarkMatter cannot forge or alter the record
3. Verification requires only the **public key** and the **exported bundle** — no DarkMatter account, no API calls, no SDK

---

## Prerequisites

- Python 3.8+
- [DarkMatter account](https://darkmatterhub.ai) (free)
- `pip install darkmatter-sdk cryptography`

---

## Quickstart

### Step 1 — Generate a signing key

```bash
darkmatter keys generate --name my-signing-key
```

This creates two files locally:

```
my-signing-key.pem      ← private key — keep secret, never commit
my-signing-key.pub.pem  ← public key  — safe to share
```

Your private key **never leaves your machine**.

---

### Step 2 — Register the public key

```bash
darkmatter keys register \
  --key-id my-signing-key \
  --public-key my-signing-key.pub.pem
```

DarkMatter stores your public key to verify future signatures. The private key is never uploaded.

Add to your `.env`:

```bash
DARKMATTER_API_KEY=dm_sk_...
DARKMATTER_AGENT_ID=dm_...
DARKMATTER_SIGNING_MODE=customer
DARKMATTER_SIGNING_KEY_ID=my-signing-key
DARKMATTER_SIGNING_KEY_PATH=./my-signing-key.pem
```

---

### Step 3 — Make an L3 signed commit

```bash
python commit.py
```

Or directly with the SDK:

```python
import darkmatter as dm

dm.configure(
    api_key = "dm_sk_...",
    signing = dm.SigningConfig(
        key_id           = "my-signing-key",
        private_key_path = "./my-signing-key.pem",
    ),
)

ctx = dm.commit(
    to_agent_id = "dm_...",
    payload     = {
        "input":  "Approve refund for order #84721",
        "output": "Refund approved: $1,240.00",
    },
    metadata = {"model": "claude-sonnet-4-6"},
)

print(ctx["assurance_level"])   # "L3"
print(ctx["verify_url"])        # shows L3 NON-REPUDIATION badge
```

The commit is signed **locally** before being sent. DarkMatter receives an already-signed record.

---

### Step 4 — Export the proof bundle

```bash
curl -H "Authorization: Bearer $DARKMATTER_API_KEY" \
     https://darkmatterhub.ai/api/export/<ctx_id> \
     > bundle.json
```

Replace `<ctx_id>` with the ID printed by `commit.py`.

The bundle contains: payload, metadata, hashes, canonical envelope, and the Ed25519 signature. Everything needed to verify offline.

---

### Step 5 — Verify offline

```bash
python verify_offline.py bundle.json \
  --public-key my-signing-key.pub.pem
```

Expected output:

```
DarkMatter  L3 offline verifier

────────────────────────────────────────────────────

  Trace ID:   ctx_...
  Steps:      1

  Step 1  ctx_...
    ✔ Payload hash      sha256:...
    ✔ Metadata hash     sha256:...
    ✔ Envelope hash     sha256:...
    ✔ Ed25519 signature valid  key_id=my-signing-key

────────────────────────────────────────────────────

  ✔ Hash chain N/A (single commit)

────────────────────────────────────────────────────

  ✔ All checks passed — L3 verified

  This record was signed by a customer-controlled key
  before DarkMatter received it.
  DarkMatter cannot forge this record.
  Verification used only the public key — no DarkMatter dependency.
```

**Zero network calls. Zero DarkMatter dependency. Only math.**

---

## Verify against the included example bundle

Don't have an account? Run against the pre-committed example bundle:

```bash
python verify_offline.py example_bundle.json
```

The bundle was signed with a test key embedded in the bundle itself. All 4 checks pass.

---

## What `verify_offline.py` checks

| Check | What it verifies |
|---|---|
| Payload hash | `SHA-256(canonical_json(payload))` matches the signed envelope |
| Metadata hash | `SHA-256(canonical_json(metadata))` matches the signed envelope |
| Envelope hash | `SHA-256(canonical_json(envelope))` is internally consistent |
| Ed25519 signature | The envelope was signed by the private key corresponding to `public_key` |
| Hash chain | `parent_hash` of each step matches `integrity_hash` of the previous step |

The canonical JSON format is deterministic: keys sorted alphabetically, no whitespace, UTF-8, non-ASCII characters not escaped. Defined in [ENVELOPE_SPEC_V1.md](https://github.com/darkmatter-hub/darkmatter/blob/main/ENVELOPE_SPEC_V1.md).

---

## Files

| File | Purpose |
|---|---|
| `verify_offline.py` | Offline verifier — no SDK, no network, no account |
| `commit.py` | Example L3 commit using the Python SDK |
| `register-key.py` | Register your public key with DarkMatter |
| `generate-key.sh` | Generate an Ed25519 keypair via `darkmatter keys generate` |
| `example_bundle.json` | Pre-signed example bundle — verify without an account |

---

## Dependencies

`verify_offline.py` requires:

- Python 3.8+ (stdlib only for hash checks)
- `pip install cryptography` (for Ed25519 signature verification)

`commit.py` requires:

- `pip install darkmatter-sdk cryptography`

---

## Protocol specification

The L3 signing protocol is fully specified in [`ENVELOPE_SPEC_V1.md`](https://github.com/darkmatter-hub/darkmatter/blob/main/ENVELOPE_SPEC_V1.md) in the main DarkMatter repository.

Test vectors are in [`test-vectors-envelope-v1.json`](https://github.com/darkmatter-hub/darkmatter/blob/main/test-vectors-envelope-v1.json).

Both the Python SDK and the server-side verifier must pass all 3 vectors before any release.

---

## Links

- [DarkMatter](https://darkmatterhub.ai)
- [Integrity model](https://darkmatterhub.ai/integrity)
- [Docs — L3 setup](https://darkmatterhub.ai/docs#l3-setup)
- [Envelope spec](https://github.com/darkmatter-hub/darkmatter/blob/main/ENVELOPE_SPEC_V1.md)
- [Python SDK](https://github.com/darkmatter-hub/darkmatter/tree/main/sdk/python)
