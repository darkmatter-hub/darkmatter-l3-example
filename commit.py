#!/usr/bin/env python3
"""
Step 3 — Make an L3 signed commit.

Run after:
  1. darkmatter keys generate --name my-signing-key
  2. darkmatter keys register --key-id my-signing-key --public-key my-signing-key.pub.pem

Usage:
  python commit.py

Output:
  ctx_id       — the commit ID
  verify_url   — share this link to show the L3 NON-REPUDIATION badge
  assurance    — should be "L3"
"""

import os
import sys
import json
from pathlib import Path

# Load .env if present
env_path = Path('.env')
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            os.environ.setdefault(k, v)

# ── Validate required env vars ────────────────────────────────────────────────
required = ['DARKMATTER_API_KEY', 'DARKMATTER_AGENT_ID',
            'DARKMATTER_SIGNING_KEY_ID', 'DARKMATTER_SIGNING_KEY_PATH']
missing  = [k for k in required if not os.environ.get(k)]
if missing:
    print(f'Missing env vars: {", ".join(missing)}')
    print('Add them to your .env file. See README.md for setup.')
    sys.exit(1)

# ── Import SDK ────────────────────────────────────────────────────────────────
try:
    import darkmatter as dm
except ImportError:
    print('darkmatter SDK not found.')
    print('Install: pip install darkmatter-sdk')
    sys.exit(1)

# ── Configure with L3 signing ─────────────────────────────────────────────────
try:
    dm.configure(
        api_key  = os.environ['DARKMATTER_API_KEY'],
        signing  = dm.SigningConfig(
            key_id           = os.environ['DARKMATTER_SIGNING_KEY_ID'],
            private_key_path = os.environ['DARKMATTER_SIGNING_KEY_PATH'],
        ),
    )
except Exception as e:
    print(f'Configuration error: {e}')
    sys.exit(1)

# ── Make an L3 commit ─────────────────────────────────────────────────────────
print('Committing with L3 signing...')

try:
    ctx = dm.commit(
        to_agent_id = os.environ['DARKMATTER_AGENT_ID'],
        payload     = {
            'input':  'Approve refund for order #84721',
            'output': 'Refund approved: $1,240.00 — within 30-day return window',
        },
        metadata    = {
            'model':     'claude-sonnet-4-6',
            'decision':  'refund_approved',
            'amount_usd': 1240.00,
        },
    )
except Exception as e:
    print(f'Commit failed: {e}')
    sys.exit(1)

# ── Results ───────────────────────────────────────────────────────────────────
ctx_id    = ctx.get('id', '')
assurance = ctx.get('assurance_level', 'unknown')
verify    = ctx.get('verify_url', '')

print()
print(f'  ctx_id:          {ctx_id}')
print(f'  assurance_level: {assurance}')
if verify:
    print(f'  verify_url:      {verify}')

if assurance != 'L3':
    print()
    print('WARNING: assurance_level is not L3.')
    print('Check that DARKMATTER_SIGNING_MODE=customer is set in your .env')
    sys.exit(1)

print()
print('L3 commit recorded.')
print()
print(f'Next — export the proof bundle:')
print()
print(f'  curl -H "Authorization: Bearer $DARKMATTER_API_KEY" \\')
print(f'       https://darkmatterhub.ai/api/export/{ctx_id} \\')
print(f'       > bundle.json')
print()
print(f'Then verify offline:')
print()
print(f'  python verify_offline.py bundle.json \\')
print(f'    --public-key my-signing-key.pub.pem')
