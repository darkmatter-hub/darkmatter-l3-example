#!/usr/bin/env python3
"""
Step 2 — Register your public key with DarkMatter.

Run after: bash generate-key.sh

This uploads only your PUBLIC key. Your private key never leaves your machine.
DarkMatter stores the public key to verify future L3 signatures.

Usage:
  python register-key.py
"""

import os
import sys
from pathlib import Path

# Load .env
env_path = Path('.env')
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            os.environ.setdefault(k, v)

api_key = os.environ.get('DARKMATTER_API_KEY')
if not api_key:
    print('DARKMATTER_API_KEY not set. Add it to your .env file.')
    sys.exit(1)

pub_key_path = Path('my-signing-key.pub.pem')
if not pub_key_path.exists():
    print('my-signing-key.pub.pem not found.')
    print('Run: bash generate-key.sh')
    sys.exit(1)

try:
    import darkmatter as dm
except ImportError:
    print('darkmatter SDK not found. Install: pip install darkmatter-sdk')
    sys.exit(1)

dm.configure(api_key=api_key)

print('Registering public key with DarkMatter...')
try:
    result = dm.register_signing_key(
        key_id          = 'my-signing-key',
        public_key_path = str(pub_key_path),
        description     = 'L3 example repo key',
    )
    print(f'  key_id:    {result.get("key_id")}')
    print(f'  algorithm: {result.get("algorithm")}')
    print(f'  status:    {result.get("status")}')
    print()
    print('Public key registered.')
    print()
    print('Add to your .env:')
    print()
    print('  DARKMATTER_SIGNING_MODE=customer')
    print('  DARKMATTER_SIGNING_KEY_ID=my-signing-key')
    print(f'  DARKMATTER_SIGNING_KEY_PATH={Path("my-signing-key.pem").resolve()}')
    print()
    print('Then: python commit.py')
except Exception as e:
    print(f'Registration failed: {e}')
    sys.exit(1)
