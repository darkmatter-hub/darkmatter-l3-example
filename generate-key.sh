#!/usr/bin/env bash
# Step 1 — Generate an Ed25519 signing key
# Run this once. Keep my-signing-key.pem secret — never commit it.

set -e

darkmatter keys generate --name my-signing-key

echo ""
echo "Generated:"
echo "  my-signing-key.pem      ← private key (keep secret)"
echo "  my-signing-key.pub.pem  ← public key  (safe to share)"
echo ""
echo "Next:"
echo "  python register-key.py"
