#!/usr/bin/env bash
# Creates secrets/kek (base64 of 32 random bytes) and prints strong passwords for .env.
# The KEK seals every signing key and secret in the database: back it up OFFLINE. Without it no database
# or backup can be opened (mvp/README.md, "Backup and restore"). Never overwrites an existing KEK.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p secrets
if [ -e secrets/kek ]; then echo "secrets/kek exists, leaving it alone"; else
  (umask 077; openssl rand -base64 32 > secrets/kek)
  echo "wrote secrets/kek (mode 0600). Back it up offline."
fi
for v in POSTGRES_ADMIN_PASSWORD TESSERA_OWNER_PASSWORD TESSERA_APP_PASSWORD; do
  echo "$v=$(openssl rand -hex 24)"
done
echo "Paste the passwords above into .env (hex, so they are safe inside the DSNs)."
