#!/usr/bin/env bash
# Regenerates the SOPS/age test fixture with a THROWAWAY key (test-only, committed on purpose).
set -euo pipefail
cd "$(dirname "$0")"
age-keygen -o test.age.key 2>/dev/null
PUB=$(grep -o 'age1[a-z0-9]*' test.age.key | head -1)
printf 'DB_URL=postgres://u:p@h/db\nsecret=forge\n' > plain.env
sops -e --age "$PUB" --input-type binary --output-type binary plain.env > fixture.env.sops
rm plain.env
echo "fixture for $PUB"
