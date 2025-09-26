#!/usr/bin/env bash
set -euo pipefail

# Requisito: python3 presente. Installa git-filter-repo se manca.
if ! command -v git-filter-repo >/dev/null 2>&1; then
  python3 -m pip install --user git-filter-repo >/dev/null
  export PATH="$HOME/.local/bin:$PATH"
fi

# Restiamo sul tuo ramo di lavoro locale
git rev-parse --verify canbus-internal >/dev/null

# Costruisci le regole di sostituzione (rimuove blocchi PEM ovunque)
tmprep="$(mktemp)"
cat > "$tmprep" <<'TXT'
regex:(?s)"[REMOVED CERTIFICATE]\\n?"==>""
regex:(?s)"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.*?-----END (?:RSA |EC )?PRIVATE KEY-----\\n?"==>""
regex:(?s)[REMOVED CERTIFICATE]==>[REMOVED CERTIFICATE]
regex:(?s)-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.+?-----END (?:RSA |EC )?PRIVATE KEY-----==>[REMOVED KEY]
TXT

# Crea/aggiorna un ramo COPIA solo locale
git branch -f canbus-sanitized canbus-internal

# Riscrivi la STORIA della copia (non tocca il working tree)
git filter-repo --force --replace-text "$tmprep" --refs refs/heads/canbus-sanitized

# Push della copia sanificata verso il ramo pubblico canbus
git push --force origin canbus-sanitized:canbus

echo "✅ Pubblicato su origin/canbus (sanificato)."
