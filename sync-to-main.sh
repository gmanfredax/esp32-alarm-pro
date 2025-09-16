#!/bin/bash
# Script per sincronizzare repo locale -> GitHub + GitLab
# Autore: Gabriele Manfreda

set -e

# Messaggio commit di default = timestamp se non specificato
COMMIT_MSG=${1:-"Sync $(date '+%Y-%m-%d %H:%M:%S')"}

echo "== Sync locale -> remoti =="
echo "--> Commit con messaggio: $COMMIT_MSG"

# Aggiunge tutti i file modificati
git add -A

# Se ci sono modifiche, fa il commit
if ! git diff --cached --quiet; then
    git commit -m "$COMMIT_MSG"
else
    echo "--> Nessuna modifica da committare"
fi

# Push su GitHub (origin)
echo "--> Push su GitHub..."
git push origin HEAD:main

# Push su GitLab (gitlab)
echo "--> Push su GitLab..."
git push gitlab HEAD:main

echo "== OK: repo sincronizzate =="
