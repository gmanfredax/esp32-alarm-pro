#!/usr/bin/env bash
# sync-simple.sh — commit (se serve) + rebase da GitHub + push su GitHub e GitLab
# Uso:
#   bash ./sync-simple.sh            # sul branch corrente
#   bash ./sync-simple.sh main       # su 'main'

set -e

REMOTE_GITHUB="origin"    # GitHub
REMOTE_GITLAB="gitlab"    # GitLab
BRANCH="${1:-$(git rev-parse --abbrev-ref HEAD)}"

echo "== Branch: $BRANCH =="

# 0) Preflight
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "Non sei in una repo git"; exit 1; }

# 1) Commit automatico se ci sono modifiche
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "--> Modifiche locali: commit automatico"
  git add -A
  git commit -m "sync: auto $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
else
  echo "--> Nessuna modifica locale da committare"
fi

# 2) Fetch e (se esiste) rebase da GitHub
echo "--> Fetch da $REMOTE_GITHUB"
git fetch "$REMOTE_GITHUB" --prune || true
if git show-ref --verify --quiet "refs/remotes/$REMOTE_GITHUB/$BRANCH"; then
  echo "--> Rebase su $REMOTE_GITHUB/$BRANCH"
  git pull --rebase "$REMOTE_GITHUB" "$BRANCH"
else
  echo "!!  $REMOTE_GITHUB/$BRANCH non esiste: salto rebase"
fi

# 3) Push su GitHub
echo "--> Push su GitHub ($REMOTE_GITHUB -> $BRANCH)"
git push "$REMOTE_GITHUB" "$BRANCH"

# 4) Push su GitLab (se configurato)
if git remote get-url "$REMOTE_GITLAB" >/dev/null 2>&1; then
  echo "--> Push su GitLab ($REMOTE_GITLAB -> $BRANCH)"
  if git push "$REMOTE_GITLAB" "$BRANCH"; then
    echo "OK  GitLab aggiornato"
  else
    echo "!!  Push su GitLab fallito: provo integrazione e ripeto"
    # Integra eventuali commit GitLab e riprova
    git pull --rebase "$REMOTE_GITLAB" "$BRANCH" || true
    git push "$REMOTE_GITHUB" "$BRANCH" || true
    git push "$REMOTE_GITLAB"  "$BRANCH"
  fi
else
  echo "!!  Remote '$REMOTE_GITLAB' non configurato: salto"
fi

echo "== Finito =="
