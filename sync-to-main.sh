#!/usr/bin/env bash
# sync-to-main.sh — porta lo stato locale dentro 'main' e push su GitHub e GitLab
# Uso:
#   bash ./sync-to-main.sh          # usa 'main'
#   bash ./sync-to-main.sh develop  # usa un branch target diverso

set -e

REMOTE1="${REMOTE1:-origin}"   # GitHub
REMOTE2="${REMOTE2:-gitlab}"   # GitLab
TARGET="${1:-main}"

# 0) Preflight
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "Non sei in una repo git"; exit 1; }
SRC_BRANCH="$(git rev-parse --abbrev-ref HEAD)"

echo "== Sorgente: $SRC_BRANCH → Target: $TARGET =="

# 1) Commit automatico delle modifiche locali (sul branch sorgente)
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "--> Commit automatico delle modifiche locali su $SRC_BRANCH"
  git add -A
  git commit -m "sync: merge in $TARGET - $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
else
  echo "--> Nessuna modifica locale da committare su $SRC_BRANCH"
fi

# 2) Fetch dei remoti
echo "--> Fetch remoti"
git fetch "$REMOTE1" --prune || true
git fetch "$REMOTE2" --prune || true

# 3) Assicura che il branch TARGET esista localmente
if ! git show-ref --verify --quiet "refs/heads/$TARGET"; then
  echo "--> Creo branch locale $TARGET"
  if git show-ref --verify --quiet "refs/remotes/$REMOTE1/$TARGET"; then
    git branch "$TARGET" "$REMOTE1/$TARGET"
  elif git show-ref --verify --quiet "refs/remotes/$REMOTE2/$TARGET"; then
    git branch "$TARGET" "$REMOTE2/$TARGET"
  else
    # se non esiste da nessuna parte, lo inizializzo allo stato corrente
    git branch "$TARGET" "$SRC_BRANCH"
  fi
fi

# 4) Passa a TARGET e riallinea con il remoto principale (GitHub)
echo "--> Switch a $TARGET"
git switch "$TARGET" 2>/dev/null || git checkout "$TARGET"

if git show-ref --verify --quiet "refs/remotes/$REMOTE1/$TARGET"; then
  echo "--> Rebase di $TARGET su $REMOTE1/$TARGET"
  git pull --rebase "$REMOTE1" "$TARGET"
fi

# 5) Merge del branch sorgente in TARGET (porta dentro i file locali)
if [ "$SRC_BRANCH" != "$TARGET" ]; then
  echo "--> Merge di $SRC_BRANCH in $TARGET"
  git merge --no-ff --no-edit "$SRC_BRANCH" || {
    echo "!! CONFLITTI: risolvili, poi esegui:"
    echo "   git add -A && git commit"
    echo "   git push $REMOTE1 $TARGET"
    [ -n "$REMOTE2" ] && echo "   git push $REMOTE2 $TARGET"
    exit 1
  }
else
  echo "--> Sei già su $TARGET: nessun merge necessario"
fi

# 6) Push su GitHub e GitLab
echo "--> Push su GitHub ($REMOTE1 → $TARGET)"
git push "$REMOTE1" "$TARGET"

if git remote get-url "$REMOTE2" >/dev/null 2>&1; then
  echo "--> Push su GitLab ($REMOTE2 → $TARGET)"
  git push "$REMOTE2" "$TARGET"
else
  echo "!! Remote '$REMOTE2' non configurato: salto"
fi

# 7) Torna al branch di partenza
echo "--> Torno a $SRC_BRANCH"
git switch "$SRC_BRANCH" 2>/dev/null || git checkout "$SRC_BRANCH"

echo "== Fatto: $TARGET aggiornato su $REMOTE1 e $REMOTE2 =="
