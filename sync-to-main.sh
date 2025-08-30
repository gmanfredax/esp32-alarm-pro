#!/usr/bin/env bash
# push-local-to-main.sh — Copia lo stato locale nel branch 'main' remoto (GitHub+GitLab)
# NON fa pull/fetch/rebase. Solo commit locale (se serve) e push forzato verso 'main'.
#
# Uso:
#   bash ./push-local-to-main.sh            # push HEAD -> origin/main e gitlab/main con --force-with-lease
#   bash ./push-local-to-main.sh -m "msg"   # con messaggio commit auto
#   bash ./push-local-to-main.sh --hard     # usa --force (sovrascrive sempre, ignorando cambi remoti)
#   TARGET=develop bash ./push-local-to-main.sh   # push su branch remoto diverso da 'main'
#
# Variabili remoti (override facoltativo):
#   REMOTE1=origin  REMOTE2=gitlab  TARGET=main  bash ./push-local-to-main.sh

set -e

REMOTE1="${REMOTE1:-origin}"   # GitHub
REMOTE2="${REMOTE2:-gitlab}"   # GitLab
TARGET="${TARGET:-main}"       # branch remoto di destinazione

COMMIT_MSG=""
HARD=0

while [ $# -gt 0 ]; do
  case "$1" in
    -m|--message) shift; COMMIT_MSG="${1:-}";;
    --hard)       HARD=1;;
    *) echo "Argomento non riconosciuto: $1" >&2; exit 2;;
  esac
  shift || true
done

# 0) Preflight
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "Non sei in una repo git"; exit 1; }
CURBR="$(git rev-parse --abbrev-ref HEAD)"

echo "== Push locale -> remoti: HEAD ($CURBR) -> $TARGET =="

# 1) Commit automatico se ci sono modifiche locali
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "--> Commit automatico modifiche locali"
  git add -A
  if [ -z "$COMMIT_MSG" ]; then
    COMMIT_MSG="sync: push locale su $TARGET - $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
  fi
  git commit -m "$COMMIT_MSG"
else
  echo "--> Nessuna modifica locale da committare"
fi

# 2) Push verso GitHub (REMOTE1)
if git remote get-url "$REMOTE1" >/dev/null 2>&1; then
  echo "--> Push su $REMOTE1: HEAD -> refs/heads/$TARGET"
  if [ $HARD -eq 1 ]; then
    git push --force "$REMOTE1" HEAD:"refs/heads/$TARGET"
  else
    # tenta in modo "sicuro" senza leggere da remoto; se fallisce, suggerisce --hard
    git push --force-with-lease "$REMOTE1" HEAD:"refs/heads/$TARGET" || {
      echo "!!  Push rifiutato su $REMOTE1. Rilancia con --hard per sovrascrivere comunque."
      exit 1
    }
  fi
  echo "OK  $REMOTE1 aggiornato."
else
  echo "!!  Remote '$REMOTE1' non configurato: salto"
fi

# 3) Push verso GitLab (REMOTE2)
if git remote get-url "$REMOTE2" >/dev/null 2>&1; then
  echo "--> Push su $REMOTE2: HEAD -> refs/heads/$TARGET"
  if [ $HARD -eq 1 ]; then
    git push --force "$REMOTE2" HEAD:"refs/heads/$TARGET" || {
      echo "!!  Push rifiutato su $REMOTE2 (branch protetto?). Vedi note sotto."
      exit 1
    }
  else
    git push --force-with-lease "$REMOTE2" HEAD:"refs/heads/$TARGET" || {
      echo "!!  Push rifiutato su $REMOTE2. Rilancia con --hard per sovrascrivere comunque."
      exit 1
    }
  fi
  echo "OK  $REMOTE2 aggiornato."
else
  echo "!!  Remote '$REMOTE2' non configurato: salto"
fi

echo "== Finito =="

