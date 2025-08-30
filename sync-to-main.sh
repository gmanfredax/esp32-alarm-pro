#!/usr/bin/env bash
# push-local-to-main.sh — spinge SEMPRE lo stato locale online.
# - GitHub (origin/main): push (usa --force-with-lease per essere unidirezionale da locale)
# - GitLab (gitlab/main): se push rifiutato (branch protetto), crea branch di sync + Merge Request automatica.
#
# Variabili:
#   REMOTE1=origin   REMOTE2=gitlab   TARGET=main
#   GL_TOKEN=<PAT con scope api>      GL_PROJECT_ID=<ID numerico del progetto GitLab>
#
# Uso:
#   bash ./push-local-to-main.sh
#   bash ./push-local-to-main.sh -m "msg commit"
#   TARGET=develop bash ./push-local-to-main.sh -m "sync develop"
#
# NOTE: Nessun fetch/pull: non prende mai da online.

set -e

REMOTE1="${REMOTE1:-origin}"
REMOTE2="${REMOTE2:-gitlab}"
TARGET="${TARGET:-main}"
COMMIT_MSG=""

while [ $# -gt 0 ]; do
  case "$1" in
    -m|--message) shift; COMMIT_MSG="${1:-}";;
    *) echo "Argomento non riconosciuto: $1" >&2; exit 2;;
  esac
  shift || true
done

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "Non sei in una repo git"; exit 1; }

CURBR="$(git rev-parse --abbrev-ref HEAD)"
echo "== Locale HEAD ($CURBR) -> remoti ($TARGET) =="

# 1) Commit auto se ci sono modifiche
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "--> Commit automatico modifiche locali"
  git add -A
  [ -z "$COMMIT_MSG" ] && COMMIT_MSG="sync: push locale su $TARGET - $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
  git commit -m "$COMMIT_MSG"
else
  echo "--> Nessuna modifica locale da committare"
fi

# 2) Push su GitHub (origin)
if git remote get-url "$REMOTE1" >/dev/null 2>&1; then
  echo "--> Push GitHub ($REMOTE1: HEAD -> $TARGET)"
  git push --force-with-lease "$REMOTE1" HEAD:"refs/heads/$TARGET"
  echo "OK  GitHub aggiornato"
else
  echo "!!  Remote '$REMOTE1' non configurato: salto GitHub"
fi

# 3) Push su GitLab (gitlab)
if git remote get-url "$REMOTE2" >/dev/null 2>&1; then
  echo "--> Push GitLab ($REMOTE2: HEAD -> $TARGET)"
  set +e
  git push --force-with-lease "$REMOTE2" HEAD:"refs/heads/$TARGET"
  rc=$?
  set -e

  if [ $rc -eq 0 ]; then
    echo "OK  GitLab aggiornato"
  else
    echo "!!  Push rifiutato su GitLab (branch protetto?). Avvio fallback MR."

    # 3a) Crea branch di sync e pusha
    TS="$(date -u +'%Y%m%d-%H%M%S')"
    SYNC_BRANCH="sync/$TS"
    echo "--> Creo branch di sync: $SYNC_BRANCH"
    git branch -f "$SYNC_BRANCH" HEAD
    git push "$REMOTE2" "$SYNC_BRANCH:refs/heads/$SYNC_BRANCH"

    # 3b) Crea Merge Request via API (serve GL_TOKEN e GL_PROJECT_ID)
    if [ -z "${GL_TOKEN:-}" ] || [ -z "${GL_PROJECT_ID:-}" ]; then
      echo "!!  Variabili GL_TOKEN e/o GL_PROJECT_ID mancanti: non posso aprire la MR automaticamente."
      echo "    Apri manualmente la MR: source_branch=$SYNC_BRANCH -> target_branch=$TARGET"
      exit 0
    fi

    MR_TITLE="Sync from local $TS"
    echo "--> Creo MR automatica: $SYNC_BRANCH -> $TARGET"

    curl -sS -X POST "https://gitlab.com/api/v4/projects/${GL_PROJECT_ID}/merge_requests" \
      -H "PRIVATE-TOKEN: ${GL_TOKEN}" \
      --data-urlencode "source_branch=${SYNC_BRANCH}" \
      --data-urlencode "target_branch=${TARGET}" \
      --data-urlencode "title=${MR_TITLE}" \
      --data-urlencode "remove_source_branch=true" \
      --data "squash=0" >/dev/null

    echo "OK  MR creata. Vai su GitLab e fai Merge."
  fi
else
  echo "!!  Remote '$REMOTE2' non configurato: salto GitLab"
fi

echo "== Finito =="

