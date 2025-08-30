#!/usr/bin/env bash
# sync-remotes.sh — Commit + rebase su GitHub + push su GitHub & GitLab (ASCII only)

set -euo pipefail

REMOTE_GITHUB="${REMOTE_GITHUB:-origin}"   # GitHub
REMOTE_GITLAB="${REMOTE_GITLAB:-gitlab}"   # GitLab

REBASE_ON_GITHUB=1
FORCE_GITLAB=0
MERGE_GITLAB_ON_FAIL=0
DRY_RUN=0
COMMIT_MSG=""
TARGET_BRANCH=""

msg()  { printf '>> %s\n' "$*"; }
ok()   { printf 'OK  %s\n' "$*"; }
warn() { printf '!!  %s\n' "$*" >&2; }
die()  { printf 'ERR %s\n' "$*" >&2; exit 1; }

# --- Parse args ---
while [ $# -gt 0 ]; do
  case "$1" in
    -m|--message) shift; COMMIT_MSG="${1:-}"; [ -n "$COMMIT_MSG" ] || die "Messaggio mancante dopo -m/--message";;
    -b|--branch)  shift; TARGET_BRANCH="${1:-}"; [ -n "$TARGET_BRANCH" ] || die "Branch mancante dopo -b/--branch";;
    --no-rebase)  REBASE_ON_GITHUB=0;;
    --force)      FORCE_GITLAB=1;;
    --merge-gitlab) MERGE_GITLAB_ON_FAIL=1;;
    -n|--dry-run) DRY_RUN=1;;
    *) die "Argomento non riconosciuto: $1";;
  esac
  shift || true
done

# --- Preflight ---
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "Non sei in una repo git."
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
BRANCH="${TARGET_BRANCH:-$CURRENT_BRANCH}"

git remote get-url "$REMOTE_GITHUB" >/dev/null 2>&1 || die "Remote '$REMOTE_GITHUB' (GitHub) mancante."
if ! git remote get-url "$REMOTE_GITLAB" >/dev/null 2>&1; then
  warn "Remote '$REMOTE_GITLAB' (GitLab) mancante: faro' solo GitHub."
  REMOTE_GITLAB=""
fi

# --- Commit automatico se ci sono modifiche ---
if [ -n "$(git status --porcelain)" ]; then
  msg "Modifiche locali rilevate: preparo commit."
  git add -A
  : "${COMMIT_MSG:=sync: auto $(date -u +'%Y-%m-%d %H:%M:%S UTC')}"
  if [ "$DRY_RUN" -eq 1 ]; then
    warn "[dry-run] git commit -m \"$COMMIT_MSG\""
  else
    git commit -m "$COMMIT_MSG"
    ok "Commit creato."
  fi
else
  msg "Nessuna modifica locale da committare."
fi

# --- Fetch remoti ---
msg "Fetch remoti…"
git fetch "$REMOTE_GITHUB" --prune
[ -n "$REMOTE_GITLAB" ] && git fetch "$REMOTE_GITLAB" --prune || true

# --- Rebase su GitHub (se il branch remoto esiste) ---
if [ "$REBASE_ON_GITHUB" -eq 1 ]; then
  if git show-ref --verify --quiet "refs/remotes/$REMOTE_GITHUB/$BRANCH"; then
    msg "Rebase di '$BRANCH' su $REMOTE_GITHUB/$BRANCH…"
    if [ "$DRY_RUN" -eq 1 ]; then
      warn "[dry-run] git pull --rebase $REMOTE_GITHUB $BRANCH"
    else
      git pull --rebase "$REMOTE_GITHUB" "$BRANCH" || die "Rebase fallito: risolvi i conflitti e riprova."
      ok "Rebase completato."
    fi
  else
    warn "Remoto $REMOTE_GITHUB/$BRANCH inesistente: salto rebase."
  fi
else
  msg "Rebase disattivato (--no-rebase)."
fi

# --- Imposta upstream su GitHub se mancante ---
if ! git rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then
  msg "Imposto upstream su $REMOTE_GITHUB/$BRANCH…"
  if [ "$DRY_RUN" -eq 1 ]; then
    warn "[dry-run] git branch --set-upstream-to=$REMOTE_GITHUB/$BRANCH $BRANCH"
  else
    git branch --set-upstream-to="$REMOTE_GITHUB/$BRANCH" "$BRANCH" || true
  fi
fi

# --- Push su GitHub ---
msg "Push su GitHub ($REMOTE_GITHUB → $BRANCH)…"
if [ "$DRY_RUN" -eq 1 ]; then
  warn "[dry-run] git push $REMOTE_GITHUB $BRANCH"
else
  git push "$REMOTE_GITHUB" "$BRANCH"
  ok "GitHub aggiornato."
fi

# --- Push su GitLab (se configurato) ---
if [ -n "$REMOTE_GITLAB" ]; then
  msg "Push su GitLab ($REMOTE_GITLAB → $BRANCH)…"
  PUSH_ARGS=""
  [ "$FORCE_GITLAB" -eq 1 ] && PUSH_ARGS="--force-with-lease"

  if [ "$DRY_RUN" -eq 1 ]; then
    warn "[dry-run] git push $PUSH_ARGS $REMOTE_GITLAB $BRANCH"
    exit 0
  fi

  set +e
  git push $PUSH_ARGS "$REMOTE_GITLAB" "$BRANCH"
  rc=$?
  set -e

  if [ $rc -ne 0 ]; then
    warn "Push su GitLab fallito (branch protetto o non-fast-forward)."
    if [ "$MERGE_GITLAB_ON_FAIL" -eq 1 ]; then
      msg "Integro i commit da $REMOTE_GITLAB/$BRANCH (pull --rebase) e riprovo…"
      git pull --rebase "$REMOTE_GITLAB" "$BRANCH" || die "Rebase da GitLab fallito: risolvi conflitti e riprova."
      git push "$REMOTE_GITHUB" "$BRANCH"
      git push "$REMOTE_GITLAB"  "$BRANCH" || die "Push su GitLab ancora fallito (branch protetto?)."
      ok "GitHub e GitLab allineati."
    else
      warn "Suggerimenti:"
      warn " - Branch protetto su GitLab? Usa MR oppure abilita push per il tuo ruolo."
      warn " - Oppure rilancia con --merge-gitlab per integrare i commit GitLab localmente."
      warn " - Oppure (se autorizzato) usa --force per forzare il push su GitLab."
      exit $rc
    fi
  else
    ok "GitLab aggiornato."
  fi
fi

ok "Sincronizzazione completata."
