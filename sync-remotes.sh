#!/usr/bin/env bash
# sync-remotes.sh — Commit + rebase su GitHub + push su GitHub & GitLab
# Uso base:   ./sync-remotes.sh
# Opzioni:
#   -m, --message "msg"   Messaggio commit auto (se ci sono modifiche non committate)
#   -b, --branch  nome    Branch da sincronizzare (default: branch corrente)
#       --no-rebase       Non fare rebase su GitHub prima del push
#       --force           Usa --force-with-lease su GitLab (se permesso)
#       --merge-gitlab    In caso di rifiuto su GitLab, integra i commit di GitLab (pull --rebase) e riprova
#   -n, --dry-run         Prova senza modificare nulla (mostra cosa farebbe)
#
# Requisiti:
#   remoti:
#     origin = GitHub (ssh: git@github.com:<user>/<repo>.git)
#     gitlab = GitLab (ssh: git@gitlab.com:<group-or-user>/<repo>.git)

set -Eeuo pipefail

REMOTE_GITHUB="${REMOTE_GITHUB:-origin}"
REMOTE_GITLAB="${REMOTE_GITLAB:-gitlab}"
REBASE_ON_GITHUB=true
FORCE_GITLAB=false
MERGE_GITLAB_ON_FAIL=false
DRY_RUN=false
COMMIT_MSG=""
TARGET_BRANCH=""

msg(){ printf "▶ %s\n" "$*"; }
ok(){ printf "✅ %s\n" "$*"; }
warn(){ printf "�️  %s\n" "$*"; }
err(){ printf "❌ %s\n" "$*" >&2; exit 1; }

# --- Parse args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--message) COMMIT_MSG="$2"; shift 2 ;;
    -b|--branch)  TARGET_BRANCH="$2"; shift 2 ;;
    --no-rebase)  REBASE_ON_GITHUB=false; shift ;;
    --force)      FORCE_GITLAB=true; shift ;;
    --merge-gitlab) MERGE_GITLAB_ON_FAIL=true; shift ;;
    -n|--dry-run) DRY_RUN=true; shift ;;
    *) err "Argomento non riconosciuto: $1" ;;
  esac
done

# --- Preflight ---
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || err "Non sei in una repo git."
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
BRANCH="${TARGET_BRANCH:-$CURRENT_BRANCH}"

# Verifica remoti
git remote get-url "$REMOTE_GITHUB" >/dev/null 2>&1 || err "Remote '$REMOTE_GITHUB' (GitHub) mancante."
git remote get-url "$REMOTE_GITLAB"  >/dev/null 2>&1 || warn "Remote '$REMOTE_GITLAB' (GitLab) mancante: salto push su GitLab."

# --- Commit automatico se ci sono modifiche ---
if [[ -n "$(git status --porcelain)" ]]; then
  msg "Modifiche locali rilevate → preparo commit."
  git add -A
  if [[ -z "$COMMIT_MSG" ]]; then
    COMMIT_MSG="sync: auto $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
  fi
  if [[ "$DRY_RUN" == true ]]; then
    warn "[dry-run] Avrei eseguito: git commit -m \"$COMMIT_MSG\""
  else
    git commit -m "$COMMIT_MSG"
    ok "Commit creato."
  fi
else
  msg "Nessuna modifica locale da committare."
fi

# --- Fetch remoti ---
msg "Allineo riferimenti remoti…"
git fetch "$REMOTE_GITHUB" --prune
if git remote get-url "$REMOTE_GITLAB" >/dev/null 2>&1; then
  git fetch "$REMOTE_GITLAB" --prune || warn "Fetch GitLab fallito (continua)…"
fi

# --- Rebase (GitHub come sorgente di verit�) ---
if [[ "$REBASE_ON_GITHUB" == true ]]; then
  if git show-ref --verify --quiet "refs/remotes/$REMOTE_GITHUB/$BRANCH"; then
    msg "Rebase di '$BRANCH' su $REMOTE_GITHUB/$BRANCH…"
    if [[ "$DRY_RUN" == true ]]; then
      warn "[dry-run] Avrei eseguito: git pull --rebase $REMOTE_GITHUB $BRANCH"
    else
      git pull --rebase "$REMOTE_GITHUB" "$BRANCH" || err "Rebase fallito: risolvi conflitti e riprova."
      ok "Rebase completato."
    fi
  else
    warn "Remoto $REMOTE_GITHUB/$BRANCH inesistente: salto rebase."
  fi
else
  msg "Rebase disattivato (--no-rebase)."
fi

# --- Imposta upstream su GitHub se mancante ---
if ! git rev-parse --abbrev-ref --symbolic-full-name "@{u}" >/dev/null 2>&1; then
  msg "Imposto upstream su $REMOTE_GITHUB/$BRANCH…"
  if [[ "$DRY_RUN" == true ]]; then
    warn "[dry-run] Avrei eseguito: git branch --set-upstream-to=$REMOTE_GITHUB/$BRANCH $BRANCH"
  else
    git branch --set-upstream-to="$REMOTE_GITHUB/$BRANCH" "$BRANCH" || true
  fi
fi

# --- Push su GitHub ---
msg "Push su GitHub ($REMOTE_GITHUB → $BRANCH)…"
if [[ "$DRY_RUN" == true ]]; then
  warn "[dry-run] Avrei eseguito: git push $REMOTE_GITHUB $BRANCH"
else
  git push "$REMOTE_GITHUB" "$BRANCH"
  ok "GitHub aggiornato."
fi

# --- Push su GitLab ---
if git remote get-url "$REMOTE_GITLAB" >/dev/null 2>&1; then
  msg "Push su GitLab ($REMOTE_GITLAB → $BRANCH)…"
  PUSH_ARGS=()
  if [[ "$FORCE_GITLAB" == true ]]; then
    PUSH_ARGS+=(--force-with-lease)
  fi

  if [[ "$DRY_RUN" == true ]]; then
    warn "[dry-run] Avrei eseguito: git push ${PUSH_ARGS[*]:-} $REMOTE_GITLAB $BRANCH"
    exit 0
  fi

  set +e
  git push "${PUSH_ARGS[@]:-}" "$REMOTE_GITLAB" "$BRANCH"
  rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    warn "Push su GitLab fallito (branch protetto o non-fast-forward)."
    if [[ "$MERGE_GITLAB_ON_FAIL" == true ]]; then
      msg "Integro i commit presenti su GitLab (pull --rebase $REMOTE_GITLAB $BRANCH)…"
      git pull --rebase "$REMOTE_GITLAB" "$BRANCH" || err "Rebase da GitLab fallito: risolvi conflitti e riprova."
      msg "Rispingo su GitHub e GitLab per riallineare entrambi…"
      git push "$REMOTE_GITHUB" "$BRANCH"
      git push "$REMOTE_GITLAB"  "$BRANCH" || err "Push su GitLab ancora fallito (branch protetto?)."
      ok "GitHub e GitLab allineati."
    else
      cat <<EOF
Suggerimenti:
  • Branch protetto su GitLab? Apri Settings → Repository → Protected branches e consenti il push (o usa MR).
  • Oppure rilancia lo script con:  --merge-gitlab   per integrare i commit di GitLab localmente e riprovare.
  • Oppure, se sei autorizzato, usa: --force         per forzare (usa --force-with-lease) il push su GitLab.
EOF
      exit $rc
    fi
  else
    ok "GitLab aggiornato."
  fi
else
  warn "Remote GitLab non configurato: salto."
fi

ok "Sincronizzazione completata."
