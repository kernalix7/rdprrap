#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# purge-history.sh — Permanently remove archive traces from git history
#
# Purpose: After committing archive.sh output to git, this script removes
#          all traces from local + remote history via filter-repo/filter-branch.
#
# Usage:
#   ./tmp-igbkp/purge-history.sh                    # Interactive confirmation
#   ./tmp-igbkp/purge-history.sh --confirm          # Skip confirmation
#   ./tmp-igbkp/purge-history.sh --path "path"      # Custom path to purge
#
# WARNING: This is a destructive operation involving force push.
#          Notify all collaborators before running.
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find PROJECT_ROOT
PROJECT_ROOT="$SCRIPT_DIR"
while [[ "$PROJECT_ROOT" != "/" ]]; do
    [[ -d "$PROJECT_ROOT/.git" ]] && break
    PROJECT_ROOT="$(dirname "$PROJECT_ROOT")"
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[purge]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; }

CONFIRM=false
PURGE_PATH="tmp-igbkp"
REMOTE="origin"
BRANCH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --confirm) CONFIRM=true; shift ;;
        --path) PURGE_PATH="$2"; shift 2 ;;
        --remote) REMOTE="$2"; shift 2 ;;
        --branch) BRANCH="$2"; shift 2 ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

cd "$PROJECT_ROOT"

# Detect current branch
if [[ -z "$BRANCH" ]]; then
    BRANCH=$(git rev-parse --abbrev-ref HEAD)
fi

# Check for git filter-repo or git filter-branch
USE_FILTER_REPO=false
if command -v git-filter-repo >/dev/null 2>&1; then
    USE_FILTER_REPO=true
fi

# Check if path exists in history
COMMITS_WITH_PATH=$(git log --all --oneline -- "$PURGE_PATH" 2>/dev/null | wc -l)
if [[ "$COMMITS_WITH_PATH" -eq 0 ]]; then
    log "'$PURGE_PATH' not found in git history. Nothing to do."
    exit 0
fi

log "Found ${COMMITS_WITH_PATH} commits with '$PURGE_PATH' in history"

# Warning & confirmation
if [[ "$CONFIRM" != true ]]; then
    echo ""
    echo -e "${RED}==================================================${NC}"
    echo -e "${RED} WARNING: DESTRUCTIVE OPERATION${NC}"
    echo -e "${RED}==================================================${NC}"
    echo ""
    echo " The following will be performed:"
    echo "   1. Remove '$PURGE_PATH' from ALL git history"
    echo "   2. Force push to $REMOTE/$BRANCH"
    echo ""
    echo " Related commits:"
    git log --all --oneline -- "$PURGE_PATH" | head -10
    echo ""
    echo -n "Continue? (yes/no): "
    read -r answer
    if [[ "$answer" != "yes" ]]; then
        log "Cancelled."
        exit 0
    fi
fi

# Backup: save current HEAD hash before rewrite
BACKUP_SHA=$(git rev-parse HEAD)
log "Current HEAD saved: $BACKUP_SHA (recover: git reset --hard $BACKUP_SHA)"

# filter-repo deletes remotes, save URL first
REMOTE_URL=""
if git remote get-url "$REMOTE" >/dev/null 2>&1; then
    REMOTE_URL=$(git remote get-url "$REMOTE")
    log "Remote URL saved: $REMOTE_URL"
fi

# Remove path from history
if [[ "$USE_FILTER_REPO" == true ]]; then
    log "Cleaning history with git filter-repo..."
    git filter-repo --invert-paths --path "$PURGE_PATH" --force

    # Restore remote deleted by filter-repo
    if [[ -n "$REMOTE_URL" ]]; then
        git remote add "$REMOTE" "$REMOTE_URL" 2>/dev/null || true
        log "Remote restored: $REMOTE → $REMOTE_URL"
    fi
else
    log "Cleaning history with git filter-branch..."
    warn "git filter-repo recommended (pip install git-filter-repo)"

    git filter-branch --force --index-filter \
        "git rm -rf --cached --ignore-unmatch '$PURGE_PATH'" \
        --prune-empty --tag-name-filter cat -- --all 2>/dev/null || {
            err "filter-branch failed. Install git-filter-repo:"
            err "  pip install git-filter-repo"
            exit 1
        }

    # Clean filter-branch remnants
    rm -rf .git/refs/original/ 2>/dev/null || true
fi

# Force push to remote
if git remote get-url "$REMOTE" >/dev/null 2>&1; then
    log "Force pushing to $REMOTE..."
    git push "$REMOTE" "$BRANCH" --force-with-lease 2>/dev/null || {
        warn "force-with-lease failed, retrying with --force..."
        git push "$REMOTE" "$BRANCH" --force
    }
    log "Remote updated"
else
    warn "Remote '$REMOTE' not configured. Push manually:"
    warn "  git push <remote> $BRANCH --force"
fi

echo ""
echo "=========================================="
echo " History Purge Complete"
echo "=========================================="
echo " Purged path: $PURGE_PATH"
echo " Recovery:    git reset --hard $BACKUP_SHA"
echo " Remote:      $REMOTE/$BRANCH"
echo ""
echo " Notify collaborators:"
echo "   git fetch origin && git reset --hard origin/$BRANCH"
echo ""
echo " Once confirmed OK, clean reflog (makes recovery impossible):"
echo "   git reflog expire --expire=now --all && git gc --prune=now --aggressive"
echo "=========================================="
