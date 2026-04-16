#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# archive.sh — Encrypted full-project backup
#
# Purpose: Encrypts all project files (including .git) with AES-256-CBC,
#          splits for GitHub 100MB limit, safe for public repos.
#
# Usage:
#   ./tmp-igbkp/archive.sh
#
# Output:
#   output/ folder with split encrypted files + manifest.txt
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPLIT_SIZE="95M"  # GitHub 100MB limit → 95MB margin

# Find PROJECT_ROOT (walk up to find .git)
PROJECT_ROOT="$SCRIPT_DIR"
while [[ "$PROJECT_ROOT" != "/" ]]; do
    [[ -d "$PROJECT_ROOT/.git" ]] && break
    PROJECT_ROOT="$(dirname "$PROJECT_ROOT")"
done

# Toolkit folder name (relative to PROJECT_ROOT)
TOOLKIT_REL="${SCRIPT_DIR#$PROJECT_ROOT/}"
OUTPUT_DIR="$SCRIPT_DIR/output"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'

log()  { echo -e "${GREEN}[archive]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; }

# sha256 wrapper (macOS: shasum, Linux: sha256sum)
if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$@"; }
else
    err "sha256sum or shasum required."; exit 1
fi

# GNU split check (macOS: gsplit needed)
if command -v gsplit >/dev/null 2>&1; then
    SPLIT_CMD="gsplit"
elif split --version 2>&1 | grep -q GNU 2>/dev/null; then
    SPLIT_CMD="split"
else
    err "GNU split required. macOS: brew install coreutils"; exit 1
fi

# Basic dependencies
for cmd in tar openssl; do
    command -v "$cmd" >/dev/null 2>&1 || { err "'$cmd' command required."; exit 1; }
done

if [[ ! -d "$PROJECT_ROOT/.git" ]]; then
    err "Git repository not found."
    exit 1
fi

# Password input (must be interactive)
if [[ $# -gt 0 ]]; then
    err "Password must not be passed as CLI argument (shell history exposure risk)."
    err "Usage: ./$TOOLKIT_REL/archive.sh"
    exit 1
fi

echo -n "Enter encryption password: "
read -rs PASSWORD
echo
echo -n "Confirm password: "
read -rs PASSWORD_CONFIRM
echo
if [[ "$PASSWORD" != "$PASSWORD_CONFIRM" ]]; then
    err "Passwords do not match."
    exit 1
fi

if [[ ${#PASSWORD} -lt 8 ]]; then
    err "Password must be at least 8 characters."
    exit 1
fi

# Prepare
cd "$PROJECT_ROOT"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

TMPDIR_WORK="$SCRIPT_DIR/.work"
rm -rf "$TMPDIR_WORK"
mkdir -p "$TMPDIR_WORK"
trap 'rm -rf "$TMPDIR_WORK"' EXIT

# Collect project files (exclude toolkit folder)
log "Collecting project files..."
FILE_COUNT=$(find . -not -path "./$TOOLKIT_REL/*" -not -path "./$TOOLKIT_REL" \
                    \( -type f -o -type l \) | wc -l)

if [[ "$FILE_COUNT" -eq 0 ]]; then
    log "No files to back up."
    exit 0
fi

log "Archive target: $FILE_COUNT files"

# Create tar
TAR_FILE="$TMPDIR_WORK/project.tar.gz"
log "Creating tar.gz..."
tar czf "$TAR_FILE" \
    --exclude="./$TOOLKIT_REL" \
    .

TAR_SIZE=$(du -h "$TAR_FILE" | cut -f1)
log "tar.gz size: $TAR_SIZE"

# AES-256-CBC encryption
ENC_FILE="$TMPDIR_WORK/project.tar.gz.enc"
log "Encrypting with AES-256-CBC (PBKDF2, 600k iterations)..."
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 600000 \
    -in "$TAR_FILE" -out "$ENC_FILE" \
    -pass "fd:3" 3<<< "$PASSWORD"

ENC_SIZE=$(du -h "$ENC_FILE" | cut -f1)
log "Encrypted file size: $ENC_SIZE"

# Split
log "Splitting (unit: $SPLIT_SIZE)..."
$SPLIT_CMD -b "$SPLIT_SIZE" -d --additional-suffix=".part" "$ENC_FILE" "$OUTPUT_DIR/igbkp_"

# Timestamp (GNU/BSD compatible)
if date -Iseconds >/dev/null 2>&1; then
    TIMESTAMP=$(date -Iseconds)
else
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S%z")
fi

# Generate manifest
MANIFEST="$OUTPUT_DIR/manifest.txt"
{
    echo "# project full backup manifest"
    echo "# created: $TIMESTAMP"
    echo "# project: $(basename "$PROJECT_ROOT")"
    echo "# encryption: AES-256-CBC, PBKDF2, 600000 iterations"
    echo "# split_size: $SPLIT_SIZE"
    echo "# original_tar_size: $TAR_SIZE"
    echo "# encrypted_size: $ENC_SIZE"
    echo "# file_count: $FILE_COUNT"
    echo "#"
    echo "# SHA-256 checksums:"
    for f in "$OUTPUT_DIR"/igbkp_*.part; do
        (cd "$OUTPUT_DIR" && sha256 "$(basename "$f")")
    done
} > "$MANIFEST"

# Results
PART_COUNT=$(ls "$OUTPUT_DIR"/igbkp_*.part 2>/dev/null | wc -l)
log "Done!"
echo ""
echo "=========================================="
echo " Archive Complete"
echo "=========================================="
echo " Output: $OUTPUT_DIR/"
echo " Files:  ${FILE_COUNT}"
echo " Parts:  ${PART_COUNT}"
echo ""
echo " Restore: ./$TOOLKIT_REL/restore.sh"
echo "=========================================="
