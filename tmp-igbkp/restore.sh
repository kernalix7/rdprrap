#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# restore.sh — Restore encrypted project backup
#
# Purpose: Decrypts split encrypted files from archive.sh,
#          deletes existing project, and replaces entirely with backup.
#
# Usage:
#   ./tmp-igbkp/restore.sh              # Interactive password input
#   ./tmp-igbkp/restore.sh --dry-run    # List files only
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find PROJECT_ROOT
PROJECT_ROOT="$SCRIPT_DIR"
while [[ "$PROJECT_ROOT" != "/" ]]; do
    [[ -d "$PROJECT_ROOT/.git" ]] && break
    PROJECT_ROOT="$(dirname "$PROJECT_ROOT")"
done

TOOLKIT_REL="${SCRIPT_DIR#$PROJECT_ROOT/}"
OUTPUT_DIR="$SCRIPT_DIR/output"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${GREEN}[restore]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; }

# sha256 wrapper
if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$@"; }
else
    err "sha256sum or shasum required."; exit 1
fi

for cmd in cat openssl tar diff; do
    command -v "$cmd" >/dev/null 2>&1 || { err "'$cmd' command required."; exit 1; }
done

if [[ ! -d "$PROJECT_ROOT/.git" ]]; then
    err "Git repository not found."
    exit 1
fi

# Parse args
DRY_RUN=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# Check split files exist
PARTS=("$OUTPUT_DIR"/igbkp_*.part)
if [[ ! -f "${PARTS[0]}" ]]; then
    err "Split files not found: $OUTPUT_DIR/igbkp_*.part"
    exit 1
fi

log "${#PARTS[@]} split files found"

# Checksum verification
MANIFEST="$OUTPUT_DIR/manifest.txt"
if [[ -f "$MANIFEST" ]]; then
    log "Verifying checksums..."
    while IFS= read -r line; do
        [[ "$line" =~ ^# ]] && continue
        [[ -z "$line" ]] && continue
        expected=$(echo "$line" | awk '{print $1}')
        filename=$(echo "$line" | awk '{print $2}')
        if [[ -f "$OUTPUT_DIR/$filename" ]]; then
            actual=$(sha256 "$OUTPUT_DIR/$filename" | awk '{print $1}')
            if [[ "$expected" != "$actual" ]]; then
                err "Checksum mismatch: $filename"
                exit 1
            fi
        fi
    done < "$MANIFEST"
    log "Checksum verification passed"
fi

# Password input
echo -n "Enter decryption password: "
read -rs PASSWORD
echo

TMPDIR_WORK="$SCRIPT_DIR/.work"
rm -rf "$TMPDIR_WORK"
mkdir -p "$TMPDIR_WORK"
CLEANUP=true
trap '[[ "$CLEANUP" == true ]] && rm -rf "$TMPDIR_WORK"' EXIT

# Decrypt
ENC_FILE="$TMPDIR_WORK/project.tar.gz.enc"
TAR_FILE="$TMPDIR_WORK/project.tar.gz"

log "Joining split files..."
cat "${PARTS[@]}" > "$ENC_FILE"

log "Decrypting..."
if ! openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter 600000 \
    -in "$ENC_FILE" -out "$TAR_FILE" \
    -pass "fd:3" 3<<< "$PASSWORD" 2>/dev/null; then
    err "Decryption failed. Wrong password or corrupted file."
    exit 1
fi

log "Decryption successful"

# dry-run
if [[ "$DRY_RUN" == true ]]; then
    log "File list (dry-run):"
    tar tzf "$TAR_FILE" | head -100
    TOTAL=$(tar tzf "$TAR_FILE" | wc -l)
    echo "... total $TOTAL items"
    exit 0
fi

# Extract to temp dir (for comparison)
EXTRACT_DIR="$TMPDIR_WORK/extracted"
mkdir -p "$EXTRACT_DIR"
log "Extracting..."
tar xzf "$TAR_FILE" -C "$EXTRACT_DIR" --no-same-owner 2>/dev/null || \
    tar xzf "$TAR_FILE" -C "$EXTRACT_DIR"

# Compare with existing project
log "Comparing with existing project..."

DIFF_REPORT="$TMPDIR_WORK/diff_report.txt"
MODIFIED=0
NEW_FILES=0
DELETED=0

while IFS= read -r rel_path; do
    current="$PROJECT_ROOT/$rel_path"
    backup="$EXTRACT_DIR/$rel_path"
    if [[ ! -e "$current" ]]; then
        echo "[NEW]      $rel_path" >> "$DIFF_REPORT"
        ((NEW_FILES++)) || true
    elif [[ -f "$current" && -f "$backup" ]]; then
        if ! diff -q "$current" "$backup" >/dev/null 2>&1; then
            echo "[MODIFIED] $rel_path" >> "$DIFF_REPORT"
            ((MODIFIED++)) || true
        fi
    fi
done < <(cd "$EXTRACT_DIR" && find . \( -type f -o -type l \) 2>/dev/null | sed 's|^\./||')

while IFS= read -r rel_path; do
    if [[ ! -e "$EXTRACT_DIR/$rel_path" ]]; then
        echo "[DELETED]  $rel_path" >> "$DIFF_REPORT"
        ((DELETED++)) || true
    fi
done < <(cd "$PROJECT_ROOT" && find . -not -path "./$TOOLKIT_REL/*" -not -path "./$TOOLKIT_REL" \
    \( -type f -o -type l \) 2>/dev/null | sed 's|^\./||')

TOTAL_DIFF=$((MODIFIED + NEW_FILES + DELETED))

if [[ "$TOTAL_DIFF" -eq 0 ]]; then
    log "Existing project and backup are identical. Nothing to restore."
    exit 0
fi

# Difference warning
echo ""
echo -e "${YELLOW}==================================================${NC}"
echo -e "${YELLOW} Differences found between project and backup${NC}"
echo -e "${YELLOW}==================================================${NC}"
echo ""
echo -e "  Modified files: ${CYAN}${MODIFIED}${NC}"
echo -e "  New files:      ${CYAN}${NEW_FILES}${NC}"
echo -e "  To be deleted:  ${CYAN}${DELETED}${NC}"
echo ""

if [[ -f "$DIFF_REPORT" ]]; then
    head -30 "$DIFF_REPORT"
    REPORT_LINES=$(wc -l < "$DIFF_REPORT")
    if [[ "$REPORT_LINES" -gt 30 ]]; then
        echo "  ... and $((REPORT_LINES - 30)) more"
    fi
fi

echo ""
echo -e "${RED} This will DELETE the existing project and REPLACE with backup.${NC}"
echo -n " Continue? (yes/no): "
read -r answer
if [[ "$answer" != "yes" ]]; then
    log "Cancelled."
    exit 0
fi

# Start deletion — preserve extracted data on failure
CLEANUP=false

cd "$PROJECT_ROOT"
TOOLKIT_NAME="$(basename "$SCRIPT_DIR")"
log "Deleting existing files (excluding $TOOLKIT_NAME/)..."
find . -mindepth 1 -maxdepth 1 -not -name "$TOOLKIT_NAME" -exec rm -rf {} +

log "Restoring backup files..."
cp -a "$EXTRACT_DIR"/. "$PROJECT_ROOT"/

RESTORED=$(cd "$EXTRACT_DIR" && find . \( -type f -o -type l \) | wc -l)

# Restore success — cleanup OK
CLEANUP=true
log "Done! ${RESTORED} files restored (full replacement)"
