# Project Backup Toolkit

Encrypted full-project backup/restore with git history purge capability.

Uses AES-256-CBC encryption for safe storage on public GitHub repositories,
with automatic splitting for GitHub's 100MB file limit.

## Scripts

| Script | Purpose |
|--------|---------|
| `archive.sh` | Full project → encrypted split backup |
| `restore.sh` | Delete existing project and replace with backup |
| `purge-history.sh` | Permanently remove tmp-igbkp/ traces from git history |

## Usage

```bash
# 1. Create backup (password is interactive input)
./tmp-igbkp/archive.sh

# 2. Commit & push to GitHub
git add tmp-igbkp/output/
git commit -m "chore: add encrypted project backup"
git push

# 3. Restore on another environment (e.g., Codespaces)
git clone <repo>
./tmp-igbkp/restore.sh

# 4. After restore, purge commit traces
./tmp-igbkp/purge-history.sh
```

## Backup Scope

- **All files** in the project directory (including `.git/`, files + symlinks)
- Excluded: `tmp-igbkp/` only

## Use in Other Projects

Copy the entire `tmp-igbkp/` folder — it works in any git project with zero modifications.
All paths are auto-detected relative to the project root.

```bash
cp -r tmp-igbkp/ /path/to/other-project/tmp-igbkp/
```

## Security

- **Password**: Always interactive input (CLI args blocked — prevents shell history exposure)
- **Encryption**: AES-256-CBC (OpenSSL)
- **Key derivation**: PBKDF2, 600,000 iterations (brute-force defense)
- **Password passing**: fd (file descriptor) method (prevents `/proc/PID/cmdline` exposure)
- **Splitting**: GitHub 100MB limit compliance (95MB auto-split)
- **Integrity**: SHA-256 checksum verification (manifest.txt)
