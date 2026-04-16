# Contributing to rdprrap

**English** | [한국어](docs/CONTRIBUTING.ko.md)

Thanks for your interest in contributing to rdprrap.

## Development Setup

### Prerequisites
- Rust toolchain (stable, MSVC)
- Windows SDK
- Windows environment for integration testing

### Build
```bash
git clone https://github.com/kernalix7/rdprrap.git
cd rdprrap
rustup target add x86_64-pc-windows-msvc
rustup target add i686-pc-windows-msvc
cargo build --release
```

### Test
```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-change`
3. Commit with Conventional Commits style
4. Push and open a Pull Request

## Pull Request Checklist

- [ ] The change has a clear scope and rationale
- [ ] Tests are added/updated where applicable
- [ ] `cargo build --release` — zero errors
- [ ] `cargo clippy --all-targets -- -D warnings` — zero warnings
- [ ] `cargo test` — all tests pass
- [ ] All `unsafe` blocks have `// SAFETY:` comments
- [ ] No `.unwrap()` in non-test code
- [ ] README / docs are updated when behavior changes

## Commit Message Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `refactor:` for internal improvements without behavior changes
- `test:` for test updates
- `chore:` for maintenance tasks

## Security

For security issues, follow the process in [SECURITY.md](SECURITY.md).
