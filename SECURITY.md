# Security Policy

**English** | [한국어](docs/SECURITY.ko.md)

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |

As rdprrap is in active development, security updates are applied to the latest version on the `main` branch.

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them through [GitHub Security Advisories](https://github.com/kernalix7/rdprrap/security/advisories/new).

### What to Include

1. **Description** — A clear description of the vulnerability
2. **Steps to Reproduce** — Detailed steps to reproduce the issue
3. **Impact** — The potential impact of the vulnerability
4. **Affected Components** — Which crates/DLLs of rdprrap are affected
5. **Environment** — Windows version, architecture (x64/x86), termsrv.dll version

### Response Timeline

- **Acknowledgment** — Within 48 hours of the report
- **Initial Assessment** — Within 7 days
- **Fix & Disclosure** — Coordinated with the reporter; typically within 30 days for critical issues

### Scope

The following areas are considered in-scope for security reports:

- Memory safety violations in `unsafe` blocks
- DLL hijacking / loading path vulnerabilities
- Buffer overflows in PE parsing or disassembly
- Race conditions in thread suspension/resumption
- WriteProcessMemory targeting incorrect addresses
- Privilege escalation through wrapper DLLs

### Out of Scope

- Bugs that require physical access to the user's machine
- Social engineering attacks
- Issues in third-party dependencies (please report these upstream, but let us know)

## Security Best Practices

rdprrap follows these security practices:

- All `unsafe` blocks documented with `// SAFETY:` invariants
- No raw pointer arithmetic without bounds verification
- DLL loading restricted to system32 paths (`LOAD_LIBRARY_SEARCH_SYSTEM32`)
- Thread suspension uses snapshot-based enumeration to prevent TOCTOU races
- `cargo audit` run before releases

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Contributors who report valid security issues will be acknowledged (with permission) in our release notes.

---

*This security policy is subject to change as the project matures.*
