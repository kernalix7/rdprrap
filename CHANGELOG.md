# Changelog

**English** | [한국어](docs/CHANGELOG.ko.md)

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (2026-04)
- **`rdprrap-installer`**: Rust CLI installer/uninstaller — service registration, registry (KEY_WOW64_64KEY + SDDL-protected uninstall key), firewall rules (TCP+UDP 3389, locale-safe names), install-dir ACL hardening (SetEntriesInAclW + SetNamedSecurityInfoW for SYSTEM + LocalService), `netsvcs` cohort service restart, `VerQueryValueW`-based termsrv.dll version check, `--force` / `--skip-firewall` / `--skip-restart` / `--disable-nla` flags
- **`rdprrap-check`**: RDP loopback tester — spawns `mstsc /v:127.0.0.2:PORT`, `NlaGuard` RAII (SecurityLayer/UserAuthentication registry backup+restore, Drop-safe on panic), 44 disconnect-reason codes
- **`rdprrap-conf`**: Configuration GUI — native-windows-gui 1.0 + Frame-based layout, 1s timer diagnostics (Wrapper state, TermService SCM, termsrv version, RDP-Tcp listener, support level) + runtime settings (Enable RDP, Port, SingleSession, HideUsers, AllowCustom, AuthMode, Shadow), read-only mode when unprivileged
- Original rdpwrap feature-gap closure: C2 CheckInstall preflight + `--force`, H1 cohort service restart (EnumServicesStatusExW), H2 CheckTermsrvVersion, H3 install-dir ACL, H4 CheckTermsrvDependencies preflight, H4 fDenyTSConnections backup/restore
- 3 security audits completed: 0 CRITICAL, all HIGH/MEDIUM addressed (SDDL-protected backup key, reparse-point defense, NLA opt-in, fDenyTSConnections backup/restore, path validation, transactional rollback, DLL search-path hardening)
- CI updated: Windows x64/x86 × debug/release matrix, all 8 crates built + binary verification (DLL exports, PE architecture, size sanity, installer/check/conf `--help`)
- Memory system: `.priv-storage/memory/` portable persistent memory (iced-x86 API gotchas, NWG 1.0.13 API gotchas, team orchestration rules)
- **`rdprrap-installer plan` subcommand**: prints the full install contract — install directory, wrapper-DLL names, ServiceDll target, every HKLM registry key/value (name + DWORD/SZ data + type), firewall rule names + ports, uninstall behavior. Pure formatting over the `contract` module — no I/O, no registry access, no elevation required. Runs on Linux CI.
- **`contract` module**: single-source-of-truth for install-time constants (DLL names, registry keys, registry value names + data, firewall rule names + port). `paths`, `registry`, `firewall`, `install`, `uninstall` all re-export from `contract` so drift between code paths and the documented contract is impossible.
- **insta snapshot test**: pins the full `plan` manifest byte-for-byte — any change to DLL names, registry keys/values, firewall rules, or the ServiceDll value requires explicit `cargo insta accept`, catching unintended contract drift on Linux before it reaches a Windows host.
- **cargo-deny CI gate** (`deny.toml` + `deny` job): license allow-list (MIT/Apache/BSD/ISC/Unicode), banned-dep check, source-registry policy, `publish = false` at workspace level so the Cargo registry can never accept this crate.
- **offset-finder `--assert-all` mode** + Windows CI smoke test: runs the offset-finder against the hosted runner's own `C:\Windows\System32\termsrv.dll` on every release build — exercises the full runtime pattern-matching pipeline end-to-end against a real, current Windows build (hosted image is Server 2022, 10.0.20348.x).
- **windows-2025 matrix row**: adds one release x64 job pinned to the windows-2025 image so the offset-finder smoke test also hits a Server 2025 termsrv.dll alongside whatever `windows-latest` currently maps to. Server 2019 coverage was removed — the image was retired by GitHub Actions on 2025-06-30.

### Added (2026-03 initial release)
- Cargo workspace with 5 crates: `patcher`, `termwrap-dll`, `umwrap-dll`, `endpwrap-dll`, `offset-finder`
- `patcher` crate: PE header/section/import parsing, 4-byte aligned pattern matching, iced-x86 disassembly wrapper, WriteProcessMemory-based patching, 14 verified bytecode constants
- `termwrap-dll`: termsrv.dll proxy DLL with 7 patch types
  - DefPolicyPatch (direct CMP + indirect MOV+CMP, x64/x86, JZ/JNZ variants)
  - SingleUserPatch (memset→VerifyVersionInfoW and CMP patterns)
  - LocalOnlyPatch (TEST→JS/JNS→CMP→JZ to unconditional JMP)
  - NonRDPPatch (IsAllowNonRDPStack with inlined IsAppServerInstalled fallback)
  - PropertyDevicePatch (SHR+AND PnP device filtering with registry checks)
  - CSLQuery::Initialize SL policy variable patching (bRemoteConnAllowed, bFUSEnabled, bAppServerAllowed, bMultimonAllowed, bInitialized)
- `umwrap-dll`: umrdp.dll proxy DLL for USB/camera PnP redirection (legacy + modern modes, camera secondary patch)
- `endpwrap-dll`: rdpendp.dll proxy DLL for audio recording redirection (TSAudioCaptureAllowed)
- `offset-finder`: standalone CLI tool for termsrv.dll offset detection using pelite (x64 xref + x86 string scan)
- x64 function resolution via exception table xref search with unwind chain backtrace
- x86 function resolution via prologue scanning (8B FF 55 8B EC) with branch-following priority queue
- Thread suspension/resumption for safe in-memory patching
- DLL export forwarding (ServiceMain, SvchostPushServiceGlobals, GetTSAudioEndpointEnumeratorForSession, DllGetClassObject, DllCanUnloadNow)
- GitHub CI: Linux check + Windows x64/x86 full build with artifact upload
- 11 unit tests (pattern matching + disassembly)
- Bilingual documentation (English + Korean): README, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, CHANGELOG
- GitHub templates: PR template, bug report, feature request
- AI multi-tool configuration (.priv-storage/ v2.0)
- Encrypted backup toolkit (tmp-igbkp/)
