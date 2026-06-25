# rdprrap

RDP Wrapper rewritten in Rust.

**English** | [한국어](docs/README.ko.md)

## Key Features

| Component | Description |
|-----------|-------------|
| **termwrap-dll** | Core RDP patching — multi-session support, policy bypass for Home/non-Server editions. 7 patch types: DefPolicy, SingleUser, LocalOnly, NonRDP, PropertyDevice, SLPolicy, CSLQuery::Initialize |
| **umwrap-dll** | USB/camera PnP device redirection on modern (non-slc.dll) `umrdp.dll` builds. The legacy slc.dll path (older SKUs) is detected but skipped — it needs a build-specific stack-slot displacement that cannot be recovered dynamically |
| **endpwrap-dll** | Audio recording redirection (TSAudioCaptureAllowed) |
| **patcher** | Shared library — PE parsing, x86/x64 disassembly, ARM64 `.pdata` function scanning, runtime pattern matching, runtime patch-byte emission (`patcher::analyze` + `patcher::encode`) plus 18 fixed bytecode templates for the static patches |
| **ARM64 support** | `aarch64-pc-windows-msvc` build target with experimental ARM64 `termwrap`/`umwrap`/`endpwrap` runtime patchers. Real Windows ARM64 validation is still required before calling it production-supported |
| **offset-finder** | Standalone CLI tool for x86/x64/ARM64 offset detection (pelite-based, no PDB required). `--dry-run` (`-d`) reports each captured patch site + the exact bytes that would be written; `--assert-all` implies it and exits non-zero on any miss |
| **rdprrap-installer** | Rust CLI installer/uninstaller — service registration, registry setup, firewall rules, cohort service restart, install-dir ACL hardening (replaces Delphi `RDPWInst.exe`) |
| **rdprrap-check** | RDP connection tester — loopback `127.0.0.2` via `mstsc.exe`, NLA guard RAII, 44 disconnect-reason codes (replaces `RDPCheck.exe`) |
| **rdprrap-conf** | Configuration GUI — native-windows-gui panel for diagnostics + runtime RDP settings (Enable/Port/SingleSession/HideUsers/AllowCustom/AuthMode/Shadow), replaces `RDPConf.exe` |

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Rust (stable, MSVC toolchain) |
| Disassembler | [iced-x86](https://crates.io/crates/iced-x86) (pure Rust) |
| PE Parsing | [pelite](https://crates.io/crates/pelite) |
| Windows API | [windows-rs](https://crates.io/crates/windows) |
| Target | x86_64-pc-windows-msvc, i686-pc-windows-msvc, aarch64-pc-windows-msvc |
| CI | GitHub Actions (Linux check + Windows x64/x86 build, ARM64 build/static artifact checks) |

## Quick Start

### Prerequisites
- Rust toolchain (stable, MSVC)
- Windows SDK

### Installation

```bash
git clone https://github.com/kernalix7/rdprrap.git
cd rdprrap

rustup target add x86_64-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup target add aarch64-pc-windows-msvc

cargo build --release
```

### Usage

From an elevated (Administrator) command prompt on the target Windows host:

```powershell
# Install — copies DLLs, writes registry, opens firewall (TCP+UDP 3389),
# grants install-dir ACL (SYSTEM + LocalService), restarts TermService cohort
rdprrap-installer.exe install --source <dir-containing-built-DLLs>

# Check current state (ServiceDll, registry, firewall, termsrv.dll version)
rdprrap-installer.exe status

# Print the install contract (paths, DLL names, registry keys+values,
# firewall rules) — pure documentation, no I/O, no elevation required
rdprrap-installer.exe plan

# Uninstall — restores original ServiceDll, AllowMultipleTSSessions,
# fDenyTSConnections, AddIns, and removes firewall rules
rdprrap-installer.exe uninstall
```

Additional flags:

| Flag | Effect |
|------|--------|
| `--source DIR` | Directory to copy DLLs from (defaults to the installer's own directory) |
| `--force` | Reinstall and replace existing wrapper DLLs even if ServiceDll already points to the wrapper |
| `--skip-firewall` | Do not add/remove firewall rules |
| `--skip-restart` | Do not restart TermService (apply changes manually or on reboot) |
| `--disable-nla` | Set `UserAuthentication=0` (opt-in, required for legacy clients) |
| `-i` / `-u` | Legacy aliases for install / uninstall (RDPWInst compatibility) |

After install, the two GUIs are launched from `%ProgramFiles%\RDP Wrapper\`:

```powershell
# Configuration panel — live state + runtime settings toggles
rdprrap-conf.exe

# Loopback RDP test — spawns mstsc /v:127.0.0.2 with NLA-guard RAII
rdprrap-check.exe
```

Manual install (without `rdprrap-installer.exe`) remains possible — copy the DLLs into `%ProgramFiles%\RDP Wrapper\` and merge the appropriate registry file. See the original [TermWrap](https://github.com/llccd/TermWrap) for the DLL interface reference.

To self-diagnose a `termsrv.dll` before (or after) installing, run the standalone offset finder:

```powershell
# Report every captured patch site and the exact bytes that would be
# written (or NOT FOUND) — purely diagnostic, no writes.
offset-finder.exe --dry-run C:\Windows\System32\termsrv.dll

# Exit non-zero if any required string/function/patch site is missing.
# --assert-all implies --dry-run.
offset-finder.exe --assert-all C:\Windows\System32\termsrv.dll
```

## Project Structure

```
rdprrap/
├── crates/
│   ├── patcher/            # Shared: PE parsing, disassembly, pattern matching, memory patching
│   │   └── src/
│   │       ├── pe.rs       # PE header/section/import/exception table parsing
│   │       ├── pattern.rs  # 4-byte aligned string pattern matching in .rdata
│   │       ├── disasm.rs   # iced-x86 decoder wrapper, xref search, branch helpers
│   │       ├── arm64.rs    # ARM64 .pdata function scan + ADR/ADRP/ADD/BL helpers
│   │       └── patch.rs    # WriteProcessMemory wrapper, NOP fill, 18 bytecode constants
│   ├── termwrap-dll/       # cdylib: termsrv.dll proxy (core RDP)
│   │   └── src/patches/    # DefPolicy, SingleUser, LocalOnly, NonRDP, PropertyDevice, SLPolicy
│   ├── umwrap-dll/         # cdylib: umrdp.dll proxy (USB/camera redirection)
│   ├── endpwrap-dll/       # cdylib: rdpendp.dll proxy (audio recording)
│   ├── offset-finder/      # Binary: standalone offset detection CLI
│   ├── rdprrap-installer/  # Binary: install/uninstall CLI (registry, service, firewall, ACL)
│   ├── rdprrap-check/      # Binary: RDP loopback tester (mstsc + NLA guard)
│   └── rdprrap-conf/       # Binary: configuration GUI (native-windows-gui)
├── .github/
│   └── workflows/ci.yml   # Linux check + Windows x64/x86 build matrix + ARM64 static checks
└── docs/                   # Korean documentation
```

## How It Works

1. Wrapper DLLs proxy original system DLLs (`termsrv.dll`, `umrdp.dll`, `rdpendp.dll`)
2. On `DLL_PROCESS_ATTACH`, the original DLL is loaded and exports are forwarded
3. All threads are suspended, in-memory patches applied via `WriteProcessMemory`, then resumed
4. Patch offsets found at runtime:
   - **x64**: Scan `.rdata` for known strings → search exception table for LEA xrefs → backtrace unwind chains to function start
   - **x86**: Scan `.text` for function prologues (`8B FF 55 8B EC`) → follow branches → match PUSH/MOV immediates to string RVAs
   - **ARM64**: `.pdata` function ranges plus ADR/ADRP+ADD string references locate policy checks. `termwrap` patches ARM64 DefPolicy, SingleUser, LocalOnly, AppServer/NonRDP, PropertyDevice, and SL policy paths with ARM64-specific bytecodes; `umwrap` patches PnP/camera BL calls to `mov w0,#1`; `endpwrap` patches the referenced audio-capture function start to `mov w0,#1; ret`.

### Resilience / Why rdprrap

rdprrap needs **no PDB symbols and no hand-maintained per-build offset
table**. Patch sites are located symbol-free (string scan + disassembly +
xref) and, for DefPolicy/PropertyDevice, the struct displacement, register,
and branch direction are captured *dynamically at runtime* and the patch
bytes are emitted by the `patcher::encode` instruction encoder. Because
nothing is keyed to a fixed offset or a fixed byte template, the patches
keep working across `termsrv.dll` struct-layout shifts that ship with new
Windows builds — there is no offset map to update when Microsoft moves a
field.

## Patch Types (termsrv.dll)

| Patch | Purpose | Mechanism |
|-------|---------|-----------|
| DefPolicyPatch | Allow multiple RDP sessions | `patcher::analyze` disassembles the policy function and captures the struct displacement, register, and branch direction at runtime; `patcher::encode` then emits the `mov reg, 0x100` + `mov [base+disp32], reg` bytes for the captured layout, so the patch survives struct-offset shifts |
| SingleUserPatch | Disable per-user session limit | NOP out VerifyVersionInfoW call or CMP instruction |
| LocalOnlyPatch | Remove local-only license restriction | Convert JZ to unconditional JMP |
| NonRDPPatch | Allow non-RDP stack | Replace CALL with `inc [ecx]; xor eax,eax` |
| PropertyDevicePatch | Enable PnP device redirection | `patcher::analyze` captures the destination register dynamically at runtime; `patcher::encode` emits the `mov reg, 0` for that register, so the patch survives instruction/register changes across builds |
| SLPolicyPatch | Set SL policy variables to 1 | Direct memory write to bRemoteConnAllowed, bFUSEnabled, etc. |

## Testing

```bash
cargo test                                          # Unit tests
cargo clippy --all-targets -- -D warnings           # Lint
cargo fmt --check                                   # Format check
```

CI runs automatically on push/PR: Linux check + Windows x64/x86 full build + ARM64 build/static artifact checks.

## Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| RDP multi-session worked, then stopped after a Windows update / new build | A `termsrv.dll` change moved a patch site so the patcher could not resolve it on the new build (the issue-#3 class of regression) | Run `offset-finder --dry-run C:\Windows\System32\termsrv.dll` and look at the `[Patch Dry-Run]` block. A `NOT FOUND` line tells you exactly which patch site failed to resolve. Capture that output plus the `termsrv.dll` version and file it for triage. |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and workflow.

## Security

For security issues, follow the process in [SECURITY.md](SECURITY.md).

## References

- [stascorp/rdpwrap](https://github.com/stascorp/rdpwrap) — Original RDP Wrapper
- [llccd/TermWrap](https://github.com/llccd/TermWrap) — C++ rewrite with integrated offset finder
- [llccd/RDPWrapOffsetFinder](https://github.com/llccd/RDPWrapOffsetFinder) — PDB-based offset finder

## License

MIT License — see [LICENSE](LICENSE) for details.

Portions of rdprrap are ports or reimplementations of upstream
projects (rdpwrap under Apache-2.0; TermWrap and RDPWrapOffsetFinder
under MIT). See [NOTICE](NOTICE) for attribution, the full texts of
those upstream licenses under [vendor/licenses/](vendor/licenses/),
and `THIRD_PARTY_LICENSES.txt` (generated at release time; bundled
inside each release ZIP) for the compiled Rust-dependency attributions.
