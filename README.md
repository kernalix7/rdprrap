# rdprrap

RDP Wrapper rewritten in Rust.

**English** | [한국어](docs/README.ko.md)

## Key Features

| Component | Description |
|-----------|-------------|
| **termwrap-dll** | Core RDP patching — multi-session support, policy bypass for Home/non-Server editions. 7 patch types: DefPolicy, SingleUser, LocalOnly, NonRDP, PropertyDevice, SLPolicy, CSLQuery::Initialize |
| **umwrap-dll** | USB/camera PnP device redirection for all SKUs (legacy + modern Windows) |
| **endpwrap-dll** | Audio recording redirection (TSAudioCaptureAllowed) |
| **patcher** | Shared library — PE parsing, x86/x64 disassembly, runtime pattern matching, 14 verified bytecode patches |
| **offset-finder** | Standalone CLI tool for offset detection (pelite-based, no PDB required) |
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
| Target | x86_64-pc-windows-msvc, i686-pc-windows-msvc |
| CI | GitHub Actions (Linux check + Windows x64/x86 build) |

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
| `--force` | Reinstall even if ServiceDll already points to the wrapper |
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

## Project Structure

```
rdprrap/
├── crates/
│   ├── patcher/            # Shared: PE parsing, disassembly, pattern matching, memory patching
│   │   └── src/
│   │       ├── pe.rs       # PE header/section/import/exception table parsing
│   │       ├── pattern.rs  # 4-byte aligned string pattern matching in .rdata
│   │       ├── disasm.rs   # iced-x86 decoder wrapper, xref search, branch helpers
│   │       └── patch.rs    # WriteProcessMemory wrapper, NOP fill, 14 bytecode constants
│   ├── termwrap-dll/       # cdylib: termsrv.dll proxy (core RDP)
│   │   └── src/patches/    # DefPolicy, SingleUser, LocalOnly, NonRDP, PropertyDevice, SLPolicy
│   ├── umwrap-dll/         # cdylib: umrdp.dll proxy (USB/camera redirection)
│   ├── endpwrap-dll/       # cdylib: rdpendp.dll proxy (audio recording)
│   ├── offset-finder/      # Binary: standalone offset detection CLI
│   ├── rdprrap-installer/  # Binary: install/uninstall CLI (registry, service, firewall, ACL)
│   ├── rdprrap-check/      # Binary: RDP loopback tester (mstsc + NLA guard)
│   └── rdprrap-conf/       # Binary: configuration GUI (native-windows-gui)
├── .github/
│   └── workflows/ci.yml   # Linux check + Windows x64/x86 build matrix
└── docs/                   # Korean documentation
```

## How It Works

1. Wrapper DLLs proxy original system DLLs (`termsrv.dll`, `umrdp.dll`, `rdpendp.dll`)
2. On `DLL_PROCESS_ATTACH`, the original DLL is loaded and exports are forwarded
3. All threads are suspended, in-memory patches applied via `WriteProcessMemory`, then resumed
4. Patch offsets found at runtime:
   - **x64**: Scan `.rdata` for known strings → search exception table for LEA xrefs → backtrace unwind chains to function start
   - **x86**: Scan `.text` for function prologues (`8B FF 55 8B EC`) → follow branches → match PUSH/MOV immediates to string RVAs

## Patch Types (termsrv.dll)

| Patch | Purpose | Mechanism |
|-------|---------|-----------|
| DefPolicyPatch | Allow multiple RDP sessions | Replace CMP at offset 0x63c/0x320 with `mov reg, 0x100` |
| SingleUserPatch | Disable per-user session limit | NOP out VerifyVersionInfoW call or CMP instruction |
| LocalOnlyPatch | Remove local-only license restriction | Convert JZ to unconditional JMP |
| NonRDPPatch | Allow non-RDP stack | Replace CALL with `inc [ecx]; xor eax,eax` |
| PropertyDevicePatch | Enable PnP device redirection | Replace SHR+AND with `mov reg, 0` |
| SLPolicyPatch | Set SL policy variables to 1 | Direct memory write to bRemoteConnAllowed, bFUSEnabled, etc. |

## Testing

```bash
cargo test                                          # Unit tests
cargo clippy --all-targets -- -D warnings           # Lint
cargo fmt --check                                   # Format check
```

CI runs automatically on push/PR: Linux check + Windows x64/x86 full build.

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
