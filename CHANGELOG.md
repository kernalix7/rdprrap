# Changelog

**English** | [한국어](docs/CHANGELOG.ko.md)

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
