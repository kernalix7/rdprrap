# Windows Runtime Verification Checklist

**English** | [한국어](TESTING.ko.md)

Linux CI builds and Windows CI builds (x64/x86, debug/release) cover
compile + clippy + unit tests. What CI cannot cover:

- Loading the wrapper DLLs into a real `svchost.exe` / `umrdp.dll` /
  `rdpendp.dll` host.
- Exercising the patch paths against actual `termsrv.dll` bytes that ship
  with Windows 10, 11, Server 2022, Server 2025.
- Validating the installer/uninstaller end-to-end as `SYSTEM`.

This document captures the manual checks that close those gaps. Run
them on a disposable VM snapshot. Restore the snapshot between runs so
ACLs, registry, and service state all reset cleanly.

For a Linux-friendly way to cover the x64 rows without a separate VM,
see [TESTING_WINPODX.md](TESTING_WINPODX.md) — it walks through
reusing a [winpodx](https://github.com/kernalix7/winpodx) container
(dockur/windows + FreeRDP) as the target Windows host.

## Prerequisites

- Windows VM with RDP disabled by default.
- Matching build artefact from `cargo build --release`
  (x64 host → `x86_64-pc-windows-msvc`, x86 host → `i686-pc-windows-msvc`).
- Admin account, Remote Desktop client (`mstsc.exe`) on a second machine.
- Optional: DebugView (SysInternals) to capture `OutputDebugString`.

## Build Targets to Verify

Each row below must be verified on both architectures the target OS
supports. Modern Windows SKUs no longer ship x86, but older x86 VMs
(Win10 32-bit, Windows 7 lab images) are still the only place the
i686 path gets real coverage.

| OS                 | x64 | x86 | Notes                                              |
|--------------------|-----|-----|----------------------------------------------------|
| Windows 10 22H2    | ✅  | ⚠️  | x86 coverage only via legacy images                |
| Windows 11 23H2    | ✅  | —   | x86 not shipped                                    |
| Windows 11 24H2    | ✅  | —   | Latest consumer SKU                                |
| Server 2022        | ✅  | —   | Matches `windows-latest` runner                    |
| Server 2025        | ✅  | —   | Matches `windows-2025` runner                      |

Tick a row only after the full **Install**, **Runtime**, **Uninstall**
sections below all pass on that OS/arch pair.

## 1. Install

```powershell
# Run from an elevated PowerShell on the target VM.
.\rdprrap-installer.exe plan   # preview contract, no changes made
.\rdprrap-installer.exe install
```

Pass criteria:
- [ ] Exit code 0.
- [ ] `%ProgramFiles%\RDP Wrapper\` created, contains `termwrap.dll`,
      `umwrap.dll`, `endpwrap.dll`.
- [ ] `HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters\ServiceDll`
      points into `%ProgramFiles%\RDP Wrapper\`.
- [ ] `HKLM\SOFTWARE\rdprrap\Installer` exists and is writable only by
      SYSTEM + Administrators (`icacls` output).
- [ ] Firewall rules `rdprrap-RDP-TCP` and `rdprrap-RDP-UDP` present,
      TCP/UDP 3389 allowed.
- [ ] `sc query TermService` returns `STATE : 4 RUNNING`.

## 2. Runtime — termwrap (x64 + x86)

```powershell
# From a second machine:
mstsc /v:<target-ip>
```

Pass criteria:
- [ ] RDP connection completes with non-admin credentials if another
      admin is already signed in locally (concurrent-session smoke test).
- [ ] DebugView shows `TermWrap:` patch-applied messages, no
      `patch not found` warnings.
- [ ] `rdprrap-check` (run on target) reports loopback RDP OK.
- [ ] `rdprrap-conf` (run on target) shows green status for Wrapper,
      TermService, termsrv version, RDP-Tcp listener.

Repeat on Windows 11 to catch termsrv.dll layout changes. Any red
status in `rdprrap-conf` means the patcher failed to resolve an offset —
run `offset-finder --assert-all C:\Windows\System32\termsrv.dll` and
triage from its report.

## 3. Runtime — umwrap (PnP redirection)

Goal: prove the i686 path patched something real, not just compiled.

- [ ] Redirect a USB storage device from the RDP client
      (`mstsc` → Local Resources → More → Drives).
- [ ] Device appears in `This PC` inside the RDP session.
- [ ] DebugView shows `UmWrap:` patch-applied messages, no
      `PnpRedirection patch not found`.

Camera redirection (Win10+):
- [ ] USB camera redirection passes through.
- [ ] DebugView shows camera-secondary patch applied when
      `CameraRedirectionAllowed` string was present in `.rdata`.

## 4. Runtime — endpwrap (audio capture)

- [ ] RDP client with `audiocapture:i:1` in `.rdp` file (or
      Local Resources → Remote audio → Recording: Record from this
      computer) captures microphone audio into the remote session.
- [ ] DebugView shows `EndpWrap:` patch-applied messages.

## 5. Installer preflights + negative cases

- [ ] Run installer on an OS/termsrv build not covered by
      `offset-finder --assert-all` ⇒ installer aborts with a version
      mismatch error (CheckTermsrvVersion).
- [ ] Run with `--skip-firewall` ⇒ no firewall rules created; all other
      steps complete.
- [ ] Run with `--skip-restart` ⇒ TermService stays in its old state;
      restart is the user's responsibility.
- [ ] Run with `--disable-nla` ⇒ `HKLM\...\RDP-Tcp\UserAuthentication`
      set to 0; uninstall restores the previous value.
- [ ] Re-run installer over an existing install (idempotency): succeeds,
      re-registers the same state, no drift in the `HKLM\SOFTWARE\rdprrap\Installer`
      backup subtree.
- [ ] Simulate tampered backup: manually set
      `HKLM\SOFTWARE\rdprrap\Installer\OriginalServiceDll` to
      `C:\ProgramData\Evil.dll`, then run uninstall ⇒ uninstaller
      refuses to restore (SDDL-protected validation path).

## 6. Uninstall

```powershell
.\rdprrap-installer.exe uninstall
```

Pass criteria:
- [ ] Exit code 0.
- [ ] `ServiceDll` restored to `%SystemRoot%\System32\termsrv.dll`.
- [ ] `%ProgramFiles%\RDP Wrapper\` removed.
- [ ] Firewall rules removed.
- [ ] `HKLM\SOFTWARE\rdprrap\Installer` removed.
- [ ] `fDenyTSConnections` restored to its pre-install value (if the
      installer recorded one).
- [ ] AddIns subtree removed only if the installer originally created
      the AddIns parent key; pre-existing AddIns configurations left
      untouched.
- [ ] TermService still starts cleanly after uninstall; RDP behaves
      exactly as it did on a fresh OS.

## 7. offset-finder runtime smoke

On each OS image:

```powershell
offset-finder --assert-all C:\Windows\System32\termsrv.dll
```

- [ ] Exit code 0.
- [ ] All named strings resolve (no `NOT_FOUND`).
- [ ] All named functions resolve via xref (no `NOT_FOUND`).

If the above fails on a supported OS, open a patcher-team ticket with
the full stdout and the termsrv.dll version (`(Get-Item termsrv.dll).VersionInfo`).

## Reporting

Record the result of each checklist run in a table with: OS build
number, termsrv.dll version, architecture, date, pass/fail per section,
and any DebugView extracts that show `not found` messages. Stale
offsets are the dominant failure mode — a full DebugView capture is
the fastest way to triage them.
