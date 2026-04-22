# Runtime Testing via winpodx

**English** | [한국어](TESTING_WINPODX.ko.md)

[winpodx](https://github.com/kernalix7/winpodx) runs a real Windows
container on Linux (dockur/windows + KVM/QEMU, exposed via FreeRDP
RemoteApp on `127.0.0.1:3390`). Because it boots an unmodified
Windows image — not WINE — `termsrv.dll`, `umrdp.dll` and
`rdpendp.dll` inside the container are genuine. That makes winpodx
the fastest way to verify the **x64 rows** of [TESTING.md](TESTING.md)
from a Linux development host without keeping a separate VM.

This document is a subset of [TESTING.md](TESTING.md) adapted to the
container environment. For x86 coverage and multi-OS matrix runs
beyond what winpodx supports, fall back to a standalone VM.

## Scope

| Covered | Not covered |
|---------|-------------|
| x64 `termwrap` / `umwrap` / `endpwrap` on Win10/11/Server 2022/2025 | x86 (i686) builds — dockur/windows is x64-only |
| Installer install/uninstall round-trip under SYSTEM | Multi-arch USB redirection (host USB passthrough varies) |
| `offset-finder --assert-all` against the container's termsrv.dll | Parallel matrix of multiple Windows versions in one run |
| Multi-session smoke via a second RDP client | Physical hardware peripherals beyond what Podman/KVM exposes |
| DebugView capture of `OutputDebugString` logs | Touch / DPI scaling quirks tied to physical displays |

## 0. Prerequisites

- Linux host with KVM + Podman (or Docker) installed, as per winpodx README.
- winpodx checked out and working (`winpodx run notepad` succeeds).
- `rdprrap` release artifacts. On Linux, use
  [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin) — it
  provides the MSVC SDK + CRT that `cargo build --target
  x86_64-pc-windows-msvc` otherwise fails to find:
  ```bash
  cargo install cargo-xwin            # one-time
  sudo zypper install lld             # openSUSE (or: apt install lld)
  cargo xwin build --release --target x86_64-pc-windows-msvc --workspace
  ```
  Artifacts land under `target/x86_64-pc-windows-msvc/release/`:
  `termwrap_dll.dll`, `umwrap_dll.dll`, `endpwrap_dll.dll`,
  `rdprrap-installer.exe`, `rdprrap-check.exe`, `rdprrap-conf.exe`,
  `offset-finder.exe`. The installer renames the DLLs at install time
  to their canonical names (`termwrap.dll`, `umwrap.dll`,
  `endpwrap.dll`).

  > For i686 builds (only needed if you also plan to drive a
  > separate 32-bit VM from [TESTING.md](TESTING.md) — winpodx itself
  > is x64-only), cargo-xwin skips the x86 SDK by default. Add it
  > explicitly:
  > ```bash
  > XWIN_ARCH=x86,x86_64 cargo xwin build --release \
  >   --target i686-pc-windows-msvc --workspace
  > ```
- A second RDP client on the host: `xfreerdp` or `Remmina`.
- **DebugView** (`Dbgview.exe`) copied into the container for log capture
  (optional but highly recommended for triage).

## 1. Prepare the container

1. Edit your winpodx config to pin a deterministic Windows image — e.g.
   Windows 11 24H2 or Server 2022. Note the `version=` value you pick;
   you will record it in the test report later.
2. Disable `auto_suspend` for the duration of the test run:
   ```toml
   # winpodx.toml
   [pod]
   auto_suspend = false
   ```
   Restoring TermService will momentarily drop the RemoteApp session —
   if winpodx thinks the pod went idle it may suspend mid-test.
3. Boot the container:
   ```bash
   winpodx pod start
   winpodx pod status   # confirm RDP is up on 127.0.0.1:3390
   ```
4. Snapshot the container storage (Podman `podman container commit` or
   the backing qcow2 overlay, depending on winpodx config). You will
   restore to this snapshot between install/uninstall cycles.

## 2. Ship the artifacts into the container

winpodx mounts the Linux home as `\\tsclient\home` by default, so the
simplest path is:

```powershell
# Inside the Windows RDP session (an admin PowerShell):
New-Item -ItemType Directory -Path C:\rdprrap -Force
Copy-Item \\tsclient\home\<you>\…\target\x86_64-pc-windows-msvc\release\*.exe C:\rdprrap\
Copy-Item \\tsclient\home\<you>\…\target\x86_64-pc-windows-msvc\release\*.dll C:\rdprrap\
```

Or scp over the winpodx SSH port if you configured one. Either way,
end state: `C:\rdprrap\` contains all seven artifacts.

## 3. Preflight

Before touching TermService, confirm the container's termsrv.dll is
one the patcher actually recognises:

```powershell
cd C:\rdprrap
.\offset-finder.exe --assert-all C:\Windows\System32\termsrv.dll
```

- [ ] Exit code 0.
- [ ] No `NOT_FOUND` lines in the report.

If this fails, **stop**. Do not run the installer. Capture the full
stdout (including the termsrv version reported by `Get-Item
C:\Windows\System32\termsrv.dll | Select-Object -Expand VersionInfo`)
and file it — the patcher's pattern set is stale for that build, and
running the installer anyway will leave the service in a broken state.

## 4. Install

```powershell
# Start a transcript — the RDP session WILL drop when TermService restarts.
Start-Transcript -Path C:\rdprrap\install.log -Append

.\rdprrap-installer.exe plan     # preview the contract
.\rdprrap-installer.exe install  # RDP session drops here; reconnect automatically

Stop-Transcript
```

- [ ] Install transcript shows exit code 0.
- [ ] After reconnect, `Get-Service TermService` reports `Running`.
- [ ] `%ProgramFiles%\RDP Wrapper\` exists and contains
      `termwrap.dll`, `umwrap.dll`, `endpwrap.dll`.
- [ ] `reg query "HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters" /v ServiceDll`
      points into `%ProgramFiles%\RDP Wrapper\`.
- [ ] `icacls %ProgramFiles%\RDP Wrapper` shows SYSTEM + Administrators
      with full control and nothing else writable.

## 5. Multi-session smoke

winpodx's native RemoteApp session holds session 1. To prove the
multi-session patch works, open a **second** RDP connection from the
Linux host to `127.0.0.1:3390`, signing in as a different local
Windows account:

```bash
xfreerdp /u:user2 /p:<password2> /v:127.0.0.1:3390
```

- [ ] Second session completes login without kicking the winpodx session.
- [ ] Both sessions remain usable concurrently (switch focus, type in each).
- [ ] DebugView shows `TermWrap:` patch-applied lines, zero
      `patch not found` lines.
- [ ] `rdprrap-conf.exe` inside the session shows Wrapper, TermService,
      termsrv version, RDP-Tcp listener all green.
- [ ] `rdprrap-check.exe` reports loopback RDP OK.

> **Note**: If the second session is rejected with
> `CONNECTION_TERMINATED`, check DebugView first — a missing
> `NonRDPPatch` or `DefPolicyPatch` is the most common cause.

## 6. umwrap — PnP + camera (optional, Podman USB passthrough required)

winpodx inherits whatever USB passthrough the underlying Podman /
libvirt stack exposes. If you wired a USB stick or camera through
to the container:

- [ ] Enable USB drive redirection in the RDP client
      (`xfreerdp /drive:usbstick,/media/usb`).
- [ ] Stick appears inside the RDP session as a drive letter.
- [ ] DebugView shows `UmWrap:` patch-applied lines.
- [ ] Camera redirection (if available) passes through.

If your container has no physical USB access, skip this section and
flag it in the final report — that row in the full checklist stays
uncovered.

## 7. endpwrap — audio capture

- [ ] Start the second RDP client with `/microphone` (xfreerdp) or
      an `.rdp` file containing `audiocapture:i:1`.
- [ ] Inside the session, `Sound settings → Input` shows the
      redirected microphone.
- [ ] DebugView shows `EndpWrap:` patch-applied lines.

## 8. Uninstall

```powershell
Start-Transcript -Path C:\rdprrap\uninstall.log -Append
.\rdprrap-installer.exe uninstall   # session drops here, reconnect
Stop-Transcript
```

- [ ] Exit code 0.
- [ ] `ServiceDll` restored to `%SystemRoot%\System32\termsrv.dll`.
- [ ] `%ProgramFiles%\RDP Wrapper\` removed.
- [ ] Firewall rules `rdprrap-RDP-TCP`, `rdprrap-RDP-UDP` removed.
- [ ] `HKLM\SOFTWARE\rdprrap\Installer` removed.
- [ ] Second-session login no longer succeeds (multi-session reverts
      to default Windows behaviour).

## 9. Snapshot rollback + next image

1. Stop the container:
   ```bash
   winpodx pod stop
   ```
2. Restore the snapshot taken in step 1.4.
3. If covering a different Windows version, change the `version=`
   line in winpodx config and repeat from step 1.

## Reporting

Fill in one row per run:

```
Container image  : <version=... from winpodx config>
termsrv.dll ver  : <output of (Get-Item ...).VersionInfo>
Architecture     : x64
Date             : <YYYY-MM-DD>
Sections passed  : 3, 4, 5, 7, 8    (skip 6 if no USB passthrough)
DebugView excerpt: <any "not found" lines, or "none">
Notes            : <winpodx config deltas, anything unusual>
```

Attach the Start-Transcript outputs and the DebugView log to the
report. That's enough context for future triage without having to
re-boot the container.
