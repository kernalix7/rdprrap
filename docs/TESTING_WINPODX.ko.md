# winpodx 로 런타임 테스트

[English](TESTING_WINPODX.md) | **한국어**

[winpodx](https://github.com/kernalix7/winpodx) 는 Linux 위에서
실제 Windows 컨테이너를 (dockur/windows + KVM/QEMU, FreeRDP RemoteApp
로 `127.0.0.1:3390` 에 노출) 구동합니다. 수정되지 않은 Windows
이미지를 부팅하므로 — WINE 이 아닙니다 — 컨테이너 내부의
`termsrv.dll`, `umrdp.dll`, `rdpendp.dll` 은 전부 진짜입니다. 덕분에
winpodx 는 별도 VM 없이 Linux 개발 호스트에서
[TESTING.ko.md](TESTING.ko.md) 의 **x64 행들** 을 가장 빠르게
검증할 수 있는 수단입니다.

이 문서는 [TESTING.ko.md](TESTING.ko.md) 의 부분집합을 컨테이너
환경에 맞게 각색한 것입니다. winpodx 가 커버하지 못하는 x86 커버리지
및 다중 OS 매트릭스는 독립 VM 으로 돌아가세요.

## 적용 범위

| 커버 가능                                                      | 커버 불가                                                   |
|---------------------------------------------------------------|------------------------------------------------------------|
| Win10/11/Server 2022/2025 에서 x64 `termwrap`/`umwrap`/`endpwrap` | x86 (i686) 빌드 — dockur/windows 는 x64 전용                |
| SYSTEM 권한 설치/제거 왕복                                     | 다양한 아키텍처의 USB 리다이렉션 (호스트 USB 패스스루 의존)   |
| 컨테이너 termsrv.dll 에 대한 `offset-finder --assert-all`      | 한 번의 실행으로 여러 Windows 버전 병렬 매트릭스             |
| 두 번째 RDP 클라이언트로 멀티세션 smoke                        | Podman/KVM 이 노출하지 않는 물리 주변기기                    |
| `OutputDebugString` 로그 DebugView 캡처                        | 물리 디스플레이 기반 터치/DPI 스케일링 특이사항             |

## 0. 사전 준비

- winpodx README 에 따라 KVM + Podman(또는 Docker) 이 설치된 Linux 호스트.
- winpodx 가 작동하는 상태 (`winpodx run notepad` 성공).
- `rdprrap` 릴리스 산출물. Linux 에서는
  [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin) 을
  사용합니다 — `cargo build --target x86_64-pc-windows-msvc` 가
  찾지 못하는 MSVC SDK + CRT 를 자동으로 가져와 링크합니다:
  ```bash
  cargo install cargo-xwin            # 1회성
  sudo zypper install lld             # openSUSE (또는: apt install lld)
  cargo xwin build --release --target x86_64-pc-windows-msvc --workspace
  ```
  산출물은 `target/x86_64-pc-windows-msvc/release/` 에 생성됩니다:
  `termwrap_dll.dll`, `umwrap_dll.dll`, `endpwrap_dll.dll`,
  `rdprrap-installer.exe`, `rdprrap-check.exe`, `rdprrap-conf.exe`,
  `offset-finder.exe`. 인스톨러가 설치 시점에 DLL 을 정식 이름
  (`termwrap.dll`, `umwrap.dll`, `rdpendp.dll`) 으로 변경합니다.

  > i686 빌드가 필요한 경우 (winpodx 자체는 x64 전용이므로
  > [TESTING.ko.md](TESTING.ko.md) 의 별도 32비트 VM 을 돌릴
  > 계획이 있을 때만 해당), cargo-xwin 이 기본적으로는 x86 SDK 를
  > 받지 않습니다. 명시적으로 추가:
  > ```bash
  > XWIN_ARCH=x86,x86_64 cargo xwin build --release \
  >   --target i686-pc-windows-msvc --workspace
  > ```
- 호스트에서 쓸 두 번째 RDP 클라이언트: `xfreerdp` 또는 `Remmina`.
- **DebugView** (`Dbgview.exe`) 를 컨테이너에 복사해두면 로그 분석이
  쉽습니다 (선택, 다만 강력 권장).

## 1. 컨테이너 준비

1. winpodx 설정에서 Windows 이미지를 고정하세요 — 예: Windows 11 24H2
   또는 Server 2022. 고른 `version=` 값은 테스트 리포트에 나중에
   기록하니 메모해두세요.
2. 테스트 동안은 `auto_suspend` 를 끕니다:
   ```toml
   # winpodx.toml
   [pod]
   auto_suspend = false
   ```
   TermService 재시작 시 RemoteApp 세션이 잠시 끊기는데, winpodx 가
   pod 가 idle 이라고 판단하면 테스트 도중에 suspend 할 수 있습니다.
3. 컨테이너 부팅:
   ```bash
   winpodx pod start
   winpodx pod status   # 127.0.0.1:3390 에 RDP 가 뜬 것 확인
   ```
4. 컨테이너 스토리지 스냅샷 (winpodx 설정에 따라 Podman
   `podman container commit` 또는 백엔드 qcow2 오버레이). 설치/제거
   사이클 사이에 이 스냅샷으로 복원합니다.

## 2. 산출물 컨테이너에 옮기기

winpodx 는 Linux 홈을 기본으로 `\\tsclient\home` 에 마운트하므로
가장 간단한 방법은:

```powershell
# Windows RDP 세션 관리자 PowerShell 내부에서:
New-Item -ItemType Directory -Path C:\rdprrap -Force
Copy-Item \\tsclient\home\<you>\…\target\x86_64-pc-windows-msvc\release\*.exe C:\rdprrap\
Copy-Item \\tsclient\home\<you>\…\target\x86_64-pc-windows-msvc\release\*.dll C:\rdprrap\
```

또는 winpodx SSH 포트를 설정해 두었다면 scp 로. 어느 쪽이든,
최종 상태: `C:\rdprrap\` 에 7개 산출물이 모두 있어야 합니다.

## 3. 사전 점검

TermService 를 건드리기 전에, 컨테이너의 termsrv.dll 을 패처가
실제로 인식하는지부터 확인:

```powershell
cd C:\rdprrap
.\offset-finder.exe --assert-all C:\Windows\System32\termsrv.dll
```

- [ ] 종료 코드 0.
- [ ] 리포트에 `NOT_FOUND` 라인이 없음.

여기서 실패하면 **중단합니다**. 인스톨러를 돌리지 마세요. 전체
stdout 과 termsrv 버전 (`Get-Item
C:\Windows\System32\termsrv.dll | Select-Object -Expand VersionInfo`
의 결과) 을 함께 기록으로 남기세요 — 해당 빌드에 대해 패처의
패턴 집합이 낡은 것이고, 그대로 인스톨러를 돌리면 서비스가
망가진 채 남습니다.

## 4. 설치

```powershell
# transcript 시작 — TermService 재시작 시 RDP 세션이 반드시 끊깁니다.
Start-Transcript -Path C:\rdprrap\install.log -Append

.\rdprrap-installer.exe plan     # 계약 미리보기
.\rdprrap-installer.exe install  # 여기서 RDP 세션 끊김 → 자동 재접속

Stop-Transcript
```

- [ ] install transcript 의 종료 코드 0.
- [ ] 재접속 후 `Get-Service TermService` 가 `Running`.
- [ ] `%ProgramFiles%\RDP Wrapper\` 가 존재하고
      `termwrap.dll`, `umwrap.dll`, `rdpendp.dll` 포함.
- [ ] `reg query "HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters" /v ServiceDll`
      이 `%ProgramFiles%\RDP Wrapper\` 내부를 가리킴.
- [ ] `icacls %ProgramFiles%\RDP Wrapper` 가 SYSTEM + Administrators 에
      full control, 다른 누구에게도 쓰기 권한 없음을 표시.

## 5. 멀티세션 smoke

winpodx 의 RemoteApp 세션이 session 1 을 차지합니다. 멀티세션 패치가
실제로 먹는지 증명하려면, Linux 호스트에서 **두 번째** RDP 연결을
`127.0.0.1:3390` 으로 열고 다른 로컬 Windows 계정으로 로그인:

```bash
xfreerdp /u:user2 /p:<password2> /v:127.0.0.1:3390
```

- [ ] 두 번째 세션이 winpodx 세션을 끊지 않고 로그인 완료.
- [ ] 두 세션이 동시에 사용 가능 (포커스 전환, 각각 타이핑).
- [ ] DebugView 에 `TermWrap:` 패치 적용 라인이 보이고,
      `patch not found` 라인은 0개.
- [ ] 세션 내부의 `rdprrap-conf.exe` 가 Wrapper, TermService,
      termsrv 버전, RDP-Tcp 리스너 모두 녹색.
- [ ] `rdprrap-check.exe` 가 루프백 RDP OK 를 리포트.

> **참고**: 두 번째 세션이 `CONNECTION_TERMINATED` 로 거부되면
> DebugView 부터 확인하세요 — 원인의 대부분은 `NonRDPPatch` 또는
> `DefPolicyPatch` 누락입니다.

## 6. umwrap — PnP + 카메라 (선택, Podman USB 패스스루 필요)

winpodx 는 Podman / libvirt 스택이 노출하는 USB 패스스루를 그대로
상속합니다. USB 메모리나 카메라를 컨테이너로 연결한 경우:

- [ ] RDP 클라이언트에서 USB 드라이브 리다이렉션 활성화
      (`xfreerdp /drive:usbstick,/media/usb`).
- [ ] RDP 세션 내에 드라이브 문자로 표시됨.
- [ ] DebugView 에 `UmWrap:` 패치 적용 라인 표시.
- [ ] (가능한 경우) 카메라 리다이렉션도 통과.

컨테이너에 물리 USB 접근이 없다면 이 섹션은 건너뛰고, 최종
리포트에 표시해두세요 — 전체 체크리스트의 해당 행은 커버되지 않은
상태로 남습니다.

## 7. endpwrap — 오디오 캡처

- [ ] 두 번째 RDP 클라이언트를 `/microphone` (xfreerdp) 또는
      `audiocapture:i:1` 이 들어간 `.rdp` 파일로 시작.
- [ ] 세션 내부의 `소리 설정 → 입력` 에 리다이렉트된 마이크가 보임.
- [ ] DebugView 에 `EndpWrap:` 패치 적용 라인 표시.

## 8. 제거

```powershell
Start-Transcript -Path C:\rdprrap\uninstall.log -Append
.\rdprrap-installer.exe uninstall   # 여기서 세션 끊김 → 재접속
Stop-Transcript
```

- [ ] 종료 코드 0.
- [ ] `ServiceDll` 이 `%SystemRoot%\System32\termsrv.dll` 로 복원.
- [ ] `%ProgramFiles%\RDP Wrapper\` 삭제.
- [ ] 방화벽 규칙 `rdprrap-RDP-TCP`, `rdprrap-RDP-UDP` 삭제.
- [ ] `HKLM\SOFTWARE\rdprrap\Installer` 삭제.
- [ ] 두 번째 세션 로그인이 더 이상 성공하지 않음 (멀티세션이
      Windows 기본 동작으로 복귀).

## 9. 스냅샷 롤백 + 다음 이미지

1. 컨테이너 중지:
   ```bash
   winpodx pod stop
   ```
2. 단계 1.4 에서 찍은 스냅샷으로 복원.
3. 다른 Windows 버전을 커버하려면 winpodx 설정의 `version=` 를
   바꿔 단계 1 부터 반복.

## 리포팅

각 실행마다 한 행씩 기록:

```
컨테이너 이미지 : <winpodx 설정의 version=...>
termsrv.dll 버전: <(Get-Item ...).VersionInfo 출력>
아키텍처        : x64
일자            : <YYYY-MM-DD>
통과 섹션       : 3, 4, 5, 7, 8    (USB 패스스루 없으면 6 제외)
DebugView 발췌  : <"not found" 라인들, 또는 "none">
비고            : <winpodx 설정 차이, 특이사항>
```

리포트에 Start-Transcript 출력과 DebugView 로그를 첨부하세요.
그것만 있으면 나중에 분류할 때 컨테이너를 다시 부팅할 필요가
없습니다.
