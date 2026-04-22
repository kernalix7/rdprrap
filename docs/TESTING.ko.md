# Windows 런타임 검증 체크리스트

[English](TESTING.md) | **한국어**

Linux CI 및 Windows CI 빌드(x64/x86, debug/release)는 컴파일 + clippy +
단위 테스트까지는 커버합니다. 반면 CI 로는 커버할 수 없는 부분이
있습니다:

- 래퍼 DLL 을 실제 `svchost.exe` / `umrdp.dll` / `rdpendp.dll` 호스트에
  로드하여 동작을 확인하는 것.
- Windows 10, 11, Server 2022, Server 2025 에 실제로 포함된
  `termsrv.dll` 바이트에 대해 패치 경로를 실행하는 것.
- `SYSTEM` 권한으로 인스톨러/언인스톨러를 엔드투엔드로 검증하는 것.

이 문서는 그 공백을 메우기 위한 수동 검증 절차를 기록합니다. 일회용
VM 스냅샷에서 실행하세요. 실행 사이마다 스냅샷을 복원하여 ACL,
레지스트리, 서비스 상태가 깨끗하게 초기화되도록 합니다.

별도 VM 없이 Linux 에서 x64 행들만이라도 돌려보고 싶다면
[TESTING_WINPODX.ko.md](TESTING_WINPODX.ko.md) 를 참고하세요 —
[winpodx](https://github.com/kernalix7/winpodx) 컨테이너
(dockur/windows + FreeRDP) 를 타깃 Windows 호스트로 재활용하는
절차를 설명합니다.

## 사전 준비

- RDP 가 기본 비활성화된 Windows VM.
- `cargo build --release` 로 생성된 해당 아키텍처 빌드 산출물
  (x64 호스트 → `x86_64-pc-windows-msvc`, x86 호스트 → `i686-pc-windows-msvc`).
- 관리자 계정, 별도 머신의 원격 데스크톱 클라이언트(`mstsc.exe`).
- 선택: DebugView (SysInternals) — `OutputDebugString` 캡처용.

## 검증 대상 빌드 매트릭스

아래 표의 각 행은 해당 OS 가 지원하는 두 아키텍처 모두에 대해 검증되어야
합니다. 최신 Windows SKU 들은 더 이상 x86 을 공식 공급하지 않지만,
구형 x86 VM(Win10 32비트, Windows 7 랩 이미지) 은 i686 경로가
실제로 검증되는 유일한 장소입니다.

| OS                 | x64 | x86 | 비고                                                 |
|--------------------|-----|-----|------------------------------------------------------|
| Windows 10 22H2    | ✅  | ⚠️  | x86 커버리지는 레거시 이미지에서만 가능             |
| Windows 11 23H2    | ✅  | —   | x86 미공급                                           |
| Windows 11 24H2    | ✅  | —   | 최신 컨슈머 SKU                                      |
| Server 2022        | ✅  | —   | `windows-latest` 러너와 매칭                          |
| Server 2025        | ✅  | —   | `windows-2025` 러너와 매칭                            |

각 행은 아래 **설치 / 런타임 / 제거** 섹션이 모두 통과한 뒤에만
체크합니다.

## 1. 설치

```powershell
# 타깃 VM 의 관리자 PowerShell 에서 실행.
.\rdprrap-installer.exe plan   # 계약 미리보기, 변경 없음
.\rdprrap-installer.exe install
```

통과 기준:
- [ ] 종료 코드 0.
- [ ] `%ProgramFiles%\RDP Wrapper\` 생성, `termwrap.dll`, `umwrap.dll`,
      `endpwrap.dll` 포함.
- [ ] `HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters\ServiceDll`
      이 `%ProgramFiles%\RDP Wrapper\` 내부를 가리킴.
- [ ] `HKLM\SOFTWARE\rdprrap\Installer` 존재, SYSTEM + Administrators
      만 쓰기 가능 (`icacls` 결과).
- [ ] 방화벽 규칙 `rdprrap-RDP-TCP`, `rdprrap-RDP-UDP` 존재,
      TCP/UDP 3389 허용.
- [ ] `sc query TermService` 결과가 `STATE : 4 RUNNING`.

## 2. 런타임 — termwrap (x64 + x86)

```powershell
# 별도 머신에서:
mstsc /v:<target-ip>
```

통과 기준:
- [ ] 로컬에 이미 다른 관리자 로그인이 있을 때 관리자 아닌 자격증명으로
      RDP 접속 성공 (동시 세션 smoke 테스트).
- [ ] DebugView 에 `TermWrap:` 패치 적용 로그가 보이고,
      `patch not found` 경고가 없음.
- [ ] `rdprrap-check` (타깃에서 실행) 이 루프백 RDP OK 를 리포트.
- [ ] `rdprrap-conf` (타깃에서 실행) 가 Wrapper, TermService,
      termsrv 버전, RDP-Tcp 리스너를 녹색으로 표시.

termsrv.dll 레이아웃 변경을 잡기 위해 Windows 11 에서도 반복합니다.
`rdprrap-conf` 의 어떤 행이라도 빨간색이면 패처가 오프셋을 해결하지
못했다는 뜻 — `offset-finder --assert-all C:\Windows\System32\termsrv.dll`
를 돌려 리포트를 보고 분류합니다.

## 3. 런타임 — umwrap (PnP 리다이렉션)

목표: i686 경로가 컴파일만 된 게 아니라 실제로 뭔가를 패치했다는 증명.

- [ ] RDP 클라이언트에서 USB 저장 장치 리다이렉트
      (`mstsc` → 로컬 리소스 → 자세히 → 드라이브).
- [ ] 디바이스가 RDP 세션 내 `내 PC` 에 표시됨.
- [ ] DebugView 에 `UmWrap:` 패치 적용 로그, `PnpRedirection patch not found`
      없음.

카메라 리다이렉션 (Win10+):
- [ ] USB 카메라 리다이렉션이 통과.
- [ ] `.rdata` 에 `CameraRedirectionAllowed` 문자열이 있을 때
      DebugView 가 camera-secondary 패치 적용 로그를 표시.

## 4. 런타임 — endpwrap (오디오 캡처)

- [ ] `.rdp` 파일에 `audiocapture:i:1` 을 넣거나 (또는
      로컬 리소스 → 원격 오디오 → 녹음: 이 컴퓨터에서 녹음) 해서 RDP
      클라이언트가 마이크 오디오를 원격 세션으로 캡처.
- [ ] DebugView 에 `EndpWrap:` 패치 적용 로그가 표시됨.

## 5. 인스톨러 사전 체크 + 실패 케이스

- [ ] `offset-finder --assert-all` 이 커버하지 않는 OS/termsrv 빌드에서
      인스톨러 실행 ⇒ 버전 불일치 에러로 중단 (CheckTermsrvVersion).
- [ ] `--skip-firewall` 로 실행 ⇒ 방화벽 규칙 생성 안 됨, 나머지는 진행.
- [ ] `--skip-restart` 로 실행 ⇒ TermService 상태 유지, 재시작은 사용자 책임.
- [ ] `--disable-nla` 로 실행 ⇒ `HKLM\...\RDP-Tcp\UserAuthentication` 이 0 으로 설정,
      제거 시 이전 값 복원.
- [ ] 기존 설치 위에 인스톨러 재실행 (멱등성): 성공,
      동일 상태 재등록, `HKLM\SOFTWARE\rdprrap\Installer` 백업 서브트리 드리프트 없음.
- [ ] 백업 조작 시뮬레이션: `HKLM\SOFTWARE\rdprrap\Installer\OriginalServiceDll`
      을 수동으로 `C:\ProgramData\Evil.dll` 로 바꾸고 제거 실행 ⇒
      제거가 복원을 거부 (SDDL 보호 검증 경로).

## 6. 제거

```powershell
.\rdprrap-installer.exe uninstall
```

통과 기준:
- [ ] 종료 코드 0.
- [ ] `ServiceDll` 이 `%SystemRoot%\System32\termsrv.dll` 로 복원.
- [ ] `%ProgramFiles%\RDP Wrapper\` 삭제됨.
- [ ] 방화벽 규칙 삭제됨.
- [ ] `HKLM\SOFTWARE\rdprrap\Installer` 삭제됨.
- [ ] `fDenyTSConnections` 가 설치 전 값으로 복원 (인스톨러가
      기록한 경우).
- [ ] AddIns 서브트리는 인스톨러가 원래 AddIns 부모 키를 생성했을
      때만 제거; 기존 AddIns 설정은 건드리지 않음.
- [ ] 제거 후 TermService 가 정상 기동, RDP 가 깨끗한 OS 와 동일하게
      동작.

## 7. offset-finder 런타임 smoke

각 OS 이미지에서:

```powershell
offset-finder --assert-all C:\Windows\System32\termsrv.dll
```

- [ ] 종료 코드 0.
- [ ] 모든 명명 문자열 resolve 됨 (`NOT_FOUND` 없음).
- [ ] 모든 명명 함수가 xref 로 resolve 됨 (`NOT_FOUND` 없음).

지원 OS 에서 위가 실패하면, 전체 stdout 과 termsrv.dll 버전
(`(Get-Item termsrv.dll).VersionInfo`) 과 함께 patcher-team 티켓을
오픈합니다.

## 리포팅

각 체크리스트 실행 결과를 다음 표로 기록하세요: OS 빌드 번호,
termsrv.dll 버전, 아키텍처, 날짜, 섹션별 통과/실패, 그리고
`not found` 메시지를 보여주는 DebugView 발췌. 오프셋 드리프트가
지배적인 실패 원인 — 전체 DebugView 캡처가 가장 빠른 분류 도구입니다.
