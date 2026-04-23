# 변경 이력

[English](../CHANGELOG.md) | **한국어**

이 프로젝트의 주요 변경 사항은 이 문서에 기록됩니다.

형식은 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)를 기반으로 하며,
버전 정책은 [Semantic Versioning](https://semver.org/lang/ko/)을 지향합니다.

## [Unreleased]

## [0.1.3] - 2026-04-23

### 수정됨 (라이선스 컴플라이언스 — 추가)
- `NOTICE` 가 불완전했음. 0.1.2 에선 rdpwrap 파생 파일 9 개를 나열
  했지만, 더 깊게 감사한 결과 실제로 **16 개의 Rust 소스**가
  `stascorp/rdpwrap` 의 특정 Delphi 파일을 포트하거나 미러링하고
  있었음. `NOTICE` 를 상위 바이너리별로 재조직해서
  (`RDPWInst.exe → rdprrap-installer`,
   `RDPConf.exe  → rdprrap-conf`,
   `RDPCheck.exe → rdprrap-check`) 리뷰어가 파일별이 아니라 상위
  도구별 파생 경계를 한눈에 볼 수 있도록 함.
- `CODE_OF_CONDUCT.md` 와 `docs/CODE_OF_CONDUCT.ko.md` 에 Contributor
  Covenant 원문을 관장하는 Creative Commons Attribution 4.0
  International (CC BY 4.0) 라이선스 명시 추가. 기존 출처 블록은
  contributor-covenant.org 의 adopter 템플릿과는 일치했지만 CC BY
  자체를 명시하지는 않았음.
- Copyright 줄 일관성: `rdprrap-conf` About 다이얼로그의 MIT 텍스트가
  "Copyright (c) 2026 rdprrap contributors" 로 돼 있었는데 `LICENSE`
  / 번들 `THIRD_PARTY_LICENSES.txt` 는 "Copyright (c) 2026 Kim
  DaeHyun" — 세 곳이 서로 다르지 않도록 About 다이얼로그를 `LICENSE`
  쪽으로 정렬.

## [0.1.2] - 2026-04-23

### 수정됨
- 상위 프로젝트의 소스 귀속 고지를 바이너리와 함께 배포. rdprrap
  의 일부는 세 상위 프로젝트의 재구현 또는 동작 미러링이며, 해당
  라이선스가 저작권 고지 보존 및 / 또는 라이선스 텍스트 배포를
  요구합니다:
    * `stascorp/rdpwrap` (Apache-2.0) — RDPCheck disc-reason 테이블,
      인스톨러 / cohort-restart / ACL 계약, HKLM 레지스트리 레이아웃,
      방화벽 규칙 형태. Apache-2.0 §4(a) 는 재배포 시 라이선스
      텍스트 동반을, §4(c) 는 귀속 고지 보존을 요구.
    * `llccd/TermWrap` (MIT) — patcher 패턴 스캐너, PE 기준점 조정,
      x64 xref / x86 prologue-scan 함수 분해, DLL export 계약. MIT
      는 모든 재배포에 저작권 고지 포함을 요구.
    * `llccd/RDPWrapOffsetFinder` (MIT) — offset-finder 알고리즘
      설계 (문자열 스캔, xref, branch-follow priority queue).

  0.1.0 / 0.1.1 릴리스는 Cargo 의존성 귀속 (`THIRD_PARTY_LICENSES.txt`)
  만 번들링 했고 이 세 건의 소스 레벨 고지가 빠져 있었음 — 라이선스
  컴플라이언스 gap.

### 추가됨
- **`NOTICE`** 루트 파일 — 각 상위 프로젝트, 그로부터 파생된
  rdprrap 내 파일, 라이선스 종류, 저작권 전문 (MIT 는 인라인,
  Apache-2.0 은 레퍼런스) 기술.
- **`vendor/licenses/`** — 상위 라이선스 텍스트를 vendoring 해서
  태그 시점에 상위 리포 접근 여부에 의존하지 않도록 함:
    * `LICENSE.rdpwrap.Apache-2.0`
    * `LICENSE.TermWrap.MIT`
    * `LICENSE.RDPWrapOffsetFinder.MIT`
- 릴리스 워크플로가 `NOTICE` + `vendor/licenses/` 전체 트리를
  아치별 릴리스 ZIP 에 번들링.
- `README.md` / `docs/README.ko.md` 의 "License" 섹션이 상위 귀속은
  `NOTICE` 와 `vendor/licenses/` 로, Cargo 의존성 귀속은
  `THIRD_PARTY_LICENSES.txt` 로 안내.

## [0.1.1] - 2026-04-22

### 수정됨
- `rdprrap-installer` 의 레지스트리 readback 이 과할당된 버퍼 꼬리의
  이물질 바이트 쌍을 디코딩된 문자열에 흘려넣을 수 있었음 — 설치 전
  `ServiceDll` 값이 `HKLM\SOFTWARE\rdprrap\Installer\OriginalServiceDll`
  에 끝에 여분의 문자가 추가된 채로 저장됨 (#1 에서 `termsrv.dll` →
  `termsrv.dlll` 로 보고). 이 상태에서 `uninstall` 을 실행하면 rollback
  경로가 손상된 값을 복원하여 `TermService` 가 존재하지 않는 DLL 을
  가리키게 되고, 다음 부팅 시 RDP 불능.

  이제 `RegKey::get_string` 과 `get_service_dll` 모두 `RegQueryValueExW`
  / `RegGetValueW` 가 실제로 기록한 바이트 수 (`lpcbData` out-param) 를
  기준으로 디코딩된 버퍼를 트리밍하며, 할당 전체에 대한
  `while buf.last() == Some(0) { pop }` 에 의존하지 않음.

### 테스트
- `HKCU\Software\rdprrap-installer-tests\` 하위에서 동작하는 Windows
  전용 레지스트리 round-trip 회귀 테스트 추가 — 권한 승격 불필요, 비특권
  Windows CI 러너에서 실행 가능. 각 테스트는 invocation 별 격리된
  subkey (PID + atomic counter) 를 생성하고 Drop 에서 하위 트리를
  삭제하는 RAII 가드를 사용.

### 0.1.0 설치본 완화책
0.1.0 으로 설치된 호스트에서 `rdprrap-installer.exe uninstall` 을
실행하기 전에, 저장된 `ServiceDll` 타깃을 먼저 확인:

```
reg query "HKLM\SOFTWARE\rdprrap\Installer" /v OriginalServiceDll
```

표시된 경로가 정확히 `.dll` 로 끝나지 않으면, uninstall 전에 덮어쓰기:

```
reg add "HKLM\SOFTWARE\rdprrap\Installer" /v OriginalServiceDll ^
  /t REG_EXPAND_SZ /d "%SystemRoot%\System32\termsrv.dll" /f
```

## [0.1.0] - 2026-04-22

### 이 릴리스의 범위
0.1.0 은 멀티세션 RDP 패치 파이프라인 (`termwrap` + 인스톨러 +
check + conf + offset-finder) 을 공식 기능으로 출시. `umwrap` /
`endpwrap` 은 원본 rdpwrap 과의 레이아웃 연속성 때문에 설치
페이로드에 함께 포함되지만 현재 **dormant** (아래 *알려진 한계*
참고). 지원 Windows SKU 확장과 USB / 카메라 / 오디오 래퍼 활성화는
이후 릴리스에서 추적.

### 수정됨
- `rdprrap-installer` 제거 경로가 `restart_termservice_with_cohort`
  (설치와 동일한 프리미티브) 를 사용하도록 변경. 평범한 stop/start 는
  `UmRdpService` 나 `SessionEnv` 가 활성인 호스트에서 반드시
  `ERROR_DEPENDENT_SERVICES_RUNNING` (0x041B) 에 걸렸고, `?` 조기
  종료 때문에 상태 키 + 설치 디렉토리가 남아 있었음. 이제 재시작
  실패가 치명적이지 않음 — step 5/6 cleanup 은 항상 실행되고,
  재부팅으로 마무리하라는 메시지를 출력.
- `.cargo/config.toml` 이 두 MSVC 타깃에 대해
  `target-feature=+crt-static` 를 강제. 이게 없으면 바이너리가
  `VCRUNTIME140.dll` / `MSVCP140.dll` 에 의존해서, VC++
  Redistributable 이 없는 신규 Windows 이미지에서 기동 거부
  (STATUS_DLL_NOT_FOUND = 0xC0000135). `llvm-readobj` 로 검증:
  x64 · i686 모든 산출물에서 MSVC CRT 임포트 0 건.
- 문서: 오디오 엔드포인트 래퍼의 설치 시 canonical 이름은
  `rdpendp.dll` 이 아니라 `endpwrap.dll`. 인스톨러 계약은 처음부터
  `endpwrap.dll` 이었고 TESTING 문서가 잘못 쓰여있었음.

### 런타임 검증 (2026-04-22)
- Windows 11 x64 (빌드 10.0.26200.0) 에서 설치 → 제거 완전
  round-trip 통과 (Linux 호스트 + winpodx / dockur-windows 컨테이너).
- 멀티세션 smoke: 두 개의 인터랙티브 세션이 동시에 사용 가능,
  DebugView 에 `TermWrap:` 패치 적용 라인 확인, `patch not found`
  0건.
- `offset-finder --assert-all C:\Windows\System32\termsrv.dll` 이
  해당 빌드에서 7/7 strings, 7/7 functions 모두 해결.
- 제거 후 `ServiceDll` 이 `%SystemRoot%\System32\termsrv.dll` 로
  복원, `%ProgramFiles%\RDP Wrapper\` 트리 삭제, 방화벽 규칙
  `rdprrap-RDP-TCP` / `rdprrap-RDP-UDP` 삭제, `HKLM\SOFTWARE\rdprrap\Installer`
  제거, `fDenyTSConnections` 설치 전 값 복원.

### 알려진 한계
- **지원 SKU 가 좁음** — 런타임 end-to-end 검증된 환경은 Windows 11
  x64 (빌드 10.0.26200.0) 한 대뿐. Windows Server 2025 / 2022,
  Windows 11 24H2 / 23H2, Windows 10 22H2, 그리고 모든 i686 런타임
  경로는 컴파일 + 유닛 테스트 범위. `offset-finder` 는 패턴 기반이라
  미검증 termsrv.dll 빌드에서 우아하게 실패 (drift) 할 수 있음 —
  패턴이 안 맞으면 `--assert-all` 의 전체 stdout 과 termsrv.dll
  VersionInfo 를 함께 수집해서 보고.
- **`umwrap` / `endpwrap` 은 이 릴리스에서 dormant** — DLL 은
  `%ProgramFiles%\RDP Wrapper\` 에 들어가지만 Windows 가 로드하지
  않음. `UmRdpService` 와 오디오 엔드포인트 COM 서버는
  `System32\umrdp.dll` / `System32\rdpendp.dll` 을 직접 로드하며,
  0.1.0 은 아직 WFP / SFC 를 통과하는 DLL 리다이렉션 메커니즘을
  제공하지 않음. 따라서 USB / 카메라 리다이렉션 패치와 오디오 캡처
  패치는 0.1.0 에서 **런타임 효과 없음** — `termwrap` 의 멀티세션
  패치가 유일한 런타임 활성 컴포넌트. 활성화는 이후 릴리스에서
  추적.
- `%ProgramFiles%\RDP Wrapper\` ACL 하드닝이 Program Files 부모
  상속에 의존하며 explicit protected DACL 을 설정하지 않음. 쓰기
  권한은 여전히 SYSTEM / Administrators / TrustedInstaller 로 제한
  됨; `BUILTIN\Users` 는 상속된 read+execute 를 가짐.
- Windows PowerShell 5.1 의 `Start-Transcript` 는 인스톨러의 네이티브
  콘솔 출력을 캡처하지 못함. 신뢰할 수 있는 로그를 위해선
  `.\rdprrap-installer.exe install 2>&1 | Tee-Object install.log` 사용.

### 추가됨 (2026-04)
- **`rdprrap-installer`**: Rust CLI 인스톨러/제거 — 서비스 등록, 레지스트리(KEY_WOW64_64KEY + SDDL), 방화벽 규칙(TCP+UDP 3389, 로케일 안전), 설치 디렉토리 ACL 강화(SetEntriesInAclW + SetNamedSecurityInfoW), `netsvcs` 코호트 서비스 재시작, `VerQueryValueW` 기반 termsrv.dll 버전 체크, `--force`/`--skip-firewall`/`--skip-restart`/`--disable-nla` 플래그
- **`rdprrap-check`**: RDP 루프백 테스터 — `mstsc /v:127.0.0.2:PORT`, `NlaGuard` RAII (SecurityLayer/UserAuthentication 레지스트리 백업/복원, Drop-safe), 44개 종료 사유 코드
- **`rdprrap-conf`**: 설정 GUI — native-windows-gui 1.0 + Frame 컨테이너 레이아웃, 1초 타이머로 진단(Wrapper 상태, TermService SCM, termsrv 버전, RDP-Tcp 리스너, 지원 레벨) + 런타임 설정(Enable RDP, Port, SingleSession, HideUsers, AllowCustom, AuthMode, Shadow), 관리자 권한 없을 시 읽기 전용 모드
- 원본 rdpwrap 기능 갭 마감: C1 AllowMultipleTSSessions 백업/복원, C2 CheckInstall 사전점검 + `--force`, H1 코호트 서비스 재시작 (EnumServicesStatusExW), H2 CheckTermsrvVersion, H3 설치 디렉토리 ACL, H4 CheckTermsrvDependencies 사전점검
- 3회 보안 감사 완료: CRITICAL 0건, HIGH/MEDIUM 전부 처리 (SDDL로 보호된 백업 키, reparse-point 방어, NLA 옵트인, fDenyTSConnections 백업/복원, 경로 검증, 트랜잭셔널 롤백, DLL 검색 경로 강화)
- CI 업데이트: Windows x64/x86 × debug/release 매트릭스, 8개 크레이트 전부 빌드 + 바이너리 검증 (DLL export, PE 아키텍처, 크기 sanity, 인스톨러/체커/conf `--help` 동작)
- 메모리 시스템: `.priv-storage/memory/` 포터블 영구 메모리 (iced-x86 API 함정, NWG 1.0.13 API 함정, 팀 오케스트레이션 규칙)

### 추가됨 (2026-03 초기 릴리스)
- Cargo 워크스페이스 (5개 크레이트): `patcher`, `termwrap-dll`, `umwrap-dll`, `endpwrap-dll`, `offset-finder`
- `patcher` 크레이트: PE 헤더/섹션/임포트 파싱, 4바이트 정렬 패턴 매칭, iced-x86 디스어셈블리 래퍼, WriteProcessMemory 기반 패칭, 검증된 바이트코드 상수 14개
- `termwrap-dll`: termsrv.dll 프록시 DLL, 7가지 패치 타입
  - DefPolicyPatch (직접/간접 CMP, x64/x86, JZ/JNZ 변형)
  - SingleUserPatch (memset→VerifyVersionInfoW 및 CMP 패턴)
  - LocalOnlyPatch (TEST→JS/JNS→CMP→JZ를 무조건 JMP로)
  - NonRDPPatch (IsAllowNonRDPStack, 인라인된 IsAppServerInstalled 폴백)
  - PropertyDevicePatch (SHR+AND PnP 장치 필터링, 레지스트리 확인)
  - CSLQuery::Initialize SL 정책 변수 패칭 (bRemoteConnAllowed, bFUSEnabled, bAppServerAllowed, bMultimonAllowed, bInitialized)
- `umwrap-dll`: umrdp.dll 프록시 DLL, USB/카메라 PnP 리다이렉션 (레거시 + 모던, 카메라 보조 패치)
- `endpwrap-dll`: rdpendp.dll 프록시 DLL, 오디오 녹음 리다이렉션 (TSAudioCaptureAllowed)
- `offset-finder`: pelite 기반 termsrv.dll 오프셋 탐색 CLI 도구 (x64 xref + x86 문자열 스캔)
- x64 함수 해석: exception table xref 검색 + unwind chain 역추적
- x86 함수 해석: 프롤로그 스캔 (8B FF 55 8B EC) + 분기 추적 우선순위 큐
- 안전한 인메모리 패칭을 위한 스레드 일시정지/재개
- DLL 익스포트 포워딩 (ServiceMain, SvchostPushServiceGlobals 등)
- GitHub CI: Linux 체크 + Windows x64/x86 풀 빌드 및 아티팩트 업로드
- 유닛 테스트 11개 (패턴 매칭 + 디스어셈블리)
- 이중언어 문서 (영어 + 한국어): README, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, CHANGELOG
- GitHub 템플릿: PR, 버그 리포트, 기능 요청
- AI 멀티툴 설정 (.priv-storage/ v2.0)
- 암호화 백업 툴킷 (tmp-igbkp/)
