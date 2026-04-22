# 변경 이력

[English](../CHANGELOG.md) | **한국어**

이 프로젝트의 주요 변경 사항은 이 문서에 기록됩니다.

형식은 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)를 기반으로 하며,
버전 정책은 [Semantic Versioning](https://semver.org/lang/ko/)을 지향합니다.

## [Unreleased]

## [0.1.0-rc1] - 2026-04-22

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
- Windows Server 2025 x64 (빌드 10.0.26200.0) 에서 설치 → 제거
  완전 round-trip 통과 (Linux 호스트 + winpodx 컨테이너).
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
- **테스트 매트릭스 좁음** — 실제 Windows 상에서 end-to-end 검증된
  SKU 는 Server 2025 x64 한 대뿐. Server 2022, Windows 11 24H2 /
  23H2, Windows 10 22H2, i686 런타임 경로 전부 컴파일 + 유닛 테스트
  범위만. 미검증 termsrv 빌드에서 오프셋 drift 가능성 — 그 때는
  `--assert-all` 의 전체 stdout 과 termsrv.dll VersionInfo 를
  함께 수집할 것.
- **`umwrap` / `endpwrap` DLL 이 설치되어도 비활성** — 파일은
  `%ProgramFiles%\RDP Wrapper\` 에 들어가지만 Windows 가 로드하지
  않음. `UmRdpService` 와 오디오 엔드포인트 COM 서버는
  `System32\umrdp.dll` / `System32\rdpendp.dll` 을 직접 로드하며,
  `rdprrap` 은 아직 WFP / SFC 를 통과하는 DLL 리다이렉션 메커니즘을
  구현하지 않음. 따라서 USB / 카메라 리다이렉션 패치와 오디오 캡처
  패치는 **이 릴리스에선 런타임 효과 없음**. 0.1.0 정식 전에 처리
  예정.
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
