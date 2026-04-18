# rdprrap

Rust로 재작성한 RDP Wrapper.

[English](../README.md) | **한국어**

## 주요 기능

| 컴포넌트 | 설명 |
|-----------|------|
| **termwrap-dll** | 핵심 RDP 패칭 — 다중 세션 지원, Home/비서버 에디션 정책 우회. 7가지 패치: DefPolicy, SingleUser, LocalOnly, NonRDP, PropertyDevice, SLPolicy, CSLQuery::Initialize |
| **umwrap-dll** | 모든 SKU에서 USB/카메라 PnP 장치 리다이렉션 (레거시 + 모던 Windows) |
| **endpwrap-dll** | 오디오 녹음 리다이렉션 (TSAudioCaptureAllowed) |
| **patcher** | 공유 라이브러리 — PE 파싱, x86/x64 디스어셈블리, 런타임 패턴 매칭, 검증된 바이트코드 패치 14개 |
| **offset-finder** | 독립 실행형 CLI 오프셋 탐색 도구 (pelite 기반, PDB 불필요) |
| **rdprrap-installer** | 설치/제거 CLI — 서비스 등록, 레지스트리, 방화벽(TCP+UDP 3389), 코호트 서비스 재시작, 설치 디렉토리 ACL 강화 (Delphi `RDPWInst.exe` 대체) |
| **rdprrap-check** | RDP 연결 테스터 — `mstsc.exe`로 127.0.0.2 루프백 접속, NLA 가드 RAII, 44개 종료 사유 코드 (`RDPCheck.exe` 대체) |
| **rdprrap-conf** | 설정 GUI — native-windows-gui 패널로 진단 + 런타임 RDP 설정(Enable/Port/SingleSession/HideUsers/AllowCustom/AuthMode/Shadow) 제어 (`RDPConf.exe` 대체) |

## 기술 스택

| 계층 | 기술 |
|------|------|
| 언어 | Rust (stable, MSVC 툴체인) |
| 디스어셈블러 | [iced-x86](https://crates.io/crates/iced-x86) (순수 Rust) |
| PE 파싱 | [pelite](https://crates.io/crates/pelite) |
| Windows API | [windows-rs](https://crates.io/crates/windows) |
| 타겟 | x86_64-pc-windows-msvc, i686-pc-windows-msvc |
| CI | GitHub Actions (Linux 체크 + Windows x64/x86 빌드) |

## 빠른 시작

### 사전 요구사항
- Rust 툴체인 (stable, MSVC)
- Windows SDK

### 설치

```bash
git clone https://github.com/kernalix7/rdprrap.git
cd rdprrap

rustup target add x86_64-pc-windows-msvc
rustup target add i686-pc-windows-msvc

cargo build --release
```

### 사용법

관리자 권한 명령 프롬프트에서:

```powershell
# 설치 — DLL 복사, 레지스트리 기록, 방화벽 개방(TCP+UDP 3389),
# 설치 디렉토리 ACL 부여(SYSTEM + LocalService), TermService 코호트 재시작
rdprrap-installer.exe install --source <빌드된-DLL-디렉토리>

# 현재 상태 확인
rdprrap-installer.exe status

# 제거 — ServiceDll, AllowMultipleTSSessions, fDenyTSConnections,
# AddIns 원상복구 + 방화벽 규칙 제거
rdprrap-installer.exe uninstall
```

주요 플래그:

| 플래그 | 효과 |
|--------|------|
| `--source DIR` | DLL을 복사할 디렉토리 (기본: 인스톨러 자신의 디렉토리) |
| `--force` | ServiceDll이 이미 래퍼를 가리키고 있어도 강제 재설치 |
| `--skip-firewall` | 방화벽 규칙 추가/제거 생략 |
| `--skip-restart` | TermService 재시작 생략 (수동/재부팅 시 적용) |
| `--disable-nla` | `UserAuthentication=0` 설정 (레거시 클라이언트용, 옵트인) |

설치 후 두 개의 GUI를 `%ProgramFiles%\RDP Wrapper\`에서 실행:

```powershell
# 설정 패널 — 실시간 상태 + 런타임 설정 토글
rdprrap-conf.exe

# RDP 루프백 테스트 — NLA 가드 RAII로 보호된 mstsc /v:127.0.0.2 실행
rdprrap-check.exe
```

수동 설치도 가능: DLL을 `%ProgramFiles%\RDP Wrapper\`에 복사하고 레지스트리 파일을 병합하세요. DLL 인터페이스 레퍼런스는 원본 [TermWrap](https://github.com/llccd/TermWrap) 참조.

## 프로젝트 구조

```
rdprrap/
├── crates/
│   ├── patcher/            # 공유: PE 파싱, 디스어셈블리, 패턴 매칭, 메모리 패칭
│   │   └── src/
│   │       ├── pe.rs       # PE 헤더/섹션/임포트/예외 테이블 파싱
│   │       ├── pattern.rs  # 4바이트 정렬 문자열 패턴 매칭 (.rdata)
│   │       ├── disasm.rs   # iced-x86 디코더 래퍼, xref 검색, 분기 헬퍼
│   │       └── patch.rs    # WriteProcessMemory 래퍼, NOP 채움, 바이트코드 상수 14개
│   ├── termwrap-dll/       # cdylib: termsrv.dll 프록시 (핵심 RDP)
│   │   └── src/patches/    # DefPolicy, SingleUser, LocalOnly, NonRDP, PropertyDevice, SLPolicy
│   ├── umwrap-dll/         # cdylib: umrdp.dll 프록시 (USB/카메라 리다이렉션)
│   ├── endpwrap-dll/       # cdylib: rdpendp.dll 프록시 (오디오 녹음)
│   ├── offset-finder/      # 바이너리: 독립 오프셋 탐색 CLI
│   ├── rdprrap-installer/  # 바이너리: 설치/제거 CLI (레지스트리, 서비스, 방화벽, ACL)
│   ├── rdprrap-check/      # 바이너리: RDP 루프백 테스터 (mstsc + NLA 가드)
│   └── rdprrap-conf/       # 바이너리: 설정 GUI (native-windows-gui)
├── .github/
│   └── workflows/ci.yml   # Linux 체크 + Windows x64/x86 빌드 매트릭스
└── docs/                   # 한국어 문서
```

## 동작 원리

1. 래퍼 DLL이 원본 시스템 DLL(`termsrv.dll`, `umrdp.dll`, `rdpendp.dll`)을 프록시
2. `DLL_PROCESS_ATTACH` 시 원본 DLL 로드 및 내보내기 함수 포워딩
3. 모든 스레드 일시정지 → `WriteProcessMemory`로 인메모리 패치 → 스레드 재개
4. 패치 오프셋 런타임 탐색:
   - **x64**: `.rdata`에서 알려진 문자열 스캔 → exception table에서 LEA xref 검색 → unwind chain 역추적
   - **x86**: `.text`에서 함수 프롤로그(`8B FF 55 8B EC`) 스캔 → 분기 추적 → PUSH/MOV 즉시값과 문자열 RVA 매칭

## 패치 종류 (termsrv.dll)

| 패치 | 목적 | 메커니즘 |
|------|------|----------|
| DefPolicyPatch | 다중 RDP 세션 허용 | 오프셋 0x63c/0x320의 CMP를 `mov reg, 0x100`으로 교체 |
| SingleUserPatch | 사용자별 세션 제한 비활성화 | VerifyVersionInfoW 호출 또는 CMP 명령어 NOP 처리 |
| LocalOnlyPatch | 로컬 전용 라이선스 제한 해제 | JZ를 무조건 JMP로 변환 |
| NonRDPPatch | 비-RDP 스택 허용 | CALL을 `inc [ecx]; xor eax,eax`로 교체 |
| PropertyDevicePatch | PnP 장치 리다이렉션 활성화 | SHR+AND를 `mov reg, 0`으로 교체 |
| SLPolicyPatch | SL 정책 변수를 1로 설정 | bRemoteConnAllowed, bFUSEnabled 등에 직접 메모리 쓰기 |

## 테스트

```bash
cargo test                                          # 유닛 테스트
cargo clippy --all-targets -- -D warnings           # 린트
cargo fmt --check                                   # 포맷 체크
```

CI는 push/PR 시 자동 실행: Linux 체크 + Windows x64/x86 풀 빌드.

## 기여

개발 환경 설정과 작업 흐름은 [CONTRIBUTING.ko.md](CONTRIBUTING.ko.md)를 참조하세요.

## 보안

보안 이슈는 [SECURITY.ko.md](SECURITY.ko.md)의 절차를 따라 주세요.

## 참고 프로젝트

- [stascorp/rdpwrap](https://github.com/stascorp/rdpwrap) — 원본 RDP Wrapper
- [llccd/TermWrap](https://github.com/llccd/TermWrap) — 통합 오프셋 탐색기를 포함한 C++ 재작성
- [llccd/RDPWrapOffsetFinder](https://github.com/llccd/RDPWrapOffsetFinder) — PDB 기반 오프셋 탐색기

## 라이선스

MIT 라이선스 — 자세한 내용은 [LICENSE](../LICENSE)를 참조하세요.
