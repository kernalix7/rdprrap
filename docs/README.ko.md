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

1. 빌드된 DLL을 `%ProgramFiles%\RDP Wrapper\`에 복사
2. 레지스트리 파일을 병합하여 svchost가 래퍼 DLL을 로드하도록 설정
3. 재부팅

자세한 설치 방법은 원본 [TermWrap](https://github.com/llccd/TermWrap)을 참조하세요 — DLL 인터페이스가 동일합니다.

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
│   └── offset-finder/      # 바이너리: 독립 오프셋 탐색 CLI
├── .github/
│   └── workflows/ci.yml   # Linux 체크 + Windows x64/x86 빌드
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
