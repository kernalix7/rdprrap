# 변경 이력

[English](../CHANGELOG.md) | **한국어**

이 프로젝트의 주요 변경 사항은 이 문서에 기록됩니다.

형식은 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)를 기반으로 하며,
버전 정책은 [Semantic Versioning](https://semver.org/lang/ko/)을 지향합니다.

## [Unreleased]

### 추가됨
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
