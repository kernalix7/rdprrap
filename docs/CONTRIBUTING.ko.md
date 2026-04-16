# rdprrap 기여 가이드

[English](../CONTRIBUTING.md) | **한국어**

rdprrap에 기여해 주셔서 감사합니다.

## 개발 환경 준비

### 사전 요구사항
- Rust 툴체인 (stable, MSVC)
- Windows SDK
- 통합 테스트를 위한 Windows 환경

### 빌드
```bash
git clone https://github.com/kernalix7/rdprrap.git
cd rdprrap
rustup target add x86_64-pc-windows-msvc
rustup target add i686-pc-windows-msvc
cargo build --release
```

### 테스트
```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## 작업 흐름

1. 저장소를 Fork 합니다
2. 기능 브랜치를 생성합니다: `git checkout -b feature/my-change`
3. Conventional Commits 스타일로 커밋합니다
4. Push 후 Pull Request를 생성합니다

## Pull Request 체크리스트

- [ ] 변경 범위와 목적이 명확한가?
- [ ] 필요한 테스트를 추가/갱신했는가?
- [ ] `cargo build --release` — 에러 없음
- [ ] `cargo clippy --all-targets -- -D warnings` — 경고 없음
- [ ] `cargo test` — 모든 테스트 통과
- [ ] 모든 `unsafe` 블록에 `// SAFETY:` 주석이 있는가?
- [ ] 테스트 코드 외에서 `.unwrap()` 사용이 없는가?
- [ ] 동작 변경 시 README/문서를 갱신했는가?

## 커밋 메시지 규칙

[Conventional Commits](https://www.conventionalcommits.org/)를 사용합니다:
- `feat:` 새 기능
- `fix:` 버그 수정
- `docs:` 문서 변경
- `refactor:` 동작 변경 없는 구조 개선
- `test:` 테스트 변경
- `chore:` 유지보수 작업

## 보안

보안 이슈는 [SECURITY.ko.md](SECURITY.ko.md)의 제보 절차를 따라 주세요.
