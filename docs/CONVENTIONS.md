# 개발 규칙 (Conventions)

> 목표: **돌아가기만 하는 코드가 아니라, 처음 보는 사람도 구조를 이해하고 안전하게 고칠 수 있는 코드.**
> 규칙은 사람이 기억하지 않아도 되도록 가능한 한 **도구로 자동 검사**한다 (ruff · 테스트 · CI).

---

## 1. 폴더 구조와 역할

```
briefing/                 ← 파이썬 코드는 전부 이 패키지 안에 (실행: python -m briefing <명령>)
  __main__.py             명령줄 진입점 (daily / notify / feedback)
  config.py               경로·피드 목록·한도값 — 숫자와 경로는 여기서만 바꾼다
  models.py               데이터 구조(스키마) 정의
  pipeline.py             매일 흐름을 '조립'만 한다 (세부 로직은 아래 모듈에)
  collect.py              ① 수집: RSS·KEV, 기사 본문
  llm.py                  ② 선정·요약: Gemini 호출과 프롬프트
  enrich.py               ③ 검증: NVD·EPSS·KEV 공식 지표
  consulting.py           ④ 판단 규칙: 위험도·우선순위·벡터 해석·매핑 검증
  render.py               ⑤ 게시: 정화(sanitize) 후 포스트·용어 사전·노트 양식 쓰기
  refresh.py              최근 글의 공식 지표 재조회
  notify.py / feedback.py 디스코드 알림 / 분석 노트 코칭
  netsafe.py              외부 요청 안전 장치 (SSRF 방어)
  fileio.py               파일 쓰기 (UTF-8 · LF · 원자적 교체)
tests/                    단위·보안 테스트 (네트워크 없이 실행)
scheduler/                외부 스케줄러 (Cloudflare Worker) — 매일 실행 신호·감시
infra/                    AWS 인프라 (Terraform) — bootstrap · stacks/<이름> · modules/<이름>
_layouts/ _includes/ assets/   사이트(Jekyll) 화면
_posts/ _data/            사이트 데이터 (봇이 쓰는 곳 + 사람이 쓰는 분석 노트)
state/                    봇의 내부 상태 — 이미 다룬 기사 목록 등 (사이트에 나가지 않음)
docs/                     문서 (사이트에 나가지 않음)
```

**의존 방향**: `__main__ → pipeline → (collect, llm, enrich, consulting, render, refresh) → (netsafe, fileio, config, models)`
아래쪽 모듈은 위쪽 모듈을 import 하지 않는다. 새 기능은 역할에 맞는 모듈에 넣고, `pipeline.py` 에는 흐름만 추가한다.

### 폴더·파일 이름 규칙

| 대상 | 규칙 | 예 |
|---|---|---|
| 일반 폴더 | **소문자**, 단어 구분이 필요하면 하이픈 대신 **밑줄** | `state/`, `docs/`, `assets/css/` |
| 파이썬 패키지·모듈 | 소문자 `snake_case` (하이픈 금지 — `import` 가 안 됨) | `briefing/`, `netsafe.py` |
| 테스트 파일 | `test_<대상모듈>.py` | `tests/test_netsafe.py` |
| `_` 로 시작하는 폴더 | **Jekyll 전용 이름** — 직접 만들거나 이름을 바꾸지 않는다 | `_posts/` `_layouts/` `_includes/` `_data/` |
| 점(`.`)으로 시작 | 도구 설정 (GitHub·에디터·git) | `.github/`, `.editorconfig` |
| 브리핑 글 | `_posts/YYYY-MM-DD-security-briefing.md` (Jekyll 규칙: 날짜로 시작) | `_posts/2026-11-18-security-briefing.md` |
| 분석 노트 | `_data/comments/YYYY-MM-DD.yml` | `_data/comments/2026-11-18.yml` |
| 사이트 데이터 | `_data/<이름>.json` 또는 `.yml` (사이트에서 `site.data.<이름>` 으로 읽힘) | `_data/isms_p.json` |
| 문서 | 대문자 `.md` 는 저장소 대표 문서, 그 외는 `docs/` | `README.md`, `SECURITY.md`, `docs/CONVENTIONS.md` |

**헷갈리기 쉬운 두 폴더**

| | `_data/` | `state/` |
|---|---|---|
| 누가 읽나 | 사이트(Jekyll) | 봇(파이썬)만 |
| 공개 여부 | 페이지에 내용이 표시됨 | 사이트에 나가지 않음 (`_config.yml` exclude) |
| 들어 있는 것 | 용어 사전, 분석 노트, 허용 목록, 지표 설명 | 이미 다룬 기사 목록(`seen.json`) |

새 폴더를 만들 때는 **이름만 보고 역할을 알 수 있게** 짓고, 위 1장 구조도와 이 표에 함께 추가한다.

---

## 2. 데이터 구조 (`briefing/models.py`)

| 단계 | 타입 | 신뢰 여부 |
|---|---|---|
| 수집 | `Candidate` | ❌ 외부(RSS) — 신뢰하지 않음 |
| 요약·보강 | `dict` (AI 출력 + API 응답) | ❌ 외부(AI·API) — 신뢰하지 않음 |
| 게시 | `Item`, `Term` | ✅ `render.normalize` → `render.structured_item` 을 통과한 값만 |

- 포스트 front matter 의 `items` 는 `Item` 배열(JSON)이다. **필드를 추가하면 `models.py` 와 이 표를 함께 고친다.**
- 열거형 값(지역·분류·우선순위 등)은 `Literal` 로 적고, 코드에서는 허용 목록 밖의 값을 버린다.
- 허용 목록 데이터: `_data/isms_p.json`, `_data/attack.json` / 설명 문구: `_data/metrics.yml`

---

## 3. 파이썬 코드 규칙

자동 검사: `ruff check .` · `ruff format .` (설정: `pyproject.toml`)

| 항목 | 규칙 |
|---|---|
| 스타일 | PEP 8, 줄 길이 120, 큰따옴표, LF — `ruff format` 이 맞춰 준다 |
| 이름 | 함수·변수 `snake_case`, 클래스 `PascalCase`, 상수 `UPPER_CASE`, 예외 클래스는 `...Error` |
| 내부 함수 | 모듈 밖에서 쓰지 않는 함수는 `_` 로 시작 (예: `_dump`) |
| 타입 | 모든 공개 함수에 타입 힌트. 구조가 있는 데이터는 `models.py` 의 타입 사용 |
| 주석 | **최소한으로.** 모듈·공개 함수는 무엇을 하는지 **한 줄 docstring** 만. 동작 원리·보안 장치의 세부 조건(무엇을 어떻게 막는지)은 코드 주석에 쓰지 않는다 — 사이트로 배포되는 JS·CSS·HTML 에도 주석을 남기지 않는다 |
| 상수 | 숫자·경로·URL 은 `config.py` 에 (코드 안에 매직 넘버 금지) |
| 함수 | 한 함수는 한 가지 일. 50줄이 넘으면 나눌 수 있는지 본다. `lambda` 를 변수에 담지 않는다 |
| 예외 | `except Exception: pass` 금지. 잡을 예외를 좁히고, 무시할 때는 이유를 주석으로 |
| 출력 | 로그는 `print("[info] ...")` / `[warn]` / `[error]` 접두어. **비밀값·URL 의 토큰은 절대 출력하지 않는다** |
| 의존성 | 직접 쓰는 라이브러리는 `requirements.in`(개발 도구는 `requirements-dev.in`)에 `==` 로 적고, `pip-compile --generate-hashes` 로 **해시까지 고정된** `requirements*.txt` 를 만든다. 설치는 항상 `pip install --require-hashes`. 새 라이브러리는 꼭 필요할 때만 |

---

## 4. 시큐어 코딩 규칙 ✅ (PR 마다 확인)

| # | 규칙 | 근거 / 위치 |
|---|---|---|
| 1 | **외부에서 온 문자열(RSS·기사·AI·API·사람 입력)은 전부 신뢰하지 않는다** | `models.py` 신뢰 경계 |
| 2 | 사이트에 나가는 값은 **Liquid `\| escape`** 로 출력한다 (예외: 숫자·날짜·내부 URL) | `tests/test_security.py` 가 정적 검사 |
| 3 | JS 로 화면에 글자를 넣을 때는 **`textContent` 만** 쓴다 (`innerHTML` 금지) | `assets/js/site.js` |
| 4 | 인라인 `<script>`·`<style>`·`style=""` 금지 → CSP `script-src 'self'` 유지 | `_layouts/default.html` |
| 5 | 외부 URL 요청은 **`netsafe.safe_get`** 으로만 (SSRF·크기 제한) | `briefing/netsafe.py` |
| 6 | 링크는 `http(s)` 만 (`render.safe_url`), 외부 링크엔 `rel="noopener noreferrer"` | `render.py`, 레이아웃 |
| 7 | AI 가 고른 코드값(ISMS-P·ATT&CK·분류)은 **허용 목록 안의 값만** 통과 | `consulting.clean_codes` |
| 8 | 숫자는 범위를, 식별자는 정규식을 검사한다 (CVE·CVSS·EPSS·날짜·SHA) | `enrich.py`, `render.metrics` |
| 9 | YAML 은 `yaml.safe_load` 만, JSON 은 `json.loads` 만 (`pickle`·`eval` 금지) | `feedback.py` |
| 10 | 외부 프로그램은 **셸 없이 인자 목록으로** 호출 (`shell=True` 금지) | `feedback.git` |
| 11 | 파일은 `fileio` 로만 쓰고, 파일명에 쓰는 값(날짜 등)은 정규식 검사 후 사용 (경로 조작 방지) | `render.write_post` |
| 12 | 비밀값은 GitHub Secrets → 환경변수로만. 헤더로 전송하고 로그·오류 메시지에 넣지 않는다 | `llm.py`, `notify.py` |
| 13 | 워크플로는 `permissions: {}` 로 시작해 필요한 job 에만 최소 권한. Action 은 **커밋 SHA 고정** | `.github/workflows/` |
| 14 | 워크플로에서 `${{ github.event.* }}` 값은 `run:` 에 직접 넣지 않고 **환경변수로** 넘긴다 (스크립트 주입 방지) | `note-feedback.yml` |
| 15 | 새 보안 규칙을 만들면 **악성 입력 테스트를 함께** 추가한다 | `tests/` |
| 16 | AWS 자원은 **Terraform 코드로만** 만든다. 장기 액세스 키 금지(OIDC), 권한은 자원 이름 범위로 좁히고, checkov 예외는 `infra/README.md` 에 이유를 적는다 | `infra/`, `infra.yml` |

---

## 5. 디자인 시스템 (사이트)

모든 값은 `assets/css/site.css` 맨 위 `:root` 의 **디자인 토큰**에서 가져온다. 색·간격을 직접 숫자로 쓰지 않는다.

| 토큰 | 용도 |
|---|---|
| `--bg` `--surface` `--surface-2` | 배경 / 카드 / 보조 면 |
| `--ink` `--ink-2` `--ink-3` | 본문 / 보조 / 흐린 글자 |
| `--line` `--line-2` | 구분선 |
| `--sev-1` ~ `--sev-5` | **신호색은 이것 하나뿐** — 위험도·CVSS 등급에만 사용 (`[data-sev]`, `[data-cvss]`) |
| `--radius` `--radius-sm` `--shadow` `--shadow-lift` | 모서리 / 그림자 |
| `--sans` `--mono` | 본문 글꼴 / 코드·번호(CVE, No.001) 글꼴 |

**컴포넌트**: `card`(벤토 카드) · `chip` · `fact`(지표 카드) · `meter`(게이지) · `threat`(위협 수준) · `consult`(컨설팅 뷰) · `note`(분석 노트) · `info`(ⓘ 툴팁 버튼) · `tcard`(용어 카드)
새 화면은 기존 컴포넌트를 조합하고, 새 컴포넌트가 필요하면 이 목록에 추가한다.

**원칙**
- 다크 모드: 토큰만 바꿔 자동 대응 (`prefers-color-scheme`)
- 애니메이션은 `transform`·`opacity` 만 (60fps), `prefers-reduced-motion` 이면 끈다
- 접근성: 색만으로 정보를 전달하지 않는다 (숫자·라벨 병기), 키보드 포커스 표시, `aria-label`
- AI 가 만든 값에는 **'AI 제안 / AI 초안'** 라벨, 공식 데이터에는 출처 라벨

---

## 6. Git 규칙

- **줄바꿈은 LF** (`.gitattributes`, `.editorconfig` 가 자동 처리)
- **브랜치**: `main` 에 직접 push 하지 않고 브랜치 → PR → 리뷰 → 머지
  - 이름: `feat/…` `fix/…` `refactor/…` `chore/…` `docs/…` `security/…`
  - 예외: 봇의 매일 브리핑 커밋, 분석 노트 커밋은 `main` 에 직접
- **커밋 메시지** ([Conventional Commits](https://www.conventionalcommits.org/ko/)):
  `feat:` 기능 · `fix:` 버그 · `security:` 보안 · `refactor:` 구조 변경 · `style:` 포맷 · `test:` · `docs:` · `chore:` 설정
- **머지 조건**: CI(Lint·Tests)와 Security Scan 통과 + PR 체크리스트 확인

---

## 7. 로컬에서 확인하기

```bash
pip install --require-hashes -r requirements.txt -r requirements-dev.txt
ruff check . && ruff format --check .        # 코드 규칙
python -m unittest discover tests            # 테스트 (네트워크 없이)
python -m briefing daily --dry-run           # AI 없이 수집·글 생성 시험 (만들어진 파일은 커밋하지 않기)
pip-compile --generate-hashes requirements.in            # 라이브러리 버전을 바꿨을 때 (pip install pip-tools)
pip-compile --generate-hashes --allow-unsafe requirements-dev.in
```
