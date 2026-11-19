# 🔐 Daily Security Briefing

### 👉 [블로그 바로가기 — dlwl224.github.io/security-briefing](https://dlwl224.github.io/security-briefing/)

[![Site](https://img.shields.io/badge/site-live-e11d3c?style=flat-square)](https://dlwl224.github.io/security-briefing/)
[![Daily Briefing](https://github.com/dlwl224/security-briefing/actions/workflows/daily-briefing.yml/badge.svg)](https://github.com/dlwl224/security-briefing/actions/workflows/daily-briefing.yml)
[![CI](https://github.com/dlwl224/security-briefing/actions/workflows/ci.yml/badge.svg)](https://github.com/dlwl224/security-briefing/actions/workflows/ci.yml)
[![ZAP](https://github.com/dlwl224/security-briefing/actions/workflows/zap.yml/badge.svg)](https://github.com/dlwl224/security-briefing/actions/workflows/zap.yml)
[![CodeQL](https://github.com/dlwl224/security-briefing/actions/workflows/codeql.yml/badge.svg)](https://github.com/dlwl224/security-briefing/actions/workflows/codeql.yml)

매일 오전 9시(KST), 국내·해외 보안 뉴스에서 **주요 이슈 5건**을 골라 AI로 요약하고
GitHub Pages 블로그에 자동 게시한 뒤 **Discord로 알림**을 보내는 완전 자동화 프로젝트입니다.

| 페이지 | 링크 |
|---|---|
| 🏠 오늘의 브리핑 | https://dlwl224.github.io/security-briefing/ |
| 📚 보안 용어 사전 | https://dlwl224.github.io/security-briefing/glossary/ |
| ⚙️ 동작 방식 · 지표 읽는 법 | https://dlwl224.github.io/security-briefing/about/ |
| 📡 RSS | https://dlwl224.github.io/security-briefing/feed.xml |
| 🛡️ 보안 설계 (OWASP Top 10 대응) | [SECURITY.md](SECURITY.md) |
| 🧭 개발 규칙 (구조·코드·시큐어 코딩·디자인 시스템·Git) | [docs/CONVENTIONS.md](docs/CONVENTIONS.md) |

각 이슈는 이렇게 정리됩니다:
- 🎯 **핵심**: 무슨 일이 일어났는지 짧고 정확하게
- 📖 **배경**: 이전 경과와 낯선 용어까지 쉽게
- 💥 **영향**: 우리 생활·경제·산업에 왜 중요한지
- 📚 **오늘의 보안 용어**: 기사에 나온 용어를 풀이하고, [용어 사전](glossary.md)에 계속 쌓음

## 🧑‍💼 컨설팅 뷰

각 이슈에는 자동 요약과 함께 **보안 컨설팅 관점의 정리**가 붙습니다.

| 항목 | 만드는 주체 | 근거 |
|---|---|---|
| 위험도 (1~5, 정책·동향은 '참고') | **AI는 사실만 판정, 점수는 규칙 계산** | 실제 악용(0/+1/+2, KEV면 자동 확인) + 피해 규모(0/+1/+2) + 핵심 업종(+1) + 국내 영향(+1), 근거를 칩으로 표시 |
| 조치 우선순위 (P1 즉시 / P2 우선 / P3 정기) | **규칙** (AI 아님) | CISA KEV 등재 → EPSS → CVSS 순으로 판단, 근거를 함께 표시 |
| 공격 조건 분석 | 규칙 | NVD CVSS 벡터를 한국어로 해석 (원격 공격 가능, 로그인 불필요 등) |
| CWE | NVD 공식 | 취약점 유형 분류 |
| ISMS-P 인증기준 · MITRE ATT&CK | AI 제안 | 허용 목록(`_data/isms_p.json`, `_data/attack.json`) 안의 값만 표시 |
| 권고 조치 | AI 초안 | 보안 담당자가 할 일 2~3개 |
| **분석 노트** | **사람(직접 작성)** | `_data/comments/날짜.yml` |

### 분석 노트 쓰는 법
1. 매일 오는 디스코드 알림의 **✍️ 분석 노트 쓰기** 링크를 누릅니다. (또는 저장소에서 `_data/comments/오늘날짜.yml` 열고 ✏️)
2. 따옴표 안에 의견을 적습니다.
   ```yaml
   summary: "오늘의 총평"
   issue2: "국내 금융권은 이 제품 사용률이 높아 대외 서비스부터 점검 권고"
   ```
3. **Commit changes** → 1~2분 뒤 사이트에 표시됩니다. 비워 둔 항목은 표시되지 않습니다.
4. 커밋하면 **AI 코칭이 디스코드로** 옵니다 (`briefing/feedback.py`, `note-feedback.yml`).
   위험분석 4단계(① 자산·노출 ② 위협·취약점 ③ 가능성·영향 ④ 대응 권고) 중 무엇을 다뤘는지, 잘한 점·보강할 점·사실 확인·생각해 볼 질문을 알려줍니다.
   AI 는 글을 고치지 않으며 사이트에는 내가 쓴 글만 게시됩니다.
   피드백을 다른 비공개 채널로 받고 싶으면 Secret `DISCORD_FEEDBACK_WEBHOOK_URL` 을 추가하세요 (없으면 기본 채널).

## 구조

```
GitHub Actions (cron: 매일 00:00 UTC = 09:00 KST, 비용 0원)
 │
 ├─ 1. 수집  briefing/collect.py
 │    국내: 보안뉴스 · 데일리시큐 · KISA 보호나라
 │    해외: The Hacker News · BleepingComputer · SecurityWeek · The Record
 │    CVE : CISA KEV (실제 악용 중인 취약점 목록)
 │    → 최근 36시간 기사, 이미 다룬 링크(state/seen.json)·중복 제목 제외
 │
 ├─ 2. 선정  briefing/llm.py  (Gemini API 무료 티어)
 │    중요도 + 국내/해외 균형 + 취약점/사고/정책 분야 균형으로 5건
 │
 ├─ 3. 요약  선정 기사 본문을 가져와 핵심/배경/영향 + 용어 정리 (JSON 스키마로 출력)
 │          위험도(1~5)는 AI 평가로 표시
 │
 ├─ 3.5 검증 briefing/enrich.py  (공식 데이터, 무료·키 불필요)
 │    NVD API  → CVE 실존 확인 + 공식 CVSS (없는 번호는 버림)
 │    FIRST EPSS → 30일 내 악용 확률
 │    CISA KEV → 실제 악용 확인 여부
 │
 ├─ 4. 게시  briefing/render.py → _posts/*.md 커밋 → GitHub Pages(Jekyll) 자동 배포
 │
 └─ 5. 알림  briefing/notify.py → 페이지 배포 완료를 기다렸다가 Discord 웹훅 전송
              (실패하면 실패 알림 전송)
```

| 파일 | 역할 |
|---|---|
| `briefing/config.py` | 피드 목록, 수집 기간, 이슈 개수 등 설정 |
| `briefing/collect.py` | RSS·CISA KEV 수집, 기사 본문 추출 |
| `briefing/llm.py` | Gemini 호출 (이슈 선정 + 요약 프롬프트) |
| `briefing/enrich.py` | NVD·EPSS·KEV 로 CVE 검증 및 공식 지표 보강 |
| `briefing/render.py` | 마크다운 포스트·용어 사전 생성 |
| `_data/metrics.yml` | CVE·CVSS·EPSS·KEV·위험도 설명 문구 (사이트 ⓘ 툴팁·About) |
| `briefing/__main__.py` | 실행 진입점: `python -m briefing daily / notify / feedback` |
| `briefing/pipeline.py` | 매일 파이프라인 (수집 → 요약 → 검증 → 게시) |
| `briefing/notify.py` | Discord 알림 |
| `briefing/feedback.py` | 분석 노트 AI 코칭 |
| `.github/workflows/daily-briefing.yml` | 매일 9시 자동 실행 |

---

## 설정 방법 (처음 한 번만, 약 15분)

### 1) GitHub 저장소 만들고 코드 올리기

1. GitHub에서 **New repository** → 이름 예: `security-briefing` → **Public** 선택
2. 이 폴더에서:
   ```bash
   git add .
   git commit -m "init: daily security briefing"
   git remote add origin https://github.com/<내아이디>/security-briefing.git
   git push -u origin main
   ```

> 💡 저장소 이름을 `<내아이디>.github.io` 로 만들면 블로그 주소가 `https://<내아이디>.github.io` 가 됩니다.
> 그 외 이름이면 `https://<내아이디>.github.io/<저장소이름>/` 입니다.

### 2) Gemini API 키 발급 (무료)

1. https://aistudio.google.com/apikey 접속 → Google 로그인
2. **Create API key** → 키 복사
   (결제 정보 등록 없이 쓰면 무료 티어로만 동작해서 요금이 나가지 않습니다)

### 3) Discord 웹훅 만들기

1. 알림 받을 Discord 서버(혼자 쓰는 서버를 하나 만들어도 됨)에서 채널 옆 ⚙️ **채널 편집**
2. **연동(Integrations)** → **웹후크(Webhooks)** → **새 웹후크** → 이름 `보안 브리핑`
3. **웹후크 URL 복사**
4. 폰에 Discord 앱 설치 + 해당 채널 알림을 "모든 메시지"로 설정하면 푸시가 옵니다

### 4) GitHub에 비밀값 등록

저장소 → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

| Name | Value |
|---|---|
| `GEMINI_API_KEY` | 2)에서 복사한 키 |
| `DISCORD_WEBHOOK_URL` | 3)에서 복사한 웹훅 URL |

⚠️ 키와 웹훅 URL은 절대 코드에 직접 쓰지 마세요. (공개 저장소라 누구나 볼 수 있음)

### 5) GitHub Pages 켜기

저장소 → **Settings** → **Pages** → Source: **Deploy from a branch** → Branch: `main` / `/(root)` → **Save**

### 6) 첫 실행 테스트

저장소 → **Actions** 탭 → (처음이면 워크플로 활성화 버튼 클릭) → **Daily Security Briefing** → **Run workflow**

2~5분 뒤 Discord로 알림이 오면 성공입니다. 이후로는 매일 오전 9시에 자동으로 실행됩니다.

---

## 참고

- **실행 시각**: GitHub 예약 실행은 정각에 몰려 늦거나 빠지는 일이 있어서, **08:47 · 09:17 · 09:47 (KST) 세 번** 시도합니다. 오늘 글이 이미 있으면 나머지는 건너뛰므로 중복 게시·중복 알림은 없습니다. 수동 실행 시 `force` 를 켜면 다시 생성합니다.
- **60일 규칙**: 공개 저장소에 60일 동안 커밋이 없으면 예약 실행이 자동으로 꺼집니다.
  이 봇은 매일 커밋하므로 보통 문제없지만, 꺼졌다면 Actions 탭에서 다시 켜면 됩니다.
- **무료 한도**: 하루 Gemini 호출은 2번뿐이라 무료 한도 안에 넉넉히 들어갑니다.
  모델이 바뀌거나 사라지면 `llm.py`가 다음 모델로 자동 전환하며, Secrets/Variables에 `GEMINI_MODEL`을 지정할 수도 있습니다.
- **로컬 테스트**: `pip install -r requirements.txt` 후 `python -m briefing daily --dry-run` → AI 없이 수집과 글 생성만 시험해 봅니다.
- **저작권**: 기사 원문은 옮기지 않고, 요약과 출처 링크만 게시합니다.
- 소스 추가·변경은 `briefing/config.py`의 `RSS_FEEDS`를 수정하면 됩니다.
