---
layout: page
title: About
permalink: /about/
---

## 이 블로그는 어떻게 만들어지나요?

사람이 손대지 않고 매일 오전 9시(KST)에 자동으로 글이 올라옵니다.

```
GitHub Actions (매일 09:00 KST)
  ├─ 1. 수집   : 국내(보안뉴스·데일리시큐·KISA 보호나라) / 해외(The Hacker News·BleepingComputer·SecurityWeek·The Record) RSS + CISA KEV
  ├─ 2. 선정   : Gemini가 중요도·국내외 균형·분야(취약점/사고/정책) 기준으로 5건 선정
  ├─ 3. 요약   : 기사 본문을 읽고 핵심 / 배경 / 영향 + 보안 용어 정리
  ├─ 4. 게시   : 마크다운 포스트 커밋 → GitHub Pages 자동 배포
  └─ 5. 알림   : Discord 웹훅으로 요약과 링크 전송
```

- 같은 기사가 다음 날 다시 뽑히지 않도록 이미 다룬 링크를 기억합니다.
- 요약은 AI가 작성하므로 정확한 내용은 각 글의 출처 원문을 확인해 주세요.
