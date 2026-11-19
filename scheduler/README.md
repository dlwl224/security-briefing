# ⏰ 외부 스케줄러 (Cloudflare Workers)

GitHub 예약 실행은 지연·누락될 수 있어서, 정확한 시계를 가진 Cloudflare Worker 가 매일 GitHub 에 실행 신호를 보낸다.

| 시각 (KST) | 하는 일 |
|---|---|
| 08:40 | 오늘 글이 없으면 `Daily Security Briefing` 실행 |
| 10:05 | 감시 — 그때까지 없으면 디스코드 경고 + 다시 실행 |

GitHub 자체 예약(08:47 · 09:17 · 09:47 · 10:40)은 보조로 그대로 둔다. 오늘 글이 있으면 모든 실행이 건너뛰므로 중복되지 않는다.

- 공개 URL 없음: `fetch` 는 항상 404, `workers_dev = false` — 외부에서 실행시킬 수 없다
- 토큰 권한: 이 저장소 하나, **Actions 실행 + Contents 읽기** 만

---

## 설정 (처음 한 번, 약 15분)

### 1) GitHub 토큰 만들기 (Fine-grained)
1. GitHub 오른쪽 위 프로필 → **Settings** → 왼쪽 맨 아래 **Developer settings**
2. **Personal access tokens → Fine-grained tokens → Generate new token**
3. 입력
   - Token name: `briefing-scheduler`
   - Expiration: **1년** (만료 전에 새로 발급해 4)번처럼 교체)
   - Repository access: **Only select repositories → `security-briefing`**
   - Permissions → Repository permissions
     - **Actions: Read and write**
     - **Contents: Read-only**
     - (Metadata: Read-only 는 자동)
   - 나머지 권한은 건드리지 않는다
4. **Generate token** → 표시된 토큰을 복사 (이 화면을 벗어나면 다시 볼 수 없음). 채팅·메모에 붙여넣지 말 것

### 2) Cloudflare Worker 만들기
1. https://dash.cloudflare.com 가입·로그인
2. 왼쪽 **Workers & Pages** (또는 Compute → Workers) → **Create** → **Create Worker** (Hello World 템플릿)
3. 이름: `security-briefing-scheduler` → **Deploy**
4. **Edit code** → 기존 코드를 모두 지우고 이 폴더의 [`worker.js`](worker.js) 전체를 붙여넣기 → **Deploy**

### 3) 설정값 넣기
Worker 화면 → **Settings**

**Variables and Secrets** → **Add**
| Type | Name | Value |
|---|---|---|
| Text | `GH_REPO` | `dlwl224/security-briefing` |
| Text | `WORKFLOW_FILE` | `daily-briefing.yml` |
| Text | `WATCHDOG_CRON` | `5 1 * * *` |
| **Secret** | `GITHUB_TOKEN` | 1)에서 복사한 토큰 |
| **Secret** | `DISCORD_WEBHOOK_URL` | (선택) 경고를 받을 디스코드 웹후크 |

**Trigger Events (Cron Triggers)** → **Add**
- `40 23 * * *` (08:40 KST)
- `5 1 * * *` (10:05 KST)

**Domains & Routes**
- `workers.dev` 와 **Preview URLs** 를 **Disable** (외부에서 접속할 주소를 없앤다)

### 4) 확인
- Worker 화면 → **Settings → Trigger Events** 에서 cron 옆 **⋯ → Trigger** (또는 상단 **Schedule** 테스트)를 누르면 바로 실행된다
- GitHub **Actions** 탭에 `workflow_dispatch` 로 `Daily Security Briefing` 이 생기면 성공 (오늘 글이 이미 있으면 Worker 가 아무것도 하지 않는 것이 정상)
- Worker 화면 **Logs** 에서 오류 확인

### 토큰 교체·폐기
- 만료 전: 1)을 다시 해서 새 토큰 → Worker Secret `GITHUB_TOKEN` 덮어쓰기 → 옛 토큰 **Delete**
- 유출이 의심되면: GitHub 에서 토큰 즉시 **Delete** → 새로 발급

---

## 코드로 배포하고 싶다면 (선택)
Node.js 가 있으면 대시보드 대신 `npx wrangler deploy` (이 폴더의 `wrangler.toml` 사용) 후
`npx wrangler secret put GITHUB_TOKEN` 으로 비밀값을 넣는다.
