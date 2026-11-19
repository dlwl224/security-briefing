# ☁️ AWS 인프라 (Terraform)

AWS 자원을 콘솔 클릭이 아니라 **코드로** 만든다. 모든 변경은 PR 로 리뷰되고, 자동 검사(fmt · validate · checkov)와 `plan` 을 거친 뒤 **내가 승인해야** 적용된다.

```
infra/
  modules/private_bucket/   비공개 S3 버킷 공통 모듈 (공개 차단 · 암호화 · 버전 관리 · HTTPS 전용 · 보존 기간)
  bootstrap/                처음 한 번, 사람이 CloudShell 에서 실행 — 상태 저장 버킷 · GitHub OIDC · CI 역할 · 계정 S3 공개 차단
  stacks/baseline/          GitHub Actions 가 적용 — CloudTrail (모든 리전 관리 이벤트, 로그 무결성 검증)
  .checkov.yaml             설정 점검 예외 목록 (이유는 아래 표)
```

## 보안 설계

| 항목 | 설계 | 이유 |
|---|---|---|
| 자격 증명 | **액세스 키 없음.** GitHub Actions 는 OIDC 로 1시간짜리 임시 자격 증명만 받는다 | 저장소에 유출될 장기 키 자체가 없다 |
| 역할 분리 | `tf-plan`(읽기 전용) / `tf-apply`(쓰기) 두 역할 | PR 은 계획만 볼 수 있고 바꿀 수는 없다 |
| 신뢰 조건 | plan: 이 저장소의 PR · `main` 만 / apply: 이 저장소의 **`aws` 환경**만 | 다른 저장소·포크·브랜치에서는 역할을 받을 수 없다 |
| 적용 승인 | `aws` 환경에 **필수 승인자(나)** + `main` 브랜치만 | 코드가 머지돼도 내가 승인하기 전엔 AWS 가 바뀌지 않는다 |
| 최소 권한 | apply 역할의 쓰기 권한은 `security-briefing-*` 이름의 S3 버킷·CloudTrail 만 | 다른 자원은 만들거나 바꿀 수 없다 |
| 금지 목록 | 두 역할 모두 IAM 변경, CloudTrail 중지·삭제, 상태 버킷 설정 변경, 계정 공개 차단 해제, 비밀값·임의 객체 읽기를 **명시적 거부** | 역할이 탈취돼도 권한 상승·감사 로그 지우기·비밀 열람을 못 한다 |
| 상태 파일 | 비공개 S3 (암호화 · 버전 관리 · HTTPS 전용), S3 잠금 파일(`use_lockfile`) | 상태에는 자원 정보가 들어 있어 공개되면 안 된다 |
| 공개 로그 | 공개 저장소라 Actions 로그가 공개된다 → plan/apply 원문은 출력하지 않고 **자원 주소·동작만** 요약, 계정 ID 는 마스킹 | 계정 ID·ARN 노출 최소화 |
| 공급망 | Terraform·AWS provider 버전 고정 + `.terraform.lock.hcl` 해시, Action 은 커밋 SHA 고정. CloudShell 설치 시 HashiCorp **서명과 체크섬** 검증 | 바꿔치기된 바이너리·플러그인 차단 |

## 처음 한 번 설정 (AWS 계정 확인이 끝난 뒤)

### 1) GitHub 환경 만들기 — 반드시 먼저
저장소 **Settings → Environments → New environment** → 이름 `aws`
- **Required reviewers**: 내 계정 체크
- **Deployment branches and tags**: Selected branches → `main`

> 순서가 중요하다. 승인 규칙 없이 `aws` 환경이 먼저 생기면 머지와 동시에 승인 없이 적용될 수 있다.

### 2) CloudShell 에서 부트스트랩
AWS 콘솔 오른쪽 위 리전을 **아시아 태평양(서울) ap-northeast-2** 로 바꾸고 CloudShell 을 연다.

```bash
git clone --depth 1 https://github.com/dlwl224/security-briefing.git
bash security-briefing/infra/bootstrap/bootstrap.sh
```

- Terraform 을 내려받아 서명·체크섬을 확인한 뒤 설치한다
- `plan` 이 화면에 나오면 **만들어질 자원을 읽어 보고** `yes` 입력
- 끝나면 상태 파일을 방금 만든 S3 버킷으로 옮기고, 마지막에 값 3개를 보여 준다

### 3) GitHub 에 값 넣기 (채팅·메모에 붙여넣지 말 것)
| 위치 | 이름 | 값 |
|---|---|---|
| Settings → Secrets and variables → Actions → **Secrets** | `AWS_PLAN_ROLE_ARN` | `plan_role_arn` |
| 〃 | `TF_STATE_BUCKET` | `state_bucket` |
| Settings → Environments → `aws` → **Environment secrets** | `AWS_APPLY_ROLE_ARN` | `apply_role_arn` |
| Settings → Secrets and variables → Actions → **Variables** | `AWS_BOOTSTRAPPED` | `true` |

`AWS_BOOTSTRAPPED` 를 넣기 전에는 Infra 워크플로가 검사(check)만 하고 AWS 에 접속하지 않는다.

### 4) 첫 적용
Actions → **Infra** → Run workflow (main) → Plan 요약 확인 → Apply 의 **Review deployments** 에서 승인 → CloudTrail 생성.

확인: AWS 콘솔 → CloudTrail → Trails 에 `security-briefing-trail` (Logging: On, Multi-region: Yes).

## 점검 예외 (위험 수용)

checkov 에서 끈 항목과 이유. 개인 실습 계정이라 **비용·복잡도 대비 효과가 낮은 것**만 예외로 둔다.

| 검사 | 내용 | 수용 이유 | 대신 하는 것 |
|---|---|---|---|
| CKV_AWS_145, CKV_AWS_35 | KMS 고객 관리 키 암호화 | 키 1개당 월 비용, 키 관리 부담 | S3 기본 암호화(SSE-S3) |
| CKV_AWS_18 | S3 접근 로그 | 로그용 버킷이 또 필요, 데이터 이벤트 비용 | CloudTrail 관리 이벤트로 버킷 설정 변경 추적 |
| CKV_AWS_144 | 리전 간 복제 | 비용 두 배, 실습 데이터 | 버전 관리로 삭제·덮어쓰기 복구 |
| CKV2_AWS_62 | S3 이벤트 알림 | 알림 받을 대상 없음 | — |
| CKV_AWS_252, CKV2_AWS_10 | CloudTrail SNS · CloudWatch Logs 연동 | 로그 수집 비용 | 6단계 Prowler 진단 때 다시 검토 |

## 새 스택 추가
1. `infra/stacks/<이름>/` 에 `versions.tf`(backend key `stacks/<이름>/terraform.tfstate`) · `variables.tf` · `main.tf`
2. `.github/workflows/infra.yml` 의 `matrix.stack` 두 곳에 이름 추가
3. 새 서비스 권한이 필요하면 `bootstrap/iam.tf` 의 `apply` 정책에 **이름 범위를 좁혀** 추가 → 부트스트랩을 CloudShell 에서 다시 실행 (CI 역할은 자기 권한을 바꿀 수 없다)
