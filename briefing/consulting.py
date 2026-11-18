"""컨설팅 관점 정보: CVSS 벡터 해석, 조치 우선순위, 규제·프레임워크 매핑 검증.

원칙: 공식 데이터로 계산할 수 있는 것은 규칙으로(재현 가능), AI 가 제안한 매핑은
허용 목록(_data/*.json) 안에 있는 값만 통과시키고 화면에 'AI 제안'으로 표시한다.
"""
import json
import re
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "_data"


def _load(name: str) -> dict:
    data = json.loads((DATA / name).read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


ISMS_P = _load("isms_p.json")
ATTACK = _load("attack.json")
CWE_RE = re.compile(r"^CWE-\d{1,5}$")

# ---------------------------------------------------------------------------
# 1) CVSS 벡터 → 한국어 요인 (v3.x / v4.0 기본 지표만)
#    level: "bad" = 공격자에게 유리(위험), "ok" = 공격을 어렵게 하는 요인
# ---------------------------------------------------------------------------
FACTORS = {
    "AV": ("공격 경로", {"N": ("원격(인터넷) 공격 가능", "bad"), "A": ("같은 네트워크에서만", "ok"),
                     "L": ("로컬 접근 필요", "ok"), "P": ("물리적 접근 필요", "ok")}),
    "AC": ("공격 난이도", {"L": ("공격 쉬움", "bad"), "H": ("공격 조건 까다로움", "ok")}),
    "AT": ("전제 조건", {"N": ("추가 조건 없음", "bad"), "P": ("특정 조건 필요", "ok")}),
    "PR": ("필요 권한", {"N": ("로그인 불필요", "bad"), "L": ("일반 계정 필요", "ok"), "H": ("관리자 권한 필요", "ok")}),
    "UI": ("사용자 행동", {"N": ("클릭 등 불필요", "bad"), "R": ("사용자 행동 필요", "ok"),
                       "P": ("사용자 행동 필요", "ok"), "A": ("사용자 행동 필요", "ok")}),
    "S": ("영향 범위", {"C": ("다른 시스템까지 영향", "bad"), "U": ("해당 시스템에 한정", "ok")}),
}
IMPACT = {"C": "정보 유출", "I": "데이터 변조", "A": "서비스 마비",
          "VC": "정보 유출", "VI": "데이터 변조", "VA": "서비스 마비"}
IMPACT_LEVEL = {"H": ("높음", "bad"), "L": ("낮음", "ok")}


def decode_vector(vector: str) -> list[dict]:
    """'CVSS:3.1/AV:N/AC:H/...' → [{"k": "공격 경로", "v": "원격(인터넷) 공격 가능", "level": "bad"}, ...]"""
    if not vector or not vector.startswith(("CVSS:3", "CVSS:4")):
        return []
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    out = []
    for key, (label, values) in FACTORS.items():
        if parts.get(key) in values:
            text, level = values[parts[key]]
            out.append({"k": label, "v": text, "level": level})
    for key, name in IMPACT.items():
        if parts.get(key) in IMPACT_LEVEL:
            text, level = IMPACT_LEVEL[parts[key]]
            out.append({"k": name, "v": text, "level": level})
    return out


# ---------------------------------------------------------------------------
# 2) 조치 우선순위 — 공개 규칙 (CISA KEV + FIRST EPSS + CVSS)
# ---------------------------------------------------------------------------
PRIORITY_RULES = [
    ("P1", "즉시 조치", "72시간 이내 패치·완화"),
    ("P2", "우선 조치", "2주 이내 패치"),
    ("P3", "정기 조치", "정기 패치 주기에 반영"),
]


def priority(e: dict) -> dict:
    """CVE 가 있는 이슈만 판단. 근거(reasons)를 함께 돌려준다."""
    if not e.get("cve"):
        return {"priority": "", "priority_reasons": []}
    cvss = float(e.get("cvss") or 0)
    epss = float(e.get("epss") or 0)          # % 단위
    reasons = []
    if e.get("kev"):
        reasons.append("CISA KEV 등재(실제 악용 확인)")
    if epss >= 10:
        reasons.append(f"EPSS {epss:g}% ≥ 10%")
    if reasons:
        level = "P1"
    else:
        if cvss >= 7.0:
            reasons.append(f"CVSS {cvss:g} ≥ 7.0")
        if epss >= 1:
            reasons.append(f"EPSS {epss:g}% ≥ 1%")
        level = "P2" if reasons else "P3"
        if not reasons:
            reasons.append("KEV 미등재 · CVSS 7.0 미만 · EPSS 1% 미만" if cvss else "공식 점수 미확정 → 정기 점검")
    return {"priority": level, "priority_reasons": reasons}


# ---------------------------------------------------------------------------
# 3) 매핑 검증 — 허용 목록 밖의 값(AI 환각)은 버린다
# ---------------------------------------------------------------------------
def clean_codes(values, allowed: dict, limit: int = 4) -> list[str]:
    out = []
    for v in values if isinstance(values, list) else []:
        v = str(v).strip().upper()          # 't1190' → 'T1190', '2.10.8' 은 그대로
        if v in allowed and v not in out:
            out.append(v)
    return out[:limit]


def clean_cwes(values, limit: int = 3) -> list[str]:
    out = []
    for v in values if isinstance(values, list) else []:
        v = str(v).strip().upper()
        if CWE_RE.match(v) and v not in out:
            out.append(v)
    return out[:limit]


def clean_actions(values, limit: int = 3) -> list[str]:
    out = []
    for v in values if isinstance(values, list) else []:
        v = re.sub(r"[\x00-\x1f\x7f]", " ", str(v))
        v = re.sub(r"\s+", " ", v).strip()[:120]
        if v:
            out.append(v)
    return out[:limit]


def prompt_catalog() -> str:
    """요약 프롬프트에 넣을 허용 목록 (AI 는 이 안에서만 고른다)."""
    isms = ", ".join(f"{k} {v}" for k, v in ISMS_P.items())
    attack = ", ".join(f"{k} {v.split(' · ')[0]}" for k, v in ATTACK.items())
    return f"[ISMS-P 허용 목록] {isms}\n[ATT&CK 허용 목록] {attack}"
