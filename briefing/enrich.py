"""CVE 를 공식 데이터로 검증·보강한다.

- NVD API 2.0  : CVE 존재 여부, 공식 CVSS 점수/등급/벡터 (https://nvd.nist.gov/developers/vulnerabilities)
- FIRST EPSS   : 30일 내 악용 확률 (https://www.first.org/epss/api)
- CISA KEV     : 실제 악용 확인 목록 (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

보안 메모: 외부 API 응답도 '신뢰할 수 없는 입력'이다.
형식·범위를 검사한 값만 통과시키고, 장애 시에는 해당 정보 없이 진행한다(게시를 막지 않음).
"""
import json
import os
import re
import time

import requests

from . import config
from .netsafe import safe_get

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
VECTOR_RE = re.compile(r"^[A-Za-z0-9:./()]{1,300}$")
SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"

session = requests.Session()
session.headers["User-Agent"] = config.USER_AGENT
if os.getenv("NVD_API_KEY"):                       # 선택: 있으면 호출 한도가 늘어남
    session.headers["apiKey"] = os.environ["NVD_API_KEY"]


def _num(v, lo: float, hi: float) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if lo <= f <= hi else None


def cvss_band(score: float) -> str:
    """CVSS v3/v4 정성 등급 (FIRST 기준)."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def parse_nvd(data: dict) -> dict | None:
    """NVD 응답에서 대표 CVSS 를 고른다. 우선순위: v3.1 > v4.0 > v3.0 > v2, 같은 버전이면 NVD(Primary) 우선."""
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not vulns:
        return None
    cve = vulns[0].get("cve") or {}
    result = {"status": str(cve.get("vulnStatus", ""))[:40]}
    metrics = cve.get("metrics") or {}
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = [m for m in metrics.get(key) or [] if isinstance(m, dict) and isinstance(m.get("cvssData"), dict)]
        if not entries:
            continue
        entries.sort(key=lambda m: m.get("type") != "Primary")
        m = entries[0]
        score = _num(m["cvssData"].get("baseScore"), 0, 10)
        if score is None:
            continue
        sev = str(m["cvssData"].get("baseSeverity") or m.get("baseSeverity") or "").upper()
        vector = str(m["cvssData"].get("vectorString", ""))
        result.update({
            "cvss": round(score, 1),
            "cvss_version": version,
            # v2 는 등급 체계가 달라서 v3 기준으로 다시 계산해 표시를 통일
            "cvss_severity": sev if sev in SEVERITIES and version != "2.0" else cvss_band(score),
            "cvss_vector": vector if VECTOR_RE.match(vector) else "",
            "cvss_source": "NVD" if m.get("type") == "Primary" else "CNA",
        })
        break
    return result


def parse_epss(data: dict) -> dict | None:
    rows = data.get("data") if isinstance(data, dict) else None
    if not rows or not isinstance(rows[0], dict):
        return None
    epss = _num(rows[0].get("epss"), 0, 1)
    pct = _num(rows[0].get("percentile"), 0, 1)
    if epss is None:
        return None
    date = str(rows[0].get("date", ""))
    return {
        "epss": round(epss * 100, 2),                       # %
        "epss_percentile": round((pct or 0) * 100, 1),       # 상위 몇 % 인지 계산용
        "epss_date": date if re.match(r"^\d{4}-\d{2}-\d{2}$", date) else "",
    }


def _get_json(url: str, params: dict, max_bytes: int = 2_000_000) -> dict | None:
    """성공하면 dict, 장애·한도 초과·형식 오류면 None (None 과 '결과 없음'을 구분하기 위함)."""
    for attempt in range(3):
        try:
            body, _ = safe_get(session, url, params=params, max_bytes=max_bytes)
            data = json.loads(body)
            return data if isinstance(data, dict) else None
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else 0
            if code in (403, 429, 503):                     # NVD 호출 한도
                time.sleep(7 * (attempt + 1))
                continue
            print(f"[warn] {url} 조회 실패: HTTP {code}")
            return None
        except (requests.RequestException, ValueError) as e:
            print(f"[warn] {url} 조회 실패: {type(e).__name__}")
            time.sleep(3)
    return None


def load_kev() -> dict[str, dict]:
    data = _get_json(config.CISA_KEV_URL, {}, max_bytes=15_000_000) or {}
    out = {}
    for v in data.get("vulnerabilities", []) if isinstance(data, dict) else []:
        cid = str(v.get("cveID", "")).upper()
        if CVE_RE.fullmatch(cid):
            added = str(v.get("dateAdded", ""))
            out[cid] = {
                "kev_date": added if re.match(r"^\d{4}-\d{2}-\d{2}$", added) else "",
                "kev_ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
            }
    return out


def candidate_cve(entry: dict, article_text: str) -> str:
    """AI 가 고른 CVE 를 우선, 없으면 기사 본문에 처음 나온 CVE."""
    ai = str(entry.get("cve") or "").strip().upper()
    if CVE_RE.fullmatch(ai):
        return ai
    found = CVE_RE.findall(article_text or "")
    return found[0].upper() if found else ""


def enrich(entries: list[dict], texts: list[str], refresh: bool = False) -> int:
    """entries 를 제자리에서 보강한다. texts[i] 는 entries[i] 의 기사 본문.

    refresh=True: 이미 발행된 글을 다시 조회하는 모드. NVD 장애로 응답을 못 받으면
    기존 값을 그대로 둔다 (장애 때문에 멀쩡한 CVE 가 지워지는 일을 막음).
    돌려주는 값: 실제로 갱신한 항목 수.
    """
    kev = load_kev()
    first, changed = True, 0
    for e, text in zip(entries, texts):
        cid = candidate_cve(e, text)
        if not cid:
            if not refresh:
                e.update({"cve": "", "cve_status": "", "kev": False, "cvss": 0})
            continue
        if not first:
            time.sleep(6)                                   # NVD 무키 한도: 30초에 5회
        first = False
        raw = _get_json(NVD_URL, {"cveId": cid})
        if raw is None and refresh:
            print(f"[warn] {cid}: NVD 응답 없음 → 기존 값 유지")
            continue
        before = {k: e.get(k) for k in ("cve", "cve_status", "cvss", "cvss_source", "epss", "kev")}
        ai_cvss = _num(e.get("cvss"), 0.1, 10) if e.get("cvss_source", "기사") in ("기사", "", None) else None
        e.update({"cve": "", "cve_status": "", "kev": False, "cvss": 0})
        nvd = parse_nvd(raw or {})
        in_article = cid in (text or "").upper()
        if nvd and nvd.get("status", "").lower() == "rejected":
            print(f"[warn] {cid}: NVD 에서 거부(Rejected)된 번호 → 제외")
            changed += before["cve"] != ""
            continue
        if nvd:
            e.update(nvd)
            e["cve"], e["cve_status"] = cid, "nvd"
        elif in_article:
            # NVD 에 아직 없는 아주 새로운 CVE: 기사 원문에 그대로 있을 때만 '분석 대기'로 표시
            e["cve"], e["cve_status"] = cid, "pending"
        else:
            print(f"[warn] {cid}: NVD 에도 기사에도 없음 → AI 오기로 보고 제외")
            changed += before["cve"] != ""
            continue
        if not e.get("cvss") and ai_cvss and in_article:
            e.update({"cvss": round(ai_cvss, 1), "cvss_severity": cvss_band(ai_cvss), "cvss_source": "기사", "cvss_version": ""})
        epss = parse_epss(_get_json(EPSS_URL, {"cve": cid}) or {})
        if epss:
            e.update(epss)
        if cid in kev:
            e["kev"] = True
            e.update(kev[cid])
        if before != {k: e.get(k) for k in before}:
            changed += 1
        print(f"[info] {cid}: {e['cve_status']} CVSS={e.get('cvss')} EPSS={e.get('epss')} KEV={e['kev']}")
    return changed
