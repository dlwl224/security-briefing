"""요약 결과를 Jekyll 포스트(마크다운)와 용어 사전 데이터로 만든다.

보안 메모: 글 내용은 외부 RSS와 AI 출력에서 오므로 '신뢰할 수 없는 입력'으로 취급한다.
- HTML 이스케이프 → <script> 등 저장형 XSS 차단
- 마크다운 링크/이미지 문법 무력화 → 프롬프트 인젝션으로 피싱 링크가 삽입되는 것 차단
- Liquid 문법 무력화 → Jekyll 템플릿 인젝션/빌드 실패 차단
- 링크는 http(s)만 허용 → javascript: 링크 차단
- front matter 값은 JSON 문자열로 써서 YAML 인젝션 차단
"""
import html
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from . import consulting

ROOT = Path(__file__).resolve().parent.parent
POSTS = ROOT / "_posts"
GLOSSARY = ROOT / "_data" / "glossary.json"

CATEGORIES = {"취약점": "🛠️", "사고": "🚨", "정책": "📜", "위협동향": "📡"}
REGIONS = {"국내", "해외"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MD_SPECIAL = re.compile(r"([\\`*_\[\]|!#~])")


def safe_text(s: object, max_len: int = 2000, single_line: bool = False) -> str:
    """신뢰할 수 없는 문자열을 마크다운 본문에 안전하게 넣을 수 있게 만든다."""
    s = str(s or "")
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)        # 제어문자 제거
    s = re.sub(r"\s+", " ", s) if single_line else re.sub(r"\n{2,}", "\n", s)
    s = s.strip()[:max_len]
    s = MD_SPECIAL.sub(r"\\\1", s)                                # 마크다운 문법 무력화 (링크·이미지·강조 등)
    s = html.escape(s, quote=False)                               # < > & → HTML 태그 삽입 차단
    s = s.replace("{", "&#123;").replace("}", "&#125;")           # Liquid 무력화
    return s.replace("\n", "  \n")


def safe_url(url: object) -> str:
    """http(s) URL만 허용하고, 마크다운 링크를 깨뜨리는 문자를 인코딩한다."""
    url = str(url or "").strip()
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        return ""
    return url.replace(" ", "%20").replace("(", "%28").replace(")", "%29").replace("<", "%3C").replace(">", "%3E")


def site_url() -> str:
    """GitHub Pages 주소. SITE_URL 환경변수가 있으면 그걸 쓴다."""
    if os.getenv("SITE_URL"):
        return os.environ["SITE_URL"].rstrip("/")
    repo = os.getenv("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return ""
    owner, name = repo.split("/", 1)
    if name.lower() == f"{owner.lower()}.github.io":
        return f"https://{owner.lower()}.github.io"
    return f"https://{owner.lower()}.github.io/{name}"


def post_path(date: str) -> str:
    # _config.yml 의 permalink(/briefing/:year-:month-:day/)와 맞춰야 한다
    return f"/briefing/{date}/"


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def plain(s: object, max_len: int) -> str:
    """front matter 용 평문: 제어문자 제거 + 공백 정리 + 길이 제한.
    HTML 이스케이프는 하지 않는다 — 레이아웃에서 반드시 `| escape` 로 출력한다."""
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(s or ""))
    return re.sub(r"\s+", " ", s).strip()[:max_len]


def normalize(entry: dict) -> dict:
    """AI 출력의 값을 허용된 범위로 강제한다."""
    try:
        severity = min(5, max(1, int(entry.get("severity") or 3)))
    except (TypeError, ValueError):
        severity = 3
    try:
        cvss = round(min(10.0, max(0.0, float(entry.get("cvss") or 0))), 1)
    except (TypeError, ValueError):
        cvss = 0.0
    cve = plain(entry.get("cve"), 20).upper()
    return {
        **entry,
        "category": entry.get("category") if entry.get("category") in CATEGORIES else "위협동향",
        "region": entry.get("region") if entry.get("region") in REGIONS else "해외",
        "severity": severity,
        "cvss": cvss,
        "cve": cve if CVE_RE.match(cve) else "",
    }


def _pick(v, allowed: set, default: str = "") -> str:
    return v if v in allowed else default


def _bounded(v, lo: float, hi: float) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0.0
    return round(f, 2) if lo <= f <= hi else 0.0


def metrics(e: dict) -> dict:
    """공식 지표(NVD/EPSS/KEV) — enrich 단계에서 검증됐지만 여기서 한 번 더 형식을 강제한다."""
    has_cve = bool(e["cve"])
    vector = plain(e.get("cvss_vector"), 300)
    date_ok = lambda s: s if DATE_RE.match(str(s or "")) else ""
    return {
        "cve_status": _pick(e.get("cve_status"), {"nvd", "pending"}) if has_cve else "",
        "cvss_severity": _pick(str(e.get("cvss_severity", "")).upper(), {"LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"}),
        "cvss_version": _pick(str(e.get("cvss_version", "")), {"2.0", "3.0", "3.1", "4.0"}),
        "cvss_source": _pick(e.get("cvss_source"), {"NVD", "CNA", "기사"}),
        "cvss_vector": vector if re.match(r"^[A-Za-z0-9:./()]{1,300}$", vector) else "",
        "epss": _bounded(e.get("epss"), 0, 100) if has_cve else 0.0,
        "epss_percentile": _bounded(e.get("epss_percentile"), 0, 100) if has_cve else 0.0,
        "epss_date": date_ok(e.get("epss_date")) if has_cve else "",
        "kev": bool(e.get("kev")) and has_cve,
        "kev_date": date_ok(e.get("kev_date")) if has_cve else "",
        "kev_ransomware": bool(e.get("kev_ransomware")) and has_cve,
    }


def structured_item(e: dict) -> dict:
    """레이아웃이 그릴 구조화 데이터 (모두 평문, 출력 시 escape)."""
    return {
        "title": plain(e["title"], 200),
        "region": e["region"],
        "category": e["category"],
        "severity": e["severity"],
        "core": plain(e["core"], 1200),
        "background": plain(e["background"], 1500),
        "impact": plain(e["impact"], 1200),
        "key_figure": plain(e.get("key_figure"), 16),
        "key_figure_label": plain(e.get("key_figure_label"), 30),
        "cve": e["cve"],
        "cvss": e["cvss"],
        "source": plain(e.get("source"), 50),
        "link": safe_url(e.get("link")),
        **metrics(e),
        **consulting_view(e),
    }


def consulting_view(e: dict) -> dict:
    """컨설팅 관점: 조치 우선순위(규칙), CVSS 벡터 해석, CWE(NVD), ISMS-P·ATT&CK(AI 제안, 허용 목록 검증), 권고 조치(AI 초안)."""
    m = metrics(e)
    pr = consulting.priority({**e, **m})
    return {
        **pr,
        "cvss_factors": consulting.decode_vector(m["cvss_vector"]),
        "cwe": consulting.clean_cwes(e.get("cwe")) if e["cve"] else [],
        "isms": consulting.clean_codes(e.get("isms"), consulting.ISMS_P, 3),
        "attack": consulting.clean_codes(e.get("attack"), consulting.ATTACK, 3),
        "actions": consulting.clean_actions(e.get("actions")),
    }


def issue_number(date: str) -> int:
    """이 브리핑이 몇 번째인지 (오늘 이전 포스트 수 + 1)."""
    if not POSTS.exists():
        return 1
    return 1 + sum(1 for p in POSTS.glob("*-security-briefing.md") if p.name[:10] < date)


def write_post(date: str, entries: list[dict], terms: list[dict], summary: str = "") -> Path:
    if not DATE_RE.match(date):
        raise ValueError(f"잘못된 날짜: {date}")
    entries = [normalize(e) for e in entries]
    regions = [e["region"] for e in entries]
    plain_titles = " / ".join(re.sub(r"[\s{}]+", " ", str(e["title"]))[:80] for e in entries)[:300]
    items = [structured_item(e) for e in entries]
    term_items = [
        {"term": plain(t.get("term"), 60), "english": plain(t.get("english"), 80),
         "definition": plain(t.get("definition"), 400)}
        for t in terms
    ]
    threat = round(sum(e["severity"] for e in entries) / len(entries)) if entries else 1
    dump = lambda v: json.dumps(v, ensure_ascii=False)
    lines = [
        "---",
        "layout: briefing",
        f"title: {dump(f'{date} 보안 이슈 브리핑')}",
        f"date: {date} 09:00:00 +0900",
        f"issue_no: {issue_number(date)}",
        f"threat_level: {threat}",
        f"summary: {dump(plain(summary, 120))}",
        f"tags: {dump(sorted({e['category'] for e in entries}))}",
        f"description: {dump(html.escape(plain_titles))}",
        f"items: {dump(items)}",
        f"terms: {dump(term_items)}",
        "---",
        "",
        f"> 오늘의 주요 보안 이슈 {len(entries)}건 "
        f"(국내 {regions.count('국내')} · 해외 {regions.count('해외')})",
        "",
        "## 📌 한눈에 보기",
        "",
    ]
    for i, e in enumerate(entries, 1):
        lines.append(f"{i}. **[{e['region']}·{e['category']}]** {safe_text(e['title'], 200, True)}")
    lines.append("")

    for i, e in enumerate(entries, 1):
        link = safe_url(e.get("link"))
        source = safe_text(e.get("source"), 50, True)
        lines += [
            "---",
            "",
            f"## {i}. {CATEGORIES[e['category']]} {safe_text(e['title'], 200, True)}",
            "",
            f"`{e['region']}` `{e['category']}` · 출처: " + (f"[{source}]({link})" if link else source),
            "",
            "**🎯 핵심**  ",
            safe_text(e["core"]),
            "",
            "**📖 배경**  ",
            safe_text(e["background"]),
            "",
            "**💥 영향**  ",
            safe_text(e["impact"]),
            "",
        ]

    if terms:
        lines += ["---", "", "## 📚 오늘의 보안 용어", ""]
        for t in terms:
            lines.append(
                f"- **{safe_text(t['term'], 60, True)}** ({safe_text(t['english'], 80, True)}): "
                f"{safe_text(t['definition'], 400, True)}"
            )
        lines += ["", "👉 지금까지 나온 용어는 [보안 용어 사전](../../glossary/)에서 볼 수 있어요.", ""]

    lines += [
        "---",
        "",
        "<small>이 글은 공개된 보안 뉴스를 AI(Gemini)로 요약해 자동 작성했습니다. "
        "정확한 내용은 각 출처 원문을 확인하세요.</small>",
        "",
    ]
    POSTS.mkdir(exist_ok=True)
    path = POSTS / f"{date}-security-briefing.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


COMMENTS = ROOT / "_data" / "comments"


def write_comment_template(date: str, entries: list[dict]) -> Path:
    """분석 노트 빈 양식을 만든다 (이미 있으면 사람이 쓴 내용을 지키기 위해 건드리지 않음)."""
    if not DATE_RE.match(date):
        raise ValueError(f"잘못된 날짜: {date}")
    COMMENTS.mkdir(parents=True, exist_ok=True)
    path = COMMENTS / f"{date}.yml"
    if path.exists():
        return path
    lines = [
        f"# ============================================================",
        f"#  {date} 브리핑 — 📝 분석 노트",
        f"# ============================================================",
        "#",
        "# ▶ 쓰는 법",
        "#   따옴표 \"\" 안에 적고 아래 [Commit changes] 를 누르면 1~2분 뒤 사이트에 표시됩니다.",
        "#   비워 둔 칸은 표시되지 않아요. 하루 1건, 2~3문장이면 충분합니다.",
        "#   (문장 안에 큰따옴표를 쓰려면 \\\" 로 적기)",
        "#",
        "# ▶ 위험분석 4단계 (자산 → 위협·취약점 → 위험 → 대응, NIST SP 800-30 / 국내 위험분석 절차)",
        "#   ① 누구에게 해당되나? (자산·노출)    국내 어떤 기업·기관·시스템이 영향을 받나",
        "#   ② 왜 뚫렸나? (위협·취약점)          누가 무엇을 노렸고, 어떤 통제가 약했나 (ISMS-P 몇 번)",
        "#   ③ 얼마나 급한가? (가능성·영향)       KEV·EPSS·CVSS + 업무가 멈추나/정보가 새나",
        "#   ④ 그래서 무엇을 하나? (대응 권고)     감소·회피·전가·수용 중 무엇을, 언제까지",
        "#   처음엔 하루 1건, 한 단계만 써도 충분해요. 익숙해지면 ①~④를 한 문장씩.",
        "#   모르면 질문으로 남겨도 좋아요 → 예) \"~가 왜 ~인지 아직 모르겠다. 이번 주 공부 주제.\"",
        "#",
        "# ▶ 이렇게 쓰면 좋아요",
        "#   ✅ \"~일 것 같다. 왜냐하면 ~\"  (추측과 근거를 나눠서)",
        "#   ❌ AI 요약 다시 쓰기 / \"매우 위험하다\" 같은 일반론 / 확인 안 된 단정",
        "#",
        "# ▶ 예시 (①~④를 한 문장씩)",
        "#   issue2: \"① 자바로 대외 서비스를 운영하는 국내 금융·공공이 대상. ② 인증 없는 원격 실행이라 외부 노출 서버가 위험.",
        "#            ③ CVSS 8.1·KEV 미등재라 P2지만 노출 서버는 더 급함. ④ 외부 노출 Jenkins·Jira부터 2주 내 패치(위험 감소).\"",
        "#",
        "# ▶ 커밋하면 AI 피드백이 디스코드로 옵니다 (사이트에는 내가 쓴 글만 그대로 게시)",
        "# ============================================================",
        "",
        'summary: ""   # 오늘 하루를 한 문장으로 (선택, 홈 화면에도 표시)',
        "",
    ]
    for i, e in enumerate(entries, 1):
        hint = []
        try:
            it = structured_item(normalize(e))
            if it["priority"]:
                hint.append(it["priority"])
            if it["kev"]:
                hint.append("KEV 실제 악용")
            if it["cvss"]:
                hint.append(f"CVSS {it['cvss']:g}")
            hint.append(f"{it['region']}·{it['category']}")
        except Exception:
            pass
        tag = f"  [{' · '.join(hint)}]" if hint else ""
        lines.append(f"# {i:02d}. {plain(e.get('title'), 60)}{tag}")
        lines.append(f'issue{i}: ""')
        lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def comment_edit_url(date: str) -> str:
    """GitHub 웹에서 코멘트 파일을 바로 편집하는 주소."""
    repo = os.getenv("GITHUB_REPOSITORY", "")
    if "/" not in repo or not DATE_RE.match(date):
        return ""
    server = os.getenv("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    return f"{server}/{repo}/edit/main/_data/comments/{date}.yml"


def update_glossary(date: str, terms: list[dict]) -> int:
    """용어 사전에 새 용어 추가. 값은 평문으로 저장하고, 페이지에서 escape 필터로 출력한다."""
    data = json.loads(GLOSSARY.read_text(encoding="utf-8")) if GLOSSARY.exists() else []
    norm = lambda s: re.sub(r"\s+", "", str(s)).lower()
    known = {norm(d["term"]) for d in data} | {norm(d["english"]) for d in data}
    added = 0
    for t in terms:
        item = {
            "term": re.sub(r"\s+", " ", str(t.get("term", ""))).strip()[:60],
            "english": re.sub(r"\s+", " ", str(t.get("english", ""))).strip()[:80],
            "definition": re.sub(r"\s+", " ", str(t.get("definition", ""))).strip()[:400],
        }
        keys = {norm(item["term"]), norm(item["english"])}
        if not item["term"] or keys & known:
            continue
        data.append({**item, "first_seen": date, "post": post_path(date)})
        known |= keys
        added += 1
    data.sort(key=lambda d: d["term"])
    GLOSSARY.parent.mkdir(exist_ok=True)
    GLOSSARY.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return added
