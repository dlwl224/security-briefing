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


def normalize(entry: dict) -> dict:
    """AI 출력의 값을 허용된 범위로 강제한다."""
    return {
        **entry,
        "category": entry.get("category") if entry.get("category") in CATEGORIES else "위협동향",
        "region": entry.get("region") if entry.get("region") in REGIONS else "해외",
    }


def write_post(date: str, entries: list[dict], terms: list[dict]) -> Path:
    if not DATE_RE.match(date):
        raise ValueError(f"잘못된 날짜: {date}")
    entries = [normalize(e) for e in entries]
    regions = [e["region"] for e in entries]
    plain_titles = " / ".join(re.sub(r"[\s{}]+", " ", str(e["title"]))[:80] for e in entries)[:300]
    lines = [
        "---",
        "layout: post",
        f"title: {json.dumps(f'🔐 {date} 보안 이슈 브리핑', ensure_ascii=False)}",
        f"date: {date} 09:00:00 +0900",
        f"tags: {json.dumps(sorted({e['category'] for e in entries}), ensure_ascii=False)}",
        f"description: {json.dumps(html.escape(plain_titles), ensure_ascii=False)}",
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
