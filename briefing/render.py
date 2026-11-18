"""요약 결과를 Jekyll 포스트(마크다운)와 용어 사전 데이터로 만든다."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POSTS = ROOT / "_posts"
GLOSSARY = ROOT / "_data" / "glossary.json"

CATEGORY_EMOJI = {"취약점": "🛠️", "사고": "🚨", "정책": "📜", "위협동향": "📡"}


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


def _esc(s: str) -> str:
    return s.replace('"', '\\"')


def write_post(date: str, entries: list[dict], terms: list[dict]) -> Path:
    regions = [e["region"] for e in entries]
    lines = [
        "---",
        "layout: post",
        f'title: "🔐 {date} 보안 이슈 브리핑"',
        f"date: {date} 09:00:00 +0900",
        f'tags: [{", ".join(sorted({e["category"] for e in entries}))}]',
        f'description: "{_esc(" / ".join(e["title"] for e in entries))[:300]}"',
        "---",
        "",
        f"> 오늘의 주요 보안 이슈 {len(entries)}건 "
        f"(국내 {regions.count('국내')} · 해외 {regions.count('해외')})",
        "",
        "## 📌 한눈에 보기",
        "",
    ]
    for i, e in enumerate(entries, 1):
        lines.append(f"{i}. **[{e['region']}·{e['category']}]** {e['title']}")
    lines.append("")

    for i, e in enumerate(entries, 1):
        emoji = CATEGORY_EMOJI.get(e["category"], "🔎")
        lines += [
            "---",
            "",
            f"## {i}. {emoji} {e['title']}",
            "",
            f"`{e['region']}` `{e['category']}` · 출처: [{e['source']}]({e['link']})",
            "",
            f"**🎯 핵심**  ",
            e["core"],
            "",
            f"**📖 배경**  ",
            e["background"],
            "",
            f"**💥 영향**  ",
            e["impact"],
            "",
        ]

    if terms:
        lines += ["---", "", "## 📚 오늘의 보안 용어", ""]
        for t in terms:
            lines.append(f"- **{t['term']}** ({t['english']}): {t['definition']}")
        lines += ["", "👉 지금까지 나온 용어는 [보안 용어 사전](../../glossary/)에서 볼 수 있어요.", ""]

    lines += [
        "---",
        "",
        "<small>이 글은 공개된 보안 뉴스를 AI(Gemini)로 요약해 자동 작성했습니다. "
        "정확한 내용은 각 출처 원문을 확인하세요.</small>",
        "",
    ]
    # AI가 쓴 글에 Liquid 문법({{ }}, {% %})이 섞이면 Jekyll 빌드가 깨지므로 무력화
    text = "\n".join(lines).replace("{{", "{ {").replace("{%", "{ %")
    POSTS.mkdir(exist_ok=True)
    path = POSTS / f"{date}-security-briefing.md"
    path.write_text(text, encoding="utf-8")
    return path


def update_glossary(date: str, terms: list[dict]) -> int:
    data = json.loads(GLOSSARY.read_text(encoding="utf-8")) if GLOSSARY.exists() else []
    known = {d["term"].replace(" ", "").lower() for d in data} | {d["english"].replace(" ", "").lower() for d in data}
    added = 0
    for t in terms:
        keys = {t["term"].replace(" ", "").lower(), t["english"].replace(" ", "").lower()}
        if keys & known:
            continue
        data.append({**t, "first_seen": date, "post": post_path(date)})
        known |= keys
        added += 1
    data.sort(key=lambda d: d["term"])
    GLOSSARY.parent.mkdir(exist_ok=True)
    GLOSSARY.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return added
