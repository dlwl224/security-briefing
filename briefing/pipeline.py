"""매일 보안 이슈 브리핑 생성: 수집 → 선정 → 본문 수집 → 요약 → 포스트 작성.

사용법:
  python -m briefing daily            # 실제 실행 (GEMINI_API_KEY 필요)
  python -m briefing daily --dry-run  # AI 없이 수집만 테스트하고 RSS 요약으로 임시 포스트 생성
"""

import json
from datetime import datetime

from . import collect, config, enrich, fileio, refresh, render

ROOT = config.ROOT
SEEN = config.SEEN_FILE
OUT = config.OUT_FILE


def run(dry: bool = False) -> int:
    """매일 브리핑 생성: (최근 글 지표 갱신) → 수집 → 선정 → 본문 수집 → 요약 → 공식 지표 보강 → 포스트 작성."""
    date = datetime.now(config.KST).strftime("%Y-%m-%d")
    seen = json.loads(SEEN.read_text(encoding="utf-8")) if SEEN.exists() else []

    if not dry:
        # 최근 2주 글의 CVSS·EPSS·KEV 를 공식 데이터로 다시 조회 (NVD 분석 완료, EPSS 일일 변동 반영)
        refresh.refresh_recent(date)

    candidates = collect.collect_candidates(set(seen))
    print(f"[info] 후보 {len(candidates)}건")
    if not candidates:
        print("[info] 새 기사가 없어 오늘은 건너뜀")
        OUT.unlink(missing_ok=True)
        return 0

    if dry:
        # 국내/해외 섞어서 앞에서부터 고름
        kr = [c for c in candidates if c["region"] == "국내"]
        gl = [c for c in candidates if c["region"] == "해외"]
        picked = (kr[:2] + gl[:3] + kr[2:] + gl[3:])[: config.TOP_N]
    else:
        from briefing import llm

        ids = llm.select_top(candidates, config.TOP_N)
        by_id = {c["id"]: c for c in candidates}
        picked = [by_id[i] for i in ids] or candidates[: config.TOP_N]

    for c in picked:
        c["text"] = collect.fetch_article_text(c)
        print(f"[info] 선정: ({c['source']}) {c['title']}  본문 {len(c['text'])}자")

    if dry:
        entries = [
            {
                **c,
                "category": "위협동향",
                "core": c["snippet"] or "(요약 없음)",
                "background": f"[dry-run] 본문 앞부분: {c['text'][:200]}",
                "impact": "[dry-run] AI 요약 자리",
            }
            for c in picked
        ]
        terms = [
            {"term": "드라이런", "english": "Dry run", "definition": "실제로 실행하기 전에 동작만 시험해 보는 것."}
        ]
        summary = "[dry-run] AI 요약 없이 만든 시험용 브리핑"
    else:
        result = llm.summarize(picked)
        entries = []
        for s in result.get("items", []):
            if 0 <= s["index"] < len(picked):
                src = picked[s["index"]]
                entries.append(
                    {**s, "region": src["region"], "source": src["source"], "link": src["link"], "_text": src["text"]}
                )
        terms = result.get("terms", [])
        summary = result.get("daily_summary", "")
        if not entries:
            raise RuntimeError("요약 결과가 비어 있음")

    if not dry:
        # 위험도·요약은 AI 판단, CVE/CVSS/EPSS/KEV 는 공식 데이터로 검증·보강
        enrich.enrich(entries, [e.get("_text", "") for e in entries])

    path = render.write_post(date, entries, terms, summary)
    added = render.update_glossary(date, terms)
    render.write_comment_template(date, entries)
    print(f"[info] 포스트 작성: {path.relative_to(ROOT)} / 새 용어 {added}개")

    seen = (seen + [e["link"] for e in entries])[-config.SEEN_KEEP :]
    SEEN.parent.mkdir(exist_ok=True)
    fileio.write_json(SEEN, seen, indent=0)

    fileio.write_json(
        OUT,
        {
            "date": date,
            "url": render.site_url() + render.post_path(date),
            "items": [
                {
                    **{k: e[k] for k in ("title", "region", "category", "core", "link")},
                    "cve": e.get("cve", ""),
                    "cvss": e.get("cvss", 0),
                    "kev": bool(e.get("kev")),
                }
                for e in entries
            ],
            "terms": [t["term"] for t in terms],
            "summary": summary,
            "comment_url": render.comment_edit_url(date),
        },
    )
    return 0
