"""최근 발행된 글의 공식 지표(NVD CVSS·EPSS·KEV)를 매일 다시 조회해 갱신한다."""

import json
from datetime import datetime, timedelta

import requests

from . import enrich, render

REFRESH_DAYS = 14


def _front_matter(path) -> dict:
    fm = {}
    head = path.read_text(encoding="utf-8").split("---\n")
    if len(head) < 3:
        return fm
    for line in head[1].splitlines():
        k, _, v = line.partition(": ")
        fm[k] = v
    return fm


def refresh_recent(today: str) -> list[str]:
    """갱신한 글의 날짜 목록을 돌려준다. 실패해도 예외를 밖으로 던지지 않는다 (오늘 글 발행이 우선)."""
    updated = []
    cutoff = (datetime.fromisoformat(today) - timedelta(days=REFRESH_DAYS)).date().isoformat()
    for path in sorted(render.POSTS.glob("*-security-briefing.md")):
        date = path.name[:10]
        if not render.DATE_RE.match(date) or date >= today or date < cutoff:
            continue
        try:
            fm = _front_matter(path)
            if "items" not in fm:
                continue
            items = json.loads(fm["items"])
            if not any(it.get("cve") for it in items):
                continue
            texts = [" ".join(str(it.get(k, "")) for k in ("title", "core", "background", "impact")) for it in items]
            if enrich.enrich(items, texts, refresh=True):
                render.write_post(date, items, json.loads(fm.get("terms", "[]")), json.loads(fm.get("summary", '""')))
                updated.append(date)
        except (ValueError, KeyError, TypeError, OSError, requests.RequestException) as e:
            print(f"[warn] {date} 지표 갱신 실패: {type(e).__name__}: {e}")
    if updated:
        print(f"[info] 지표 갱신된 글: {', '.join(updated)}")
    return updated
