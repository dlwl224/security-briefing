"""RSS/CISA KEV에서 후보 기사를 모으고, 선택된 기사의 본문을 가져온다."""

import calendar
import json
import re
from datetime import UTC, datetime, timedelta

import feedparser
import requests
from bs4 import BeautifulSoup, ParserRejectedMarkup

from . import config
from .netsafe import UnsafeURLError, safe_get

FETCH_ERRORS = (requests.RequestException, UnsafeURLError, ValueError)

MAX_PAGE_BYTES = 3_000_000
MAX_FEED_BYTES = 5_000_000
MAX_KEV_BYTES = 15_000_000

session = requests.Session()
session.headers["User-Agent"] = config.USER_AGENT


def _clean(html: str, limit: int = 300) -> str:
    text = BeautifulSoup(html or "", "html.parser").get_text(" ", strip=True)
    text = re.sub(r"\s+", " ", text)
    return text[:limit]


def _published(entry) -> datetime | None:
    for key in ("published_parsed", "updated_parsed"):
        t = entry.get(key)
        if t:
            return datetime.fromtimestamp(calendar.timegm(t), tz=UTC)
    return None


def collect_rss(since: datetime, seen: set[str]) -> list[dict]:
    items = []
    for feed in config.RSS_FEEDS:
        try:
            body, _ = safe_get(session, feed["url"], max_bytes=MAX_FEED_BYTES)
            parsed = feedparser.parse(body)
        except FETCH_ERRORS as e:
            print(f"[warn] {feed['name']} 수집 실패: {e}")
            continue
        count = 0
        for entry in parsed.entries:
            link = entry.get("link", "").strip()
            pub = _published(entry)
            if not link or link in seen:
                continue
            if pub and pub < since:
                continue
            items.append(
                {
                    "source": feed["name"],
                    "region": feed["region"],
                    "title": _clean(entry.get("title", ""), 200),
                    "link": link,
                    "snippet": _clean(entry.get("summary", "")),
                    "published": pub.isoformat() if pub else "",
                }
            )
            count += 1
            if count >= config.MAX_PER_SOURCE:
                break
        print(f"[info] {feed['name']}: {count}건")
    return items


def collect_kev(since: datetime, seen: set[str]) -> list[dict]:
    try:
        body, _ = safe_get(session, config.CISA_KEV_URL, max_bytes=MAX_KEV_BYTES, timeout=30)
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("KEV 형식 오류")
    except FETCH_ERRORS as e:
        print(f"[warn] CISA KEV 수집 실패: {e}")
        return []
    since_date = (since - timedelta(days=1)).date().isoformat()
    items = []
    for v in data.get("vulnerabilities", []):
        if not isinstance(v, dict) or str(v.get("dateAdded", "")) < since_date:
            continue
        cve = str(v.get("cveID", "")).upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
            continue
        link = f"https://nvd.nist.gov/vuln/detail/{cve}"
        if link in seen:
            continue
        items.append(
            {
                "source": "CISA KEV",
                "region": "해외",
                "title": f"[KEV 등재] {cve} {v.get('vendorProject', '')} {v.get('product', '')} - {v.get('vulnerabilityName', '')}",
                "link": link,
                "snippet": v.get("shortDescription", "")[:300],
                "published": v.get("dateAdded", ""),
                "kev": v,
            }
        )
    print(f"[info] CISA KEV: {len(items)}건")
    return items[: config.MAX_PER_SOURCE]


def collect_candidates(seen: set[str]) -> list[dict]:
    since = datetime.now(UTC) - timedelta(hours=config.LOOKBACK_HOURS)
    items = collect_rss(since, seen) + collect_kev(since, seen)
    uniq, titles = [], set()
    for it in items:
        key = re.sub(r"\W+", "", it["title"].lower())[:60]
        if key in titles:
            continue
        titles.add(key)
        uniq.append(it)
    for i, it in enumerate(uniq):
        it["id"] = i
    return uniq


def fetch_article_text(item: dict) -> str:
    """기사 본문을 가져온다. 실패하면 RSS 요약으로 대체."""
    if "kev" in item:
        v = item["kev"]
        return (
            f"CVE: {v['cveID']}\n제조사/제품: {v.get('vendorProject')} {v.get('product')}\n"
            f"취약점명: {v.get('vulnerabilityName')}\n설명: {v.get('shortDescription')}\n"
            f"KEV 등재일: {v.get('dateAdded')}\n조치 기한(미 연방기관): {v.get('dueDate')}\n"
            f"권고 조치: {v.get('requiredAction')}\n"
            f"랜섬웨어 악용 여부: {v.get('knownRansomwareCampaignUse')}\nCWE: {', '.join(v.get('cwes', []))}"
        )
    try:
        raw, resp = safe_get(session, item["link"], max_bytes=MAX_PAGE_BYTES)
        if "html" not in resp.headers.get("Content-Type", "html"):
            return item["snippet"]
        enc = resp.encoding if resp.encoding not in (None, "ISO-8859-1") else None
        soup = BeautifulSoup(raw, "html.parser", from_encoding=enc)
        for tag in soup(["script", "style", "nav", "header", "footer", "aside", "form"]):
            tag.decompose()
        root = (
            soup.find(id="article-view-content-div")
            or soup.find("article")
            or soup.find(id=re.compile("article|content|news", re.I))
            or soup.body
            or soup
        )
        paras = [p.get_text(" ", strip=True) for p in root.find_all(["p", "div"]) if p.find(["p", "div"]) is None]
        text = re.sub(r"\s+", " ", " ".join(t for t in paras if len(t) > 30))
        if len(text) < 200:
            text = re.sub(r"\s+", " ", root.get_text(" ", strip=True))
        if len(text) > 200:
            return text[: config.ARTICLE_CHARS]
    except (*FETCH_ERRORS, ParserRejectedMarkup, AttributeError, TypeError) as e:
        print(f"[warn] 본문 수집 실패 {item['link']}: {e}")
    return item["snippet"]
