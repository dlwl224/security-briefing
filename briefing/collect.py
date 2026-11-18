"""RSS/CISA KEV에서 후보 기사를 모으고, 선택된 기사의 본문을 가져온다."""
import calendar
import re
from datetime import datetime, timedelta, timezone

import feedparser
import requests
from bs4 import BeautifulSoup

from . import config

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
            return datetime.fromtimestamp(calendar.timegm(t), tz=timezone.utc)
    return None


def collect_rss(since: datetime, seen: set[str]) -> list[dict]:
    items = []
    for feed in config.RSS_FEEDS:
        try:
            resp = session.get(feed["url"], timeout=20)
            resp.raise_for_status()
            parsed = feedparser.parse(resp.content)
        except Exception as e:  # 한 소스가 죽어도 나머지는 계속
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
            items.append({
                "source": feed["name"],
                "region": feed["region"],
                "title": _clean(entry.get("title", ""), 200),
                "link": link,
                "snippet": _clean(entry.get("summary", "")),
                "published": pub.isoformat() if pub else "",
            })
            count += 1
            if count >= config.MAX_PER_SOURCE:
                break
        print(f"[info] {feed['name']}: {count}건")
    return items


def collect_kev(since: datetime, seen: set[str]) -> list[dict]:
    try:
        data = session.get(config.CISA_KEV_URL, timeout=30).json()
    except Exception as e:
        print(f"[warn] CISA KEV 수집 실패: {e}")
        return []
    since_date = (since - timedelta(days=1)).date().isoformat()
    items = []
    for v in data.get("vulnerabilities", []):
        if v.get("dateAdded", "") < since_date:
            continue
        cve = v["cveID"]
        link = f"https://nvd.nist.gov/vuln/detail/{cve}"
        if link in seen:
            continue
        items.append({
            "source": "CISA KEV",
            "region": "해외",
            "title": f"[KEV 등재] {cve} {v.get('vendorProject', '')} {v.get('product', '')} - {v.get('vulnerabilityName', '')}",
            "link": link,
            "snippet": v.get("shortDescription", "")[:300],
            "published": v.get("dateAdded", ""),
            "kev": v,
        })
    print(f"[info] CISA KEV: {len(items)}건")
    return items[: config.MAX_PER_SOURCE]


def collect_candidates(seen: set[str]) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(hours=config.LOOKBACK_HOURS)
    items = collect_rss(since, seen) + collect_kev(since, seen)
    # 제목이 같은 중복 제거
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
        resp = session.get(item["link"], timeout=20)
        resp.raise_for_status()
        resp.encoding = resp.apparent_encoding if resp.encoding in (None, "ISO-8859-1") else resp.encoding
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["script", "style", "nav", "header", "footer", "aside", "form"]):
            tag.decompose()
        root = (
            soup.find(id="article-view-content-div")  # 보안뉴스·데일리시큐 등 국내 언론 CMS
            or soup.find("article")
            or soup.find(id=re.compile("article|content|news", re.I))
            or soup.body
            or soup
        )
        paras = [p.get_text(" ", strip=True) for p in root.find_all(["p", "div"]) if p.find(["p", "div"]) is None]
        text = re.sub(r"\s+", " ", " ".join(t for t in paras if len(t) > 30))
        if len(text) < 200:  # <p> 없이 <br>로만 된 본문
            text = re.sub(r"\s+", " ", root.get_text(" ", strip=True))
        if len(text) > 200:
            return text[: config.ARTICLE_CHARS]
    except Exception as e:
        print(f"[warn] 본문 수집 실패 {item['link']}: {e}")
    return item["snippet"]
