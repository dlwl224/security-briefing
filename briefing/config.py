"""공통 설정: 경로, 수집 대상, 한도값. 숫자·경로를 코드 곳곳에 흩어 두지 않고 여기서만 바꾼다."""

from datetime import timedelta, timezone
from pathlib import Path

KST = timezone(timedelta(hours=9))

ROOT = Path(__file__).resolve().parent.parent
POSTS_DIR = ROOT / "_posts"
DATA_DIR = ROOT / "_data"
COMMENTS_DIR = DATA_DIR / "comments"
GLOSSARY_FILE = DATA_DIR / "glossary.json"
STATE_DIR = ROOT / "state"
SEEN_FILE = STATE_DIR / "seen.json"
OUT_FILE = ROOT / ".briefing_out.json"

RSS_FEEDS = [
    {"name": "보안뉴스", "region": "국내", "url": "https://cdn.boannews.com/rss/gn_rss_allArticle.xml"},
    {"name": "데일리시큐", "region": "국내", "url": "https://www.dailysecu.com/rss/allArticle.xml"},
    {"name": "KISA 보호나라", "region": "국내", "url": "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133"},
    {"name": "The Hacker News", "region": "해외", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "BleepingComputer", "region": "해외", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "SecurityWeek", "region": "해외", "url": "https://www.securityweek.com/feed/"},
    {"name": "The Record", "region": "해외", "url": "https://therecord.media/feed"},
]

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

LOOKBACK_HOURS = 36
MAX_PER_SOURCE = 15
TOP_N = 5
ARTICLE_CHARS = 4000
SEEN_KEEP = 1000

USER_AGENT = "Mozilla/5.0 (compatible; security-briefing-bot/1.0)"
