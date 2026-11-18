"""공통 설정: 경로, 수집 대상, 한도값. 숫자·경로를 코드 곳곳에 흩어 두지 않고 여기서만 바꾼다."""

from datetime import timedelta, timezone
from pathlib import Path

KST = timezone(timedelta(hours=9))

# ---- 경로 ---------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
POSTS_DIR = ROOT / "_posts"  # 발행된 브리핑 (Jekyll)
DATA_DIR = ROOT / "_data"  # 사이트가 읽는 데이터
COMMENTS_DIR = DATA_DIR / "comments"  # 사람이 쓰는 분석 노트
GLOSSARY_FILE = DATA_DIR / "glossary.json"
STATE_DIR = ROOT / "data"  # 사이트에 안 나가는 내부 상태
SEEN_FILE = STATE_DIR / "seen.json"
OUT_FILE = ROOT / ".briefing_out.json"  # daily → notify 로 넘기는 결과 (커밋 안 함)

# region: "국내" / "해외"
RSS_FEEDS = [
    {"name": "보안뉴스", "region": "국내", "url": "https://cdn.boannews.com/rss/gn_rss_allArticle.xml"},
    {"name": "데일리시큐", "region": "국내", "url": "https://www.dailysecu.com/rss/allArticle.xml"},
    {"name": "KISA 보호나라", "region": "국내", "url": "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133"},
    {"name": "The Hacker News", "region": "해외", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "BleepingComputer", "region": "해외", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "SecurityWeek", "region": "해외", "url": "https://www.securityweek.com/feed/"},
    {"name": "The Record", "region": "해외", "url": "https://therecord.media/feed"},
]

# 미국 CISA '실제 악용 중인 취약점(KEV)' 목록 — CVE 이슈 후보로 사용
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

LOOKBACK_HOURS = 36  # 이 시간 안에 나온 기사만 후보로 (Actions 지연 대비 여유)
MAX_PER_SOURCE = 15  # 소스별 최대 후보 수
TOP_N = 5  # 하루에 정리할 이슈 수
ARTICLE_CHARS = 4000  # 요약에 넘길 본문 최대 길이
SEEN_KEEP = 1000  # 중복 방지용으로 기억할 링크 수

USER_AGENT = "Mozilla/5.0 (compatible; security-briefing-bot/1.0)"
