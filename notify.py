"""디스코드 웹훅으로 오늘 브리핑 알림을 보낸다.

  python notify.py            # 오늘 브리핑 알림
  python notify.py --failed   # 실행 실패 알림
"""
import json
import os
import re
import sys
import time
from pathlib import Path

import requests

OUT = Path(__file__).resolve().parent / ".briefing_out.json"
WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL", "")
EMOJI = {"취약점": "🛠️", "사고": "🚨", "정책": "📜", "위협동향": "📡"}


def discord_safe(s: str) -> str:
    """AI/RSS에서 온 글자를 디스코드 마크다운으로 해석되지 않게 한다 (가짜 링크·@everyone 방지)."""
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    s = re.sub(r"([\\*_~`|>\[\]()<#:])", r"\\\1", s)
    return s.replace("@", "@​")


def send(payload: dict) -> None:
    payload["allowed_mentions"] = {"parse": []}   # 어떤 멘션(@everyone 등)도 알림으로 동작하지 않게
    if not WEBHOOK:
        print("[warn] DISCORD_WEBHOOK_URL 없음 — 보낼 내용만 출력")
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    r = requests.post(WEBHOOK, json=payload, timeout=30)
    r.raise_for_status()
    print("[info] 디스코드 알림 전송 완료")


def wait_until_live(url: str, max_wait: int = 420) -> None:
    """GitHub Pages 빌드가 끝나 글이 열릴 때까지 최대 7분 기다린다."""
    end = time.time() + max_wait
    while time.time() < end:
        try:
            if requests.get(url, timeout=15).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(20)
    print("[warn] 페이지가 아직 안 열림 — 그래도 알림은 보냄")


def main() -> int:
    if "--failed" in sys.argv:
        run = f"{os.getenv('GITHUB_SERVER_URL')}/{os.getenv('GITHUB_REPOSITORY')}/actions/runs/{os.getenv('GITHUB_RUN_ID')}"
        send({"embeds": [{
            "title": "⚠️ 오늘 보안 브리핑 생성 실패",
            "description": f"Actions 로그를 확인하세요.\n{run}",
            "color": 0x9E9E9E,
        }]})
        return 0

    if not OUT.exists():
        print("[info] 오늘 생성된 브리핑 없음 — 알림 생략")
        return 0
    data = json.loads(OUT.read_text(encoding="utf-8"))
    if data["url"].startswith("http"):
        wait_until_live(data["url"])

    lines = []
    for i, it in enumerate(data["items"], 1):
        core = it["core"] if len(it["core"]) <= 160 else it["core"][:157] + "…"
        lines.append(
            f"**{i}. {EMOJI.get(it['category'], '🔎')} [{discord_safe(it['region'])}] {discord_safe(it['title'])}**\n"
            f"{discord_safe(core)}"
        )
    desc = "\n\n".join(lines)[:3900]

    embed = {
        "title": f"🔐 {data['date']} 보안 이슈 브리핑",
        "description": desc + f"\n\n👉 **[전체 글 읽기]({data['url']})**" if data["url"].startswith("http") else desc,
        "color": 0xE53935,
    }
    if data.get("url", "").startswith("http"):
        embed["url"] = data["url"]
    if data.get("terms"):
        embed["footer"] = {"text": "📚 오늘의 용어: " + ", ".join(data["terms"])}
    send({"username": "보안 브리핑", "embeds": [embed]})
    return 0


if __name__ == "__main__":
    sys.exit(main())
