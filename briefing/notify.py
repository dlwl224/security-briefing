"""디스코드 웹훅으로 오늘 브리핑 알림을 보낸다.

python -m briefing notify            # 오늘 브리핑 알림
python -m briefing notify --failed   # 실행 실패 알림
"""

import json
import os
import re
import time

import requests

from . import config

OUT = config.OUT_FILE
WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL", "")
EMOJI = {"취약점": "🛠️", "사고": "🚨", "정책": "📜", "위협동향": "📡"}


def discord_safe(s: str) -> str:
    """AI/RSS에서 온 글자를 디스코드 마크다운으로 해석되지 않게 한다 (가짜 링크·@everyone 방지)."""
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    s = re.sub(r"([\\*_~`|>\[\]()<#:])", r"\\\1", s)
    return s.replace("@", "@​")


def send(payload: dict) -> None:
    payload["allowed_mentions"] = {"parse": []}  # 어떤 멘션(@everyone 등)도 알림으로 동작하지 않게
    if not WEBHOOK:
        print("[warn] DISCORD_WEBHOOK_URL 없음 — 보낼 내용만 출력")
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    if not WEBHOOK.startswith(("https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/")):
        raise SystemExit("[error] DISCORD_WEBHOOK_URL 형식이 디스코드 웹후크가 아님")
    # 웹후크 URL 자체가 비밀값이므로, 오류 메시지·로그에 URL 이 찍히지 않게 상태 코드만 남긴다
    try:
        r = requests.post(WEBHOOK, json=payload, timeout=30, allow_redirects=False)
    except requests.RequestException as e:
        raise SystemExit(f"[error] 디스코드 전송 실패: {type(e).__name__}") from None
    if not 200 <= r.status_code < 300:
        raise SystemExit(f"[error] 디스코드 전송 실패: HTTP {r.status_code}")
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


def run(failed: bool = False) -> int:
    """오늘 브리핑 알림 (failed=True 면 실행 실패 알림)."""
    if failed:
        run = f"{os.getenv('GITHUB_SERVER_URL')}/{os.getenv('GITHUB_REPOSITORY')}/actions/runs/{os.getenv('GITHUB_RUN_ID')}"
        send(
            {
                "embeds": [
                    {
                        "title": "⚠️ 오늘 보안 브리핑 생성 실패",
                        "description": f"Actions 로그를 확인하세요.\n{run}",
                        "color": 0x9E9E9E,
                    }
                ]
            }
        )
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
        badges = []
        if it.get("kev") is True:
            badges.append("🔴 실제 악용(KEV)")
        try:
            score = float(it.get("cvss") or 0)
            if 0 < score <= 10:
                badges.append(f"CVSS {score:.1f}")
        except (TypeError, ValueError):
            pass
        badge = f"`{' · '.join(badges)}`\n" if badges else ""
        lines.append(
            f"**{i}. {EMOJI.get(it['category'], '🔎')} [{discord_safe(it['region'])}] {discord_safe(it['title'])}**\n"
            f"{badge}{discord_safe(core)}"
        )
    desc = "\n\n".join(lines)[:3900]

    embed = {
        "title": f"🔐 {data['date']} 보안 이슈 브리핑",
        "description": desc + f"\n\n👉 **[전체 글 읽기]({data['url']})**" if data["url"].startswith("http") else desc,
        "color": 0xE53935,
    }
    if data.get("url", "").startswith("http"):
        embed["url"] = data["url"]
    comment_url = str(data.get("comment_url") or "")
    if comment_url.startswith("https://github.com/") and comment_url.endswith(".yml"):
        embed["description"] += f"\n📝 **[분석 노트 쓰기]({comment_url})** — 1건만 골라 2~3문장이면 충분해요"
    if data.get("terms"):
        embed["footer"] = {"text": "📚 오늘의 용어: " + ", ".join(data["terms"])}
    send({"username": "보안 브리핑", "embeds": [embed]})
    return 0
