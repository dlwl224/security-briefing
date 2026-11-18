"""명령줄 진입점 — 모든 실행은 `python -m briefing <명령>` 하나로 통일한다.

  python -m briefing daily              매일 브리핑 생성 (GitHub Actions 09:00 KST)
  python -m briefing daily --dry-run    AI 없이 수집·글 생성만 시험
  python -m briefing notify             오늘 브리핑을 디스코드로 알림
  python -m briefing notify --failed    실행 실패 알림
  python -m briefing feedback           새로 쓴 분석 노트에 AI 코칭 (BEFORE/AFTER 환경변수)
  python -m briefing feedback --dry-run 2026-11-18
"""
import argparse
import re
import sys

from . import feedback, notify, pipeline


def _date(value: str) -> str:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise argparse.ArgumentTypeError("날짜 형식은 YYYY-MM-DD")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="briefing", description="Daily Security Briefing")
    sub = parser.add_subparsers(dest="command", required=True)

    daily = sub.add_parser("daily", help="브리핑 생성")
    daily.add_argument("--dry-run", action="store_true", help="AI 없이 수집·글 생성만")

    noti = sub.add_parser("notify", help="디스코드 알림")
    noti.add_argument("--failed", action="store_true", help="실행 실패 알림")

    fb = sub.add_parser("feedback", help="분석 노트 AI 코칭")
    fb.add_argument("--dry-run", type=_date, metavar="YYYY-MM-DD", help="해당 날짜 노트를 AI 없이 출력만")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "daily":
        return pipeline.run(dry=args.dry_run)
    if args.command == "notify":
        return notify.run(failed=args.failed)
    return feedback.run(dry_date=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
