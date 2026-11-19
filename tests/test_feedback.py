"""분석 노트 피드백 로직 테스트 — 네트워크·AI 없이 실행."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from briefing import feedback


class FeedbackTest(unittest.TestCase):
    def test_only_new_or_changed_nonempty_notes(self):
        old = {"summary": "", "issue1": "예전 글", "issue2": "그대로"}
        new = {"summary": "", "issue1": "고친 글", "issue2": "그대로", "issue3": "  새 글  ", "issue4": ""}
        self.assertEqual(feedback.changed_notes(old, new), {"issue1": "고친 글", "issue3": "새 글"})

    def test_unexpected_keys_ignored(self):
        new = {"issue1": "ok", "__class__": "x", "issue99": "x", "../etc": "x", 3: "x"}
        self.assertEqual(feedback.changed_notes({}, new), {"issue1": "ok"})

    def test_yaml_is_loaded_safely(self):
        self.assertEqual(feedback.load_yaml("!!python/object/apply:os.system ['echo hi']"), {})
        self.assertEqual(feedback.load_yaml("- just a list"), {})
        self.assertEqual(feedback.load_yaml('issue1: "a"'), {"issue1": "a"})

    def test_invalid_commit_rejected(self):
        with self.assertRaises(SystemExit):
            feedback.collect("x", "HEAD; rm -rf /")

    def test_embed_neutralizes_mentions_and_links(self):
        note = {"date": "2026-11-18", "key": "issue1", "note": "@everyone [피싱](https://evil)"}
        fb = {"steps": [True, "yes", False], "good": "@here 좋음", "missing": "", "fact_check": "", "question": "q"}
        e = feedback.to_embed(note, {"title": "제목"}, fb)
        self.assertNotIn("@everyone", e["description"])
        self.assertNotIn("@here", e["description"])
        self.assertNotIn("](https", e["description"].replace("\\](", ""))
        self.assertIn("①자산✅", e["description"])
        self.assertIn("②원인⬜", e["description"])


if __name__ == "__main__":
    unittest.main()


class DailySkipTest(unittest.TestCase):
    def test_skips_when_today_post_exists(self):
        import tempfile
        from unittest import mock

        from briefing import pipeline, render

        with tempfile.TemporaryDirectory() as d, mock.patch.object(render, "POSTS", Path(d)):
            today = pipeline.datetime.now(pipeline.config.KST).strftime("%Y-%m-%d")
            (Path(d) / f"{today}-security-briefing.md").write_text("x", encoding="utf-8")
            with (
                mock.patch.object(pipeline.collect, "collect_candidates", side_effect=AssertionError("수집하면 안 됨")),
                mock.patch.object(pipeline.refresh, "refresh_recent", side_effect=AssertionError("갱신하면 안 됨")),
            ):
                self.assertEqual(pipeline.run(), 0)

    def test_force_flag_is_parsed(self):
        from briefing.__main__ import build_parser

        self.assertTrue(build_parser().parse_args(["daily", "--force"]).force)
        self.assertFalse(build_parser().parse_args(["daily"]).force)
