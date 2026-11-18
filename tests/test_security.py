"""악성 입력(XSS, 링크 삽입, 템플릿/YAML 인젝션)이 블로그·디스코드에 그대로 나가지 않는지 확인.

실행: python -m unittest discover tests
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import notify  # noqa: E402
from briefing import render  # noqa: E402

EVIL = (
    '<script>alert(1)</script> [클릭](javascript:alert(1)) ![x](https://evil/x.png) '
    '{{ site.github }} {% include x %} "\n---\nlayout: evil'
)
ENTRY = {
    "title": EVIL, "category": "해킹<b>", "region": "국내", "core": EVIL,
    "background": "정상 문장 & 3 < 5", "impact": "x",
    "source": "src](javascript:alert(1))", "link": "javascript:alert(1)",
}
TERMS = [{"term": "<img src=x onerror=alert(1)>", "english": "XSS", "definition": EVIL}]


class RenderSecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = render.write_post("2099-01-01", [ENTRY], TERMS)
        cls.text = path.read_text(encoding="utf-8")
        path.unlink()
        _, cls.front, cls.body = cls.text.split("---\n", 2)

    def test_no_html_tags(self):
        # 본문(마크다운)에는 HTML 태그가 그대로 남으면 안 됨.
        # front matter 의 items 는 평문 데이터이고, 레이아웃이 | escape 로 출력함 (TemplateEscapeTest 가 검사)
        self.assertIsNone(re.search(r"<(script|img|b)\b", self.body))

    def test_front_matter_items_are_valid_json_data(self):
        import json
        items_line = next(l for l in self.front.splitlines() if l.startswith("items: "))
        items = json.loads(items_line[len("items: "):])
        self.assertEqual(items[0]["link"], "")                 # javascript: 링크 제거
        self.assertNotIn("\n", items[0]["title"])              # 한 줄 평문

    def test_no_injected_markdown_links(self):
        # 이스케이프되지 않은 '](' 는 우리가 넣은 용어 사전 링크 하나뿐이어야 함
        self.assertEqual(re.findall(r"(?<!\\)\]\(", self.body), ["]("])

    def test_no_liquid(self):
        self.assertNotIn("{{", self.body)
        self.assertNotIn("{%", self.body)

    def test_front_matter_not_injected(self):
        lines = self.front.strip().splitlines()
        self.assertFalse(any(l.startswith("layout: evil") for l in lines))
        self.assertEqual([l.split(":")[0] for l in lines],
                         ["layout", "title", "date", "issue_no", "threat_level", "summary",
                          "tags", "description", "items", "terms"])

    def test_category_forced_to_allowed_value(self):
        self.assertNotIn("해킹", self.text)

    def test_structured_fields_validated(self):
        e = render.normalize({**ENTRY, "severity": "99", "cvss": "abc", "cve": "<b>CVE"})
        self.assertEqual((e["severity"], e["cvss"], e["cve"]), (5, 0.0, ""))
        item = render.structured_item(e)
        self.assertEqual(item["link"], "")          # javascript: 링크 제거
        self.assertNotIn("\n", item["core"])       # 제어문자/개행 제거

    def test_unsafe_url_rejected(self):
        self.assertEqual(render.safe_url("javascript:alert(1)"), "")
        self.assertEqual(render.safe_url("data:text/html,x"), "")
        self.assertEqual(render.safe_url("https://a.com/x (1)"), "https://a.com/x%20%281%29")

    def test_bad_date_rejected(self):
        with self.assertRaises(ValueError):
            render.write_post("../../x", [ENTRY], [])


class DiscordSecurityTest(unittest.TestCase):
    def test_mentions_and_links_neutralized(self):
        s = notify.discord_safe("@everyone [피싱](https://evil.com) **x**")
        self.assertNotIn("@everyone", s)
        self.assertNotIn("](", s.replace("\\](", ""))


if __name__ == "__main__":
    unittest.main()


class TemplateEscapeTest(unittest.TestCase):
    """레이아웃이 AI/RSS 에서 온 문자열 필드를 출력할 때 반드시 | escape 를 쓰는지 정적 검사."""

    ROOT = Path(__file__).resolve().parent.parent
    # 숫자·날짜·내부 URL 등 생성 단계에서 검증되는 필드는 예외
    SAFE_FIELDS = {"severity", "cvss", "issue_no", "threat_level", "date", "url", "size", "previous", "next", "index"}

    def test_untrusted_fields_are_escaped(self):
        files = list((self.ROOT / "_layouts").glob("*.html")) + [self.ROOT / "glossary.md"]
        bad = []
        for f in files:
            for m in re.finditer(r"\{\{-?\s*((?:it|t|p|latest|page)\.[\w.]+)([^}]*)\}\}", f.read_text(encoding="utf-8")):
                var, filters = m.group(1), m.group(2)
                field = var.split(".")[1]
                if field in self.SAFE_FIELDS or var.endswith(".size"):
                    continue
                if "escape" not in filters and "jsonify" not in filters:
                    bad.append(f"{f.name}: {m.group(0)}")
        self.assertEqual(bad, [], "escape 없이 출력되는 값: " + ", ".join(bad))
