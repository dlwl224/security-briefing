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
        self.assertIsNone(re.search(r"<(script|img|b)\b", self.text))

    def test_no_injected_markdown_links(self):
        # 이스케이프되지 않은 '](' 는 우리가 넣은 용어 사전 링크 하나뿐이어야 함
        self.assertEqual(re.findall(r"(?<!\\)\]\(", self.body), ["]("])

    def test_no_liquid(self):
        self.assertNotIn("{{", self.body)
        self.assertNotIn("{%", self.body)

    def test_front_matter_not_injected(self):
        self.assertNotIn("layout: evil", self.front)
        self.assertEqual(len(self.front.strip().splitlines()), 5)

    def test_category_forced_to_allowed_value(self):
        self.assertNotIn("해킹", self.text)

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
