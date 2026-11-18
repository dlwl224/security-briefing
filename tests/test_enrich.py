"""공식 지표 보강(NVD/EPSS/KEV) 로직 테스트 — 네트워크 없이 응답을 흉내 낸다.

실행: python -m unittest discover tests
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from briefing import enrich, render


def nvd(score, sev="CRITICAL", typ="Primary", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "vulnStatus": "Analyzed",
                    "metrics": {
                        "cvssMetricV31": [
                            {"type": typ, "cvssData": {"baseScore": score, "baseSeverity": sev, "vectorString": vector}}
                        ]
                    },
                }
            }
        ]
    }


class ParseTest(unittest.TestCase):
    def test_parse_nvd_picks_primary_v31(self):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV40": [
                                {"type": "Secondary", "cvssData": {"baseScore": 9.4, "baseSeverity": "CRITICAL"}}
                            ],
                            "cvssMetricV31": [
                                {"type": "Secondary", "cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH"}},
                                {"type": "Primary", "cvssData": {"baseScore": 9.9, "baseSeverity": "CRITICAL"}},
                            ],
                        }
                    }
                }
            ]
        }
        r = enrich.parse_nvd(data)
        self.assertEqual((r["cvss"], r["cvss_version"], r["cvss_source"]), (9.9, "3.1", "NVD"))

    def test_parse_nvd_rejects_malicious_values(self):
        r = enrich.parse_nvd(nvd(999, sev="<script>", vector="<img src=x onerror=alert(1)>"))
        self.assertNotIn("cvss", r)  # 범위 밖 점수는 버림
        r = enrich.parse_nvd(nvd(7.5, sev="<script>", vector="javascript:alert(1)<x>"))
        self.assertEqual(r["cvss_severity"], "HIGH")  # 등급은 점수로 다시 계산
        self.assertEqual(r["cvss_vector"], "")  # 형식이 다른 벡터는 버림

    def test_parse_nvd_handles_missing_cvssdata(self):
        data = {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [{"type": "Primary"}]}}}]}
        self.assertEqual(enrich.parse_nvd(data), {"status": ""})
        self.assertIsNone(enrich.parse_nvd({"vulnerabilities": []}))
        self.assertIsNone(enrich.parse_nvd("not a dict"))

    def test_parse_epss(self):
        r = enrich.parse_epss({"data": [{"epss": "0.00734", "percentile": "0.55119", "date": "2026-11-18"}]})
        self.assertEqual((r["epss"], r["epss_percentile"], r["epss_date"]), (0.73, 55.1, "2026-11-18"))
        self.assertIsNone(enrich.parse_epss({"data": [{"epss": "5"}]}))  # 확률은 0~1
        bad = enrich.parse_epss({"data": [{"epss": "0.1", "date": "<b>"}]})
        self.assertEqual(bad["epss_date"], "")


class EnrichFlowTest(unittest.TestCase):
    def run_enrich(self, entry, text, nvd_resp):
        def fake_get(url, params, **kwargs):
            if "nvd" in url:
                return nvd_resp
            if "first.org" in url:
                return {"data": [{"epss": "0.5", "percentile": "0.99", "date": "2026-11-18"}]}
            return {
                "vulnerabilities": [
                    {"cveID": "CVE-2026-0001", "dateAdded": "2026-11-17", "knownRansomwareCampaignUse": "Known"}
                ]
            }

        with mock.patch.object(enrich, "_get_json", side_effect=fake_get), mock.patch.object(enrich.time, "sleep"):
            enrich.enrich([entry], [text])
        return entry

    def test_verified_cve_gets_official_metrics(self):
        e = self.run_enrich({"cve": "cve-2026-0001", "cvss": 3.0}, "", nvd(9.8))
        self.assertEqual((e["cve"], e["cve_status"], e["cvss"], e["cvss_source"]), ("CVE-2026-0001", "nvd", 9.8, "NVD"))
        self.assertTrue(e["kev"] and e["kev_ransomware"])
        self.assertEqual(e["epss"], 50.0)

    def test_hallucinated_cve_is_dropped(self):
        e = self.run_enrich({"cve": "CVE-2026-9999", "cvss": 9.0}, "기사에는 다른 내용만 있음", {"vulnerabilities": []})
        self.assertEqual((e["cve"], e["cvss"], e["kev"]), ("", 0, False))

    def test_new_cve_in_article_kept_as_pending(self):
        e = self.run_enrich({"cve": "", "cvss": 8.8}, "취약점(CVE-2026-7777)이 공개됐다", {"vulnerabilities": []})
        self.assertEqual((e["cve"], e["cve_status"], e["cvss_source"]), ("CVE-2026-7777", "pending", "기사"))

    def test_render_metrics_revalidates(self):
        e = render.normalize(
            {
                "title": "t",
                "core": "",
                "background": "",
                "impact": "",
                "cve": "CVE-2026-1",
                "cve_status": "<x>",
                "epss": 500,
                "kev": "yes",
                "cvss_source": "evil",
            }
        )
        m = render.metrics(e)
        self.assertEqual(e["cve"], "")  # 형식 불일치 CVE
        self.assertEqual((m["cve_status"], m["epss"], m["kev"], m["cvss_source"]), ("", 0.0, False, ""))


if __name__ == "__main__":
    unittest.main()


class ConsultingTest(unittest.TestCase):
    def test_decode_vector(self):
        from briefing import consulting

        f = consulting.decode_vector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
        texts = [x["v"] for x in f]
        self.assertIn("원격(인터넷) 공격 가능", texts)
        self.assertIn("공격 조건 까다로움", texts)
        self.assertIn("로그인 불필요", texts)
        self.assertEqual(consulting.decode_vector("<script>"), [])
        self.assertEqual(consulting.decode_vector("AV:N/AC:L/Au:N/C:C/I:C/A:C"), [])  # v2 는 해석 안 함

    def test_priority_rules(self):
        from briefing import consulting

        P = lambda **k: consulting.priority({"cve": "CVE-2026-1", **k})["priority"]
        self.assertEqual(P(kev=True, cvss=4.0), "P1")  # 실제 악용이면 점수와 무관하게 즉시
        self.assertEqual(P(epss=12, cvss=5.0), "P1")
        self.assertEqual(P(cvss=8.1, epss=0.7), "P2")
        self.assertEqual(P(cvss=5.0, epss=0.2), "P3")
        self.assertEqual(consulting.priority({"cve": ""})["priority"], "")

    def test_mapping_whitelist_blocks_hallucination(self):
        from briefing import consulting

        self.assertEqual(consulting.clean_codes(["2.10.8", "9.9.9", "<b>", "2.10.8"], consulting.ISMS_P), ["2.10.8"])
        self.assertEqual(
            consulting.clean_codes(["t1190", "T9999", "T1195.002"], consulting.ATTACK), ["T1190", "T1195.002"]
        )
        self.assertEqual(consulting.clean_cwes(["CWE-502", "NVD-CWE-Other", "CWE-<x>"]), ["CWE-502"])
        self.assertEqual(consulting.clean_actions(["a\nb", "", 3]), ["a b", "3"])

    def test_comment_template_does_not_overwrite(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d, mock.patch.object(render, "COMMENTS", Path(d)):
            p = render.write_comment_template("2099-01-01", [{"title": "제목\n# 주입"}])
            self.assertIn('issue1: ""', p.read_text(encoding="utf-8"))
            self.assertNotIn("\n# 주입", p.read_text(encoding="utf-8"))  # 제목 개행으로 YAML 조작 불가
            p.write_text('issue1: "사람이 쓴 코멘트"\n', encoding="utf-8")
            render.write_comment_template("2099-01-01", [{"title": "x"}])
            self.assertIn("사람이 쓴 코멘트", p.read_text(encoding="utf-8"))
            with self.assertRaises(ValueError):
                render.write_comment_template("../../x", [])


class SeverityRuleTest(unittest.TestCase):
    """운영자와 함께 정한 위험도 규칙."""

    def S(self, **k):
        from briefing import consulting

        return consulting.severity({"category": "사고", **k})

    def test_formula(self):
        r = self.S(exploitation="active", scale="medium", critical_sector=True, domestic=True)
        self.assertEqual(r["severity"], 5)  # 2+1+1+1 = 5
        self.assertEqual(self.S(exploitation="poc", scale="unknown")["severity"], 1)
        self.assertEqual(self.S(exploitation="none", scale="small")["severity"], 1)  # 최소 1
        self.assertEqual(
            self.S(exploitation="active", scale="large", critical_sector=True, domestic=True)["severity"], 5
        )  # 최대 5
        self.assertEqual(self.S(exploitation="active", scale="large")["severity"], 4)
        self.assertEqual(r["severity_method"], "rule")

    def test_kev_overrides_ai_judgment(self):
        r = self.S(exploitation="none", scale="medium", kev=True)
        self.assertEqual(r["severity"], 3)  # KEV → 실제 악용 +2
        self.assertIn("CISA KEV", r["severity_basis"][0])

    def test_reference_categories(self):
        from briefing import consulting

        for cat in ("정책", "위협동향"):
            self.assertIsNone(
                consulting.severity({"category": cat, "exploitation": "active", "scale": "large"})["severity"]
            )

    def test_invalid_factor_values_fall_back(self):
        r = self.S(exploitation="<script>", scale="huge", severity=4)
        self.assertEqual((r["severity"], r["severity_method"]), (4, "ai"))
        self.assertEqual(
            self.S(exploitation="active", scale="small", domestic="yes")["severity"], 2
        )  # "yes" 는 True 아님

    def test_threat_level_excludes_reference(self):
        import tempfile

        base = {"title": "t", "core": "c", "background": "b", "impact": "i", "region": "국내", "link": ""}
        entries = [
            {**base, "category": "사고", "exploitation": "active", "scale": "large", "domestic": True},
            {**base, "category": "정책", "exploitation": "none", "scale": "small"},
        ]
        with tempfile.TemporaryDirectory() as d, mock.patch.object(render, "POSTS", Path(d)):
            text = render.write_post("2099-01-02", entries, []).read_text(encoding="utf-8")
        self.assertIn("threat_level: 5", text)  # 정책 기사(참고)는 평균에서 제외
