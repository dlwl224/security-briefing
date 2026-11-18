"""공식 지표 보강(NVD/EPSS/KEV) 로직 테스트 — 네트워크 없이 응답을 흉내 낸다.

실행: python -m unittest discover tests
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from briefing import enrich, render  # noqa: E402


def nvd(score, sev="CRITICAL", typ="Primary", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
    return {"vulnerabilities": [{"cve": {"vulnStatus": "Analyzed", "metrics": {"cvssMetricV31": [
        {"type": typ, "cvssData": {"baseScore": score, "baseSeverity": sev, "vectorString": vector}}]}}}]}


class ParseTest(unittest.TestCase):
    def test_parse_nvd_picks_primary_v31(self):
        data = {"vulnerabilities": [{"cve": {"metrics": {
            "cvssMetricV40": [{"type": "Secondary", "cvssData": {"baseScore": 9.4, "baseSeverity": "CRITICAL"}}],
            "cvssMetricV31": [
                {"type": "Secondary", "cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH"}},
                {"type": "Primary", "cvssData": {"baseScore": 9.9, "baseSeverity": "CRITICAL"}},
            ]}}}]}
        r = enrich.parse_nvd(data)
        self.assertEqual((r["cvss"], r["cvss_version"], r["cvss_source"]), (9.9, "3.1", "NVD"))

    def test_parse_nvd_rejects_malicious_values(self):
        r = enrich.parse_nvd(nvd(999, sev="<script>", vector="<img src=x onerror=alert(1)>"))
        self.assertNotIn("cvss", r)                       # 범위 밖 점수는 버림
        r = enrich.parse_nvd(nvd(7.5, sev="<script>", vector="javascript:alert(1)<x>"))
        self.assertEqual(r["cvss_severity"], "HIGH")       # 등급은 점수로 다시 계산
        self.assertEqual(r["cvss_vector"], "")             # 형식이 다른 벡터는 버림

    def test_parse_nvd_handles_missing_cvssdata(self):
        data = {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [{"type": "Primary"}]}}}]}
        self.assertEqual(enrich.parse_nvd(data), {"status": ""})
        self.assertIsNone(enrich.parse_nvd({"vulnerabilities": []}))
        self.assertIsNone(enrich.parse_nvd("not a dict"))

    def test_parse_epss(self):
        r = enrich.parse_epss({"data": [{"epss": "0.00734", "percentile": "0.55119", "date": "2026-11-18"}]})
        self.assertEqual((r["epss"], r["epss_percentile"], r["epss_date"]), (0.73, 55.1, "2026-11-18"))
        self.assertIsNone(enrich.parse_epss({"data": [{"epss": "5"}]}))     # 확률은 0~1
        bad = enrich.parse_epss({"data": [{"epss": "0.1", "date": "<b>"}]})
        self.assertEqual(bad["epss_date"], "")


class EnrichFlowTest(unittest.TestCase):
    def run_enrich(self, entry, text, nvd_resp):
        def fake_get(url, params, **kwargs):
            if "nvd" in url:
                return nvd_resp
            if "first.org" in url:
                return {"data": [{"epss": "0.5", "percentile": "0.99", "date": "2026-11-18"}]}
            return {"vulnerabilities": [{"cveID": "CVE-2026-0001", "dateAdded": "2026-11-17",
                                         "knownRansomwareCampaignUse": "Known"}]}
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
        e = render.normalize({"title": "t", "core": "", "background": "", "impact": "", "cve": "CVE-2026-1",
                              "cve_status": "<x>", "epss": 500, "kev": "yes", "cvss_source": "evil"})
        m = render.metrics(e)
        self.assertEqual(e["cve"], "")                       # 형식 불일치 CVE
        self.assertEqual((m["cve_status"], m["epss"], m["kev"], m["cvss_source"]), ("", 0.0, False, ""))


if __name__ == "__main__":
    unittest.main()
