"""SSRF 방어(netsafe)와 지표 갱신(refresh) 안전성 테스트 — 네트워크 없이 실행.

실행: python -m unittest discover tests
"""

import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from briefing import enrich, netsafe


def fake_dns(ip):
    return lambda host, port, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


class SSRFTest(unittest.TestCase):
    def assertBlocked(self, url, ip="93.184.216.34"):
        with mock.patch.object(netsafe.socket, "getaddrinfo", side_effect=fake_dns(ip)):
            with self.assertRaises(netsafe.UnsafeURLError, msg=url):
                netsafe.check_url(url)

    def test_blocks_internal_and_metadata_addresses(self):
        for ip in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "fd00::1",
        ]:
            self.assertBlocked("https://evil.example/", ip=ip)

    def test_blocks_bad_scheme_port_and_credentials(self):
        for url in [
            "file:///etc/passwd",
            "gopher://x/",
            "javascript:alert(1)",
            "ftp://example.com/",
            "https://example.com:22/",
            "http://user:pw@example.com/",
            "https:///nohost",
            "",
        ]:
            self.assertBlocked(url)

    def test_allows_public_https(self):
        with mock.patch.object(netsafe.socket, "getaddrinfo", side_effect=fake_dns("93.184.216.34")):
            self.assertEqual(netsafe.check_url("https://www.example.com/a?b=1"), "https://www.example.com/a?b=1")

    def test_redirect_to_internal_is_blocked(self):
        redirect = mock.Mock(
            is_redirect=True, status_code=302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}
        )
        session = mock.Mock()
        session.get.return_value = redirect
        ips = {"news.example": "93.184.216.34", "169.254.169.254": "169.254.169.254"}
        dns = lambda host, port, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ips[host], port))]
        with mock.patch.object(netsafe.socket, "getaddrinfo", side_effect=dns):
            with self.assertRaises(netsafe.UnsafeURLError):
                netsafe.safe_get(session, "https://news.example/article", max_bytes=1000)
        self.assertEqual(session.get.call_count, 1)  # 내부 주소로는 요청 자체를 보내지 않음

    def test_oversized_response_rejected(self):
        resp = mock.Mock(is_redirect=False, status_code=200)
        resp.raw.read.return_value = b"x" * 1001
        session = mock.Mock()
        session.get.return_value = resp
        with mock.patch.object(netsafe.socket, "getaddrinfo", side_effect=fake_dns("93.184.216.34")):
            with self.assertRaises(netsafe.UnsafeURLError):
                netsafe.safe_get(session, "https://news.example/big", max_bytes=1000)


class RefreshSafetyTest(unittest.TestCase):
    def test_outage_keeps_existing_metrics(self):
        item = {"cve": "CVE-2026-0001", "cve_status": "nvd", "cvss": 9.8, "cvss_source": "NVD", "kev": True}
        with mock.patch.object(enrich, "_get_json", return_value=None), mock.patch.object(enrich.time, "sleep"):
            changed = enrich.enrich([item], ["본문"], refresh=True)
        self.assertEqual(changed, 0)
        self.assertEqual((item["cve"], item["cvss"], item["kev"]), ("CVE-2026-0001", 9.8, True))

    def test_rejected_cve_is_removed(self):
        item = {"cve": "CVE-2026-0002", "cve_status": "nvd", "cvss": 7.0, "cvss_source": "NVD"}
        resp = {"vulnerabilities": [{"cve": {"vulnStatus": "Rejected", "metrics": {}}}]}
        with (
            mock.patch.object(
                enrich, "_get_json", side_effect=lambda url, *a, **k: resp if url == enrich.NVD_URL else {}
            ),
            mock.patch.object(enrich.time, "sleep"),
        ):
            changed = enrich.enrich([item], [""], refresh=True)
        self.assertEqual((changed, item["cve"]), (1, ""))


if __name__ == "__main__":
    unittest.main()
