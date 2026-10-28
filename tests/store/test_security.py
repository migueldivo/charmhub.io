import copy
import json
import pathlib
import tempfile
from unittest import TestCase
from unittest.mock import patch

from mock_data.mock_store_logic import sample_package_detail
from webapp.app import app
from webapp.store import security

SAMPLE_REPORT = {
    "charm": "test",
    "generated_at": "2026-10-28",
    "revision": 200,
    "channel": "1.16/stable",
    "base": "Ubuntu 26.04",
    "source": "https://github.com/canonical/test-operator",
    "newer_workload": None,
    "dependencies": [
        {
            "id": "resource:test-image",
            "name": "test-image",
            "type": "resource",
            "version": "rev 1",
            "relationship": "direct",
            "parent": None,
        },
        {
            "id": "interface:ingress",
            "name": "ingress",
            "type": "interface",
            "version": None,
            "relationship": "direct",
            "parent": None,
            "endpoints": [
                {"name": "ingress", "role": "requires", "optional": True}
            ],
        },
        {
            "id": "pypi:jinja2",
            "name": "jinja2",
            "type": "python-package",
            "version": "2.11.3",
            "relationship": "direct",
            "parent": None,
        },
        {
            "id": "deb:openssl",
            "name": "openssl",
            "type": "os-package",
            "version": "3.5.5",
            "relationship": "transitive",
            "parent": "resource:test-image",
        },
    ],
    "vulnerabilities": [
        {
            "id": "GHSA-1",
            "cve": "CVE-2026-1",
            "severity": "critical",
            "status": "in-progress",
            "dependency": "pypi:jinja2",
        },
        {
            "id": "GHSA-2",
            "cve": None,
            "severity": "high",
            "status": "triaged",
            "dependency": "deb:openssl",
        },
        {
            "id": "GHSA-3",
            "cve": None,
            "severity": "medium",
            "status": "fixed",
            "dependency": "pypi:jinja2",
        },
    ],
}


def vuln(severity, status="triaged"):
    return {"severity": severity, "status": status}


class TestVulnerabilityIndex(TestCase):
    def test_no_vulnerabilities_is_a(self):
        self.assertEqual(
            security.vulnerability_index([]), {"index": "A", "exposure": 0}
        )

    def test_fixed_vulnerabilities_are_ignored(self):
        result = security.vulnerability_index([vuln("critical", "fixed")])
        self.assertEqual(result["index"], "A")

    def test_weights_by_severity(self):
        result = security.vulnerability_index(
            [vuln("critical"), vuln("high"), vuln("medium"), vuln("low")]
        )
        self.assertEqual(result["exposure"], 17.5)
        self.assertEqual(result["index"], "B")

    def test_bands(self):
        self.assertEqual(
            security.vulnerability_index([vuln("critical")] * 15)["index"],
            "C",
        )
        self.assertEqual(
            security.vulnerability_index([vuln("high")] * 80)["index"], "D"
        )
        self.assertEqual(
            security.vulnerability_index([vuln("critical")] * 81)["index"],
            "F",
        )


class TestSummariseReport(TestCase):
    def test_summary(self):
        summary = security.summarise_report(SAMPLE_REPORT)

        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["open"], 2)
        self.assertEqual(summary["fixed"], 1)
        self.assertEqual(summary["affected_dependencies"], 2)
        self.assertEqual(summary["index"], "B")
        self.assertEqual(
            summary["severities"],
            [
                {"key": "critical", "count": 1},
                {"key": "high", "count": 1},
                {"key": "medium", "count": 0},
                {"key": "low", "count": 0},
            ],
        )
        statuses = {s["key"]: s["count"] for s in summary["statuses"]}
        self.assertEqual(
            statuses,
            {"triaged": 1, "in-progress": 1, "ready-for-release": 0, "fixed": 1},
        )
        types = {t["key"]: t for t in summary["dependency_types"]}
        self.assertEqual(types["python-package"]["vulnerable"], 1)
        self.assertEqual(types["interface"]["vulnerable"], 0)
        self.assertNotIn("go-module", types)


@patch("webapp.store.views.redis_cache.get", return_value=None)
@patch("webapp.store.views.get_package_details")
class TestSecurityViews(TestCase):
    def setUp(self):
        app.testing = True
        self.client = app.test_client()
        self.tmp = tempfile.TemporaryDirectory()
        data_dir = pathlib.Path(self.tmp.name)
        (data_dir / "test.json").write_text(json.dumps(SAMPLE_REPORT))
        patcher = patch.object(security, "DATA_DIR", data_dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        (data_dir / "certifications.json").write_text(
            json.dumps({"test": {"channels": {"1.16/stable": "2031"}}})
        )
        security.get_security_report.cache_clear()
        security._certifications.cache_clear()
        self.addCleanup(security.get_security_report.cache_clear)
        self.addCleanup(security._certifications.cache_clear)

    def test_security_tab(self, mock_details, _cache):
        mock_details.return_value = copy.deepcopy(sample_package_detail)

        response = self.client.get("/test/security")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('href="/test/security"', body)
        self.assertIn('href="/test/dependencies"', body)
        self.assertIn("Security report", body)
        self.assertIn("vulnerabilities found", body)
        self.assertIn("Vulnerability index B", body)
        self.assertIn("Ready for release", body)
        self.assertIn('id="security-report-data"', body)

    def test_reduced_tabs_and_security_seal(self, mock_details, _cache):
        mock_details.return_value = copy.deepcopy(sample_package_detail)

        body = self.client.get("/test/security").get_data(as_text=True)

        self.assertNotIn('href="/test/libraries"', body)
        self.assertNotIn('href="/test/configurations"', body)
        self.assertNotIn('href="/test/actions"', body)
        self.assertIn("Security approved", body)
        self.assertIn("<th>Maintained until</th>", body)
        self.assertIn("2031", body)

    def test_dependencies_tab(self, mock_details, _cache):
        mock_details.return_value = copy.deepcopy(sample_package_detail)

        response = self.client.get("/test/dependencies")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Python package", body)
        self.assertIn('id="dependencies-table"', body)

    def test_security_json(self, mock_details, _cache):
        response = self.client.get("/test/security.json")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["charm"], "test")

    def test_404_without_report(self, mock_details, _cache):
        (pathlib.Path(self.tmp.name) / "test.json").unlink()

        self.assertEqual(self.client.get("/test/security").status_code, 404)
        self.assertEqual(
            self.client.get("/test/dependencies").status_code, 404
        )

    def test_tabs_hidden_without_report(self, mock_details, _cache):
        mock_details.return_value = copy.deepcopy(sample_package_detail)
        (pathlib.Path(self.tmp.name) / "test.json").unlink()

        (pathlib.Path(self.tmp.name) / "certifications.json").unlink()
        security._certifications.cache_clear()

        body = self.client.get("/test/actions").get_data(as_text=True)

        self.assertNotIn('href="/test/security"', body)
        self.assertIn('href="/test/libraries"', body)
        self.assertNotIn("Security approved", body)
        self.assertNotIn("Maintained until", body)


class TestShippedReports(TestCase):
    def test_grafana_report_is_consistent(self):
        security.get_security_report.cache_clear()
        report = security.get_security_report("grafana-k8s")
        dependency_ids = {d["id"] for d in report["dependencies"]}
        statuses = {key for key, _, _ in security.MAINTENANCE_STATUSES}

        for item in report["vulnerabilities"]:
            self.assertIn(item["dependency"], dependency_ids)
            self.assertIn(item["status"], statuses)
            self.assertIn(item["severity"], security.SEVERITIES)
        for dep in report["dependencies"]:
            self.assertIn(dep["type"], security.DEPENDENCY_TYPES)
