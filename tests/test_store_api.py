import os
import tempfile
from unittest import TestCase
from unittest.mock import patch

from canonicalwebteam.exceptions import StoreApiResponseErrorList
from flask import Flask

from webapp.store_api import (
    TracedDeviceGW,
    TracedPubilsherGW,
    device_gateway,
    get_charm_allowlist,
    publisher_gateway,
)


FIND_RESPONSE = {
    "results": [
        {"name": "grafana-k8s"},
        {"name": "prometheus-k8s"},
        {"name": "wordpress-k8s"},
    ]
}


class TestCharmAllowlist(TestCase):
    def setUp(self):
        allowlist_file = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        allowlist_file.write(
            "# demo charms\ngrafana-k8s\n\nprometheus-k8s  # monitoring\n"
        )
        allowlist_file.close()
        self.allowlist_path = allowlist_file.name
        self.addCleanup(os.remove, self.allowlist_path)

    def set_allowlist_env(self, value):
        patcher = patch.dict(os.environ, {"CHARM_ALLOWLIST_FILE": value})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_allowlist_disabled_without_env_var(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(get_charm_allowlist())

    def test_allowlist_ignores_comments_and_blank_lines(self):
        self.set_allowlist_env(self.allowlist_path)
        self.assertEqual(get_charm_allowlist(), {"grafana-k8s", "prometheus-k8s"})

    def test_allowlist_disabled_in_testing_app_context(self):
        self.set_allowlist_env(self.allowlist_path)
        testing_app = Flask(__name__)
        testing_app.testing = True
        with testing_app.app_context():
            self.assertIsNone(get_charm_allowlist())

    def test_find_returns_everything_when_disabled(self):
        self.set_allowlist_env("")
        with patch.object(
            TracedPubilsherGW,
            "find",
            return_value={"results": list(FIND_RESPONSE["results"])},
        ):
            results = publisher_gateway.find(type="charm")["results"]

        self.assertEqual(len(results), 3)

    def test_find_filters_results(self):
        self.set_allowlist_env(self.allowlist_path)
        with patch.object(
            TracedDeviceGW,
            "find",
            return_value={"results": list(FIND_RESPONSE["results"])},
        ) as mock_find:
            results = device_gateway.find(publisher="someone")["results"]

        mock_find.assert_called_once_with(publisher="someone")
        self.assertEqual(
            [package["name"] for package in results],
            ["grafana-k8s", "prometheus-k8s"],
        )

    def test_get_item_details_allows_listed_charm(self):
        self.set_allowlist_env(self.allowlist_path)
        with patch.object(
            TracedPubilsherGW,
            "get_item_details",
            return_value={"name": "grafana-k8s"},
        ) as mock_details:
            details = publisher_gateway.get_item_details(
                name="grafana-k8s", fields=["result.title"]
            )

        mock_details.assert_called_once_with("grafana-k8s", fields=["result.title"])
        self.assertEqual(details, {"name": "grafana-k8s"})

    def test_get_item_details_hides_unlisted_charm(self):
        self.set_allowlist_env(self.allowlist_path)
        with patch.object(TracedDeviceGW, "get_item_details") as mock_details:
            with self.assertRaises(StoreApiResponseErrorList) as error:
                device_gateway.get_item_details("wordpress-k8s")

        mock_details.assert_not_called()
        self.assertEqual(error.exception.status_code, 404)
