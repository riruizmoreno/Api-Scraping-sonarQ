import unittest
from pathlib import Path

from sonar_inventory import Config, Inventory, SonarClient


class ProfileComparisonTests(unittest.TestCase):
    def test_detects_added_disabled_and_modified_rules(self):
        profiles = [
            {"key": "parent", "inheritance_api": {}},
            {
                "key": "child",
                "inheritance_api": {"parent": {"key": "parent"}},
            },
        ]
        rules = {
            "parent": [
                {"key": "repo:kept", "severity": "MAJOR", "params": [{"key": "x", "value": "1"}]},
                {"key": "repo:disabled", "severity": "MINOR"},
            ],
            "child": [
                {"key": "repo:kept", "severity": "CRITICAL", "params": [{"key": "x", "value": "2"}]},
                {"key": "repo:added", "severity": "MINOR"},
            ],
        }

        result = Inventory._compare_profiles(profiles, rules)

        self.assertEqual(len(result), 1)
        changes = {item["rule_key"]: item["change"] for item in result[0]["items"]}
        self.assertEqual(changes["repo:added"], "added_or_inherited_difference")
        self.assertEqual(changes["repo:disabled"], "deactivated_or_not_inherited")
        self.assertEqual(changes["repo:kept"], "modified")
        modified = next(item for item in result[0]["items"] if item["rule_key"] == "repo:kept")
        self.assertEqual(set(modified["fields"]), {"severity", "params"})

    def test_does_not_infer_parent_when_not_explicit(self):
        profiles = [{"key": "child", "inheritance_api": {"ancestors": []}}]
        self.assertEqual(Inventory._compare_profiles(profiles, {"child": []}), [])


class ConfigurationTests(unittest.TestCase):
    def test_parameters_are_limited_to_discovered_capabilities(self):
        client = SonarClient(Config(
            sonar_url="https://example.invalid",
            sonar_token="secret",
            output_dir=Path("."),
            verify_ssl=True,
            timeout=1,
            log_level="INFO",
        ))
        client.webservices["api/example/search"] = {"parameters": {"p", "ps"}}
        self.assertEqual(
            client.parameters_for(
                "api/example/search", {"p": 2, "ps": 50, "unknown": "ignored"}
            ),
            {"p": 2, "ps": 50},
        )

    def test_prefers_discovered_v2_equivalent(self):
        client = SonarClient(Config(
            sonar_url="https://example.invalid",
            sonar_token="secret",
            output_dir=Path("."),
            verify_ssl=True,
            timeout=1,
            log_level="INFO",
        ))
        client.webservices["api/v2/qualityprofiles/search"] = {
            "parameters": {"project"}
        }
        self.assertEqual(
            client.preferred_endpoint("api/qualityprofiles/search"),
            "api/v2/qualityprofiles/search",
        )

    def test_paginates_when_api_omits_total_count(self):
        client = SonarClient(Config(
            sonar_url="https://example.invalid",
            sonar_token="secret",
            output_dir=Path("."),
            verify_ssl=True,
            timeout=1,
            log_level="INFO",
        ))
        endpoint = "api/example/search"
        client.webservices[endpoint] = {"parameters": {"p", "ps"}}
        responses = [
            {"items": list(range(500)), "paging": {"pageIndex": 1, "pageSize": 500}},
            {"items": [500, 501], "paging": {"pageIndex": 2, "pageSize": 500}},
        ]
        client.get = lambda _endpoint, _params: responses.pop(0)

        items, stats = client._fetch_list(endpoint, ("items",))

        self.assertEqual(len(items), 502)
        self.assertEqual(stats["pages"], 2)
        self.assertIsNone(stats["reported_total"])


if __name__ == "__main__":
    unittest.main()
