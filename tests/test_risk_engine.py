import unittest
from risk_engine import severity_from_score, calculate_risk_score, parse_vulnerability


class RiskEngineTests(unittest.TestCase):
    def test_severity_bands(self):
        self.assertEqual(severity_from_score(9.8), "CRITICAL")
        self.assertEqual(severity_from_score(7.5), "HIGH")
        self.assertEqual(severity_from_score(5.0), "MEDIUM")
        self.assertEqual(severity_from_score(2.0), "LOW")

    def test_score_normalization(self):
        self.assertEqual(calculate_risk_score(9.8, "CRITICAL"), 98.0)
        self.assertEqual(calculate_risk_score(None, "HIGH"), 80.0)

    def test_parse_record(self):
        item = {"cve": {
            "id": "CVE-2025-12345",
            "descriptions": [{"lang": "en", "value": "Example description"}],
            "metrics": {"cvssMetricV31": [{
                "type": "Primary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}
            }]},
            "published": "2025-01-01T00:00:00.000",
            "lastModified": "2025-01-02T00:00:00.000",
        }}
        parsed = parse_vulnerability(item)
        self.assertEqual(parsed["cve_id"], "CVE-2025-12345")
        self.assertEqual(parsed["severity"], "HIGH")
        self.assertEqual(parsed["risk_score"], 75.0)


if __name__ == "__main__":
    unittest.main()
