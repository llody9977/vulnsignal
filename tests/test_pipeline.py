import datetime as dt
import unittest

from scripts.sync_vulnerability_data import (
    Vulnerability,
    cvss_details,
    has_public_exploit_reference,
    metric_window,
    parse_date,
    percentage,
    validate_llm_evidence,
)


class PipelineUnitTests(unittest.TestCase):
    def test_date_and_percentage_helpers(self):
        self.assertEqual(parse_date("2026-07-17T08:00:00Z"), dt.date(2026, 7, 17))
        self.assertIsNone(parse_date("not-a-date"))
        self.assertEqual(percentage(1, 4), 25.0)
        self.assertIsNone(percentage(1, 0))

    def test_cvss_selection_prefers_primary_without_maximizing(self):
        severity, score, version = cvss_details(
            {
                "cvssMetricV31": [
                    {
                        "type": "Secondary",
                        "cvssData": {
                            "baseScore": 9.9,
                            "baseSeverity": "CRITICAL",
                            "version": "3.1",
                        },
                    },
                    {
                        "type": "Primary",
                        "cvssData": {
                            "baseScore": 7.4,
                            "baseSeverity": "HIGH",
                            "version": "3.1",
                        },
                    },
                ]
            }
        )
        self.assertEqual((severity, score, version), ("HIGH", 7.4, "3.1"))

    def test_exploit_reference_tag_is_case_insensitive(self):
        self.assertTrue(
            has_public_exploit_reference(
                {"references": [{"url": "https://example.test", "tags": ["Exploit"]}]}
            )
        )
        self.assertFalse(has_public_exploit_reference({"references": [{"tags": ["Patch"]}]}))

    def test_mature_cohort_kev_rate_excludes_recent_records(self):
        records = [
            Vulnerability("CVE-2024-1", dt.date(2024, 1, 1), "HIGH", 8.0, "3.1", True, "CWE-79"),
            Vulnerability("CVE-2024-2", dt.date(2024, 2, 1), "UNKNOWN", None, None, False, None),
            Vulnerability("CVE-2024-3", dt.date(2024, 12, 15), "LOW", 2.0, "3.1", False, "CWE-20"),
        ]
        kev = {"CVE-2024-1": {"dateAdded": "2024-02-15"}}
        metrics = metric_window(
            records,
            kev,
            dt.date(2024, 1, 1),
            dt.date(2024, 12, 31),
            dt.date(2024, 12, 31),
        )
        self.assertEqual(metrics["published"], 3)
        self.assertEqual(metrics["matureCohort"], 2)
        self.assertEqual(metrics["kevWithin90Days"], 1)
        self.assertEqual(metrics["kevWithin90DayRate"], 50.0)
        self.assertEqual(metrics["severityCoverage"], 66.7)

    def test_llm_registry_rejects_duplicate_program_sources(self):
        evidence = {
            "coverage": "curated_non_exhaustive",
            "programReports": [
                {"id": "same", "sourceUrl": "https://example.test/one"},
                {"id": "same", "sourceUrl": "https://example.test/two"},
            ],
            "records": [],
        }
        with self.assertRaisesRegex(ValueError, "unique"):
            validate_llm_evidence(evidence)


if __name__ == "__main__":
    unittest.main()
