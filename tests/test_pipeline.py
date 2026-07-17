import datetime as dt
import unittest

from scripts.sync_vulnerability_data import (
    Vulnerability,
    build_llm_events,
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

    def test_llm_timeline_keeps_reveal_and_report_semantics_separate(self):
        events = build_llm_events(
            [
                {
                    "identifier": "CVE-2026-1000",
                    "revealed_at": "2026-05-20T07:40:37Z",
                },
                {
                    "identifier": "CVE-2026-1001",
                    "revealed_at": "2026-05-20T08:40:37Z",
                },
            ],
            [
                {
                    "publisher": "Example",
                    "program": "Research preview",
                    "count": 10,
                    "published": "2025-10-30",
                    "sourceUrl": "https://example.test/report",
                }
            ],
            "curated_non_exhaustive",
        )
        self.assertEqual(events[0]["kind"], "program_report")
        self.assertEqual(events[0]["reportedMinimum"], 10)
        self.assertEqual(events[1]["kind"], "public_id_revealed")
        self.assertEqual(events[1]["count"], 2)
        self.assertEqual(events[1]["dateSemantics"], "first_party_revealed_at")


if __name__ == "__main__":
    unittest.main()
