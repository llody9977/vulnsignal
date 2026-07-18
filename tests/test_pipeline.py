import datetime as dt
import gzip
import hashlib
import pathlib
import tempfile
import unittest

from scripts.sync_vulnerability_data import (
    Vulnerability,
    aggregate,
    build_llm_events,
    cwe_values,
    cvss_details,
    has_public_exploit_reference,
    metric_window,
    parse_date,
    parse_timestamp,
    percentage,
    require_comparison_coverage,
    rolling_comparison_windows,
    source_freshness,
    validate_kev_payload,
    verify_nvd_feed,
    validate_window_metrics,
    validate_llm_evidence,
)


class PipelineUnitTests(unittest.TestCase):
    def test_date_and_percentage_helpers(self):
        self.assertEqual(parse_date("2026-07-17T08:00:00Z"), dt.date(2026, 7, 17))
        self.assertIsNone(parse_date("not-a-date"))
        self.assertEqual(percentage(1, 4), 25.0)
        self.assertIsNone(percentage(1, 0))

    def test_rfc3339_timestamp_accepts_cisa_four_digit_fraction(self):
        self.assertEqual(
            parse_timestamp("2026-07-16T17:00:15.6845Z"),
            dt.datetime(2026, 7, 16, 17, 0, 15, 684500, tzinfo=dt.timezone.utc),
        )

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

    def test_each_distinct_cwe_assignment_is_retained(self):
        self.assertEqual(
            cwe_values(
                {
                    "weaknesses": [
                        {"description": [{"value": "CWE-79"}, {"value": "CWE-89"}]},
                        {"description": [{"value": "CWE-79"}, {"value": "NVD-CWE-noinfo"}]},
                    ]
                }
            ),
            ("CWE-79", "CWE-89"),
        )

    def test_mature_cohort_kev_rate_excludes_recent_records(self):
        records = [
            Vulnerability("CVE-2024-1", dt.date(2024, 1, 1), "HIGH", 8.0, "3.1", True, ("CWE-79",)),
            Vulnerability("CVE-2024-2", dt.date(2024, 2, 1), "UNKNOWN", None, None, False, ()),
            Vulnerability("CVE-2024-3", dt.date(2024, 12, 15), "LOW", 2.0, "3.1", False, ("CWE-20",)),
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
        self.assertEqual(metrics["observedKev"], 1)
        self.assertEqual(metrics["kevTimingSample"], 1)
        self.assertEqual(metrics["severityCoverage"], 66.7)
        validate_window_metrics(metrics, "test window")

    def test_cisa_kev_payload_rejects_duplicates_and_malformed_required_fields(self):
        valid_item = {
            "cveID": "CVE-2026-1000",
            "dateAdded": "2026-07-16",
            "dueDate": "2026-08-06",
        }
        valid_payload = {
            "count": 1,
            "dateReleased": "2026-07-16T17:00:15.6845Z",
            "vulnerabilities": [valid_item],
        }
        self.assertEqual(validate_kev_payload(valid_payload), [valid_item])

        invalid_payloads = (
            (
                {
                    **valid_payload,
                    "count": 2,
                    "vulnerabilities": [valid_item, dict(valid_item)],
                },
                "duplicate CISA KEV record",
            ),
            ({**valid_payload, "count": 2}, "count does not reconcile"),
            (
                {
                    **valid_payload,
                    "vulnerabilities": [{**valid_item, "dateAdded": "not-a-date"}],
                },
                "invalid dateAdded",
            ),
            (
                {
                    **valid_payload,
                    "vulnerabilities": [{**valid_item, "dueDate": None}],
                },
                "invalid dueDate",
            ),
        )
        for payload, message in invalid_payloads:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    validate_kev_payload(payload)

    def test_window_reconciliation_rejects_a_wrong_kev_rate(self):
        metrics = metric_window(
            [
                Vulnerability(
                    "CVE-2024-1",
                    dt.date(2024, 1, 1),
                    "HIGH",
                    8.0,
                    "3.1",
                    False,
                    (),
                )
            ],
            {"CVE-2024-1": {"dateAdded": "2024-02-01"}},
            dt.date(2024, 1, 1),
            dt.date(2024, 12, 31),
            dt.date(2024, 12, 31),
        )
        validate_window_metrics(metrics, "test window")
        metrics["kevWithin90DayRate"] = 50.0
        with self.assertRaisesRegex(ValueError, "does not reconcile"):
            validate_window_metrics(metrics, "test window")

    def test_metric_window_excludes_kev_additions_after_report_cutoff(self):
        records = [
            Vulnerability(
                "CVE-2024-8",
                dt.date(2024, 1, 1),
                "HIGH",
                8.0,
                "3.1",
                False,
                (),
            )
        ]
        metrics = metric_window(
            records,
            {"CVE-2024-8": {"dateAdded": "2025-01-01"}},
            dt.date(2024, 1, 1),
            dt.date(2024, 1, 31),
            dt.date(2024, 6, 1),
        )
        self.assertEqual(metrics["observedKev"], 0)
        self.assertEqual(metrics["kevWithin90Days"], 0)
        self.assertIsNone(metrics["medianDaysToKev"])

    def test_aggregate_excludes_future_kev_from_counts_and_recent_list(self):
        cutoff = dt.datetime(2026, 7, 17, 12, tzinfo=dt.timezone.utc)
        payload = aggregate(
            {},
            {
                "count": 2,
                "dateReleased": "2026-07-19T00:00:00Z",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-1000",
                        "dateAdded": "2026-06-15",
                        "dueDate": "2026-07-01",
                    },
                    {
                        "cveID": "CVE-2026-9999",
                        "dateAdded": "2026-07-18",
                        "dueDate": "2026-08-01",
                    },
                ]
            },
            [],
            {"records": [], "programReports": []},
            {"cve_records": [], "headline": {}},
            cutoff,
            2020,
            [],
        )
        june = next(item for item in payload["monthly"] if item["month"] == "2026-06")
        july = next(item for item in payload["monthly"] if item["month"] == "2026-07")
        self.assertEqual(payload["sources"]["kev"]["count"], 2)
        self.assertEqual(payload["risk"]["catalogKev"], 1)
        self.assertEqual(june["kevAdded"], 1)
        self.assertEqual(july["kevAdded"], 0)
        self.assertEqual(
            [item["cveId"] for item in payload["recentKev"]],
            ["CVE-2026-1000"],
        )

    def test_kev_entries_before_nvd_publication_count_as_zero_day(self):
        records = [
            Vulnerability(
                "CVE-2024-9",
                dt.date(2024, 2, 1),
                "HIGH",
                8.0,
                "3.1",
                False,
                ("CWE-79",),
            )
        ]
        metrics = metric_window(
            records,
            {"CVE-2024-9": {"dateAdded": "2024-01-20"}},
            dt.date(2024, 1, 1),
            dt.date(2024, 12, 31),
            dt.date(2024, 12, 31),
        )
        self.assertEqual(metrics["prePublicationKev"], 1)
        self.assertEqual(metrics["kevWithin90Days"], 1)
        self.assertEqual(metrics["kevWithin90DayRate"], 100.0)
        self.assertEqual(metrics["medianDaysToKev"], 0.0)

    def test_comparison_uses_two_adjacent_rolling_36_month_windows(self):
        earlier_start, earlier_end, recent_start, recent_end = rolling_comparison_windows(
            dt.date(2026, 6, 1)
        )
        self.assertEqual(earlier_start, dt.date(2020, 7, 1))
        self.assertEqual(earlier_end, dt.date(2023, 6, 30))
        self.assertEqual(recent_start, dt.date(2023, 7, 1))
        self.assertEqual(recent_end, dt.date(2026, 6, 30))

    def test_comparison_rejects_from_year_that_truncates_earlier_window(self):
        require_comparison_coverage(2020, dt.date(2026, 6, 1))
        with self.assertRaisesRegex(ValueError, "use 2020 or earlier"):
            require_comparison_coverage(2021, dt.date(2026, 6, 1))

    def test_source_freshness_excludes_batches_after_report_cutoff(self):
        cutoff = dt.datetime(2026, 7, 17, 12, tzinfo=dt.timezone.utc)
        freshness = source_freshness(
            [
                {
                    "fetchTime": "2026-07-18T12:00:00Z",
                    "new": [{"cveId": "CVE-2026-9999"}],
                },
                {
                    "fetchTime": "2026-07-17T11:00:00Z",
                    "updated": [{"cveId": "CVE-2026-1000"}],
                },
                {
                    "fetchTime": "2026-07-16T11:00:00Z",
                    "updated": [{"cveId": "CVE-2026-0001"}],
                },
            ],
            cutoff,
        )
        self.assertEqual(freshness["latestFetch"], "2026-07-17T11:00:00Z")
        self.assertEqual(freshness["changedRecords24h"], 1)

    def test_nvd_feed_is_rehashed_even_when_verified_marker_matches(self):
        expected_payload = b'{"vulnerabilities":[]}'
        expected_sha256 = hashlib.sha256(expected_payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            feed_path = pathlib.Path(directory) / "feed.json.gz"
            with gzip.open(feed_path, "wb") as handle:
                handle.write(b"tampered")
            marker = feed_path.with_suffix(feed_path.suffix + ".verified")
            marker.write_text(expected_sha256 + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                verify_nvd_feed(feed_path, expected_sha256)

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
