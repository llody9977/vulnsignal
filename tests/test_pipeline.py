import datetime as dt
import gzip
import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from scripts.sync_vulnerability_data import (
    EpssFeed,
    Vulnerability,
    aggregate,
    build_llm_events,
    cwe_values,
    cvss_details,
    fetch,
    has_public_exploit_reference,
    kev_addition_metrics,
    metric_window,
    parse_date,
    parse_timestamp,
    percentage,
    require_comparison_coverage,
    read_epss,
    rolling_comparison_windows,
    source_freshness,
    validate,
    validate_deploy_freshness,
    validate_kev_payload,
    verify_nvd_feed,
    validate_window_metrics,
    validate_llm_evidence,
    validate_epss_freshness,
)


class PipelineUnitTests(unittest.TestCase):
    def write_epss_fixture(
        self,
        path: pathlib.Path,
        rows: list[str],
        *,
        metadata: str = "#model_version:v2026.06.15,score_date:2026-07-17T12:00:27Z",
    ) -> None:
        with gzip.open(path, "wt", encoding="utf-8", newline="") as handle:
            handle.write(metadata + "\n")
            handle.write("cve,epss,percentile\n")
            handle.writelines(f"{row}\n" for row in rows)

    def test_epss_parser_requires_official_metadata_and_valid_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "epss.csv.gz"
            self.write_epss_fixture(
                path,
                [
                    "CVE-2021-44228,0.99999,1.0",
                    "CVE-2026-1000,0.01234,0.5",
                ],
            )
            feed = read_epss(path, minimum_records=2)
            self.assertEqual(feed.model_version, "v2026.06.15")
            self.assertEqual(
                feed.score_date,
                dt.datetime(2026, 7, 17, 12, 0, 27, tzinfo=dt.timezone.utc),
            )
            self.assertEqual(feed.record_count, 2)
            self.assertEqual(feed.scores["CVE-2021-44228"], 0.99999)

    def test_epss_parser_rejects_mock_duplicate_and_out_of_range_data(self):
        cases = (
            ("#epss-v3.0", ["CVE-2026-1000,0.1,0.5"], "mock or unsupported"),
            (
                "#model_version:v2026.06.15,score_date:2026-07-17T12:00:27Z",
                ["CVE-2026-1000,0.1,0.5", "CVE-2026-1000,0.2,0.6"],
                "duplicate CVE ID",
            ),
            (
                "#model_version:v2026.06.15,score_date:2026-07-17T12:00:27Z",
                ["CVE-2026-1000,1.01,0.5"],
                "outside \\[0, 1\\]",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, (metadata, rows, message) in enumerate(cases):
                with self.subTest(message=message):
                    path = pathlib.Path(directory) / f"epss-{index}.csv.gz"
                    self.write_epss_fixture(path, rows, metadata=metadata)
                    with self.assertRaisesRegex(ValueError, message):
                        read_epss(path, minimum_records=1)

    def test_epss_freshness_rejects_stale_and_future_snapshots(self):
        now = dt.datetime(2026, 7, 18, 12, tzinfo=dt.timezone.utc)
        validate_epss_freshness(
            EpssFeed({}, "v2026.06.15", now - dt.timedelta(hours=24), 0), now
        )
        with self.assertRaisesRegex(ValueError, "stale"):
            validate_epss_freshness(
                EpssFeed({}, "v2026.06.15", now - dt.timedelta(hours=73), 0), now
            )
        with self.assertRaisesRegex(ValueError, "after"):
            validate_epss_freshness(
                EpssFeed({}, "v2026.06.15", now + dt.timedelta(hours=2), 0), now
            )

    def test_deployment_freshness_uses_the_current_clock(self):
        checked_at = dt.datetime(2026, 7, 18, 12, tzinfo=dt.timezone.utc)
        payload = {
            "generatedAt": "2026-07-18T11:00:00Z",
            "sources": {
                "cve": {"latestFetch": "2026-07-18T11:30:00Z"},
                "nvd": {"latestSourceUpdate": "2026-07-18T10:00:00Z"},
                "epss": {"scoreDate": "2026-07-17T12:00:00Z"},
            },
        }
        validate_deploy_freshness(payload, checked_at)

        payload["sources"]["epss"]["scoreDate"] = "2026-07-15T11:59:59Z"
        with self.assertRaisesRegex(ValueError, "EPSS source score date is stale"):
            validate_deploy_freshness(payload, checked_at)

        payload["sources"]["epss"]["scoreDate"] = "2026-07-17T12:00:00Z"
        payload["generatedAt"] = "2026-07-15T11:59:59Z"
        with self.assertRaisesRegex(ValueError, "dashboard snapshot is stale"):
            validate_deploy_freshness(payload, checked_at)

    def test_validator_rejects_more_epss_matches_than_feed_records(self):
        dashboard_path = pathlib.Path(__file__).resolve().parents[1] / "data" / "dashboard.json"
        payload = json.loads(dashboard_path.read_text(encoding="utf-8"))
        payload["sources"]["epss"]["recordCount"] = (
            payload["sources"]["epss"]["matchedCveCount"] - 1
        )
        with self.assertRaisesRegex(ValueError, "exceeds the EPSS record count"):
            validate(payload)

    def test_epss_refresh_does_not_trust_the_local_cache_mtime(self):
        class Response:
            def __init__(self):
                self.read_count = 0

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                self.read_count += 1
                return b"official-feed" if self.read_count == 1 else b""

        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory) / "epss.csv.gz"
            destination.write_bytes(b"poisoned-cache")
            with mock.patch(
                "scripts.sync_vulnerability_data.urllib.request.urlopen",
                return_value=Response(),
            ) as urlopen:
                fetch(
                    "https://example.test/epss.csv.gz",
                    destination,
                    refresh=True,
                    use_local_mtime_validator=False,
                )
            request = urlopen.call_args.args[0]
            self.assertNotIn(
                "if-modified-since",
                {key.lower() for key, _value in request.header_items()},
            )
            self.assertEqual(destination.read_bytes(), b"official-feed")

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
            {r.cve_id: r for r in records},
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

    def test_kev_addition_metrics_use_an_explicit_date_added_window(self):
        records = {
            "CVE-2020-1000": Vulnerability(
                "CVE-2020-1000",
                dt.date(2020, 1, 1),
                "HIGH",
                8.0,
                "3.1",
                False,
                (),
            ),
            "CVE-2026-1000": Vulnerability(
                "CVE-2026-1000",
                dt.date(2026, 5, 1),
                "HIGH",
                8.0,
                "3.1",
                False,
                (),
            ),
        }
        metrics = kev_addition_metrics(
            records,
            {
                "CVE-2020-1000": {
                    "cveID": "CVE-2020-1000",
                    "dateAdded": "2026-06-01",
                    "dueDate": "2026-06-22",
                    "knownRansomwareCampaignUse": "Known",
                },
                "CVE-2026-1000": {
                    "cveID": "CVE-2026-1000",
                    "dateAdded": "2026-05-01",
                    "dueDate": "2026-05-15",
                    "knownRansomwareCampaignUse": "Unknown",
                },
                "CVE-2024-9999": {
                    "cveID": "CVE-2024-9999",
                    "dateAdded": "2025-06-30",
                    "dueDate": "2025-07-21",
                    "knownRansomwareCampaignUse": "Known",
                },
            },
            dt.date(2025, 7, 1),
            dt.date(2026, 6, 30),
            dt.date(2026, 7, 18),
        )
        self.assertEqual(metrics["count"], 2)
        self.assertEqual(metrics["ransomwareCount"], 1)
        self.assertEqual(metrics["ransomwareShare"], 50.0)
        self.assertEqual(metrics["dueWindowSample"], 2)
        self.assertEqual(metrics["medianDueWindow"], 17.5)
        self.assertEqual(metrics["ageSample"], 2)
        self.assertEqual(metrics["oldCount"], 1)
        self.assertEqual(metrics["oldShare"], 50.0)

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
        records = [
            Vulnerability(
                "CVE-2024-1",
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
            {r.cve_id: r for r in records},
            {"CVE-2024-1": {"dateAdded": "2024-02-01"}},
            dt.date(2024, 1, 1),
            dt.date(2024, 12, 31),
            dt.date(2024, 12, 31),
        )
        validate_window_metrics(metrics, "test window")
        metrics["kevWithin90DayRate"] = 50.0
        with self.assertRaisesRegex(ValueError, "does not reconcile"):
            validate_window_metrics(metrics, "test window")

    def test_window_reconciliation_rejects_wrong_epss_and_kev_addition_shares(self):
        records = [
            Vulnerability(
                "CVE-2024-1000",
                dt.date(2024, 1, 1),
                "HIGH",
                8.0,
                "3.1",
                False,
                (),
                0.25,
            )
        ]
        kev = {
            "CVE-2024-1000": {
                "cveID": "CVE-2024-1000",
                "dateAdded": "2024-02-01",
                "dueDate": "2024-02-22",
                "knownRansomwareCampaignUse": "Known",
            }
        }
        metrics = metric_window(
            records,
            {record.cve_id: record for record in records},
            kev,
            dt.date(2024, 1, 1),
            dt.date(2024, 12, 31),
            dt.date(2024, 12, 31),
        )
        validate_window_metrics(metrics, "test window")
        for key in ("epssHighShare", "ransomwareKevShare", "oldKevShare"):
            with self.subTest(key=key):
                broken = dict(metrics)
                broken[key] = 12.3
                with self.assertRaisesRegex(ValueError, "does not reconcile"):
                    validate_window_metrics(broken, "test window")

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
            {r.cve_id: r for r in records},
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
        with tempfile.NamedTemporaryFile() as temp_epss:
            epss_path = pathlib.Path(temp_epss.name)
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
                epss_path,
                EpssFeed({}, "v2026.06.15", cutoff - dt.timedelta(hours=12), 0),
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

    def test_aggregate_separates_build_time_from_report_cutoff(self):
        build_time = dt.datetime(2026, 7, 18, 12, tzinfo=dt.timezone.utc)
        report_cutoff = dt.datetime(2025, 12, 15, 8, tzinfo=dt.timezone.utc)
        records = {
            "CVE-2025-9999": Vulnerability(
                "CVE-2025-9999",
                dt.date(2025, 12, 20),
                "HIGH",
                8.0,
                "3.1",
                False,
                (),
                0.2,
            )
        }
        with tempfile.NamedTemporaryFile() as temp_epss:
            payload = aggregate(
                records,
                {
                    "count": 1,
                    "dateReleased": "2026-07-16T17:00:00Z",
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2025-1000",
                            "dateAdded": "2025-11-01",
                            "dueDate": "2025-11-22",
                        }
                    ],
                },
                [],
                {"records": [], "programReports": []},
                {"cve_records": [], "headline": {}},
                build_time,
                2019,
                [],
                pathlib.Path(temp_epss.name),
                EpssFeed({}, "v2026.06.15", build_time - dt.timedelta(hours=12), 0),
                report_cutoff=report_cutoff,
            )

        self.assertEqual(payload["generatedAt"], "2026-07-18T12:00:00Z")
        self.assertEqual(payload["coverage"]["asOf"], "2025-12-15")
        self.assertEqual(payload["coverage"]["latestCompleteMonth"], "2025-11")
        self.assertEqual(payload["coverage"]["recordCount"], 0)
        self.assertEqual(sum(month["published"] for month in payload["monthly"]), 0)

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
            {r.cve_id: r for r in records},
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
