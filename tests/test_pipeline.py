import copy
import datetime as dt
import gzip
import hashlib
import json
import pathlib
import re
import tempfile
import unittest
from unittest import mock

from scripts.sync_vulnerability_data import (
    EpssFeed,
    SafeRedirectHandler,
    Vulnerability,
    aggregate,
    build_llm_events,
    cwe_values,
    cvss_details,
    fetch,
    epss_history_dates,
    has_public_exploit_reference,
    kev_addition_metrics,
    metric_window,
    parse_date,
    parse_timestamp,
    percentage,
    require_comparison_coverage,
    read_epss,
    rolling_comparison_windows,
    select_cwe_analysis_ids,
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
    def dashboard_payload(self) -> dict:
        dashboard_path = pathlib.Path(__file__).resolve().parents[1] / "data" / "dashboard.json"
        return json.loads(dashboard_path.read_text(encoding="utf-8"))

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
            self.assertEqual(feed.percentiles["CVE-2021-44228"], 1.0)

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

    def test_epss_parser_rejects_bad_percentiles_and_record_overflow(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "epss.csv.gz"
            self.write_epss_fixture(path, ["CVE-2026-1000,0.1,1.01"])
            with self.assertRaisesRegex(ValueError, "percentile is outside"):
                read_epss(path, minimum_records=1)

            self.write_epss_fixture(
                path,
                ["CVE-2026-1000,0.1,0.5", "CVE-2026-1001,0.2,0.6"],
            )
            with mock.patch(
                "scripts.sync_vulnerability_data.MAX_EPSS_RECORDS", 1
            ):
                with self.assertRaisesRegex(ValueError, "record-count limit"):
                    read_epss(path, minimum_records=1)

    def test_epss_parser_enforces_a_true_decompressed_byte_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "epss.csv.gz"
            self.write_epss_fixture(path, ["CVE-2026-1000,0.1,0.5"])
            with mock.patch(
                "scripts.sync_vulnerability_data.gzip_uncompressed_size",
                return_value=0,
            ), mock.patch(
                "scripts.sync_vulnerability_data.MAX_EPSS_UNCOMPRESSED_BYTES", 16
            ):
                with self.assertRaisesRegex(ValueError, "decompressed source"):
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
        payload = self.dashboard_payload()
        payload["sources"]["epss"]["recordCount"] = (
            payload["sources"]["epss"]["matchedCveCount"] - 1
        )
        with self.assertRaisesRegex(ValueError, "exceeds the EPSS record count"):
            validate(payload)

    def test_epss_refresh_does_not_trust_the_local_cache_mtime(self):
        class Response:
            def __init__(self):
                self.read_count = 0
                self.headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                self.read_count += 1
                return b"official-feed" if self.read_count == 1 else b""

            def geturl(self):
                return "https://example.test/epss.csv.gz"

        class Opener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return Response()

        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory) / "epss.csv.gz"
            destination.write_bytes(b"poisoned-cache")
            opener = Opener()
            with mock.patch(
                "scripts.sync_vulnerability_data.urllib.request.build_opener",
                return_value=opener,
            ):
                fetch(
                    "https://example.test/epss.csv.gz",
                    destination,
                    refresh=True,
                    use_local_mtime_validator=False,
                    allowed_hosts=frozenset({"example.test"}),
                )
            request = opener.request
            self.assertNotIn(
                "if-modified-since",
                {key.lower() for key, _value in request.header_items()},
            )
            self.assertEqual(destination.read_bytes(), b"official-feed")

    def test_fetch_rejects_non_https_unapproved_hosts_and_redirects(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory) / "source.json"
            for url, message in (
                ("http://www.cisa.gov/source", "must use HTTPS"),
                ("https://untrusted.example/source", "not allowlisted"),
                ("https://www.cisa.gov:444/source", "unapproved port"),
                ("https://user@www.cisa.gov/source", "user information"),
            ):
                with self.subTest(url=url):
                    with self.assertRaisesRegex(ValueError, message):
                        fetch(url, destination, refresh=True)
            handler = SafeRedirectHandler(frozenset({"www.cisa.gov"}))
            with self.assertRaisesRegex(ValueError, "not allowlisted"):
                handler.redirect_request(
                    None,
                    None,
                    302,
                    "redirect",
                    {},
                    "https://evil.example/payload",
                )

    def test_fetch_enforces_stream_limit_and_cleans_partial_file(self):
        class Response:
            headers = {}

            def __init__(self):
                self.read_count = 0

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def geturl(self):
                return "https://example.test/source"

            def read(self, _size):
                self.read_count += 1
                return b"12345" if self.read_count == 1 else b""

        class Opener:
            def open(self, _request, timeout):
                self.timeout = timeout
                return Response()

        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory) / "source.json"
            destination.write_bytes(b"last-good")
            with mock.patch(
                "scripts.sync_vulnerability_data.urllib.request.build_opener",
                return_value=Opener(),
            ):
                with self.assertRaisesRegex(ValueError, "4-byte limit"):
                    fetch(
                        "https://example.test/source",
                        destination,
                        refresh=True,
                        max_bytes=4,
                        allowed_hosts=frozenset({"example.test"}),
                    )
            self.assertEqual(destination.read_bytes(), b"last-good")
            self.assertEqual([path.name for path in pathlib.Path(directory).iterdir()], ["source.json"])

    def test_fetch_rejects_oversized_offline_cache_and_replaces_it_without_validator(self):
        class Response:
            headers = {}

            def __init__(self):
                self.read_count = 0

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def geturl(self):
                return "https://example.test/source"

            def read(self, _size):
                self.read_count += 1
                return b"ok" if self.read_count == 1 else b""

        class Opener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return Response()

        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory) / "source.json"
            destination.write_bytes(b"oversized")
            with self.assertRaisesRegex(ValueError, "cached source exceeds"):
                fetch(
                    "https://example.test/source",
                    destination,
                    refresh=False,
                    max_bytes=4,
                    allowed_hosts=frozenset({"example.test"}),
                )

            opener = Opener()
            with mock.patch(
                "scripts.sync_vulnerability_data.urllib.request.build_opener",
                return_value=opener,
            ):
                fetch(
                    "https://example.test/source",
                    destination,
                    refresh=True,
                    max_bytes=4,
                    allowed_hosts=frozenset({"example.test"}),
                )
            self.assertNotIn(
                "if-modified-since",
                {key.lower() for key, _value in opener.request.header_items()},
            )
            self.assertEqual(destination.read_bytes(), b"ok")

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
        severity, score, version, authority = cvss_details(
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
        self.assertEqual((severity, score, version, authority), ("HIGH", 7.4, "3.1", "primary"))

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
        self.assertEqual(metrics["within7Count"], 0)
        self.assertEqual(metrics["within7Share"], 0.0)
        self.assertEqual(metrics["under21Count"], 1)
        self.assertEqual(metrics["under21Share"], 50.0)
        self.assertEqual(metrics["ageSample"], 2)
        self.assertEqual(metrics["oldCount"], 1)
        self.assertEqual(metrics["oldShare"], 50.0)

    def test_kev_deadline_share_uses_only_valid_due_window_records(self):
        metrics = kev_addition_metrics(
            {},
            {
                "CVE-2026-1000": {
                    "cveID": "CVE-2026-1000",
                    "dateAdded": "2026-01-01",
                    "dueDate": "2026-01-08",
                },
                "CVE-2026-1001": {
                    "cveID": "CVE-2026-1001",
                    "dateAdded": "2026-01-01",
                    "dueDate": "2026-01-09",
                },
                "CVE-2026-1002": {
                    "cveID": "CVE-2026-1002",
                    "dateAdded": "2026-01-01",
                    "dueDate": None,
                },
            },
            dt.date(2026, 1, 1),
            dt.date(2026, 12, 31),
            dt.date(2026, 12, 31),
        )
        self.assertEqual(metrics["count"], 3)
        self.assertEqual(metrics["dueWindowSample"], 2)
        self.assertEqual(metrics["within7Count"], 1)
        self.assertEqual(metrics["within7Share"], 50.0)

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

    def test_refresh_schedule_is_reported_in_utc(self):
        build_time = dt.datetime(2026, 7, 18, 12, tzinfo=dt.timezone.utc)
        with tempfile.NamedTemporaryFile() as temp_epss:
            payload = aggregate(
                {},
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
            )

        workflow = (
            pathlib.Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "data-refresh.yml"
        ).read_text()
        cron = re.search(r"-\s+cron:\s+['\"]([^'\"]+)['\"]", workflow)
        assert cron is not None
        minute, hour = cron.group(1).split()[:2]
        self.assertEqual(
            payload["project"]["refreshSchedule"],
            f"Daily at {int(hour):02d}:{int(minute):02d} UTC",
        )

    def test_priority_watch_filters_recent_non_kev_and_sorts_by_epss(self):
        snapshot_time = dt.datetime(2026, 7, 18, 12, tzinfo=dt.timezone.utc)
        records = {
            record.cve_id: record
            for record in (
                Vulnerability(
                    "CVE-2026-1000",
                    dt.date(2026, 7, 1),
                    "HIGH",
                    8.0,
                    "3.1",
                    False,
                    (),
                    0.5,
                    0.9,
                ),
                Vulnerability(
                    "CVE-2026-1001",
                    dt.date(2026, 6, 1),
                    "CRITICAL",
                    9.8,
                    "3.1",
                    True,
                    (),
                    0.9,
                    0.99,
                ),
                Vulnerability(
                    "CVE-2026-1002",
                    dt.date(2026, 6, 1),
                    "HIGH",
                    8.0,
                    "3.1",
                    False,
                    (),
                    0.99,
                    1.0,
                ),
                Vulnerability(
                    "CVE-2025-1000",
                    dt.date(2025, 1, 1),
                    "HIGH",
                    8.0,
                    "3.1",
                    False,
                    (),
                    0.95,
                    0.995,
                ),
                Vulnerability(
                    "CVE-2026-1003",
                    dt.date(2026, 7, 1),
                    "MEDIUM",
                    5.0,
                    "3.1",
                    False,
                    (),
                    0.05,
                    0.7,
                ),
            )
        }
        with tempfile.NamedTemporaryFile() as temp_epss:
            payload = aggregate(
                records,
                {
                    "count": 1,
                    "dateReleased": "2026-07-18T00:00:00Z",
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2026-1002",
                            "dateAdded": "2026-07-10",
                            "dueDate": "2026-07-17",
                        }
                    ],
                },
                [],
                {"records": [], "programReports": []},
                {"cve_records": [], "headline": {}},
                snapshot_time,
                2020,
                [],
                pathlib.Path(temp_epss.name),
                EpssFeed({}, "v2026.06.15", snapshot_time, 5),
            )
        self.assertEqual(payload["priorityWatch"]["total"], 2)
        self.assertEqual(
            payload["priorityWatch"]["itemsCompleteness"], "all_candidates"
        )
        self.assertEqual(
            len(payload["priorityWatch"]["items"]),
            payload["priorityWatch"]["total"],
        )
        self.assertEqual(
            [item["cveId"] for item in payload["priorityWatch"]["items"]],
            ["CVE-2026-1001", "CVE-2026-1000"],
        )
        self.assertEqual(
            payload["priorityWatch"]["items"][0]["epssPercentile"], 0.99
        )

    def test_priority_watch_publishes_every_candidate(self):
        snapshot_time = dt.datetime(2026, 7, 18, 12, tzinfo=dt.timezone.utc)
        records = {
            f"CVE-2026-{1000 + index}": Vulnerability(
                f"CVE-2026-{1000 + index}",
                dt.date(2026, 7, 1),
                "HIGH",
                8.0,
                "3.1",
                index % 2 == 0,
                (),
                0.9 - index / 100,
                0.99 - index / 1000,
            )
            for index in range(25)
        }
        with tempfile.NamedTemporaryFile() as temp_epss:
            payload = aggregate(
                records,
                {
                    "count": 1,
                    "dateReleased": "2026-07-18T00:00:00Z",
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2000-9999",
                            "dateAdded": "2020-01-01",
                            "dueDate": "2020-01-22",
                        }
                    ],
                },
                [],
                {"records": [], "programReports": []},
                {"cve_records": [], "headline": {}},
                snapshot_time,
                2020,
                [],
                pathlib.Path(temp_epss.name),
                EpssFeed({}, "v2026.06.15", snapshot_time, 25),
            )

        watch = payload["priorityWatch"]
        self.assertEqual(watch["itemsCompleteness"], "all_candidates")
        self.assertEqual(watch["total"], 25)
        self.assertEqual(len(watch["items"]), 25)
        self.assertEqual(watch["criticalHigh"], 25)
        self.assertEqual(watch["publicExploitReferences"], 13)
        self.assertEqual(watch["items"][0]["cveId"], "CVE-2026-1000")
        self.assertEqual(watch["items"][-1]["cveId"], "CVE-2026-1024")

    def test_kev_entries_before_nvd_publication_retain_signed_difference(self):
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
        self.assertEqual(metrics["medianDaysToKev"], -12.0)

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

    def test_epss_history_samples_twelve_complete_month_ends(self):
        dates = epss_history_dates(dt.date(2026, 7, 18))
        self.assertEqual(len(dates), 12)
        self.assertEqual(dates[0], dt.date(2025, 7, 31))
        self.assertEqual(dates[-1], dt.date(2026, 6, 30))
        self.assertTrue(
            all(
                date == (date.replace(day=28) + dt.timedelta(days=4)).replace(day=1)
                - dt.timedelta(days=1)
                for date in dates
            )
        )

    def test_validator_stops_epss_movements_at_model_boundaries(self):
        payload = self.dashboard_payload()
        point = payload["epssHistory"]["points"][1]
        point["modelVersion"] = "v2026.01.01"
        point["comparableToPrevious"] = False
        with self.assertRaisesRegex(ValueError, "movements cross a model boundary"):
            validate(payload)

    def test_priority_watch_validation_catches_sort_and_percentile_errors(self):
        base = self.dashboard_payload()
        reversed_payload = copy.deepcopy(base)
        reversed_payload["priorityWatch"]["items"][:2] = reversed(
            reversed_payload["priorityWatch"]["items"][:2]
        )
        with self.assertRaisesRegex(ValueError, "not sorted by EPSS"):
            validate(reversed_payload)

        percentile_payload = copy.deepcopy(base)
        percentile_payload["priorityWatch"]["items"][0]["epssPercentile"] = 1.1
        with self.assertRaisesRegex(ValueError, "priority-watch item is invalid"):
            validate(percentile_payload)

    def test_priority_watch_validation_requires_complete_exact_details(self):
        base = self.dashboard_payload()

        incomplete_payload = copy.deepcopy(base)
        incomplete_payload["priorityWatch"]["items"].pop()
        with self.assertRaisesRegex(ValueError, "does not reconcile with its total"):
            validate(incomplete_payload)

        completeness_payload = copy.deepcopy(base)
        completeness_payload["priorityWatch"]["itemsCompleteness"] = "top_candidates"
        with self.assertRaisesRegex(ValueError, "item completeness is invalid"):
            validate(completeness_payload)

        summary_payload = copy.deepcopy(base)
        summary_payload["priorityWatch"]["criticalHigh"] -= 1
        with self.assertRaisesRegex(ValueError, "summaries do not reconcile"):
            validate(summary_payload)

        exploit_summary_payload = copy.deepcopy(base)
        exploit_summary_payload["priorityWatch"]["publicExploitReferences"] += 1
        with self.assertRaisesRegex(ValueError, "summaries do not reconcile"):
            validate(exploit_summary_payload)

        duplicate_payload = copy.deepcopy(base)
        duplicate_payload["priorityWatch"]["items"][1] = copy.deepcopy(
            duplicate_payload["priorityWatch"]["items"][0]
        )
        with self.assertRaisesRegex(ValueError, "priority-watch item is invalid"):
            validate(duplicate_payload)

        invalid_row_payload = copy.deepcopy(base)
        invalid_row_payload["priorityWatch"]["items"][0][
            "publicExploitReference"
        ] = "yes"
        with self.assertRaisesRegex(ValueError, "priority-watch item is invalid"):
            validate(invalid_row_payload)

        with mock.patch(
            "scripts.sync_vulnerability_data.MAX_PRIORITY_WATCH_ITEMS",
            len(base["priorityWatch"]["items"]) - 1,
        ):
            with self.assertRaisesRegex(ValueError, "publication safety limit"):
                validate(base)

    def test_cwe_mover_and_source_name_validation(self):
        payload = self.dashboard_payload()
        payload["topCwes"][0]["name"] = ""
        with self.assertRaisesRegex(ValueError, "invalid MITRE metadata"):
            validate(payload)

        payload = self.dashboard_payload()
        mover = payload["cweMovers"]["rising"][0]
        mover["count"] = 1
        mover["priorCount"] = 1
        with self.assertRaisesRegex(ValueError, "below the sample floor"):
            validate(payload)

    def test_cwe_analysis_selection_respects_the_sample_floor(self):
        as_of = dt.date(2026, 7, 18)
        records = [
            Vulnerability(
                f"CVE-2026-{1000 + index}",
                dt.date(2026, 1, 1),
                "HIGH",
                8.0,
                "3.1",
                False,
                ("CWE-79",),
            )
            for index in range(3)
        ]
        with mock.patch("scripts.sync_vulnerability_data.CWE_MOVER_MIN_COUNT", 2):
            selected = select_cwe_analysis_ids(records, as_of)
        self.assertEqual(selected, ["CWE-79"])

    def test_change_digest_must_reconcile_with_source_activity(self):
        payload = self.dashboard_payload()
        payload["changeDigest"]["cve"]["newRecords"] += 1
        with self.assertRaisesRegex(ValueError, "change digest does not reconcile"):
            validate(payload)

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

    def test_ransomware_overlap_membership(self):
        from scripts.sync_vulnerability_data import build_signal_overlap, Vulnerability
        import datetime as dt

        records = [
            Vulnerability("CVE-2026-1000", dt.date(2026, 1, 1), "HIGH", 8.0, "3.1", False, (), 0.2),
            Vulnerability("CVE-2026-1001", dt.date(2026, 1, 1), "HIGH", 8.0, "3.1", False, (), 0.2),
            Vulnerability("CVE-2026-1002", dt.date(2026, 1, 1), "HIGH", 8.0, "3.1", False, (), 0.2),
            Vulnerability("CVE-2026-1003", dt.date(2026, 1, 1), "HIGH", 8.0, "3.1", False, (), 0.2),
        ]
        kev_by_id = {
            "CVE-2026-1000": {"cveID": "CVE-2026-1000", "knownRansomwareCampaignUse": "Known"},
            "CVE-2026-1001": {"cveID": "CVE-2026-1001", "knownRansomwareCampaignUse": "Unknown"},
            "CVE-2026-1002": {"cveID": "CVE-2026-1002"},
        }
        res = build_signal_overlap(records, kev_by_id)
        
        ransomware_entries = [r for r in res if r["sets"]["ransomware"]]
        non_ransomware_entries = [r for r in res if not r["sets"]["ransomware"]]
        
        self.assertEqual(sum(r["count"] for r in ransomware_entries), 1)
        self.assertEqual(sum(r["count"] for r in non_ransomware_entries), 3)

    def test_heatmap_unscored_epss_only_in_column_zero(self):
        from scripts.sync_vulnerability_data import build_cvss_epss_heatmap, Vulnerability
        import datetime as dt

        records = [
            Vulnerability("CVE-2026-1000", dt.date(2026, 1, 1), "HIGH", 8.0, "3.1", False, (), None),
            Vulnerability("CVE-2026-1001", dt.date(2026, 1, 1), "HIGH", 8.0, "3.1", False, (), 0.005),
            Vulnerability("CVE-2026-1002", dt.date(2026, 1, 1), "HIGH", 8.0, "3.1", False, (), 0.85),
        ]
        res = build_cvss_epss_heatmap(records, set())
        grid = res["grid"]
        
        self.assertEqual(grid["HIGH"][0]["count"], 1)
        self.assertEqual(grid["HIGH"][1]["count"], 1)
        self.assertEqual(grid["HIGH"][6]["count"], 1)
        for i in (2, 3, 4, 5):
            self.assertEqual(grid["HIGH"][i]["count"], 0)

    def test_heatmap_invariants(self):
        from scripts.sync_vulnerability_data import build_cvss_epss_heatmap, Vulnerability
        import datetime as dt

        records = [
            Vulnerability("CVE-2026-1000", dt.date(2026, 1, 1), "HIGH", 8.0, "3.1", False, (), None),
            Vulnerability("CVE-2026-1001", dt.date(2026, 1, 1), "HIGH", 8.0, "3.1", False, (), 0.005),
            Vulnerability("CVE-2026-1002", dt.date(2026, 1, 1), "LOW", 3.0, "3.1", False, (), 0.85),
        ]
        res = build_cvss_epss_heatmap(records, set())
        
        total_cells_count = 0
        for row in res["grid"].values():
            self.assertEqual(len(row), 7)
            total_cells_count += sum(c["count"] for c in row)
        self.assertEqual(total_cells_count, res["total"])
        self.assertEqual(total_cells_count, len(records))

    def test_overlap_invariants(self):
        from scripts.sync_vulnerability_data import build_signal_overlap, Vulnerability
        import datetime as dt

        records = [
            Vulnerability("CVE-2026-1000", dt.date(2026, 1, 1), "HIGH", 8.0, "3.1", False, (), None),
            Vulnerability("CVE-2026-1001", dt.date(2026, 1, 1), "HIGH", 8.0, "3.1", False, (), 0.005),
            Vulnerability("CVE-2026-1002", dt.date(2026, 1, 1), "LOW", 3.0, "3.1", False, (), 0.85),
        ]
        res = build_signal_overlap(records, {})
        
        seen_sets = []
        for item in res:
            self.assertNotIn(item["sets"], seen_sets)
            seen_sets.append(item["sets"])
            
        total_overlap_count = sum(item["count"] for item in res)
        self.assertEqual(total_overlap_count, len(records))

    def test_kev_lag_invariants(self):
        from scripts.sync_vulnerability_data import build_kev_lag_heatmap, Vulnerability
        import datetime as dt

        records = [
            Vulnerability("CVE-2026-1000", dt.date(2026, 1, 1), "HIGH", 8.0, "3.1", False, (), 0.2),
            Vulnerability("CVE-2026-1001", dt.date(2026, 6, 1), "HIGH", 8.0, "3.1", False, (), 0.2),
            Vulnerability("CVE-2026-1002", dt.date(2025, 1, 1), "HIGH", 8.0, "3.1", False, (), 0.2),
        ]
        kev_by_id = {
            "CVE-2026-1000": {"cveID": "CVE-2026-1000", "dateAdded": "2026-01-05"},
            "CVE-2026-1001": {"cveID": "CVE-2026-1001", "dateAdded": "2026-06-01"},
            "CVE-2026-1002": {"cveID": "CVE-2026-1002", "dateAdded": "2025-02-15"},
        }
        as_of = dt.date(2026, 7, 1)
        res = build_kev_lag_heatmap(records, kev_by_id, as_of)
        
        grid = res["grid"]
        cohort_totals = res["cohortTotals"]
        for year, buckets in grid.items():
            self.assertEqual(sum(buckets.values()), cohort_totals.get(year, 0))

    def test_completeness_percentages_range(self):
        from scripts.sync_vulnerability_data import build_enrichment_completeness, Vulnerability
        import datetime as dt

        records = [
            Vulnerability("CVE-2026-1000", dt.date(2026, 1, 1), "HIGH", 8.0, "3.1", False, (), 0.2),
            Vulnerability("CVE-2026-1001", dt.date(2026, 1, 1), "UNKNOWN", None, None, False, (), None),
        ]
        res = build_enrichment_completeness(records)
        for row in res:
            self.assertTrue(0 <= row["cvssPercent"] <= 100)
            self.assertTrue(0 <= row["cwePercent"] <= 100)
            self.assertTrue(0 <= row["exploitRefPercent"] <= 100)
            self.assertTrue(0 <= row["epssPercent"] <= 100)

    def test_production_dashboard_invariants(self):
        import json
        import pathlib
        path = pathlib.Path(__file__).parent.parent / "data" / "dashboard.json"
        if not path.exists():
            return
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)

        # 1. Heatmap cell counts sum to the cohort total.
        heatmap = payload.get("cvssEpssHeatmap", {})
        grid = heatmap.get("grid", {})
        total_cells_count = 0
        for row in grid.values():
            self.assertEqual(len(row), 7)
            total_cells_count += sum(c["count"] for c in row)
        self.assertEqual(total_cells_count, heatmap.get("total"))

        # 2. Every overlap record appears in exactly one intersection.
        overlap = payload.get("signalOverlap", [])
        seen_sets = []
        for item in overlap:
            self.assertNotIn(item["sets"], seen_sets)
            seen_sets.append(item["sets"])
        self.assertEqual(
            sum(item["count"] for item in overlap),
            heatmap.get("total"),
        )

        # 3. KEV lag buckets sum to each publication-year cohort total.
        kev_lag = payload.get("kevLagHeatmap", {})
        grid_lag = kev_lag.get("grid", {})
        cohort_totals = kev_lag.get("cohortTotals", {})
        for year, buckets in grid_lag.items():
            self.assertEqual(sum(buckets.values()), cohort_totals.get(year, 0))

        # 4. Completeness percentages remain between 0 and 100.
        completeness = payload.get("enrichmentCompleteness", [])
        for row in completeness:
            self.assertTrue(0 <= row["cvssPercent"] <= 100)
            self.assertTrue(0 <= row["cwePercent"] <= 100)
            self.assertTrue(0 <= row["exploitRefPercent"] <= 100)
            self.assertTrue(0 <= row["epssPercent"] <= 100)

    def test_golden_fixture_pre_pub_kev_timing(self):
        from scripts.sync_vulnerability_data import metric_window, Vulnerability
        import datetime as dt

        start = dt.date(2026, 1, 1)
        end = dt.date(2026, 3, 31)
        obs = dt.date(2026, 7, 1)

        # Record 1: Listed 10 days BEFORE NVD publication (raw_days = -10)
        # Record 2: Listed 20 days AFTER NVD publication (raw_days = 20)
        records = [
            Vulnerability("CVE-2026-0001", dt.date(2026, 2, 15), "HIGH", 8.0, "3.1", False, (), 0.2),
            Vulnerability("CVE-2026-0002", dt.date(2026, 2, 1), "HIGH", 8.0, "3.1", False, (), 0.2),
        ]
        kev_by_id = {
            "CVE-2026-0001": {"cveID": "CVE-2026-0001", "dateAdded": "2026-02-05"}, # -10 days
            "CVE-2026-0002": {"cveID": "CVE-2026-0002", "dateAdded": "2026-02-21"}, # +20 days
        }

        res = metric_window(records, {r.cve_id: r for r in records}, kev_by_id, start, end, obs)
        self.assertEqual(res["prePublicationKev"], 1)
        self.assertEqual(res["prePublicationKevShare"], 50.0)
        self.assertEqual(res["medianDaysToKev"], 5.0) # median(-10, 20) = 5.0
        self.assertEqual(res["medianDaysToKevNonNegative"], 20.0) # median(20) = 20.0

    def test_golden_fixture_cvss_version_hierarchy(self):
        from scripts.sync_vulnerability_data import cvss_details

        metrics = {
            "cvssMetricV40": [
                {"type": "Primary", "cvssData": {"baseScore": 9.2, "version": "4.0"}}
            ],
            "cvssMetricV31": [
                {"type": "Primary", "cvssData": {"baseScore": 8.8, "version": "3.1"}}
            ],
            "cvssMetricV2": [
                {"type": "Primary", "cvssData": {"baseScore": 7.5, "version": "2.0"}}
            ],
        }
        severity, score, version, authority = cvss_details(metrics)
        self.assertEqual(severity, "CRITICAL")
        self.assertEqual(score, 9.2)
        self.assertEqual(version, "4.0")
        self.assertEqual(authority, "primary")

    def test_golden_fixture_duplicate_cwes(self):
        from scripts.sync_vulnerability_data import cwe_values

        item = {
            "weaknesses": [
                {"description": [{"value": "CWE-79"}]},
                {"description": [{"value": "CWE-79"}]},
                {"description": [{"value": "CWE-89"}]},
            ]
        }
        cwes = cwe_values(item)
        self.assertEqual(cwes, ("CWE-79", "CWE-89"))

    def test_golden_fixture_metrics_dictionary_existence(self):
        import json
        import pathlib
        path = pathlib.Path(__file__).parent.parent / "data" / "metrics_dictionary.json"
        self.assertTrue(path.exists(), "data/metrics_dictionary.json must exist")
        with open(path, "r", encoding="utf-8") as f:
            dictionary = json.load(f)
        self.assertIn("metrics", dictionary)
        self.assertIn("medianPublicationToKevGap", dictionary["metrics"])
    def test_golden_fixture_epss_predictive_performance(self):
        from scripts.sync_vulnerability_data import build_epss_predictive_performance, EpssHistorySample
        history = [
            EpssHistorySample(
                score_date=dt.date(2025, 1, 31),
                model_version="v2025.03.14",
                record_count=100,
                high_ids=frozenset({"CVE-2025-0001", "CVE-2025-0002"}),
                source_url="https://example.test",
                sha256="abc",
                sample_kind="month_end",
            )
        ]
        kev_by_id = {
            "CVE-2025-0001": {"dateAdded": "2025-02-15"},
        }
        # 45 days after score_date (2025-01-31 -> 2025-03-17)
        as_of = dt.date(2025, 3, 17)
        res = build_epss_predictive_performance(history, kev_by_id, as_of)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["snapshotDate"], "2025-01-31")
        self.assertEqual(res[0]["candidateCount"], 2)
        self.assertTrue(res[0]["isMature30d"])
        self.assertFalse(res[0]["isMature60d"])
        self.assertFalse(res[0]["isMature90d"])
        self.assertEqual(res[0]["kevAdditions30d"], 1)
        self.assertEqual(res[0]["conversionRate30d"], 50.0)
        self.assertEqual(res[0]["recall30d"], 100.0)
        self.assertIsNone(res[0]["conversionRate60d"])
        self.assertIsNone(res[0]["conversionRate90d"])


    def test_cvss_v2_version_aware_severity_fallback(self):
        from scripts.sync_vulnerability_data import cvss_details
        v2_metrics = {
            "cvssMetricV2": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "2.0",
                        "baseScore": 0.0,
                    }
                }
            ]
        }
        severity, score, version, authority = cvss_details(v2_metrics)
        self.assertEqual(severity, "LOW")
        self.assertEqual(score, 0.0)

        v3_metrics = {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 0.0,
                    }
                }
            ]
        }
        severity_v3, score_v3, version_v3, authority_v3 = cvss_details(v3_metrics)
        self.assertEqual(severity_v3, "NONE")
        self.assertEqual(score_v3, 0.0)


if __name__ == "__main__":
    unittest.main()

