import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  change,
  comparisonYearOptions,
  completeMonths,
  hasRecordedValue,
  llmEvidenceForMonth,
  matchedYearPoints,
  monthsForYear,
  rollingMonths,
  severityShare,
  summarizePeriod,
  type LlmEvidenceEvent,
  type MonthPoint,
} from "../app/trend-model.ts";

const dashboard = JSON.parse(
  readFileSync(new URL("../data/dashboard.json", import.meta.url), "utf8"),
) as {
  coverage: { latestCompleteMonth: string };
  monthly: MonthPoint[];
  llmDiscovery: { events: LlmEvidenceEvent[] };
};

const latestCompleteMonth = dashboard.coverage.latestCompleteMonth;

test("complete periods exclude the partial month and retain full historical years", () => {
  const complete = completeMonths(dashboard.monthly, latestCompleteMonth);
  assert.equal(complete.at(-1)?.month, latestCompleteMonth);
  assert.ok(complete.every((point) => !point.partial));

  const year2025 = monthsForYear(
    dashboard.monthly,
    2025,
    latestCompleteMonth,
  );
  assert.equal(year2025.length, 12);
  assert.ok(year2025.reduce((total, point) => total + point.published, 0) > 40_000);
});

test("year comparisons stop both series at the same complete month", () => {
  const latestYear = Number(latestCompleteMonth.slice(0, 4));
  const previousYear = latestYear - 1;
  const latestMonthNumber = Number(latestCompleteMonth.slice(5, 7));
  const monthSuffix = latestCompleteMonth.slice(5, 7);
  const matched = matchedYearPoints(
    dashboard.monthly,
    previousYear,
    latestYear,
    latestCompleteMonth,
  );
  assert.equal(matched.monthCap, latestMonthNumber);
  assert.equal(matched.first.length, matched.second.length);
  assert.equal(matched.first.at(-1)?.month, `${previousYear}-${monthSuffix}`);
  assert.equal(matched.second.at(-1)?.month, latestCompleteMonth);
});

test("year comparisons align the intersection when an interior month is missing", () => {
  const point = (month: string): MonthPoint => ({
    month,
    published: 1,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    none: 0,
    unknown: 1,
    severityCoverage: 0,
    publicExploitReferences: 0,
    kevAdded: 0,
    partial: false,
    enriching: false,
    epssHigh: 0,
  });
  const matched = matchedYearPoints(
    [
      point("2025-01"),
      point("2025-03"),
      point("2026-01"),
      point("2026-02"),
      point("2026-03"),
    ],
    2025,
    2026,
    "2026-03",
  );

  assert.deepEqual(matched.matchedMonths, [1, 3]);
  assert.deepEqual(matched.first.map((item) => item.month), ["2025-01", "2025-03"]);
  assert.deepEqual(matched.second.map((item) => item.month), ["2026-01", "2026-03"]);
});

test("relative changes distinguish zero-to-zero from a missing percentage baseline", () => {
  assert.equal(change(0, 0), 0);
  assert.equal(change(5, 0), null);
  assert.equal(change(0, 5), -100);
});

test("comparison year options prevent selecting the same year twice", () => {
  assert.deepEqual(comparisonYearOptions([2026, 2025, 2024], 2025), [2026, 2024]);
});

test("month focus keeps six-month momentum context inside its trailing window", () => {
  const rolling = rollingMonths(
    dashboard.monthly,
    "2026-06",
    latestCompleteMonth,
  );
  assert.equal(rolling.length, 12);
  assert.equal(rolling[0].month, "2025-07");
  assert.equal(rolling.at(-1)?.month, "2026-06");
  assert.notEqual(summarizePeriod(rolling, dashboard.llmDiscovery.events).momentum, null);
});

test("exploit-reference share never falls back to an enriching cohort", () => {
  const point = (
    month: string,
    published: number,
    publicExploitReferences: number,
    enriching: boolean,
  ): MonthPoint => ({
    month,
    published,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    none: 0,
    unknown: published,
    severityCoverage: 0,
    publicExploitReferences,
    kevAdded: 0,
    partial: false,
    enriching,
    epssHigh: 0,
  });

  const enrichingOnly = summarizePeriod(
    [point("2026-06", 100, 5, true)],
    [],
  );
  assert.equal(enrichingOnly.publicExploitShare, null);
  assert.equal(enrichingOnly.publicExploitMatureMonths, 0);
  assert.equal(enrichingOnly.publicExploitEnrichingMonths, 1);

  const mixed = summarizePeriod(
    [
      point("2025-12", 100, 20, false),
      point("2026-01", 200, 2, true),
    ],
    [],
  );
  assert.equal(mixed.publicExploitShare, 20);
  assert.equal(mixed.publicExploitMatureReferences, 20);
  assert.equal(mixed.publicExploitMaturePublished, 100);
  assert.equal(mixed.publicExploitMatureMonths, 1);
  assert.equal(mixed.publicExploitEnrichingMonths, 1);
});

test("severity shares use all published CVEs and reconcile to 100%", () => {
  const point: MonthPoint = {
    month: "2026-06",
    published: 100,
    critical: 5,
    high: 20,
    medium: 40,
    low: 10,
    none: 5,
    unknown: 20,
    severityCoverage: 80,
    publicExploitReferences: 0,
    kevAdded: 0,
    partial: false,
    enriching: true,
    epssHigh: 0,
  };
  const keys = ["critical", "high", "medium", "low", "none", "unknown"] as const;
  assert.equal(
    keys.reduce((total, key) => total + (severityShare(point, key) ?? 0), 0),
    100,
  );
  assert.equal(severityShare({ ...point, published: 0 }, "critical"), null);
});

test("critical and high KPI uses scored CVEs while chart shares use all publications", () => {
  const point: MonthPoint = {
    month: "2026-06",
    published: 100,
    critical: 5,
    high: 20,
    medium: 40,
    low: 10,
    none: 5,
    unknown: 20,
    severityCoverage: 80,
    publicExploitReferences: 0,
    kevAdded: 0,
    partial: false,
    enriching: true,
    epssHigh: 0,
  };
  const summary = summarizePeriod([point], []);

  assert.equal(summary.criticalHigh, 25);
  assert.equal(summary.scored, 80);
  assert.equal(summary.criticalHighShare, 31.3);
  assert.equal(severityShare(point, "critical"), 5);
  assert.equal(severityShare(point, "high"), 20);
});

test("legend availability keeps zero values and omits all-null series", () => {
  assert.equal(hasRecordedValue([null, 0, null]), true);
  assert.equal(hasRecordedValue([null, null]), false);
});

test("LLM evidence uses the largest monthly lower bound and never sums programs", () => {
  const events: LlmEvidenceEvent[] = [
    {
      kind: "public_id_revealed",
      date: "2026-05-20",
      dateSemantics: "first_party_revealed_at",
      coverage: "curated_non_exhaustive",
      count: 14,
    },
    {
      kind: "program_report",
      date: "2026-05-22",
      dateSemantics: "report_publication_date",
      coverage: "curated_non_exhaustive",
      reportedMinimum: 28,
    },
    {
      kind: "program_report",
      date: "2026-05-23",
      dateSemantics: "report_publication_date",
      coverage: "curated_non_exhaustive",
      reportedMinimum: 10,
    },
  ];

  assert.equal(llmEvidenceForMonth("2026-05", events), 28);
  assert.equal(llmEvidenceForMonth("2026-04", events), 0);
});
