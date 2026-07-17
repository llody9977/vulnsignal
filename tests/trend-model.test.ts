import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  completeMonths,
  llmEvidenceForMonth,
  matchedYearPoints,
  monthsForYear,
  rollingMonths,
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
  assert.equal(
    year2025.reduce((total, point) => total + point.published, 0),
    48_162,
  );
});

test("year comparisons stop both series at the same complete month", () => {
  const matched = matchedYearPoints(
    dashboard.monthly,
    2025,
    2026,
    latestCompleteMonth,
  );
  assert.equal(matched.monthCap, 6);
  assert.equal(matched.first.length, matched.second.length);
  assert.equal(matched.first.at(-1)?.month, "2025-06");
  assert.equal(matched.second.at(-1)?.month, "2026-06");
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
