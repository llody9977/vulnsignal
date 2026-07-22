"use client";

import {
  Fragment,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from "react";
import {
  availableYears,
  comparisonYearOptions,
  completeMonths,
  hasRecordedValue,
  llmEvidenceForMonth,
  matchedYearPoints,
  monthsForYear,
  percentage,
  rollingMonths,
  severityShare,
  summarizePeriod,
  type LlmEvidenceEvent,
  type MonthPoint,
} from "./trend-model";

type ViewMode = "year" | "month" | "compare";
type ChartFamily = "signals" | "severity";
type ScaleMode = "indexed" | "absolute";
type SeverityMode = "count" | "share";
type MetricKey =
  | "published"
  | "kevAdded"
  | "publicExploitReferences"
  | "llmEvidence"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "none"
  | "unknown"
  | "epssHigh";

type ChartSeries = {
  key: string;
  label: string;
  shortLabel: string;
  values: Array<number | null>;
  color: string;
  axis: "left" | "right";
  dashed?: boolean;
  render?: "line" | "event";
  shape?: "circle" | "square" | "diamond";
  valueFormat?: "count" | "percent";
};

type ComparisonDisplay = {
  tone: "up" | "down" | "flat" | "new" | "unavailable";
  label: string;
  baseline?: string;
};

type MatrixRow = {
  label: string;
  values: Array<number | null>;
  event?: boolean;
  valueFormat?: "count" | "percent";
};

type IndicatorKey =
  | "criticalHigh"
  | "published"
  | "kevAdded"
  | "publicExploitReferences"
  | "severityCoverage"
  | "priorityWatch";

type PriorityWatchItem = {
  cveId: string;
  published: string;
  severity: string;
  score: number | null;
  cvssVersion: string | null;
  epss: number;
  epssPercentile: number;
  publicExploitReference: boolean;
  url: string;
};

type PriorityWatchDetail = {
  window: {
    start: string;
    end: string;
    days: number;
    scoreDate: string;
    threshold: number;
    thresholdSemantics: string;
  };
  total: number;
  criticalHigh: number;
  publicExploitReferences: number;
  itemsCompleteness?: "all_candidates";
  items: PriorityWatchItem[];
};

const metricOptions: Array<{ key: MetricKey; label: string }> = [
  { key: "published", label: "Published CVEs" },
  { key: "kevAdded", label: "KEV additions" },
  { key: "publicExploitReferences", label: "CVEs with exploit references" },
  { key: "llmEvidence", label: "LLM disclosure events" },
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
  { key: "none", label: "None (CVSS 0.0)" },
  { key: "unknown", label: "Unscored" },
  { key: "epssHigh", label: "Current EPSS ≥ 0.1 (project threshold)" },
];

function number(value: number) {
  return new Intl.NumberFormat("en-SG").format(Math.round(value));
}

function compact(value: number) {
  return new Intl.NumberFormat("en-SG", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(value);
}

function percent(value: number | null) {
  return value === null ? "—" : `${value.toFixed(1)}%`;
}

function chartValue(value: number, format: ChartSeries["valueFormat"] = "count") {
  return format === "percent" ? `${value.toFixed(1)}%` : number(value);
}

function monthLabel(value: string, short = false) {
  const date = new Date(`${value}-01T00:00:00Z`);
  return new Intl.DateTimeFormat("en-SG", {
    month: short ? "short" : "long",
    year: short ? "2-digit" : "numeric",
    timeZone: "UTC",
  }).format(date);
}

function shortMonth(value: string) {
  return new Intl.DateTimeFormat("en-SG", {
    month: "short",
    timeZone: "UTC",
  }).format(new Date(`${value}-01T00:00:00Z`));
}

function scoreDateLabel(value?: string | null) {
  if (!value) return "latest available score snapshot";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "latest available score snapshot";
  return new Intl.DateTimeFormat("en-SG", {
    day: "numeric",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  }).format(date);
}

function shortDateLabel(value: string) {
  const date = new Date(`${value.slice(0, 10)}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-SG", {
    day: "numeric",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  }).format(date);
}

function periodLabel(points: MonthPoint[], year: number) {
  if (!points.length) return String(year);
  const first = shortMonth(points[0].month);
  const last = shortMonth(points.at(-1)!.month);
  return `${first}${first === last ? "" : `–${last}`} ${year}`;
}

function metricValue(
  point: MonthPoint,
  key: MetricKey,
  events: LlmEvidenceEvent[],
) {
  return key === "llmEvidence"
    ? llmEvidenceForMonth(point.month, events)
    : point[key];
}

function metricPeriodValue(
  points: MonthPoint[],
  key: MetricKey,
  events: LlmEvidenceEvent[],
) {
  const values = points.map((point) => metricValue(point, key, events));
  return key === "llmEvidence"
    ? Math.max(...values, 0)
    : values.reduce((total, value) => total + value, 0);
}

function relativeComparison(
  current: number,
  previous: number,
  baselineLabel: string,
  hasBaseline: boolean,
): ComparisonDisplay {
  if (!hasBaseline) {
    return { tone: "unavailable", label: `No comparable ${baselineLabel} data` };
  }
  const baseline = `Baseline: ${number(previous)}`;
  if (previous === 0) {
    return current === 0
      ? { tone: "flat", label: `No change from ${baselineLabel}`, baseline }
      : { tone: "new", label: `New activity; ${baselineLabel} was zero`, baseline };
  }
  const delta = Math.round(((current - previous) / previous) * 1000) / 10;
  if (delta === 0) {
    return { tone: "flat", label: `No change from ${baselineLabel}`, baseline };
  }
  return {
    tone: delta > 0 ? "up" : "down",
    label: `${Math.abs(delta).toFixed(1)}% ${delta > 0 ? "higher" : "lower"} than ${baselineLabel}`,
    baseline,
  };
}

function pointComparison(
  current: number | null,
  previous: number | null,
  baselineLabel: string,
  hasBaseline: boolean,
): ComparisonDisplay {
  if (!hasBaseline || current === null || previous === null) {
    return { tone: "unavailable", label: `No comparable ${baselineLabel} data` };
  }
  const difference = Math.round((current - previous) * 10) / 10;
  const baseline = `Baseline: ${previous.toFixed(1)}%`;
  if (difference === 0) {
    return { tone: "flat", label: `No change from ${baselineLabel}`, baseline };
  }
  return {
    tone: difference > 0 ? "up" : "down",
    label: `${Math.abs(difference).toFixed(1)} percentage points ${difference > 0 ? "higher" : "lower"} than ${baselineLabel}`,
    baseline,
  };
}

function llmComparison(): ComparisonDisplay {
  return {
    tone: "unavailable",
    label: "Not comparable — sparse disclosure evidence",
    baseline: "Programme reports are separate lower bounds",
  };
}

function exploitComparison(
  currentPoints: MonthPoint[],
  previousPoints: MonthPoint[],
  current: number,
  previous: number,
  baselineLabel: string,
  hasBaseline: boolean,
): ComparisonDisplay {
  if (
    currentPoints.some((point) => point.enriching)
    || previousPoints.some((point) => point.enriching)
  ) {
    return {
      tone: "unavailable",
      label: "Not comparable — recent records are still being enriched",
      baseline: "Raw monthly counts remain visible",
    };
  }
  return relativeComparison(current, previous, baselineLabel, hasBaseline);
}

function exploitShareDetail(
  summary: ReturnType<typeof summarizePeriod>,
) {
  if (summary.publicExploitEnrichingMonths === 0) {
    return `${percent(summary.publicExploitShare)} of published CVEs`;
  }
  if (summary.publicExploitMatureMonths === 0) {
    return "Share unavailable; all selected months are still being enriched";
  }
  const monthWord = summary.publicExploitMatureMonths === 1 ? "month" : "months";
  const excludedWord = summary.publicExploitEnrichingMonths === 1 ? "month" : "months";
  return `${percent(summary.publicExploitShare)} in ${summary.publicExploitMatureMonths} mature ${monthWord}; ${summary.publicExploitEnrichingMonths} recent ${excludedWord} excluded`;
}

function MetricCell({
  metric,
  label,
  value,
  detail,
  comparison,
  active,
  onDrilldown,
}: {
  metric: IndicatorKey;
  label: string;
  value: string;
  detail: string;
  comparison: ComparisonDisplay;
  active: boolean;
  onDrilldown: (trigger: HTMLButtonElement) => void;
}) {
  const symbol = comparison.tone === "up" || comparison.tone === "new"
    ? "↑"
    : comparison.tone === "down"
      ? "↓"
      : comparison.tone === "flat"
        ? "→"
        : "—";
  return (
    <article className={`indicator-cell${active ? " indicator-cell--active" : ""}`}>
      <div className="indicator-cell__label">
        <strong>{label}</strong>
      </div>
      <button
        className="indicator-cell__value-link"
        id={`indicator-trigger-${metric}`}
        type="button"
        aria-label={`${active ? "Close" : "Open"} ${label} details: ${value}`}
        aria-haspopup="dialog"
        aria-expanded={active}
        aria-controls="indicator-drilldown"
        onClick={(event) => onDrilldown(event.currentTarget)}
      >
        <span>{value}</span>
        <b aria-hidden="true">↗</b>
      </button>
      <p>{detail}</p>
      <div className={`indicator-cell__comparison indicator-cell__comparison--${comparison.tone}`}>
        <span aria-hidden="true">{symbol}</span>
        <div>
          <strong>{comparison.label}</strong>
          {comparison.baseline ? <small>{comparison.baseline}</small> : null}
        </div>
      </div>
    </article>
  );
}

type DrilldownRow = {
  key: string;
  cells: ReactNode[];
};

function DrilldownFacts({
  items,
}: {
  items: Array<{ label: string; value: string; detail?: string }>;
}) {
  return (
    <dl className="indicator-drilldown__facts">
      {items.map((item) => (
        <div key={item.label}>
          <dt>{item.label}</dt>
          <dd>
            {item.value}
            {item.detail ? <small>{item.detail}</small> : null}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function DrilldownTable({
  caption,
  headers,
  rows,
}: {
  caption: string;
  headers: string[];
  rows: DrilldownRow[];
}) {
  return (
    <div className="indicator-drilldown__table-wrap">
      <table className="indicator-drilldown__table">
        <caption>{caption}</caption>
        <thead>
          <tr>{headers.map((header) => <th scope="col" key={header}>{header}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>{row.cells.map((cell, index) => index === 0
              ? <th scope="row" key={`${row.key}-${index}`}>{cell}</th>
              : <td key={`${row.key}-${index}`}>{cell}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function probabilityLabel(value: number) {
  const result = value * 100;
  return `${result < 1 ? result.toFixed(2) : result.toFixed(1)}%`;
}

function percentileLabel(value: number) {
  return `EPSS percentile ${(value * 100).toFixed(1)}%`;
}

function IndicatorDrilldown({
  metric,
  periodTitle,
  points,
  summary,
  baseline,
  baselineLabel,
  hasBaseline,
  priorityWatch,
  onRequestClose,
}: {
  metric: IndicatorKey;
  periodTitle: string;
  points: MonthPoint[];
  summary: ReturnType<typeof summarizePeriod>;
  baseline: ReturnType<typeof summarizePeriod>;
  baselineLabel: string;
  hasBaseline: boolean;
  priorityWatch?: PriorityWatchDetail | null;
  onRequestClose: () => void;
}) {
  const [priorityQuery, setPriorityQuery] = useState("");
  const [prioritySeverity, setPrioritySeverity] = useState("ALL");
  const peakPublished = points.reduce<MonthPoint | null>(
    (peak, point) => (!peak || point.published > peak.published ? point : peak),
    null,
  );
  const lowestPublished = points.reduce<MonthPoint | null>(
    (lowest, point) => (!lowest || point.published < lowest.published ? point : lowest),
    null,
  );
  const peakKev = points.reduce<MonthPoint | null>(
    (peak, point) => (!peak || point.kevAdded > peak.kevAdded ? point : peak),
    null,
  );
  const priorityItems = priorityWatch?.items ?? [];
  const normalizedQuery = priorityQuery.trim().toUpperCase();
  const filteredPriority = priorityItems.filter((item) =>
    (!normalizedQuery || item.cveId.includes(normalizedQuery))
    && (prioritySeverity === "ALL" || item.severity === prioritySeverity),
  );

  if (metric === "criticalHigh") {
    return (
      <>
        <div className="indicator-drilldown__intro">
          <p className="eyebrow">Severity composition / {periodTitle}</p>
          <h2 id="indicator-drilldown-title">Critical + high share</h2>
          <p><strong>{number(summary.criticalHigh)} ÷ {number(summary.scored)} scored CVEs = {percent(summary.criticalHighShare)}</strong>. The primary selected CVSS assessment is used; scores are not maximised.</p>
        </div>
        <DrilldownFacts items={[
          { label: "Critical", value: number(summary.critical) },
          { label: "High", value: number(summary.high) },
          { label: "Scored denominator", value: number(summary.scored), detail: `${number(summary.unknown)} unscored excluded` },
          { label: hasBaseline ? baselineLabel : "Baseline", value: hasBaseline ? percent(baseline.criticalHighShare) : "Not available" },
        ]} />
        <p className="indicator-drilldown__note">The severity chart’s Share view divides each category by all published CVEs. On that denominator, Critical + High is {percent(percentage(summary.criticalHigh, summary.published))}; this KPI excludes unscored records and is therefore {percent(summary.criticalHighShare)}.</p>
        <DrilldownTable
          caption="Critical and high severity breakdown by publication month"
          headers={["Month", "Critical", "High", "Scored", "Critical + High share"]}
          rows={points.map((point) => {
            const scored = point.published - point.unknown;
            return {
              key: point.month,
              cells: [<strong key="month">{monthLabel(point.month, true)}</strong>, number(point.critical), number(point.high), number(scored), percent(percentage(point.critical + point.high, scored))],
            };
          })}
        />
      </>
    );
  }

  if (metric === "published") {
    return (
      <>
        <div className="indicator-drilldown__intro">
          <p className="eyebrow">Publication volume / {periodTitle}</p>
          <h2 id="indicator-drilldown-title">CVEs published</h2>
          <p>This counts active NVD records by publication month. It measures reporting volume, not vulnerability incidence or organisational risk.</p>
        </div>
        <DrilldownFacts items={[
          { label: "Period total", value: number(summary.published) },
          { label: "Monthly average", value: summary.monthlyAverage.toFixed(1), detail: `${number(points.length)} complete ${points.length === 1 ? "month" : "months"}` },
          { label: "Highest month", value: peakPublished ? number(peakPublished.published) : "—", detail: peakPublished ? monthLabel(peakPublished.month) : undefined },
          { label: "Lowest month", value: lowestPublished ? number(lowestPublished.published) : "—", detail: lowestPublished ? monthLabel(lowestPublished.month) : undefined },
        ]} />
        <DrilldownTable
          caption="CVE publication volume by month"
          headers={["Month", "Published CVEs", "Share of selected period"]}
          rows={points.map((point) => ({
            key: point.month,
            cells: [<strong key="month">{monthLabel(point.month, true)}</strong>, number(point.published), percent(percentage(point.published, summary.published))],
          }))}
        />
      </>
    );
  }

  if (metric === "kevAdded") {
    return (
      <>
        <div className="indicator-drilldown__intro">
          <p className="eyebrow">Confirmed exploitation / {periodTitle}</p>
          <h2 id="indicator-drilldown-title">CISA KEV additions</h2>
          <p>Rows are grouped by CISA’s <code>dateAdded</code>. A KEV listing confirms known exploitation; it does not say when exploitation first began.</p>
        </div>
        <DrilldownFacts items={[
          { label: "Period total", value: number(summary.kevAdded) },
          { label: "Monthly average", value: (summary.kevAdded / Math.max(points.length, 1)).toFixed(1) },
          { label: "Highest month", value: peakKev ? number(peakKev.kevAdded) : "—", detail: peakKev ? monthLabel(peakKev.month) : undefined },
          { label: hasBaseline ? baselineLabel : "Baseline", value: hasBaseline ? number(baseline.kevAdded) : "Not available" },
        ]} />
        <a className="indicator-drilldown__jump" href="#kev-watch" onClick={onRequestClose}>View recently added KEV records ↘</a>
        <DrilldownTable
          caption="CISA KEV additions by month"
          headers={["Month", "KEV additions", "Share of selected period"]}
          rows={points.map((point) => ({
            key: point.month,
            cells: [<strong key="month">{monthLabel(point.month, true)}</strong>, number(point.kevAdded), percent(percentage(point.kevAdded, summary.kevAdded))],
          }))}
        />
      </>
    );
  }

  if (metric === "publicExploitReferences") {
    return (
      <>
        <div className="indicator-drilldown__intro">
          <p className="eyebrow">Public reference signal / {periodTitle}</p>
          <h2 id="indicator-drilldown-title">CVEs with exploit references</h2>
          <p>An NVD reference tagged “Exploit” points to public material. It does not prove that the material works or that the CVE is being exploited.</p>
        </div>
        <DrilldownFacts items={[
          { label: "Raw selected count", value: number(summary.publicExploitReferences) },
          { label: "Mature-cohort count", value: number(summary.publicExploitMatureReferences), detail: `${number(summary.publicExploitMaturePublished)} published CVEs in denominator` },
          { label: "Mature-cohort share", value: percent(summary.publicExploitShare) },
          { label: "Months still enriching", value: number(summary.publicExploitEnrichingMonths), detail: `${number(summary.publicExploitMatureMonths)} mature months` },
        ]} />
        <p className="indicator-drilldown__note">Recent records gain exploit tags as NVD enrichment continues. Raw counts stay visible, but shares and comparisons exclude enriching months rather than presenting the lag as a security trend.</p>
        <DrilldownTable
          caption="Exploit-reference signals and enrichment status by month"
          headers={["Month", "Exploit-reference CVEs", "Share of publications", "Cohort status"]}
          rows={points.map((point) => ({
            key: point.month,
            cells: [
              <strong key="month">{monthLabel(point.month, true)}</strong>,
              number(point.publicExploitReferences),
              point.enriching ? "Not calculated" : percent(percentage(point.publicExploitReferences, point.published)),
              <span className={`cohort-status cohort-status--${point.enriching ? "enriching" : "mature"}`} key="status">{point.enriching ? "Still enriching" : "Mature"}</span>,
            ],
          }))}
        />
      </>
    );
  }

  if (metric === "severityCoverage") {
    return (
      <>
        <div className="indicator-drilldown__intro">
          <p className="eyebrow">Scoring coverage / {periodTitle}</p>
          <h2 id="indicator-drilldown-title">CVEs with severity scores</h2>
          <p><strong>{number(summary.scored)} ÷ {number(summary.published)} published CVEs = {percent(summary.severityCoverage)}</strong>. A CVSS score of 0.0 is scored as “None”; only records without a selected score are unscored.</p>
        </div>
        <DrilldownFacts items={[
          { label: "Scored CVEs", value: number(summary.scored) },
          { label: "Unscored CVEs", value: number(summary.unknown) },
          { label: "Coverage", value: percent(summary.severityCoverage) },
          { label: hasBaseline ? baselineLabel : "Baseline", value: hasBaseline ? percent(baseline.severityCoverage) : "Not available" },
        ]} />
        <DrilldownTable
          caption="CVSS severity coverage by publication month"
          headers={["Month", "Published", "Scored", "Unscored", "Coverage"]}
          rows={points.map((point) => {
            const scored = point.published - point.unknown;
            return {
              key: point.month,
              cells: [<strong key="month">{monthLabel(point.month, true)}</strong>, number(point.published), number(scored), number(point.unknown), percent(percentage(scored, point.published))],
            };
          })}
        />
      </>
    );
  }

  const severityOptions = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"];
  return (
    <>
      <div className="indicator-drilldown__intro">
        <p className="eyebrow">Current snapshot / independent of report filters</p>
        <h2 id="indicator-drilldown-title">90-day EPSS screening watch</h2>
        <p>Current EPSS ≥ {priorityWatch?.window.threshold ?? 0.1}, published in the previous {priorityWatch?.window.days ?? 90} days and absent from the downloaded CISA KEV catalogue. This is an analytical screening list based on project thresholds, NOT a recommended remediation queue or patch priority order.</p>
      </div>
      <DrilldownFacts items={[
        { label: "Candidates", value: number(priorityWatch?.total ?? 0), detail: priorityWatch ? `${shortDateLabel(priorityWatch.window.start)}–${shortDateLabel(priorityWatch.window.end)}` : undefined },
        { label: "Critical or high", value: number(priorityWatch?.criticalHigh ?? 0), detail: percent(percentage(priorityWatch?.criticalHigh ?? 0, priorityWatch?.total ?? 0)) },
        { label: "Exploit reference", value: number(priorityWatch?.publicExploitReferences ?? 0), detail: percent(percentage(priorityWatch?.publicExploitReferences ?? 0, priorityWatch?.total ?? 0)) },
        { label: "EPSS score date", value: scoreDateLabel(priorityWatch?.window.scoreDate) },
      ]} />
      <p className="indicator-drilldown__note">EPSS is a probability estimate and can change daily. The ≥ {priorityWatch?.window.threshold ?? 0.1} threshold is defined by this project, not an official severity band. Absence from KEV does not prove that exploitation has not occurred.</p>
      <div className="indicator-drilldown__filters" aria-label="Priority candidate filters">
        <label>
          <span>Find CVE</span>
          <input type="search" value={priorityQuery} onChange={(event) => setPriorityQuery(event.target.value)} placeholder="CVE-2026-…" />
        </label>
        <label>
          <span>Severity</span>
          <select value={prioritySeverity} onChange={(event) => setPrioritySeverity(event.target.value)}>
            {severityOptions.map((severity) => <option key={severity} value={severity}>{severity === "ALL" ? "All severities" : severity === "UNKNOWN" ? "Unscored" : severity}</option>)}
          </select>
        </label>
        <p><strong>{number(filteredPriority.length)}</strong> of {number(priorityItems.length)} detailed candidates</p>
      </div>
      {filteredPriority.length ? (
        <DrilldownTable
          caption="Current 90-day EPSS screening watch candidates sorted by EPSS probability"
          headers={["CVE", "Published", "Severity", "EPSS", "Exploit reference"]}
          rows={filteredPriority.map((item) => ({
            key: item.cveId,
            cells: [
              <a href={item.url} key="cve">{item.cveId}</a>,
              shortDateLabel(item.published),
              <span key="severity"><span className={`severity-badge severity-badge--${item.severity.toLowerCase()}`}>{item.severity === "UNKNOWN" ? "Unscored" : `${item.severity}${item.score === null ? "" : ` ${item.score}`}`}</span>{item.cvssVersion ? <small>CVSS {item.cvssVersion}</small> : null}</span>,
              <span key="epss"><strong>{probabilityLabel(item.epss)}</strong><small>{percentileLabel(item.epssPercentile)}</small></span>,
              <span key="exploit-reference">
                {item.publicExploitReference ? (
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${item.cveId}#vulnHyperlinksSection`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <strong>Yes</strong>
                  </a>
                ) : (
                  <strong>No</strong>
                )}
                <small>{item.publicExploitReference ? "NVD-tagged exploit reference" : "No NVD exploit tag in this snapshot"}</small>
              </span>,
            ],
          }))}
        />
      ) : <p className="indicator-drilldown__empty">No candidates match these filters.</p>}
      {priorityWatch?.itemsCompleteness !== "all_candidates" ? <p className="indicator-drilldown__note">The snapshot does not state that every candidate detail row is retained.</p> : null}
    </>
  );
}

type PlotPoint = { x: number; y: number; value: number; index: number };

function plotPoints(values: Array<number | null>, maximum: number): Array<PlotPoint | null> {
  return values.map((value, index) => {
    if (value === null) return null;
    return {
      x: values.length === 1 ? 50 : 4 + (index / (values.length - 1)) * 92,
      y: 90 - (value / Math.max(maximum, 1)) * 74,
      value,
      index,
    };
  });
}

function UnifiedChart({
  labels,
  series,
  scaleMode,
  activeIndex,
  onActiveIndex,
}: {
  labels: string[];
  series: ChartSeries[];
  scaleMode: ScaleMode;
  activeIndex: number;
  onActiveIndex: (index: number) => void;
}) {
  const axisMax = {
    left: Math.max(
      ...series
        .filter((item) => item.axis === "left")
        .flatMap((item) => item.values.map((value) => value ?? 0)),
      1,
    ),
    right: Math.max(
      ...series
        .filter((item) => item.axis === "right")
        .flatMap((item) => item.values.map((value) => value ?? 0)),
      1,
    ),
  };
  const hasValues = (item: ChartSeries) => item.values.some((value) => value !== null);
  const hasRightAxis = series.some((item) => item.axis === "right" && hasValues(item));
  const hasLeftAxis = series.some((item) => item.axis === "left" && hasValues(item));
  const leftUsesPercent = series.some(
    (item) => item.axis === "left" && hasValues(item),
  ) && series
    .filter((item) => item.axis === "left" && hasValues(item))
    .every((item) => item.valueFormat === "percent");
  const rightUsesPercent = series.some(
    (item) => item.axis === "right" && hasValues(item),
  ) && series
    .filter((item) => item.axis === "right" && hasValues(item))
    .every((item) => item.valueFormat === "percent");
  const leftAxisTitle = leftUsesPercent
    ? "Share of monthly CVEs"
    : series
      .filter((item) => item.axis === "left" && hasValues(item))
      .map((item) => item.shortLabel)
      .join(" / ");
  const rightAxisTitle = rightUsesPercent
    ? "Share"
    : series
      .filter((item) => item.axis === "right" && hasValues(item))
      .map((item) => item.shortLabel)
      .join(" / ");
  const leftAxisLabels = scaleMode === "indexed"
    ? ["100%", "50%", "0"]
    : leftUsesPercent
      ? [`${axisMax.left.toFixed(1)}%`, `${(axisMax.left / 2).toFixed(1)}%`, "0%"]
      : [compact(axisMax.left), compact(axisMax.left / 2), "0"];
  const rightAxisLabels = [
    rightUsesPercent ? `${axisMax.right.toFixed(1)}%` : compact(axisMax.right),
    rightUsesPercent ? `${(axisMax.right / 2).toFixed(1)}%` : compact(axisMax.right / 2),
    rightUsesPercent ? "0%" : "0",
  ];
  const safeActive = Math.min(Math.max(activeIndex, 0), Math.max(labels.length - 1, 0));

  return (
    <div className="unified-chart">
      <div
        className="chart-stage"
        role="group"
        aria-label={`Combined vulnerability trend with ${series.length} visible data series`}
      >
        <div className="chart-stage__grid" aria-hidden="true" />
        {scaleMode === "indexed" || hasLeftAxis ? (
          <div className="chart-y-axis chart-y-axis--left" aria-hidden="true">
            {leftAxisLabels.map((label, index) => <span key={`${label}-${index}`}>{label}</span>)}
          </div>
        ) : null}
        {scaleMode === "absolute" && hasRightAxis ? (
          <div className="chart-y-axis chart-y-axis--right" aria-hidden="true">
            {rightAxisLabels.map((label, index) => <span key={`${label}-${index}`}>{label}</span>)}
          </div>
        ) : null}
        {scaleMode === "absolute" && hasLeftAxis && hasRightAxis ? (
          <div className="chart-scale-keys" aria-hidden="true">
            <span>Left · {leftAxisTitle}</span>
            <span>Right · {rightAxisTitle}</span>
          </div>
        ) : null}
        {labels.length > 0 ? (
          <span
            className="chart-stage__cursor"
            style={{
              "--cursor-x": `${labels.length === 1 ? 50 : 4 + (safeActive / (labels.length - 1)) * 92}%`,
            } as CSSProperties}
            aria-hidden="true"
          />
        ) : null}
        {series.map((item) => {
          const seriesMax = Math.max(...item.values.map((value) => value ?? 0), 1);
          const maximum = scaleMode === "indexed" ? seriesMax : axisMax[item.axis];
          const points = plotPoints(item.values, maximum);
          return (
            <span className="chart-series" key={item.key}>
              <svg
                className="chart-lines"
                viewBox="0 0 100 100"
                preserveAspectRatio="none"
                aria-hidden="true"
                focusable="false"
              >
                {item.render === "event"
                  ? points.map((point) => point ? (
                    <line
                      key={`${item.key}-${point.index}-stem`}
                      x1={point.x}
                      y1="90"
                      x2={point.x}
                      y2={point.y}
                      stroke={item.color}
                      strokeWidth="2"
                      strokeDasharray="3 3"
                      strokeLinecap="round"
                      vectorEffect="non-scaling-stroke"
                    />
                  ) : null)
                  : points.slice(0, -1).map((point, index) => {
                      const next = points[index + 1];
                      if (!point || !next) return null;
                      return (
                        <line
                          key={`${item.key}-${point.index}`}
                          x1={point.x}
                          y1={point.y}
                          x2={next.x}
                          y2={next.y}
                          stroke={item.color}
                          strokeWidth="2"
                          strokeDasharray={item.dashed ? "6 4" : undefined}
                          strokeLinecap="round"
                          vectorEffect="non-scaling-stroke"
                        />
                      );
                    })}
              </svg>
              {points.map((point) =>
                point ? (
                  <Fragment key={`${item.key}-${point.index}-point`}>
                    <button
                      type="button"
                      className={`chart-point chart-point--${item.shape ?? "circle"}${item.render === "event" ? " chart-point--event" : ""}`}
                      style={{
                        "--x": `${point.x}%`,
                        "--y": `${point.y}%`,
                        "--series": item.color,
                      } as CSSProperties}
                      aria-label={`${labels[point.index]}: ${item.label} ${item.render === "event" ? "at least " : ""}${chartValue(point.value, item.valueFormat)}`}
                      onFocus={() => onActiveIndex(point.index)}
                      onMouseEnter={() => onActiveIndex(point.index)}
                      onClick={() => onActiveIndex(point.index)}
                    />
                    {item.render === "event" ? (
                      <span
                        className="chart-event-label"
                        style={{
                          "--x": `${point.x}%`,
                          "--y": `${point.y}%`,
                          "--series": item.color,
                        } as CSSProperties}
                        aria-hidden="true"
                      >
                        ≥ {number(point.value)}
                      </span>
                    ) : null}
                  </Fragment>
                ) : null,
              )}
            </span>
          );
        })}
      </div>

      <div className="chart-axis" aria-hidden="true">
        {labels.map((label) => <span key={label}>{label}</span>)}
      </div>

      {labels.length > 1 ? (
        <label className="chart-scrubber">
          <span>Inspect month</span>
          <input
            type="range"
            min="0"
            max={labels.length - 1}
            value={safeActive}
            onChange={(event) => onActiveIndex(Number(event.target.value))}
          />
        </label>
      ) : null}

      <div className="chart-readout" aria-live="polite">
        <strong>{labels[safeActive] ?? "No data"}</strong>
        <div>
          {series.map((item) => (
            <span key={item.key}>
              <i style={{ background: item.color }} />
              {item.shortLabel}
              <b>
                {item.values[safeActive] === null
                  ? item.render === "event" ? "No recorded event" : "—"
                  : item.render === "event"
                    ? `≥ ${number(item.values[safeActive] ?? 0)}`
                    : chartValue(item.values[safeActive] ?? 0, item.valueFormat)}
              </b>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function SignalMatrix({
  points,
  events,
  compareRows,
  severityMode,
}: {
  points: MonthPoint[];
  events: LlmEvidenceEvent[];
  compareRows?: MatrixRow[];
  severityMode: SeverityMode;
}) {
  const severityValues = (
    key: "critical" | "high" | "medium" | "low" | "none" | "unknown",
  ) => points.map((point) => severityMode === "share"
    ? severityShare(point, key)
    : point[key]);
  const severityFormat = severityMode === "share" ? "percent" as const : "count" as const;
  const standardRows: MatrixRow[] = [
    { label: "CVE", values: points.map((point) => point.published) },
    { label: "Critical", values: severityValues("critical"), valueFormat: severityFormat },
    { label: "High", values: severityValues("high"), valueFormat: severityFormat },
    { label: "Medium", values: severityValues("medium"), valueFormat: severityFormat },
    { label: "Low", values: severityValues("low"), valueFormat: severityFormat },
    { label: "None (CVSS 0.0)", values: severityValues("none"), valueFormat: severityFormat },
    { label: "Unscored", values: severityValues("unknown"), valueFormat: severityFormat },
    { label: "KEV", values: points.map((point) => point.kevAdded) },
    { label: "Exploit ref", values: points.map((point) => point.publicExploitReferences) },
    { label: "Current EPSS ≥ 0.1", values: points.map((point) => point.epssHigh) },
    {
      label: "LLM disclosures",
      values: points.map((point) => llmEvidenceForMonth(point.month, events) || null),
      event: true,
    },
  ];
  const rows = compareRows ?? standardRows;
  return (
    <div className="matrix-wrap">
      <table className="signal-matrix">
        <caption>Values aligned to the combined trend chart</caption>
        <thead>
          <tr>
            <th>Signal</th>
            {points.map((point) => (
              <th key={point.month}>
                {monthLabel(point.month, true)}
                {point.enriching ? " *" : ""}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const maximum = Math.max(...row.values.map((value) => value ?? 0), 1);
            return (
              <tr key={row.label}>
                <th scope="row">{row.label}</th>
                {row.values.map((value, index) => {
                  const opacity = value === null ? 0 : 0.035 + (value / maximum) * 0.18;
                  return (
                    <td
                      key={`${row.label}-${points[index]?.month ?? index}`}
                      className={value === null ? "is-no-event" : undefined}
                      style={{ "--heat-opacity": opacity } as CSSProperties}
                      aria-label={row.event
                        ? value === null
                          ? "No recorded disclosure event"
                          : `At least ${number(value)} CVEs reported in this disclosure event`
                        : undefined}
                    >
                      {value === null
                        ? "—"
                        : row.event
                          ? `≥ ${number(value)}`
                          : row.valueFormat === "percent"
                            ? `${value.toFixed(1)}%`
                            : number(value)}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
      {rows.some((row) => row.event) ? (
        <p className="matrix-note">— means the registry has no recorded disclosure event for that month. It does not mean zero LLM-assisted discoveries.</p>
      ) : null}
      {points.some((point) => point.enriching) ? (
        <p className="matrix-note">* Recent months are still being enriched by NVD with exploit references.</p>
      ) : null}
    </div>
  );
}

export function TrendExplorer({
  monthly,
  latestCompleteMonth,
  events,
  epssScoreDate,
  priorityWatch,
}: {
  monthly: MonthPoint[];
  latestCompleteMonth: string;
  events: LlmEvidenceEvent[];
  epssScoreDate?: string | null;
  priorityWatch?: PriorityWatchDetail | null;
}) {
  const complete = useMemo(
    () => completeMonths(monthly, latestCompleteMonth),
    [monthly, latestCompleteMonth],
  );
  const years = useMemo(
    () => availableYears(monthly, latestCompleteMonth),
    [monthly, latestCompleteMonth],
  );
  const latestYear = Number(latestCompleteMonth.slice(0, 4));
  const priorYear = years.includes(latestYear - 1) ? latestYear - 1 : years.at(-2) ?? latestYear;
  const [viewMode, setViewMode] = useState<ViewMode>("year");
  const [chartFamily, setChartFamily] = useState<ChartFamily>("signals");
  const [scaleMode, setScaleMode] = useState<ScaleMode>("absolute");
  const [severityMode, setSeverityMode] = useState<SeverityMode>("count");
  const [selectedYear, setSelectedYear] = useState(latestYear);
  const [selectedMonth, setSelectedMonth] = useState(latestCompleteMonth);
  const [compareFirst, setCompareFirst] = useState(priorYear);
  const [compareSecond, setCompareSecond] = useState(latestYear);
  const [compareMetric, setCompareMetric] = useState<MetricKey>("published");
  const [hiddenSeries, setHiddenSeries] = useState<string[]>([]);
  const [activeIndex, setActiveIndex] = useState(11);
  const [activeIndicator, setActiveIndicator] = useState<IndicatorKey | null>(null);
  const drilldownDialogRef = useRef<HTMLDialogElement>(null);
  const drilldownTriggerRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    const dialog = drilldownDialogRef.current;
    if (!activeIndicator || !dialog || dialog.open) return;
    dialog.showModal();
    requestAnimationFrame(() => dialog.querySelector<HTMLButtonElement>("button")?.focus());
  }, [activeIndicator]);

  const matched = matchedYearPoints(
    monthly,
    compareFirst,
    compareSecond,
    latestCompleteMonth,
  );
  const yearPoints = monthsForYear(monthly, selectedYear, latestCompleteMonth);
  const yearMonthNumbers = new Set(
    yearPoints.map((point) => Number(point.month.slice(5, 7))),
  );
  const previousYearPoints = monthsForYear(
    monthly,
    selectedYear - 1,
    latestCompleteMonth,
  ).filter((point) => yearMonthNumbers.has(Number(point.month.slice(5, 7))));
  const rolling = rollingMonths(monthly, selectedMonth, latestCompleteMonth);
  const previousSelectedMonth = `${Number(selectedMonth.slice(0, 4)) - 1}-${selectedMonth.slice(5, 7)}`;
  const chartPoints = viewMode === "year"
    ? yearPoints
    : viewMode === "month"
      ? rolling
      : matched.second;
  const summaryPoints = viewMode === "month"
    ? complete.filter((point) => point.month === selectedMonth)
    : chartPoints;
  const baselinePoints = viewMode === "compare"
    ? matched.first
    : viewMode === "month"
      ? complete.filter(
          (point) => point.month === previousSelectedMonth,
        )
      : previousYearPoints;
  const summary = summarizePeriod(summaryPoints, events);
  const baseline = summarizePeriod(baselinePoints, events);
  const baselineLabel = viewMode === "compare"
    ? periodLabel(matched.first, compareFirst)
    : viewMode === "month"
      ? monthLabel(baselinePoints[0]?.month ?? previousSelectedMonth, true)
      : periodLabel(baselinePoints, selectedYear - 1);
  const hasBaseline = baselinePoints.length > 0;

  const labels = chartPoints.map((point) =>
    viewMode === "compare" ? shortMonth(point.month) : monthLabel(point.month, true),
  );
  const signalSeries: ChartSeries[] = [
    {
      key: "published",
      label: "Published CVEs",
      shortLabel: "CVE",
      values: chartPoints.map((point) => point.published),
      color: "var(--ink)",
      axis: "left",
    },
    {
      key: "kevAdded",
      label: "CISA KEV additions",
      shortLabel: "KEV",
      values: chartPoints.map((point) => point.kevAdded),
      color: "var(--accent)",
      axis: "right",
      shape: "square",
    },
    {
      key: "publicExploitReferences",
      label: "CVEs with public exploit references",
      shortLabel: "Exploit",
      values: chartPoints.map((point) => point.publicExploitReferences),
      color: "var(--amber)",
      axis: "left",
      dashed: true,
    },
    {
      key: "epssHigh",
      label: "Current EPSS ≥ 0.1 (project threshold)",
      shortLabel: "EPSS ≥ 0.1",
      values: chartPoints.map((point) => point.epssHigh),
      color: "var(--critical)",
      axis: "left",
      dashed: true,
      shape: "circle",
    },
    {
      key: "llmEvidence",
      label: "LLM disclosure events",
      shortLabel: "LLM",
      values: chartPoints.map((point) => {
        const value = llmEvidenceForMonth(point.month, events);
        return value || null;
      }),
      color: "var(--teal)",
      axis: "right",
      render: "event",
      shape: "diamond",
    },
  ];
  const severityValues = (
    key: "critical" | "high" | "medium" | "low" | "none" | "unknown",
  ) => chartPoints.map((point) => severityMode === "share"
    ? severityShare(point, key)
    : point[key]);
  const severityFormat = severityMode === "share" ? "percent" as const : "count" as const;
  const severitySeries: ChartSeries[] = [
    { key: "critical", label: "Critical", shortLabel: "Critical", values: severityValues("critical"), valueFormat: severityFormat, color: "var(--critical)", axis: "left", shape: "square" },
    { key: "high", label: "High", shortLabel: "High", values: severityValues("high"), valueFormat: severityFormat, color: "var(--amber)", axis: "left" },
    { key: "medium", label: "Medium", shortLabel: "Medium", values: severityValues("medium"), valueFormat: severityFormat, color: "var(--accent)", axis: "left", dashed: true },
    { key: "low", label: "Low", shortLabel: "Low", values: severityValues("low"), valueFormat: severityFormat, color: "var(--teal)", axis: "left", shape: "diamond" },
    { key: "none", label: "None (CVSS 0.0)", shortLabel: "None", values: severityValues("none"), valueFormat: severityFormat, color: "var(--neutral)", axis: "left" },
    { key: "unknown", label: "Unscored", shortLabel: "Unscored", values: severityValues("unknown"), valueFormat: severityFormat, color: "var(--neutral)", axis: "left", dashed: true, shape: "square" },
  ];
  const comparisonSeries: ChartSeries[] = [
    {
      key: `compare-${compareFirst}`,
      label: `${compareFirst} ${metricOptions.find((item) => item.key === compareMetric)?.label}`,
      shortLabel: String(compareFirst),
      values: matched.first.map((point) => {
        const value = metricValue(point, compareMetric, events);
        return compareMetric === "llmEvidence" ? value || null : value;
      }),
      color: "var(--neutral)",
      axis: "left",
      dashed: compareMetric !== "llmEvidence",
      render: compareMetric === "llmEvidence" ? "event" : "line",
      shape: compareMetric === "llmEvidence" ? "diamond" : undefined,
    },
    {
      key: `compare-${compareSecond}`,
      label: `${compareSecond} ${metricOptions.find((item) => item.key === compareMetric)?.label}`,
      shortLabel: String(compareSecond),
      values: matched.second.map((point) => {
        const value = metricValue(point, compareMetric, events);
        return compareMetric === "llmEvidence" ? value || null : value;
      }),
      color: "var(--accent)",
      axis: "left",
      render: compareMetric === "llmEvidence" ? "event" : "line",
      shape: compareMetric === "llmEvidence" ? "diamond" : "square",
    },
  ];
  const allSeries = viewMode === "compare"
    ? comparisonSeries
    : chartFamily === "signals"
      ? signalSeries
      : severitySeries;
  const availableSeries = allSeries.filter((series) =>
    hasRecordedValue(series.values),
  );
  const visibleSeries = availableSeries.filter((series) => !hiddenSeries.includes(series.key));
  const llmLayerOmitted = viewMode !== "compare"
    && chartFamily === "signals"
    && signalSeries.find((series) => series.key === "llmEvidence")?.values.every((value) => value === null);
  const effectiveScale = viewMode === "compare" || chartFamily === "severity" ? "absolute" : scaleMode;
  const safeActive = Math.min(activeIndex, Math.max(labels.length - 1, 0));
  const comparisonMetricLabel = metricOptions.find(
    (item) => item.key === compareMetric,
  )?.label ?? "Selected signal";
  const compareFirstValue = metricPeriodValue(
    matched.first,
    compareMetric,
    events,
  );
  const compareSecondValue = metricPeriodValue(
    matched.second,
    compareMetric,
    events,
  );
  const compareDifference = compareSecondValue - compareFirstValue;
  const compareChange = compareMetric === "llmEvidence"
    ? llmComparison()
    : compareMetric === "publicExploitReferences"
      ? exploitComparison(
          matched.second,
          matched.first,
          compareSecondValue,
          compareFirstValue,
          periodLabel(matched.first, compareFirst),
          matched.first.length > 0,
        )
      : relativeComparison(
          compareSecondValue,
          compareFirstValue,
          periodLabel(matched.first, compareFirst),
          matched.first.length > 0,
        );
  const compareDifferenceLabel = compareMetric === "llmEvidence"
    || (compareMetric === "publicExploitReferences" && compareChange.tone === "unavailable")
    ? "Not calculated"
    : `${compareDifference > 0 ? "+" : compareDifference < 0 ? "−" : ""}${number(Math.abs(compareDifference))}`;
  const compareValueLabel = (value: number) => compareMetric === "llmEvidence"
    ? value ? `≥ ${number(value)}` : "No event"
    : number(value);

  const periodTitle = viewMode === "year"
    ? yearPoints.length === 12
      ? `${selectedYear} annual report`
      : `${selectedYear} year to date (${periodLabel(yearPoints, selectedYear).replace(` ${selectedYear}`, "")})`
    : viewMode === "month"
      ? `${monthLabel(selectedMonth)} report`
      : `${periodLabel(matched.first, compareFirst)} vs ${periodLabel(matched.second, compareSecond)}`;
  const drilldownPeriodTitle = viewMode === "compare"
    ? `${periodLabel(matched.second, compareSecond)} comparison value`
    : periodTitle;
  const periodDetail = viewMode === "month"
    ? "Indicators use the selected month; the plot keeps 12 complete months of context."
    : viewMode === "compare"
      ? "Both periods include the same complete calendar months."
      : "Partial months are excluded from totals and trend lines.";

  const toggleSeries = (key: string) => {
    setHiddenSeries((current) =>
      current.includes(key) ? current.filter((item) => item !== key) : [...current, key],
    );
  };

  const openDrilldown = (
    metric: IndicatorKey,
    trigger: HTMLButtonElement,
  ) => {
    drilldownTriggerRef.current = trigger;
    setActiveIndicator(metric);
  };

  const closeDrilldown = () => {
    drilldownDialogRef.current?.close();
  };

  const closeDrilldownForNavigation = () => {
    drilldownTriggerRef.current = null;
    closeDrilldown();
  };

  const handleDrilldownClosed = () => {
    setActiveIndicator(null);
    requestAnimationFrame(() => drilldownTriggerRef.current?.focus());
  };

  const compareRows = viewMode === "compare"
    ? [
        { label: periodLabel(matched.first, compareFirst), values: comparisonSeries[0].values, event: compareMetric === "llmEvidence" },
        { label: periodLabel(matched.second, compareSecond), values: comparisonSeries[1].values, event: compareMetric === "llmEvidence" },
      ]
    : undefined;

  return (
    <section className="report-console" id="reporting">
      <div className="report-console__header">
        <div>
          <p className="eyebrow">[01] Interactive report</p>
          <h2>{periodTitle}</h2>
          <p>{periodDetail}</p>
        </div>
        <span className="data-state"><i />Complete through {monthLabel(latestCompleteMonth)}</span>
      </div>

      <div className="filter-rail" aria-label="Report filters">
        <fieldset>
          <legend>Report view</legend>
          <div className="segmented-control">
            {(["year", "month", "compare"] as ViewMode[]).map((mode) => (
              <button
                type="button"
                key={mode}
                aria-pressed={viewMode === mode}
                onClick={() => {
                  setViewMode(mode);
                  setHiddenSeries([]);
                }}
              >
                {mode === "compare" ? "Compare years" : mode}
              </button>
            ))}
          </div>
        </fieldset>

        {viewMode === "year" ? (
          <label>
            <span>Calendar year</span>
            <select value={selectedYear} onChange={(event) => setSelectedYear(Number(event.target.value))}>
              {[...years].reverse().map((year) => <option key={year}>{year}</option>)}
            </select>
          </label>
        ) : null}

        {viewMode === "month" ? (
          <label>
            <span>Complete month</span>
            <select value={selectedMonth} onChange={(event) => setSelectedMonth(event.target.value)}>
              {[...complete].reverse().map((point) => (
                <option value={point.month} key={point.month}>{monthLabel(point.month)}</option>
              ))}
            </select>
          </label>
        ) : null}

        {viewMode === "compare" ? (
          <>
            <label>
              <span>Baseline year</span>
              <select value={compareFirst} onChange={(event) => setCompareFirst(Number(event.target.value))}>
                {comparisonYearOptions([...years].reverse(), compareSecond).map((year) => <option value={year} key={year}>{year}</option>)}
              </select>
            </label>
            <label>
              <span>Comparison year</span>
              <select value={compareSecond} onChange={(event) => setCompareSecond(Number(event.target.value))}>
                {comparisonYearOptions([...years].reverse(), compareFirst).map((year) => <option value={year} key={year}>{year}</option>)}
              </select>
            </label>
            <label>
              <span>Metric</span>
              <select value={compareMetric} onChange={(event) => setCompareMetric(event.target.value as MetricKey)}>
                {metricOptions.map((item) => <option value={item.key} key={item.key}>{item.label}</option>)}
              </select>
            </label>
          </>
        ) : (
          <fieldset>
            <legend>Chart data</legend>
            <div className="segmented-control">
              {(["signals", "severity"] as ChartFamily[]).map((family) => (
                <button
                  type="button"
                  key={family}
                  aria-pressed={chartFamily === family}
                  onClick={() => {
                    setChartFamily(family);
                    setHiddenSeries([]);
                  }}
                >
                  {family}
                </button>
              ))}
            </div>
          </fieldset>
        )}
      </div>

      {viewMode === "compare" ? (
        <div className="comparison-summary" aria-live="polite">
          <div className="comparison-summary__title">
            <span>Selected comparison</span>
            <strong>{comparisonMetricLabel}</strong>
          </div>
          <div>
            <span>{periodLabel(matched.first, compareFirst)}</span>
            <strong>{compareValueLabel(compareFirstValue)}</strong>
          </div>
          <div>
            <span>{periodLabel(matched.second, compareSecond)}</span>
            <strong>{compareValueLabel(compareSecondValue)}</strong>
          </div>
          <div className={`comparison-summary__change comparison-summary__change--${compareChange.tone}`}>
            <span>Difference</span>
            <strong>{compareDifferenceLabel}</strong>
            <small>{compareMetric === "llmEvidence" ? "No difference is calculated because programme counts may overlap." : compareChange.label}</small>
          </div>
        </div>
      ) : null}

      <div className="indicator-grid">
        <MetricCell
          metric="criticalHigh"
          label="Critical + high share"
          value={percent(summary.criticalHighShare)}
          detail={`${number(summary.criticalHigh)} critical or high CVEs among scored records`}
          comparison={pointComparison(summary.criticalHighShare, baseline.criticalHighShare, baselineLabel, hasBaseline)}
          active={activeIndicator === "criticalHigh"}
          onDrilldown={(trigger) => openDrilldown("criticalHigh", trigger)}
        />
        <MetricCell
          metric="published"
          label="CVEs published"
          value={number(summary.published)}
          detail={`${compact(summary.monthlyAverage)} average per complete month`}
          comparison={relativeComparison(summary.published, baseline.published, baselineLabel, hasBaseline)}
          active={activeIndicator === "published"}
          onDrilldown={(trigger) => openDrilldown("published", trigger)}
        />
        <MetricCell
          metric="kevAdded"
          label="KEV additions"
          value={number(summary.kevAdded)}
          detail={`${(summary.kevAdded / Math.max(summaryPoints.length, 1)).toFixed(1)} average per month`}
          comparison={relativeComparison(summary.kevAdded, baseline.kevAdded, baselineLabel, hasBaseline)}
          active={activeIndicator === "kevAdded"}
          onDrilldown={(trigger) => openDrilldown("kevAdded", trigger)}
        />
        <MetricCell
          metric="publicExploitReferences"
          label="CVEs with exploit references"
          value={number(summary.publicExploitReferences)}
          detail={exploitShareDetail(summary)}
          comparison={exploitComparison(
            summaryPoints,
            baselinePoints,
            summary.publicExploitReferences,
            baseline.publicExploitReferences,
            baselineLabel,
            hasBaseline,
          )}
          active={activeIndicator === "publicExploitReferences"}
          onDrilldown={(trigger) => openDrilldown("publicExploitReferences", trigger)}
        />
        <MetricCell
          metric="severityCoverage"
          label="CVEs with severity scores"
          value={percent(summary.severityCoverage)}
          detail={`${number(summary.unknown)} records remain unscored`}
          comparison={pointComparison(summary.severityCoverage, baseline.severityCoverage, baselineLabel, hasBaseline)}
          active={activeIndicator === "severityCoverage"}
          onDrilldown={(trigger) => openDrilldown("severityCoverage", trigger)}
        />
        <MetricCell
          metric="priorityWatch"
          label="90-day EPSS screening watch"
          value={priorityWatch ? number(priorityWatch.total) : "—"}
          detail={priorityWatch
            ? `${number(priorityWatch.criticalHigh)} are critical or high; published ${shortDateLabel(priorityWatch.window.start)}–${shortDateLabel(priorityWatch.window.end)}`
            : "Current watchlist data is not available"}
          comparison={{
            tone: "unavailable",
            label: "Current watchlist — not a period trend",
            baseline: priorityWatch
              ? `EPSS snapshot: ${scoreDateLabel(priorityWatch.window.scoreDate)}`
              : undefined,
          }}
          active={activeIndicator === "priorityWatch"}
          onDrilldown={(trigger) => openDrilldown("priorityWatch", trigger)}
        />
      </div>

      <dialog
        className="indicator-drilldown"
        id="indicator-drilldown"
        ref={drilldownDialogRef}
        aria-labelledby="indicator-drilldown-title"
        onClose={handleDrilldownClosed}
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            event.preventDefault();
            closeDrilldown();
          }
        }}
      >
        <div className="indicator-drilldown__bar">
          <span>Metric details</span>
          <button type="button" onClick={closeDrilldown}>Close details <b aria-hidden="true">×</b></button>
        </div>
        <div className="indicator-drilldown__body">
          {activeIndicator ? (
            <IndicatorDrilldown
              metric={activeIndicator}
              periodTitle={drilldownPeriodTitle}
              points={summaryPoints}
              summary={summary}
              baseline={baseline}
              baselineLabel={baselineLabel}
              hasBaseline={hasBaseline}
              priorityWatch={priorityWatch}
              onRequestClose={closeDrilldownForNavigation}
            />
          ) : null}
        </div>
      </dialog>

      <article className="unified-panel">
        <div className="unified-panel__heading">
          <div>
            <p className="eyebrow">Combined timeline</p>
            <h3>{viewMode === "compare" ? metricOptions.find((item) => item.key === compareMetric)?.label : chartFamily === "signals" ? "CVE, KEV, exploit and EPSS trends, with LLM disclosure events" : "Severity by publication month"}</h3>
          </div>
          {viewMode !== "compare" && chartFamily === "signals" ? (
            <div className="scale-control" aria-label="Chart display">
              <span>Chart display</span>
              {(["indexed", "absolute"] as ScaleMode[]).map((mode) => (
                <button type="button" key={mode} aria-pressed={scaleMode === mode} onClick={() => setScaleMode(mode)}>{mode === "indexed" ? "Relative trend" : "Actual counts"}</button>
              ))}
            </div>
          ) : viewMode !== "compare" && chartFamily === "severity" ? (
            <div className="scale-control" aria-label="Severity display">
              <span>Severity display</span>
              {(["count", "share"] as SeverityMode[]).map((mode) => (
                <button type="button" key={mode} aria-pressed={severityMode === mode} onClick={() => setSeverityMode(mode)}>{mode === "count" ? "Counts" : "Share"}</button>
              ))}
            </div>
          ) : <span className="scale-note">Actual counts on one scale</span>}
        </div>

        <div className="scale-explainer" role="note">
          <strong>{chartFamily === "severity" && viewMode !== "compare" && severityMode === "share"
            ? "Share of monthly CVEs"
            : effectiveScale === "indexed"
              ? "Relative trend"
              : "Actual counts"}</strong>
          <span>
            {chartFamily === "severity" && viewMode !== "compare" && severityMode === "share"
              ? "Each severity category is divided by all CVEs published that month. None and Unscored remain separate, so the six categories reconcile to 100%."
              : effectiveScale === "indexed"
              ? "Each line is scaled against its own peak, shown as 100%. LLM markers show separate disclosure events and are scaled against the largest reported minimum."
              : viewMode === "compare" && compareMetric === "epssHigh"
                ? `Each line groups CVEs by publication month and applies the current EPSS snapshot dated ${scoreDateLabel(epssScoreDate)}.`
                : viewMode === "compare" || chartFamily === "severity"
                ? compareMetric === "llmEvidence"
                  ? "Each marker shows a first-party report or reveal date. A blank month means no event is recorded in the registry."
                  : "Every visible line shares one count scale, so line height can be compared directly."
                : "CVE, exploit and current EPSS trends use the left axis; KEV and LLM event stems use the right axis."}
          </span>
        </div>

        {availableSeries.length ? <div className="series-legend" aria-label="Visible chart layers">
          {availableSeries.map((item) => {
            const visible = !hiddenSeries.includes(item.key);
            return (
              <button type="button" key={item.key} aria-pressed={visible} onClick={() => toggleSeries(item.key)}>
                <i className={item.render === "event" ? "is-event" : item.dashed ? "is-dashed" : ""} style={{ "--series": item.color } as CSSProperties} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div> : null}
        {llmLayerOmitted ? <p className="legend-status">No LLM disclosure event is recorded in this period, so no LLM legend marker is shown. This does not mean zero LLM-assisted discoveries.</p> : null}
        {!availableSeries.length ? <p className="legend-status">No recorded events are available for the selected months. A blank period does not mean zero LLM-assisted discoveries.</p> : null}

        <UnifiedChart
          labels={labels}
          series={visibleSeries}
          scaleMode={effectiveScale}
          activeIndex={safeActive}
          onActiveIndex={setActiveIndex}
        />

        <p className="chart-method-note">
          Diamond markers show separate first-party disclosure events, not a monthly trend. A blank month means no event is recorded; it does not mean zero LLM-assisted discoveries. Counts from different programmes remain separate. EPSS values use the current score snapshot dated {scoreDateLabel(epssScoreDate)} and are grouped by CVE publication month; ≥ 0.1 is a project-defined threshold, not an official FIRST severity band.
        </p>

        <div className="matrix-heading">
          <div><p className="eyebrow">Monthly values</p><h3>Monthly values by indicator</h3></div>
          <span>Exact monthly values. Scroll horizontally on smaller screens.</span>
        </div>
        <SignalMatrix points={chartPoints} events={events} compareRows={compareRows} severityMode={severityMode} />
      </article>
    </section>
  );
}
