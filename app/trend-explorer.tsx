"use client";

import { useMemo, useState, type CSSProperties } from "react";
import {
  availableYears,
  comparisonYearOptions,
  completeMonths,
  llmEvidenceForMonth,
  matchedYearPoints,
  monthsForYear,
  rollingMonths,
  summarizePeriod,
  type LlmEvidenceEvent,
  type MonthPoint,
} from "./trend-model";

type ViewMode = "year" | "month" | "compare";
type ChartFamily = "signals" | "severity";
type ScaleMode = "indexed" | "absolute";
type MetricKey =
  | "published"
  | "kevAdded"
  | "publicExploitReferences"
  | "llmEvidence"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "unknown";

type ChartSeries = {
  key: string;
  label: string;
  shortLabel: string;
  values: Array<number | null>;
  color: string;
  axis: "left" | "right";
  dashed?: boolean;
  shape?: "circle" | "square" | "diamond";
};

type ComparisonDisplay = {
  tone: "up" | "down" | "flat" | "new" | "unavailable";
  label: string;
  baseline?: string;
};

const metricOptions: Array<{ key: MetricKey; label: string }> = [
  { key: "published", label: "Published CVEs" },
  { key: "kevAdded", label: "KEV additions" },
  { key: "publicExploitReferences", label: "Exploit references" },
  { key: "llmEvidence", label: "LLM evidence" },
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
  { key: "unknown", label: "Unscored" },
];

function number(value: number) {
  return new Intl.NumberFormat("en").format(Math.round(value));
}

function compact(value: number) {
  return new Intl.NumberFormat("en", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(value);
}

function percent(value: number | null) {
  return value === null ? "—" : `${value.toFixed(1)}%`;
}

function monthLabel(value: string, short = false) {
  const date = new Date(`${value}-01T00:00:00Z`);
  return new Intl.DateTimeFormat("en", {
    month: short ? "short" : "long",
    year: short ? "2-digit" : "numeric",
    timeZone: "UTC",
  }).format(date);
}

function shortMonth(value: string) {
  return new Intl.DateTimeFormat("en", {
    month: "short",
    timeZone: "UTC",
  }).format(new Date(`${value}-01T00:00:00Z`));
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

function llmComparison(
  current: number,
  previous: number,
  baselineLabel: string,
  hasBaseline: boolean,
): ComparisonDisplay {
  if (!hasBaseline) {
    return { tone: "unavailable", label: `No comparable ${baselineLabel} evidence` };
  }
  if (current === previous) {
    return {
      tone: "flat",
      label: `Same documented floor as ${baselineLabel}`,
      baseline: previous ? `Baseline: ≥ ${number(previous)}` : "Baseline: no event",
    };
  }
  return {
    tone: current > previous ? "up" : "down",
    label: `${current > previous ? "Higher" : "Lower"} documented floor than ${baselineLabel}`,
    baseline: previous ? `Baseline: ≥ ${number(previous)}` : "Baseline: no event",
  };
}

function MetricCell({
  label,
  value,
  detail,
  comparison,
}: {
  label: string;
  value: string;
  detail: string;
  comparison: ComparisonDisplay;
}) {
  const symbol = comparison.tone === "up" || comparison.tone === "new"
    ? "↑"
    : comparison.tone === "down"
      ? "↓"
      : comparison.tone === "flat"
        ? "→"
        : "—";
  return (
    <article className="indicator-cell">
      <div className="indicator-cell__label">
        <strong>{label}</strong>
      </div>
      <div className="indicator-cell__value">{value}</div>
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
  const hasRightAxis = series.some((item) => item.axis === "right");
  const hasLeftAxis = series.some((item) => item.axis === "left");
  const leftAxisTitle = series
    .filter((item) => item.axis === "left")
    .map((item) => item.shortLabel)
    .join(" / ");
  const rightAxisTitle = series
    .filter((item) => item.axis === "right")
    .map((item) => item.shortLabel)
    .join(" / ");
  const leftAxisLabels = scaleMode === "indexed"
    ? ["100%", "50%", "0"]
    : [compact(axisMax.left), compact(axisMax.left / 2), "0"];
  const rightAxisLabels = [
    compact(axisMax.right),
    compact(axisMax.right / 2),
    "0",
  ];
  const safeActive = Math.min(Math.max(activeIndex, 0), Math.max(labels.length - 1, 0));

  return (
    <div className="unified-chart">
      <div
        className="chart-stage"
        role="group"
        aria-label={`Combined vulnerability trend with ${series.length} visible series`}
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
                {points.slice(0, -1).map((point, index) => {
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
                  <button
                    type="button"
                    className={`chart-point chart-point--${item.shape ?? "circle"}`}
                    key={`${item.key}-${point.index}-point`}
                    style={{
                      "--x": `${point.x}%`,
                      "--y": `${point.y}%`,
                      "--series": item.color,
                    } as CSSProperties}
                    aria-label={`${labels[point.index]}: ${item.label} ${number(point.value)}`}
                    onFocus={() => onActiveIndex(point.index)}
                    onMouseEnter={() => onActiveIndex(point.index)}
                    onClick={() => onActiveIndex(point.index)}
                  />
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
              <b>{item.values[safeActive] === null ? "—" : number(item.values[safeActive] ?? 0)}</b>
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
}: {
  points: MonthPoint[];
  events: LlmEvidenceEvent[];
  compareRows?: Array<{ label: string; values: number[] }>;
}) {
  const standardRows = [
    { label: "CVE", values: points.map((point) => point.published) },
    { label: "Critical", values: points.map((point) => point.critical) },
    { label: "High", values: points.map((point) => point.high) },
    { label: "Medium", values: points.map((point) => point.medium) },
    { label: "Low", values: points.map((point) => point.low) },
    { label: "KEV", values: points.map((point) => point.kevAdded) },
    { label: "Exploit ref", values: points.map((point) => point.publicExploitReferences) },
    { label: "LLM evidence", values: points.map((point) => llmEvidenceForMonth(point.month, events)) },
  ];
  const rows = compareRows ?? standardRows;
  return (
    <div className="matrix-wrap">
      <table className="signal-matrix">
        <caption>Values aligned to the combined trend chart</caption>
        <thead>
          <tr>
            <th>Signal</th>
            {points.map((point) => <th key={point.month}>{monthLabel(point.month, true)}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const maximum = Math.max(...row.values, 1);
            return (
              <tr key={row.label}>
                <th scope="row">{row.label}</th>
                {row.values.map((value, index) => {
                  const opacity = 0.035 + (value / maximum) * 0.18;
                  return (
                    <td
                      key={`${row.label}-${points[index]?.month ?? index}`}
                      style={{ "--heat-opacity": opacity } as CSSProperties}
                    >
                      {number(value)}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function TrendExplorer({
  monthly,
  latestCompleteMonth,
  events,
}: {
  monthly: MonthPoint[];
  latestCompleteMonth: string;
  events: LlmEvidenceEvent[];
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
  const [scaleMode, setScaleMode] = useState<ScaleMode>("indexed");
  const [selectedYear, setSelectedYear] = useState(latestYear);
  const [selectedMonth, setSelectedMonth] = useState(latestCompleteMonth);
  const [compareFirst, setCompareFirst] = useState(priorYear);
  const [compareSecond, setCompareSecond] = useState(latestYear);
  const [compareMetric, setCompareMetric] = useState<MetricKey>("published");
  const [hiddenSeries, setHiddenSeries] = useState<string[]>([]);
  const [activeIndex, setActiveIndex] = useState(11);

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
  const momentumPoints = viewMode === "month" ? rolling : summaryPoints;
  const baselineMomentumPoints = viewMode === "month"
    ? rollingMonths(monthly, previousSelectedMonth, latestCompleteMonth)
    : baselinePoints;
  const momentumSummary = summarizePeriod(momentumPoints, events);
  const baselineMomentumSummary = summarizePeriod(
    baselineMomentumPoints,
    events,
  );
  const momentum = momentumSummary.momentum;
  const baselineMomentum = baselineMomentumSummary.momentum;
  const baselineLabel = viewMode === "compare"
    ? periodLabel(matched.first, compareFirst)
    : viewMode === "month"
      ? monthLabel(baselinePoints[0]?.month ?? previousSelectedMonth, true)
      : periodLabel(baselinePoints, selectedYear - 1);
  const hasBaseline = baselinePoints.length > 0;
  const peakSummary = viewMode === "month" ? momentumSummary : summary;
  const peakBaseline = viewMode === "month" ? baselineMomentumSummary : baseline;
  const peakBaselineLabel = viewMode === "month"
    ? `the trailing 12 months ending ${monthLabel(previousSelectedMonth)}`
    : baselineLabel;

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
      label: "Public exploit references",
      shortLabel: "Exploit ref",
      values: chartPoints.map((point) => point.publicExploitReferences),
      color: "var(--amber)",
      axis: "left",
      dashed: true,
    },
    {
      key: "llmEvidence",
      label: "LLM CVE evidence disclosed",
      shortLabel: "LLM evidence",
      values: chartPoints.map((point) => {
        const value = llmEvidenceForMonth(point.month, events);
        return value || null;
      }),
      color: "var(--teal)",
      axis: "right",
      dashed: true,
      shape: "diamond",
    },
  ];
  const severitySeries: ChartSeries[] = [
    { key: "critical", label: "Critical", shortLabel: "Critical", values: chartPoints.map((point) => point.critical), color: "var(--critical)", axis: "left", shape: "square" },
    { key: "high", label: "High", shortLabel: "High", values: chartPoints.map((point) => point.high), color: "var(--amber)", axis: "left" },
    { key: "medium", label: "Medium", shortLabel: "Medium", values: chartPoints.map((point) => point.medium), color: "var(--accent)", axis: "left", dashed: true },
    { key: "low", label: "Low", shortLabel: "Low", values: chartPoints.map((point) => point.low), color: "var(--teal)", axis: "left", shape: "diamond" },
    { key: "unknown", label: "Unscored", shortLabel: "Unscored", values: chartPoints.map((point) => point.unknown), color: "var(--neutral)", axis: "left", dashed: true, shape: "square" },
  ];
  const comparisonSeries: ChartSeries[] = [
    {
      key: `compare-${compareFirst}`,
      label: `${compareFirst} ${metricOptions.find((item) => item.key === compareMetric)?.label}`,
      shortLabel: String(compareFirst),
      values: matched.first.map((point) => metricValue(point, compareMetric, events)),
      color: "var(--neutral)",
      axis: "left",
      dashed: true,
    },
    {
      key: `compare-${compareSecond}`,
      label: `${compareSecond} ${metricOptions.find((item) => item.key === compareMetric)?.label}`,
      shortLabel: String(compareSecond),
      values: matched.second.map((point) => metricValue(point, compareMetric, events)),
      color: "var(--accent)",
      axis: "left",
      shape: "square",
    },
  ];
  const allSeries = viewMode === "compare"
    ? comparisonSeries
    : chartFamily === "signals"
      ? signalSeries
      : severitySeries;
  const visibleSeries = allSeries.filter((series) => !hiddenSeries.includes(series.key));
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
    ? llmComparison(
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
    ? "Not additive"
    : `${compareDifference > 0 ? "+" : compareDifference < 0 ? "−" : ""}${number(Math.abs(compareDifference))}`;
  const compareValueLabel = (value: number) => compareMetric === "llmEvidence"
    ? value ? `≥ ${number(value)}` : "No event"
    : number(value);

  const periodTitle = viewMode === "year"
    ? yearPoints.length === 12
      ? `${selectedYear} annual report`
      : `${periodLabel(yearPoints, selectedYear)} year to date`
    : viewMode === "month"
      ? `${monthLabel(selectedMonth)} focus`
      : `${periodLabel(matched.first, compareFirst)} vs ${periodLabel(matched.second, compareSecond)}`;
  const periodDetail = viewMode === "month"
    ? "Indicators use the selected month; the plot keeps 12 complete months of context."
    : viewMode === "compare"
      ? "Both years stop at the same complete month for a like-for-like comparison."
      : "Partial months are excluded from totals and trend lines.";

  const toggleSeries = (key: string) => {
    setHiddenSeries((current) =>
      current.includes(key) ? current.filter((item) => item !== key) : [...current, key],
    );
  };

  const compareRows = viewMode === "compare"
    ? [
        { label: periodLabel(matched.first, compareFirst), values: comparisonSeries[0].values.map((value) => value ?? 0) },
        { label: periodLabel(matched.second, compareSecond), values: comparisonSeries[1].values.map((value) => value ?? 0) },
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
                {mode === "compare" ? "Year vs year" : mode}
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
              <span>Compared signal</span>
              <select value={compareMetric} onChange={(event) => setCompareMetric(event.target.value as MetricKey)}>
                {metricOptions.map((item) => <option value={item.key} key={item.key}>{item.label}</option>)}
              </select>
            </label>
          </>
        ) : (
          <fieldset>
            <legend>Series family</legend>
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
            <small>{compareMetric === "llmEvidence" ? `${compareChange.label}; program counts may overlap` : compareChange.label}</small>
          </div>
        </div>
      ) : null}

      <div className="indicator-grid">
        <MetricCell
          label="CVEs published"
          value={number(summary.published)}
          detail={`${compact(summary.monthlyAverage)} average per complete month`}
          comparison={relativeComparison(summary.published, baseline.published, baselineLabel, hasBaseline)}
        />
        <MetricCell
          label="Critical + high"
          value={number(summary.criticalHigh)}
          detail={`${percent(summary.criticalHighShare)} of scored CVEs`}
          comparison={relativeComparison(summary.criticalHigh, baseline.criticalHigh, baselineLabel, hasBaseline)}
        />
        <MetricCell
          label="KEV additions"
          value={number(summary.kevAdded)}
          detail={`${(summary.kevAdded / Math.max(summaryPoints.length, 1)).toFixed(1)} average per month`}
          comparison={relativeComparison(summary.kevAdded, baseline.kevAdded, baselineLabel, hasBaseline)}
        />
        <MetricCell
          label="Exploit references"
          value={number(summary.publicExploitReferences)}
          detail={`${percent(summary.publicExploitShare)} of published CVEs`}
          comparison={relativeComparison(summary.publicExploitReferences, baseline.publicExploitReferences, baselineLabel, hasBaseline)}
        />
        <MetricCell
          label="LLM-reported CVEs"
          value={summary.llmEvidence ? `≥ ${number(summary.llmEvidence)}` : "—"}
          detail="Largest count disclosed by one first-party program or public-ID release; program totals are not added"
          comparison={llmComparison(summary.llmEvidence, baseline.llmEvidence, baselineLabel, hasBaseline)}
        />
        <MetricCell
          label="Severity coverage"
          value={percent(summary.severityCoverage)}
          detail={`${number(summary.unknown)} records remain unscored`}
          comparison={pointComparison(summary.severityCoverage, baseline.severityCoverage, baselineLabel, hasBaseline)}
        />
        <MetricCell
          label={viewMode === "month" ? "Trailing 12-month peak" : "Peak publication month"}
          value={peakSummary.peakMonth ? number(peakSummary.peakMonth.published) : "—"}
          detail={peakSummary.peakMonth ? monthLabel(peakSummary.peakMonth.month) : "No complete month in range"}
          comparison={relativeComparison(
            peakSummary.peakMonth?.published ?? 0,
            peakBaseline.peakMonth?.published ?? 0,
            peakBaselineLabel,
            Boolean(peakSummary.peakMonth && peakBaseline.peakMonth),
          )}
        />
        <MetricCell
          label="Three-month momentum"
          value={percent(momentum)}
          detail="Latest three-month CVE average versus the preceding three"
          comparison={pointComparison(momentum, baselineMomentum, baselineLabel, baselineMomentum !== null)}
        />
      </div>

      <article className="unified-panel">
        <div className="unified-panel__heading">
          <div>
            <p className="eyebrow">SIG / Combined timeline</p>
            <h3>{viewMode === "compare" ? metricOptions.find((item) => item.key === compareMetric)?.label : chartFamily === "signals" ? "CVE, KEV, exploit and LLM evidence" : "Severity by publication month"}</h3>
          </div>
          {viewMode !== "compare" && chartFamily === "signals" ? (
            <div className="scale-control" aria-label="Chart display">
              <span>Chart display</span>
              {(["indexed", "absolute"] as ScaleMode[]).map((mode) => (
                <button type="button" key={mode} aria-pressed={scaleMode === mode} onClick={() => setScaleMode(mode)}>{mode === "indexed" ? "Relative trend" : "Actual counts"}</button>
              ))}
            </div>
          ) : <span className="scale-note">Actual counts / shared scale</span>}
        </div>

        <div className="scale-explainer" role="note">
          <strong>{effectiveScale === "indexed" ? "Relative trend" : "Actual counts"}</strong>
          <span>
            {effectiveScale === "indexed"
              ? "Each line’s own peak equals 100%. Compare direction and timing—not line height. Exact counts remain below."
              : viewMode === "compare" || chartFamily === "severity"
                ? "Every visible line shares one count scale, so line height can be compared directly."
                : "Monthly totals use the left axis for CVE and exploit references, and the right axis for KEV and LLM evidence."}
          </span>
        </div>

        <div className="series-legend" aria-label="Visible chart series">
          {allSeries.map((item) => {
            const visible = !hiddenSeries.includes(item.key);
            return (
              <button type="button" key={item.key} aria-pressed={visible} onClick={() => toggleSeries(item.key)}>
                <i className={item.dashed ? "is-dashed" : ""} style={{ "--series": item.color } as CSSProperties} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>

        <UnifiedChart
          labels={labels}
          series={visibleSeries}
          scaleMode={effectiveScale}
          activeIndex={safeActive}
          onActiveIndex={setActiveIndex}
        />

        <p className="chart-method-note">
          LLM points mark first-party report or reveal dates—not discovery dates—and program totals are never summed.
        </p>

        <div className="matrix-heading">
          <div><p className="eyebrow">MAT / Signal matrix</p><h3>All indicators, one time grid</h3></div>
          <span>Exact values / scroll horizontally on small screens</span>
        </div>
        <SignalMatrix points={chartPoints} events={events} compareRows={compareRows} />
      </article>
    </section>
  );
}
