"use client";

import { useMemo, useState, type CSSProperties } from "react";
import {
  availableYears,
  change,
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

function metricValue(
  point: MonthPoint,
  key: MetricKey,
  events: LlmEvidenceEvent[],
) {
  return key === "llmEvidence"
    ? llmEvidenceForMonth(point.month, events)
    : point[key];
}

function deltaLabel(value: number | null, baseline: string) {
  if (value === null) return `No ${baseline} baseline`;
  return `${value > 0 ? "+" : ""}${value.toFixed(1)}% vs ${baseline}`;
}

function MetricCell({
  code,
  label,
  value,
  detail,
  delta,
  baseline,
  footer,
}: {
  code: string;
  label: string;
  value: string;
  detail: string;
  delta: number | null;
  baseline: string;
  footer?: string;
}) {
  const tone = delta === null || delta === 0 ? "flat" : delta > 0 ? "up" : "down";
  return (
    <article className="indicator-cell">
      <div className="indicator-cell__label">
        <span>{code}</span>
        <strong>{label}</strong>
      </div>
      <div className="indicator-cell__value">{value}</div>
      <p>{detail}</p>
      <span className={`indicator-cell__delta indicator-cell__delta--${footer ? "flat" : tone}`}>
        {footer ?? deltaLabel(delta, baseline)}
      </span>
    </article>
  );
}

type PlotPoint = { x: number; y: number; value: number; index: number };

function plotPoints(values: Array<number | null>, maximum: number): Array<PlotPoint | null> {
  return values.map((value, index) => {
    if (value === null) return null;
    return {
      x: values.length === 1 ? 50 : (index / (values.length - 1)) * 100,
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
  const safeActive = Math.min(Math.max(activeIndex, 0), Math.max(labels.length - 1, 0));

  return (
    <div className="unified-chart">
      <div
        className="chart-stage"
        role="group"
        aria-label={`Combined vulnerability trend with ${series.length} visible series`}
      >
        <div className="chart-stage__grid" aria-hidden="true" />
        {labels.length > 0 ? (
          <span
            className="chart-stage__cursor"
            style={{
              "--cursor-x": `${labels.length === 1 ? 50 : (safeActive / (labels.length - 1)) * 100}%`,
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
                      style={{ backgroundColor: `rgba(99, 60, 255, ${opacity})` }}
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
  const rolling = rollingMonths(monthly, selectedMonth, latestCompleteMonth);
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
          (point) => point.month === `${Number(selectedMonth.slice(0, 4)) - 1}-${selectedMonth.slice(5, 7)}`,
        )
      : monthsForYear(monthly, selectedYear - 1, latestCompleteMonth).filter(
          (point) => Number(point.month.slice(5, 7)) <= yearPoints.length,
        );
  const summary = summarizePeriod(summaryPoints, events);
  const baseline = summarizePeriod(baselinePoints, events);
  const momentum = summarizePeriod(
    viewMode === "month" ? rolling : summaryPoints,
    events,
  ).momentum;
  const baselineLabel = viewMode === "compare"
    ? String(compareFirst)
    : viewMode === "month"
      ? monthLabel(baselinePoints[0]?.month ?? `${Number(selectedMonth.slice(0, 4)) - 1}-${selectedMonth.slice(5, 7)}`, true)
      : String(selectedYear - 1);

  const labels = chartPoints.map((point) => monthLabel(point.month, true));
  const signalSeries: ChartSeries[] = [
    {
      key: "published",
      label: "Published CVEs",
      shortLabel: "CVE",
      values: chartPoints.map((point) => point.published),
      color: "#0c0c10",
      axis: "left",
    },
    {
      key: "kevAdded",
      label: "CISA KEV additions",
      shortLabel: "KEV",
      values: chartPoints.map((point) => point.kevAdded),
      color: "#708f00",
      axis: "right",
      shape: "square",
    },
    {
      key: "publicExploitReferences",
      label: "Public exploit references",
      shortLabel: "Exploit ref",
      values: chartPoints.map((point) => point.publicExploitReferences),
      color: "#f07f2f",
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
      color: "#633cff",
      axis: "right",
      dashed: true,
      shape: "diamond",
    },
  ];
  const severitySeries: ChartSeries[] = [
    { key: "critical", label: "Critical", shortLabel: "Critical", values: chartPoints.map((point) => point.critical), color: "#0c0c10", axis: "left", shape: "square" },
    { key: "high", label: "High", shortLabel: "High", values: chartPoints.map((point) => point.high), color: "#633cff", axis: "left" },
    { key: "medium", label: "Medium", shortLabel: "Medium", values: chartPoints.map((point) => point.medium), color: "#a995ff", axis: "left", dashed: true },
    { key: "low", label: "Low", shortLabel: "Low", values: chartPoints.map((point) => point.low), color: "#708f00", axis: "left", shape: "diamond" },
    { key: "unknown", label: "Unscored", shortLabel: "Unscored", values: chartPoints.map((point) => point.unknown), color: "#88847c", axis: "left", dashed: true, shape: "square" },
  ];
  const comparisonSeries: ChartSeries[] = [
    {
      key: `compare-${compareFirst}`,
      label: `${compareFirst} ${metricOptions.find((item) => item.key === compareMetric)?.label}`,
      shortLabel: String(compareFirst),
      values: matched.first.map((point) => metricValue(point, compareMetric, events)),
      color: "#8c8880",
      axis: "left",
      dashed: true,
    },
    {
      key: `compare-${compareSecond}`,
      label: `${compareSecond} ${metricOptions.find((item) => item.key === compareMetric)?.label}`,
      shortLabel: String(compareSecond),
      values: matched.second.map((point) => metricValue(point, compareMetric, events)),
      color: "#633cff",
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

  const periodTitle = viewMode === "year"
    ? `${selectedYear} / ${yearPoints.length === 12 ? "Annual report" : `Jan–${monthLabel(yearPoints.at(-1)?.month ?? latestCompleteMonth, true)} YTD`}`
    : viewMode === "month"
      ? `${monthLabel(selectedMonth)} / Month focus`
      : `${compareFirst} vs ${compareSecond} / Matched ${matched.monthCap}-month view`;
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
        { label: `${compareFirst}`, values: comparisonSeries[0].values.map((value) => value ?? 0) },
        { label: `${compareSecond}`, values: comparisonSeries[1].values.map((value) => value ?? 0) },
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
        <span className="data-state"><i />DATA / COMPLETE THROUGH {latestCompleteMonth}</span>
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
                {[...years].reverse().map((year) => <option key={year}>{year}</option>)}
              </select>
            </label>
            <label>
              <span>Comparison year</span>
              <select value={compareSecond} onChange={(event) => setCompareSecond(Number(event.target.value))}>
                {[...years].reverse().map((year) => <option key={year}>{year}</option>)}
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

      <div className="indicator-grid">
        <MetricCell
          code="VOL"
          label="CVEs published"
          value={number(summary.published)}
          detail={`${compact(summary.monthlyAverage)} average per complete month`}
          delta={change(summary.published, baseline.published)}
          baseline={baselineLabel}
        />
        <MetricCell
          code="SEV"
          label="Critical + high"
          value={number(summary.criticalHigh)}
          detail={`${percent(summary.criticalHighShare)} of scored CVEs`}
          delta={change(summary.criticalHigh, baseline.criticalHigh)}
          baseline={baselineLabel}
        />
        <MetricCell
          code="KEV"
          label="KEV additions"
          value={number(summary.kevAdded)}
          detail={`${(summary.kevAdded / Math.max(summaryPoints.length, 1)).toFixed(1)} average per month`}
          delta={change(summary.kevAdded, baseline.kevAdded)}
          baseline={baselineLabel}
        />
        <MetricCell
          code="EXP"
          label="Exploit references"
          value={number(summary.publicExploitReferences)}
          detail={`${percent(summary.publicExploitShare)} of published CVEs`}
          delta={change(summary.publicExploitReferences, baseline.publicExploitReferences)}
          baseline={baselineLabel}
        />
        <MetricCell
          code="LLM"
          label="Documented evidence"
          value={summary.llmEvidence ? `≥${number(summary.llmEvidence)}` : "—"}
          detail="Largest first-party report or public-ID reveal event"
          delta={null}
          baseline={baselineLabel}
          footer="Program totals are not summed"
        />
        <MetricCell
          code="QLT"
          label="Severity coverage"
          value={percent(summary.severityCoverage)}
          detail={`${number(summary.unknown)} records remain unscored`}
          delta={null}
          baseline={baselineLabel}
          footer={
            summary.severityCoverage !== null && baseline.severityCoverage !== null
              ? `${summary.severityCoverage - baseline.severityCoverage > 0 ? "+" : ""}${(
                  summary.severityCoverage - baseline.severityCoverage
                ).toFixed(1)} pp vs ${baselineLabel}`
              : `No ${baselineLabel} baseline`
          }
        />
        <MetricCell
          code="PEAK"
          label="Peak publication month"
          value={summary.peakMonth ? number(summary.peakMonth.published) : "—"}
          detail={summary.peakMonth ? monthLabel(summary.peakMonth.month) : "No complete month in range"}
          delta={change(
            summary.peakMonth?.published ?? 0,
            baseline.peakMonth?.published ?? 0,
          )}
          baseline={baselineLabel}
        />
        <MetricCell
          code="MOM"
          label="Three-month momentum"
          value={percent(momentum)}
          detail="Latest three-month CVE average versus the preceding three"
          delta={null}
          baseline={baselineLabel}
          footer={viewMode === "month" ? "Six-month context through selected month" : "Within the selected period"}
        />
      </div>

      <article className="unified-panel">
        <div className="unified-panel__heading">
          <div>
            <p className="eyebrow">SIG / Combined timeline</p>
            <h3>{viewMode === "compare" ? metricOptions.find((item) => item.key === compareMetric)?.label : chartFamily === "signals" ? "CVE, KEV, exploit and LLM evidence" : "Severity by publication month"}</h3>
          </div>
          {viewMode !== "compare" && chartFamily === "signals" ? (
            <div className="scale-control" aria-label="Chart scale">
              <span>Scale</span>
              {(["indexed", "absolute"] as ScaleMode[]).map((mode) => (
                <button type="button" key={mode} aria-pressed={scaleMode === mode} onClick={() => setScaleMode(mode)}>{mode}</button>
              ))}
            </div>
          ) : <span className="scale-note">Shared absolute scale</span>}
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
          {effectiveScale === "indexed"
            ? "Indexed view scales each series to its own peak so differently sized signals can share one plot. Values remain absolute in the readout and matrix."
            : "Absolute view uses shared axes: publication/severity signals on the left scale and KEV/LLM evidence on the right."}
          {" "}LLM points mark first-party report or reveal dates—not discovery dates—and program totals are never summed.
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
