"use client";

import React, { useState, useMemo } from "react";
import type { CSSProperties, ReactNode } from "react";
import rawDashboard from "@/data/dashboard.json";
import { TrendExplorer } from "./trend-explorer";
import { FreshnessBanner } from "./freshness-banner";
import type { LlmEvidenceEvent, MonthPoint } from "./trend-model";

type WindowMetrics = {
  start: string;
  end: string;
  monthlyAverage: number;
  criticalHighShare: number | null;
  publicExploitShare: number | null;
  kevWithin90DayRate: number | null;
  medianDaysToKev: number | null;
  epssHighShare: number | null;
};

type ProgramReport = {
  id: string;
  publisher: string;
  program: string;
  metric: string;
  count: number;
  sourceUrl: string;
  published: string;
};

type DateWindow = {
  start: string;
  end: string;
  count?: number;
  publishedCves?: number;
  matureCves?: number;
  kevEntriesWithTiming?: number;
  scoredCves?: number;
  highEpssCves?: number;
  dueWindowSample?: number;
  ageSample?: number;
  scoreDate?: string | null;
};

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

type PriorityWatch = {
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
  itemsCompleteness: "all_candidates";
  items: PriorityWatchItem[];
};

type EpssHistoryPoint = {
  date: string;
  modelVersion: string;
  recordCount: number;
  highCount: number;
  notInKevCount: number;
  enteredHigh: number | null;
  exitedHigh: number | null;
  comparableToPrevious: boolean;
  sampleKind: "month_end" | "current";
  sourceUrl: string;
  sha256: string;
};

type EpssPredictivePerformanceRecord = {
  snapshotDate: string;
  modelVersion: string;
  candidateCount: number;
  baselineCount: number;
  ageDays: number;
  isMature30d: boolean;
  isMature60d: boolean;
  isMature90d: boolean;
  kevAdditions30d: number | null;
  conversionRate30d: number | null;
  baselineRate30d: number | null;
  lift30d: number | null;
  recall30d: number | null;
  kevAdditions60d: number | null;
  conversionRate60d: number | null;
  baselineRate60d: number | null;
  lift60d: number | null;
  recall60d: number | null;
  kevAdditions90d: number | null;
  conversionRate90d: number | null;
  baselineRate90d: number | null;
  lift90d: number | null;
  recall90d: number | null;
};

type EpssHistory = {
  threshold: number;
  semantics: string;
  modelBoundaryPolicy: string;
  points: EpssHistoryPoint[];
  predictivePerformance?: EpssPredictivePerformanceRecord[];
};

type ComparisonWindow = {
  start: string;
  end: string;
  publishedCves?: number;
  matureCves?: number;
  count?: number;
  ransomwareCount?: number;
  ransomwareShare?: number | null;
  ageSample?: number;
  oldCount?: number;
  oldShare?: number | null;
  within7Count?: number;
  within7Share?: number | null;
  under21Count?: number;
  under21Share?: number | null;
  dueWindowSample?: number;
  sample?: number;
  prePublicationKev?: number;
  prePublicationKevShare?: number | null;
  medianDays?: number | null;
  medianDaysNonNegative?: number | null;
  p75Days?: number | null;
  p75DaysNonNegative?: number | null;
};

type CweRow = {
  cwe: string;
  name?: string;
  url?: string;
  count: number;
  priorCount?: number;
  change?: number;
  recentTotal?: number;
  priorTotal?: number;
  recentShare?: number;
  priorShare?: number;
  changePoints?: number;
};

type DashboardData = {
  generatedAt: string;
  snapshot: {
    id: string;
    generatedAt: string;
    inputCount: number;
    inputFingerprintSha256: string;
  };
  project: {
    name: string;
    repo: string;
    description: string;
    refreshSchedule?: string;
  };
  coverage: {
    start: string;
    asOf: string;
    latestCompleteMonth: string;
    recordCount: number;
    notice: string;
  };
  sources: {
    cve: {
      name: string;
      url: string;
      latestFetch: string | null;
      changedRecords24h: number;
    };
    nvd: { name: string; url: string; latestSourceUpdate: string | null };
    kev: {
      name: string;
      url: string;
      catalogVersion: string;
      released: string;
      count: number;
    };
    anthropic: {
      name: string;
      url: string;
      asOf: string | null;
      revision: number | null;
      reportedCves: number;
      publicCveRecords: number;
    };
    epss?: {
      name: string;
      url: string;
      feedUrl?: string;
      modelVersion?: string | null;
      scoreDate?: string | null;
      recordCount?: number;
      matchedCveCount?: number;
      coveragePercent?: number | null;
      thresholdPercentile?: number | null;
      contentFingerprintSha256?: string;
    };
    llmRegistry: {
      name: string;
      url: string;
      lastReviewed: string;
      latestEvidenceDate: string;
      programmeSources: {
        publisher: string;
        programme: string;
        published: string;
        url: string;
      }[];
    };
  };
  latestCompleteMonth: {
    month: string;
    published: number;
    criticalHigh: number;
    severityCoverage: number | null;
    kevAdded: number;
    publicExploitReferences: number;
  };
  risk: {
    catalogKev: number;
    matureCohortStart: string;
    matureCohortEnd: string;
    kevWithin90DayRate: number | null;
    kevWithin90Days: number;
    matureCohort: number;
    kevTimingSample: number;
    prePublicationKev: number;
    medianDaysToKev: number | null;
    p75DaysToKev: number | null;
    medianDaysToKevNonNegative?: number | null;
    p75DaysToKevNonNegative?: number | null;
    prePublicationKevShare?: number | null;
    kevWithin90DayKevShare?: number | null;
    allCveKevConversion?: number | null;
    exploitRefKevConversion?: number | null;
    cvssVersionMix?: Record<string, { count: number; share: number }>;
    kevAgeBands?: Record<string, number>;
    highEpss: number;
    highEpssNotInKevCount: number;
    highEpssNotInKevShare: number | null;
    ransomwareKevShare: number | null;
    ransomwareKevCount: number;
    medianKevDueWindow: number | null;
    kevDueWindowSample: number;
    kevAdditionsCount: number;
    kevAgeSample: number;
    oldKevCount: number;
    oldKevShare: number | null;
    kevAdditionsWindow?: DateWindow;
    kevTimingWindow?: DateWindow;
    epssCohortWindow?: DateWindow;
    kevDeadlineComparison?: {
      current: ComparisonWindow;
      prior: ComparisonWindow;
      within7ShareChangePoints: number | null;
      under21ShareChangePoints: number | null;
    };
    kevAdditionComparison?: {
      current: ComparisonWindow;
      prior: ComparisonWindow;
      ransomwareShareChangePoints: number | null;
      oldShareChangePoints: number | null;
    };
    kevTimingComparison?: {
      current: ComparisonWindow;
      prior: ComparisonWindow;
      medianDaysChange: number | null;
      p75DaysChange: number | null;
    };
  };
  llmDiscovery: {
    value: number | null;
    verifiedCount: number;
    basis: string;
    coverage: string;
    events: LlmEvidenceEvent[];
    programReports: ProgramReport[];
  };
  comparison: {
    method: "adjacent_rolling_windows";
    windowMonths: number;
    note: string;
    earlier: WindowMetrics;
    recent: WindowMetrics;
  };
  monthly: MonthPoint[];
  topCwes: CweRow[];
  priorityWatch?: PriorityWatch;
  epssHistory?: EpssHistory;
  cweMovers?: {
    window: {
      currentStart: string;
      currentEnd: string;
      priorStart: string;
      priorEnd: string;
    };
    sampleFloor: number;
    denominatorSemantics: string;
    rising: CweRow[];
    falling: CweRow[];
  };
  changeDigest?: {
    cve: {
      period: string;
      newRecords: number;
      updatedRecords: number;
      distinctChanged: number;
    };
    kev: {
      period: string;
      date: string | null;
      additions: number;
    };
    epss: {
      period: string;
      from: string | null;
      to: string | null;
      enteredHigh: number | null;
      exitedHigh: number | null;
      comparable: boolean;
    };
    priority: {
      period: string;
      count: number;
    };
  };
  recentKev: {
    cveId: string;
    vendor: string;
    product: string;
    name: string;
    dateAdded: string;
    dueDate: string;
    ransomware: string;
    severity: string;
    score: number | null;
    cvssVersion: string | null;
    publicExploitReference: boolean | null;
  }[];
  weaknessAnalysis?: {
    period: string;
    start: string;
    end: string;
    totalRecords: number;
    specificCount: number;
    noinfoCount: number;
    otherCount: number;
    noneCount: number;
  };
  cvssEpssHeatmap?: {
    total: number;
    grid: {
      [key: string]: {
        count: number;
        kevCount: number;
        exploitRefCount: number;
      }[];
    };
  };
  signalOverlap?: {
    sets: {
      cvssHigh: boolean;
      epssHigh: boolean;
      exploitRef: boolean;
      cisaKev: boolean;
      ransomware: boolean;
    };
    count: number;
  }[];
  kevLagHeatmap?: {
    grid: {
      [year: string]: {
        [bucket: string]: number;
      };
    };
    cohortTotals: {
      [year: string]: number;
    };
  };
  enrichmentCompleteness?: {
    month: string;
    total: number;
    cvssPercent: number;
    cwePercent: number;
    exploitRefPercent: number;
    epssPercent: number;
  }[];
  cweHeatmap?: {
    quarters: string[];
    quarterTotals: {
      [quarter: string]: number;
    };
    grid: {
      [cwe: string]: {
        [quarter: string]: number;
      };
    };
  };
};

const dashboard = rawDashboard as DashboardData;

function number(value: number) {
  return new Intl.NumberFormat("en-SG").format(value);
}

function percent(value: number | null) {
  return value === null ? "—" : `${value.toFixed(1)}%`;
}

function dateLabel(value: string, includeDay = false) {
  const date = new Date(`${value.length === 7 ? `${value}-01` : value}T00:00:00Z`);
  return new Intl.DateTimeFormat("en-SG", {
    month: "short",
    year: "numeric",
    ...(includeDay ? { day: "numeric" } : {}),
    timeZone: "UTC",
  }).format(date);
}

function shortDateLabel(value: string) {
  return dateLabel(value.slice(0, 10), true);
}

function MetricValue({
  children,
  href,
  tooltip,
}: {
  children: ReactNode;
  href?: string;
  tooltip: string;
}) {
  if (href) {
    return (
      <a className="metric-value metric-value--link" href={href} title={tooltip}>
        <span>{children}</span><b aria-hidden="true">↗</b>
      </a>
    );
  }
  return (
    <span
      className="metric-value metric-value--info"
      data-tooltip={tooltip}
      tabIndex={0}
      aria-label={tooltip}
    >
      {children}
    </span>
  );
}

function timestampLabel(value: string | null) {
  if (!value) return "Not available";
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(value);
  return new Intl.DateTimeFormat("en-SG", {
    day: "numeric",
    month: "short",
    year: "numeric",
    ...(dateOnly ? {} : { hour: "2-digit", minute: "2-digit", hourCycle: "h23" as const }),
    timeZone: "UTC",
    ...(dateOnly ? {} : { timeZoneName: "short" as const }),
  }).format(new Date(value));
}

function dateRangeLabel(window?: DateWindow, fallback?: DateWindow) {
  const selected = window ?? fallback;
  if (!selected?.start || !selected?.end) return "Period not available";
  return `${dateLabel(selected.start, true)}–${dateLabel(selected.end, true)}`;
}

function ComparisonRow({
  label,
  earlier,
  recent,
  suffix = "",
  changeMode = "relative",
}: {
  label: string;
  earlier: number | null;
  recent: number | null;
  suffix?: string;
  changeMode?: "relative" | "points";
}) {
  const safeEarlier = earlier ?? 0;
  const safeRecent = recent ?? 0;
  const max = Math.max(safeEarlier, safeRecent, 1);
  const ratio = safeEarlier ? ((safeRecent - safeEarlier) / safeEarlier) * 100 : null;
  const pointDifference = recent !== null && earlier !== null ? recent - earlier : null;
  const changeLabel = changeMode === "points"
    ? pointDifference === null
      ? "—"
      : `${pointDifference > 0 ? "↑" : pointDifference < 0 ? "↓" : "→"} ${Math.abs(pointDifference).toFixed(1)} points`
    : ratio === null
      ? "—"
      : `${ratio > 0 ? "↑" : ratio < 0 ? "↓" : "→"} ${Math.abs(ratio).toFixed(1)}%`;
  return (
    <div className="comparison-row">
      <div className="comparison-row__label">
        <span>{label}</span>
        <span>{changeLabel}</span>
      </div>
      <div className="comparison-bars">
        <div
          className="comparison-bar comparison-bar--pre"
          style={{ "--bar": `${(safeEarlier / max) * 100}%` } as CSSProperties}
        >
          <span><MetricValue tooltip={`${label}, earlier period value`}>{earlier === null ? "—" : `${number(earlier)}${suffix}`}</MetricValue></span>
        </div>
        <div
          className="comparison-bar comparison-bar--recent"
          style={{ "--bar": `${(safeRecent / max) * 100}%` } as CSSProperties}
        >
          <span><MetricValue tooltip={`${label}, recent period value`}>{recent === null ? "—" : `${number(recent)}${suffix}`}</MetricValue></span>
        </div>
      </div>
    </div>
  );
}

function probability(value: number) {
  return `${(value * 100).toFixed(value >= 0.1 ? 1 : 2)}%`;
}

function percentileLabel(value: number) {
  return `EPSS percentile ${(value * 100).toFixed(1)}%`;
}

function ageLabel(published: string, asOf: string) {
  const start = new Date(`${published.slice(0, 10)}T00:00:00Z`).getTime();
  const end = new Date(`${asOf.slice(0, 10)}T00:00:00Z`).getTime();
  if (!Number.isFinite(start) || !Number.isFinite(end)) return "Age unavailable";
  const days = Math.max(0, Math.floor((end - start) / 86_400_000));
  return `${number(days)} ${days === 1 ? "day" : "days"} old`;
}

function DeltaTag({
  value,
  unit,
}: {
  value: number | null | undefined;
  unit: "days" | "points";
}) {
  if (value === null || value === undefined) {
    return <em className="metric-delta metric-delta--neutral">No prior comparison</em>;
  }
  const direction = value > 0 ? "↑" : value < 0 ? "↓" : "→";
  const label = unit === "points"
    ? `${Math.abs(value).toFixed(1)} percentage points`
    : `${number(Math.abs(value))} ${Math.abs(value) === 1 ? "day" : "days"}`;
  return (
    <em className={`metric-delta metric-delta--${value > 0 ? "up" : value < 0 ? "down" : "neutral"}`}>
      {direction} {label} vs prior period
    </em>
  );
}

function WhatChanged({
  digest,
  cveUrl,
}: {
  digest?: DashboardData["changeDigest"];
  cveUrl: string;
}) {
  if (!digest) return null;
  const epssText = digest.epss.comparable
    ? `${number(digest.epss.enteredHigh ?? 0)} entered and ${number(digest.epss.exitedHigh ?? 0)} exited the project threshold`
    : "Not compared across an EPSS model boundary";
  return (
    <section className="change-digest" aria-labelledby="change-digest-title">
      <div className="change-digest__heading">
        <div><p className="eyebrow">Source activity / stated windows</p><h2 id="change-digest-title">What changed</h2></div>
        <p>Source activity and security signals are kept separate.</p>
      </div>
      <div className="change-digest__grid">
        <article>
          <span>Source maintenance · last 24 hours</span>
          <strong><MetricValue href={cveUrl} tooltip="Open the official CVE List source">{number(digest.cve.distinctChanged)} CVE records changed</MetricValue></strong>
          <p>{number(digest.cve.newRecords)} newly published and {number(digest.cve.updatedRecords)} updated in 24 hours; categories can overlap. This is feed activity, not vulnerability incidence.</p>
        </article>
        <article>
          <span>Confirmed exploitation · CISA KEV</span>
          <strong><MetricValue href="#kev-watch" tooltip="Jump to the recently added CISA KEV records">{number(digest.kev.additions)} KEV additions</MetricValue></strong>
          <p>{digest.kev.date ? `Added by CISA on ${dateLabel(digest.kev.date, true)}.` : "No dated KEV additions in this refresh."}</p>
        </article>
        <article>
          <span>EPSS threshold movement · adjacent sample</span>
          <strong><MetricValue href="#epss-history" tooltip="Jump to the EPSS threshold history">{epssText}</MetricValue></strong>
          <p>Uses adjacent official snapshots only when their model versions are comparable.</p>
        </article>
        <article>
          <span>Current priority watch · current snapshot</span>
          <strong><MetricValue href="#priority-watch-panel" tooltip="Jump to the VulnSignal screening threshold candidate table">{number(digest.priority.count)} candidates</MetricValue></strong>
          <p>Current EPSS ≥ 0.1, published in 90 days and not listed in CISA KEV. This is a screening list, not a recommended remediation queue or patch priority list.</p>
        </article>
      </div>
    </section>
  );
}

function PriorityWatchPanel({ watch, topPercentText }: { watch?: PriorityWatch; topPercentText?: string }) {
  const [filterMode, setFilterMode] = useState<"all" | "top5" | "top1" | "criticalHigh">("all");
  
  const filteredItems = useMemo(() => {
    const items = watch?.items ?? [];
    if (filterMode === "top5") {
      return items.filter((item) => item.epssPercentile >= 0.95);
    } else if (filterMode === "top1") {
      return items.filter((item) => item.epssPercentile >= 0.99);
    } else if (filterMode === "criticalHigh") {
      return items.filter((item) => item.epss >= 0.10 && (item.severity === "CRITICAL" || item.severity === "HIGH"));
    }
    return items;
  }, [watch?.items, filterMode]);

  const visibleItems = filteredItems.slice(0, 10);

  return (
    <article className="flat-panel priority-watch" id="priority-watch-panel">
      <div className="panel-heading">
        <div><p className="eyebrow">EPSS screening watch / 90 days</p><h3>VulnSignal screening candidates not in CISA KEV</h3></div>
        <span>{watch ? `EPSS scores ${timestampLabel(watch.window.scoreDate)}` : "Awaiting EPSS history"}</span>
      </div>
      {watch ? (
        <>
          <div className="priority-watch__summary">
            <div><span>Candidates</span><strong><MetricValue href="#priority-watch-table" tooltip="Jump to the highest-probability candidate records">{number(watch.total)}</MetricValue></strong></div>
            <div><span>Critical or high</span><strong><MetricValue href="#priority-watch-table" tooltip="Jump to candidate severity and EPSS details">{number(watch.criticalHigh)}</MetricValue></strong></div>
            <div><span>NVD reference tagged "Exploit"</span><strong><MetricValue href="#priority-watch-table" tooltip="Jump to candidate exploit-reference details">{number(watch.publicExploitReferences)}</MetricValue></strong></div>
          </div>

          <div className="metric-select-tabs" style={{ marginTop: "12px", marginBottom: "8px" }}>
            <button className={filterMode === "all" ? "active" : ""} onClick={() => setFilterMode("all")}>All Candidates (EPSS ≥ 0.10)</button>
            <button className={filterMode === "top5" ? "active" : ""} onClick={() => setFilterMode("top5")}>Top 5% Percentile (≥ 95th)</button>
            <button className={filterMode === "top1" ? "active" : ""} onClick={() => setFilterMode("top1")}>Top 1% Percentile (≥ 99th)</button>
            <button className={filterMode === "criticalHigh" ? "active" : ""} onClick={() => setFilterMode("criticalHigh")}>Critical + High Only</button>
          </div>

          <p className="priority-watch__note">
            Published {dateLabel(watch.window.start, true)}–{dateLabel(watch.window.end, true)}. EPSS ≥ 0.10 is a project-defined screening threshold ({topPercentText || "approximately the top 4.9%"} of scored CVEs). Not appearing in CISA KEV does not prove that exploitation has not occurred. This list is a focused screening tool, not a recommended remediation queue or patch priority list. “Yes” under exploit reference means NVD has at least one reference tagged <code>Exploit</code>; “No” means that tag is absent in this snapshot.
          </p>
          {visibleItems.length ? (
            <div className="priority-table-wrap" id="priority-watch-table">
              <table className="priority-table">
                <caption>Showing highest EPSS probabilities among {number(filteredItems.length)} candidates matching filter criteria</caption>
                <thead><tr><th>Vulnerability</th><th>Published</th><th>Severity</th><th>EPSS probability</th><th>NVD reference tagged "Exploit"</th></tr></thead>
                <tbody>
                  {visibleItems.map((item) => (
                    <tr key={item.cveId}>
                      <td data-label="Vulnerability"><a href={item.url}>{item.cveId}</a></td>
                      <td data-label="Published"><strong>{dateLabel(item.published, true)}</strong><span>{ageLabel(item.published, watch.window.scoreDate)}</span></td>
                      <td data-label="Severity"><span className={`severity-badge severity-badge--${item.severity.toLowerCase()}`}>{item.severity === "UNKNOWN" ? "Unscored" : `${item.severity}${item.score === null ? "" : ` ${item.score}`}`}</span>{item.cvssVersion ? <small>CVSS {item.cvssVersion}</small> : null}</td>
                      <td data-label="EPSS probability"><strong>{probability(item.epss)}</strong><span>{percentileLabel(item.epssPercentile)}</span></td>
                      <td data-label="NVD reference tagged 'Exploit'">
                        {item.publicExploitReference ? (
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${item.cveId}#vulnHyperlinksSection`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="signal signal--active"
                          >
                            Yes
                          </a>
                        ) : (
                          <span className="signal">No</span>
                        )}
                        <small>{item.publicExploitReference ? "NVD-tagged exploit reference" : "No NVD exploit tag in this snapshot"}</small>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filteredItems.length > visibleItems.length ? <p className="table-note">Showing the {number(visibleItems.length)} highest EPSS probabilities here. {number(filteredItems.length)} candidate rows match this filter.</p> : null}
            </div>
          ) : <p className="panel-empty">No candidate CVEs match the selected filter criteria.</p>}
        </>
      ) : <p className="panel-empty">EPSS screening watch data is not available in this snapshot.</p>}
    </article>
  );
}

function EpssHistoryPanel({ history }: { history?: EpssHistory }) {
  const points = history?.points ?? [];
  const shares = points.map((point) => point.recordCount
    ? Math.round((point.highCount / point.recordCount) * 10_000) / 100
    : 0);
  const maximum = Math.max(...shares, 0.1);
  const plotted = points.map((point, index) => ({
    ...point,
    share: shares[index],
    x: points.length === 1 ? 50 : 5 + (index / (points.length - 1)) * 90,
    y: 44 - (shares[index] / maximum) * 34,
  }));
  const models = Array.from(new Set(points.map((point) => point.modelVersion)));
  return (
    <article className="flat-panel epss-history" id="epss-history">
      <div className="panel-heading">
        <div><p className="eyebrow">Official historical snapshots</p><h3>EPSS threshold history</h3></div>
        <span>{points.length} dated samples</span>
      </div>
      {plotted.length ? (
        <>
          <div className="epss-history__chart" role="img" aria-label={`Historical share of EPSS records at or above ${history?.threshold ?? 0.1}, from ${shortDateLabel(points[0].date)} to ${shortDateLabel(points.at(-1)!.date)}`}>
            <span className="epss-history__max">{maximum.toFixed(2)}%</span>
            <span className="epss-history__zero">0%</span>
            <svg viewBox="0 0 100 50" preserveAspectRatio="none" aria-hidden="true">
              {plotted.map((point, index) => index > 0 && !point.comparableToPrevious
                ? <line className="model-boundary" key={`${point.date}-boundary`} x1={point.x} y1="6" x2={point.x} y2="45" vectorEffect="non-scaling-stroke" />
                : null)}
              {plotted.slice(1).map((point, index) => {
                const previous = plotted[index];
                if (!point.comparableToPrevious) return null;
                return <line key={`${point.date}-line`} x1={previous.x} y1={previous.y} x2={point.x} y2={point.y} vectorEffect="non-scaling-stroke" />;
              })}
              {plotted.map((point) => <circle key={point.date} cx={point.x} cy={point.y} r="1.4" vectorEffect="non-scaling-stroke" />)}
            </svg>
            {plotted.map((point, index) => index === 0 || !point.comparableToPrevious
              ? <span className="epss-history__model-marker" key={`${point.date}-model`} style={{ "--x": `${point.x}%` } as CSSProperties}>{point.modelVersion}</span>
              : null)}
          </div>
          <div className="epss-history__axis"><span>{dateLabel(points[0].date)}</span><span>{dateLabel(points.at(-1)!.date)}</span></div>
          <div className="epss-history__latest">
            <span>Latest sampled share</span>
            <strong><MetricValue href={points.at(-1)?.sourceUrl} tooltip="Open the official dated EPSS snapshot">{shares.at(-1)?.toFixed(2)}%</MetricValue></strong>
            <small>{number(points.at(-1)?.notInKevCount ?? 0)} threshold records not in KEV</small>
          </div>
          <div className="epss-models"><span>Model versions</span>{models.map((model) => <em key={model}>{model}</em>)}</div>
          <a className="panel-source-link" href={points.at(-1)?.sourceUrl}>View latest historical source ↗</a>
          <p className="panel-note">Each point comes from its dated official EPSS snapshot. Dashed markers show model changes and lines stop at those boundaries; current scores are not applied backwards.</p>
          {history?.predictivePerformance && history.predictivePerformance.length > 0 ? (
            <div className="predictive-performance-panel" style={{ marginTop: "16px", paddingTop: "12px", borderTop: "1px solid var(--border)" }}>
              <p className="eyebrow" style={{ fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--muted)", marginBottom: "4px" }}>
                Association between historical EPSS scores and later KEV listing
              </p>
              <h4 style={{ fontSize: "13px", fontWeight: 600, margin: "0 0 4px 0" }}>
                Historical EPSS ≥ 0.10 subsequent KEV-entry rate
              </h4>
              <p style={{ fontSize: "11px", color: "var(--muted)", margin: "0 0 8px 0" }}>
                Subsequent KEV entry rate, lift over baseline, and recall for EPSS ≥ 0.10 candidates at historical score snapshot. Immature horizons (&lt;30/60/90d) are excluded from rate calculations.
              </p>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "8px" }}>
                {history.predictivePerformance.slice(-4).map((item) => (
                  <div key={item.snapshotDate} style={{ background: "var(--surface-muted, rgba(255,255,255,0.03))", padding: "8px", borderRadius: "6px", border: "1px solid var(--border)" }}>
                    <span style={{ display: "block", fontSize: "11px", fontWeight: 600 }}>{shortDateLabel(item.snapshotDate)}</span>
                    <span style={{ display: "block", fontSize: "10px", color: "var(--muted)" }}>{number(item.candidateCount)} candidates</span>
                    <div style={{ marginTop: "4px", fontSize: "10px", lineHeight: "1.4" }}>
                      <div>
                        30d: {item.isMature30d && item.conversionRate30d !== null ? (
                          <><strong>{item.conversionRate30d}%</strong> ({item.lift30d}× lift, {item.recall30d}% recall)</>
                        ) : <span style={{ color: "var(--muted)" }}>— (not mature)</span>}
                      </div>
                      <div>
                        60d: {item.isMature60d && item.conversionRate60d !== null ? (
                          <><strong>{item.conversionRate60d}%</strong> ({item.lift60d}× lift, {item.recall60d}% recall)</>
                        ) : <span style={{ color: "var(--muted)" }}>— (not mature)</span>}
                      </div>
                      <div>
                        90d: {item.isMature90d && item.conversionRate90d !== null ? (
                          <><strong>{item.conversionRate90d}%</strong> ({item.lift90d}× lift, {item.recall90d}% recall)</>
                        ) : <span style={{ color: "var(--muted)" }}>— (not mature)</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </>
      ) : <p className="panel-empty">Historical EPSS samples are not available in this snapshot.</p>}
    </article>
  );
}


function CvssEpssHeatmapPanel({
  data,
  coverage,
  epss,
}: {
  data?: DashboardData["cvssEpssHeatmap"];
  coverage?: DashboardData["coverage"];
  epss?: DashboardData["sources"]["epss"];
}) {
  const [metric, setMetric] = useState<"count" | "kevCount" | "exploitRefCount">("count");
  if (!data) return null;

  const rows = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"];
  const cols = ["Unscored", "<1%", "1–5%", "5–10%", "10–30%", "30–70%", "≥70%"];
  const colKeys = [0, 1, 2, 3, 4, 5, 6];

  let maxValue = 1;
  rows.forEach((r) => {
    data.grid[r]?.forEach((cell) => {
      const v = cell[metric];
      if (v > maxValue) maxValue = v;
    });
  });

  const getIntensity = (val: number) => {
    if (val === 0) return 0;
    return 0.1 + (val / maxValue) * 0.9;
  };

  const getBgColor = (intensity: number) => {
    if (intensity === 0) return "var(--rule-strong)";
    if (metric === "count") {
      return `rgba(239, 68, 68, ${intensity})`; // Red
    } else if (metric === "kevCount") {
      return `rgba(249, 115, 22, ${intensity})`; // Orange
    } else {
      return `rgba(14, 165, 233, ${intensity})`; // Blue
    }
  };

  const startLabel = coverage ? dateLabel(coverage.start, true) : "";
  const asOfLabel = coverage ? dateLabel(coverage.asOf, true) : "";
  const scoreDateLabel = epss?.scoreDate ? timestampLabel(epss.scoreDate) : "";

  return (
    <article className="flat-panel heatmap-panel" id="cvss-epss-heatmap">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Visual correlation / 6x7 Distribution</p>
          <h3>CVSS × EPSS distribution</h3>
        </div>
        <div className="metric-select-tabs">
          <button className={metric === "count" ? "active" : ""} onClick={() => setMetric("count")}>CVEs</button>
          <button className={metric === "kevCount" ? "active" : ""} onClick={() => setMetric("kevCount")}>KEVs</button>
          <button className={metric === "exploitRefCount" ? "active" : ""} onClick={() => setMetric("exploitRefCount")}>Exploit Refs</button>
        </div>
      </div>
      <p className="panel-desc">
        Distribution of {number(data.total)} active NVD records across CVSS base severities and EPSS probability bands.
      </p>
      {startLabel && asOfLabel && (
        <p className="panel-note" style={{ marginTop: "-8px", marginBottom: "4px" }}>
          Cohort: Active NVD records published {startLabel}–{asOfLabel}; current EPSS snapshot dated {scoreDateLabel || "N/A"}. Rejected CVEs are excluded.
        </p>
      )}
      
      <div className="heatmap-container">
        <div className="heatmap-grid" style={{ display: "grid", gridTemplateColumns: "110px repeat(7, minmax(60px, 1fr))", gap: "2px" }}>
          <div className="heatmap-label heatmap-label--corner">CVSS \ EPSS</div>
          {cols.map((col) => (
            <div key={col} className="heatmap-col-header">{col}</div>
          ))}

          {rows.map((row) => {
            const cells = data.grid[row] || [];
            return (
              <React.Fragment key={row}>
                <div className="heatmap-row-header">{row}</div>
                {colKeys.map((colIdx) => {
                  const cell = cells[colIdx] || { count: 0, kevCount: 0, exploitRefCount: 0 };
                  const val = cell[metric];
                  const intensity = getIntensity(val);
                  return (
                    <div
                      key={colIdx}
                      className="heatmap-cell"
                      style={{
                        background: getBgColor(intensity),
                        color: intensity > 0.5 ? "#fff" : "var(--fg)",
                      }}
                      title={`${row} severity, EPSS ${cols[colIdx]}: ${
                        metric === "count"
                          ? `${number(val)} CVEs`
                          : metric === "kevCount"
                            ? `${number(val)} CISA KEV-listed CVEs`
                            : `${number(val)} CVEs with an NVD exploit-tagged reference`
                      }`}
                    >
                      <span>{number(val)}</span>
                    </div>
                  );
                })}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </article>
  );
}


function SignalOverlapPanel({
  data,
  cvssEpssHeatmap,
}: {
  data?: DashboardData["signalOverlap"];
  cvssEpssHeatmap?: DashboardData["cvssEpssHeatmap"];
}) {
  const [sortBy, setSortBy] = useState<"count" | "signals">("count");
  if (!data) return null;

  const getActiveSignalsCount = (sets: { cvssHigh: boolean; epssHigh: boolean; exploitRef: boolean; cisaKev: boolean; ransomware: boolean }) => {
    return (sets.cvssHigh ? 1 : 0) + (sets.epssHigh ? 1 : 0) + (sets.exploitRef ? 1 : 0) + (sets.cisaKev ? 1 : 0) + (sets.ransomware ? 1 : 0);
  };

  const sortedData = [...data].sort((a, b) => {
    if (sortBy === "count") {
      return b.count - a.count;
    } else {
      const sigA = getActiveSignalsCount(a.sets);
      const sigB = getActiveSignalsCount(b.sets);
      if (sigB !== sigA) return sigB - sigA;
      return b.count - a.count;
    }
  });

  const maxCount = Math.max(...data.map(d => d.count), 1);

  let unscoredEpssCount = 0;
  if (cvssEpssHeatmap?.grid) {
    Object.values(cvssEpssHeatmap.grid).forEach((cells) => {
      unscoredEpssCount += cells[0]?.count ?? 0;
    });
  }

  return (
    <article className="flat-panel overlap-panel" id="signal-overlap">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Intersection matrix / UpSet style</p>
          <h3>Signal overlap intersections</h3>
        </div>
        <div className="metric-select-tabs">
          <button className={sortBy === "count" ? "active" : ""} onClick={() => setSortBy("count")}>Sort by Count</button>
          <button className={sortBy === "signals" ? "active" : ""} onClick={() => setSortBy("signals")}>Sort by Signal Count</button>
        </div>
      </div>
      <p className="panel-desc">
        Co-occurrence of key risk signals: CVSS High/Critical, EPSS ≥ 10%, public Exploit Ref tag, CISA KEV listing, and confirmed Ransomware Campaign Use.
      </p>
      <p className="panel-note" style={{ marginTop: "-8px", marginBottom: "8px" }}>
        Note: Each CVE appears in exactly one intersection row (intersections are mutually exclusive). An active dot means the CVE satisfies that signal; an inactive dot means it does not. An inactive EPSS signal includes both scores below 10% and records without a current EPSS score.
        {unscoredEpssCount > 0 ? ` ${number(unscoredEpssCount)} records in this cohort do not have a current EPSS score.` : ""}
      </p>

      <div className="overlap-matrix-container">
        <table className="overlap-table">
          <thead>
            <tr>
              <th className="signal-header">CVSS High</th>
              <th className="signal-header">EPSS ≥ 10%</th>
              <th className="signal-header">Exploit Ref</th>
              <th className="signal-header">CISA KEV</th>
              <th className="signal-header">Ransomware Campaign Use</th>
              <th className="bar-header">Intersection Size</th>
            </tr>
          </thead>
          <tbody>
            {sortedData.map((row, idx) => {
              const activeCount = getActiveSignalsCount(row.sets);
              return (
                <tr key={idx} className={activeCount >= 3 ? "high-priority-row" : ""}>
                  <td className="circle-cell"><span className={`circle ${row.sets.cvssHigh ? "active cvss" : ""}`} /></td>
                  <td className="circle-cell"><span className={`circle ${row.sets.epssHigh ? "active epss" : ""}`} /></td>
                  <td className="circle-cell"><span className={`circle ${row.sets.exploitRef ? "active exploit" : ""}`} /></td>
                  <td className="circle-cell"><span className={`circle ${row.sets.cisaKev ? "active kev" : ""}`} /></td>
                  <td className="circle-cell"><span className={`circle ${row.sets.ransomware ? "active ransomware" : ""}`} /></td>
                  <td className="bar-cell">
                    <div className="overlap-bar-wrapper">
                      <div className="overlap-bar" style={{ width: `${(row.count / maxCount) * 100}%` }} />
                      <strong className="overlap-count">{number(row.count)}</strong>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </article>
  );
}


function KevLagHeatmapPanel({ data }: { data?: DashboardData["kevLagHeatmap"] }) {
  const [viewMode, setViewMode] = useState<"count" | "percent">("percent");
  if (!data) return null;

  const years = Object.keys(data.grid).sort((a, b) => {
    if (a === "2017 & earlier") return 1;
    if (b === "2017 & earlier") return -1;
    return b.localeCompare(a);
  });

  const buckets = [
    { key: "pre_pub", label: "Pre-pub" },
    { key: "same_day", label: "Same day" },
    { key: "1_7_days", label: "1–7d" },
    { key: "8_30_days", label: "8–30d" },
    { key: "31_90_days", label: "31–90d" },
    { key: "91_365_days", label: "91–365d" },
    { key: "over_365_days", label: ">365d" },
  ];

  let maxVal = 1;
  years.forEach((y) => {
    const total = data.cohortTotals[y] || 1;
    buckets.forEach((b) => {
      const val = data.grid[y][b.key] || 0;
      if (viewMode === "count") {
        if (val > maxVal) maxVal = val;
      } else {
        const pct = (val / total) * 100;
        if (pct > maxVal) maxVal = pct;
      }
    });
  });

  const getBgColor = (val: number, total: number) => {
    if (val === 0) return "var(--rule-strong)";
    const ratio = viewMode === "count" ? val / maxVal : ((val / total) * 100) / maxVal;
    const intensity = 0.1 + ratio * 0.9;
    return `rgba(239, 68, 68, ${intensity})`;
  };

  return (
    <article className="flat-panel heatmap-panel" id="kev-lag-heatmap">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Time lag / CVE pub year vs KEV dateAdded</p>
          <h3>CISA KEV addition lag</h3>
        </div>
        <div className="metric-select-tabs">
          <button className={viewMode === "percent" ? "active" : ""} onClick={() => setViewMode("percent")}>% of Year</button>
          <button className={viewMode === "count" ? "active" : ""} onClick={() => setViewMode("count")}>Counts</button>
        </div>
      </div>
      <p className="panel-desc">
        Time delta between NVD publication and CISA KEV addition, grouped by CVE publication year. Pre-publication indicates KEV listing preceded NVD metadata publication.
      </p>

      <div className="heatmap-container">
        <div className="heatmap-grid" style={{ display: "grid", gridTemplateColumns: "110px repeat(7, minmax(60px, 1fr))", gap: "2px" }}>
          <div className="heatmap-label heatmap-label--corner">CVE Year</div>
          {buckets.map((b) => (
            <div key={b.key} className="heatmap-col-header">{b.label}</div>
          ))}

          {years.map((y) => {
            const total = data.cohortTotals[y] || 0;
            return (
              <React.Fragment key={y}>
                <div className="heatmap-row-header">{y} <small style={{ display: "block", fontSize: "10px", color: "var(--muted)" }}>(n={number(total)})</small></div>
                {buckets.map((b) => {
                  const val = data.grid[y][b.key] || 0;
                  const pct = total > 0 ? (val / total) * 100 : 0;
                  return (
                    <div
                      key={b.key}
                      className="heatmap-cell"
                      style={{
                        background: getBgColor(val, total),
                        color: (viewMode === "count" ? val / maxVal : pct / maxVal) > 0.5 ? "#fff" : "var(--fg)",
                      }}
                      title={`${pct.toFixed(1)}% — ${number(val)} of ${number(total)} KEV-matched CVEs`}
                    >
                      <span>{viewMode === "count" ? number(val) : `${pct.toFixed(1)}%`}</span>
                    </div>
                  );
                })}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </article>
  );
}


function EnrichmentCompletenessPanel({ data }: { data?: DashboardData["enrichmentCompleteness"] }) {
  if (!data) return null;

  return (
    <article className="flat-panel completeness-panel" id="enrichment-completeness">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Quality signals / Trailing 36 months</p>
          <h3>Enrichment availability &amp; observed security signals</h3>
        </div>
      </div>
      <p className="panel-desc">
        Availability metrics (CVSS, CWE, and EPSS coverage) track how completely records are enriched over time. The observed security signal (NVD exploit-reference share) tracks the prevalence of exploit-tagged references. Recent periods naturally have lower availability as source records and downstream enrichment continue to mature.
      </p>

      <div className="completeness-table-container">
        <table className="completeness-table">
          <thead>
            <tr>
              <th className="month-header" rowSpan={2} style={{ verticalAlign: "middle", borderBottom: "1px solid var(--rule-strong)" }}>Month</th>
              <th className="num-header" rowSpan={2} style={{ verticalAlign: "middle", borderBottom: "1px solid var(--rule-strong)", textAlign: "right" }}>CVEs</th>
              <th className="num-header" colSpan={3} style={{ textAlign: "center", borderBottom: "1px solid var(--rule-strong)", fontWeight: 600 }}>Enrichment availability</th>
              <th className="num-header" colSpan={1} style={{ textAlign: "center", borderBottom: "1px solid var(--rule-strong)", fontWeight: 600 }}>Observed signal</th>
            </tr>
            <tr>
              <th className="num-header" style={{ textAlign: "right" }}>CVSS coverage</th>
              <th className="num-header" style={{ textAlign: "right" }}>Specific CWE coverage</th>
              <th className="num-header" style={{ textAlign: "right" }}>EPSS coverage</th>
              <th className="num-header" style={{ textAlign: "right" }}>NVD exploit-tag share</th>
            </tr>
          </thead>
          <tbody>
            {[...data].reverse().map((row, idx) => {
              let tag = "";
              if (idx === 0) {
                tag = " (Partial)";
              } else if (idx < 6) {
                tag = " (Enriching)";
              } else {
                tag = " (Mature)";
              }
              return (
                <tr key={row.month}>
                  <td className="month-cell">
                    {row.month}
                    <small style={{ display: "block", fontSize: "9px", color: "var(--muted)", marginTop: "2px" }}>{tag}</small>
                  </td>
                  <td className="num-cell">{number(row.total)}</td>
                  <td className="num-cell pct-cell">
                    <div className="pct-bar-wrapper" title={`${row.cvssPercent}%`}>
                      <div className="pct-bar cvss" style={{ width: `${row.cvssPercent}%` }} />
                      <span>{row.cvssPercent}%</span>
                    </div>
                  </td>
                  <td className="num-cell pct-cell">
                    <div className="pct-bar-wrapper" title={`${row.cwePercent}%`}>
                      <div className="pct-bar cwe" style={{ width: `${row.cwePercent}%` }} />
                      <span>{row.cwePercent}%</span>
                    </div>
                  </td>
                  <td className="num-cell pct-cell">
                    <div className="pct-bar-wrapper" title={`${row.epssPercent}%`}>
                      <div className="pct-bar epss" style={{ width: `${row.epssPercent}%` }} />
                      <span>{row.epssPercent}%</span>
                    </div>
                  </td>
                  <td className="num-cell pct-cell">
                    <div className="pct-bar-wrapper" title={`${row.exploitRefPercent}%`}>
                      <div className="pct-bar exploit" style={{ width: `${row.exploitRefPercent}%` }} />
                      <span>{row.exploitRefPercent}%</span>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </article>
  );
}


function CweHeatmapPanel({ data, topCwes }: { data?: DashboardData["cweHeatmap"], topCwes: CweRow[] }) {
  const [viewMode, setViewMode] = useState<"count" | "percent">("percent");
  if (!data) return null;

  const quarters = data.quarters;
  const cweIds = Object.keys(data.grid);

  let maxVal = 1;
  let maxPct = 0.1;
  cweIds.forEach((cwe) => {
    quarters.forEach((q) => {
      const val = data.grid[cwe][q] || 0;
      const total = data.quarterTotals[q] || 1;
      const pct = (val / total) * 100;
      if (val > maxVal) maxVal = val;
      if (pct > maxPct) maxPct = pct;
    });
  });

  const getBgColor = (val: number, total: number) => {
    if (val === 0) return "var(--rule-strong)";
    const ratio = viewMode === "count" ? val / maxVal : ((val / total) * 100) / maxPct;
    const intensity = 0.1 + ratio * 0.9;
    return `rgba(139, 92, 246, ${intensity})`;
  };

  return (
    <article className="flat-panel heatmap-panel" id="cwe-heatmap">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Weakness distribution / Top 6 CWEs by Quarter</p>
          <h3>CWE quarterly distribution</h3>
        </div>
        <div className="metric-select-tabs">
          <button className={viewMode === "percent" ? "active" : ""} onClick={() => setViewMode("percent")}>Shares (%)</button>
          <button className={viewMode === "count" ? "active" : ""} onClick={() => setViewMode("count")}>Counts</button>
        </div>
      </div>
      <p className="panel-desc">
        Distribution share or count for the current top 6 CWE classes over the last 8 quarters.
      </p>

      <div className="heatmap-container">
        <div className="heatmap-grid" style={{ display: "grid", gridTemplateColumns: "110px repeat(8, minmax(50px, 1fr))", gap: "2px" }}>
          <div className="heatmap-label heatmap-label--corner">CWE ID</div>
          {quarters.map((q, qIdx) => (
            <div key={q} className="heatmap-col-header">
              {q}
              {qIdx === quarters.length - 1 ? (
                <small style={{ display: "block", fontSize: "9px", color: "var(--muted)", marginTop: "2px" }}>(Incomplete)</small>
              ) : null}
            </div>
          ))}

          {cweIds.map((cwe) => {
            return (
              <React.Fragment key={cwe}>
                <div className="heatmap-row-header" title={topCwes.find(t => t.cwe === cwe)?.name}>{cwe}</div>
                {quarters.map((q) => {
                  const val = data.grid[cwe][q] || 0;
                  const total = data.quarterTotals[q] || 1;
                  const pct = (val / total) * 100;
                  return (
                    <div
                      key={q}
                      className="heatmap-cell"
                      style={{
                        background: getBgColor(val, total),
                        color: (viewMode === "count" ? val / maxVal : pct / maxPct) > 0.5 ? "#fff" : "var(--fg)",
                      }}
                      title={`${cwe}: ${number(val)} of ${number(total)} CVEs (${pct.toFixed(1)}% of quarter's publications)`}
                    >
                      <span>{viewMode === "count" ? number(val) : `${pct.toFixed(1)}%`}</span>
                    </div>
                  );
                })}
              </React.Fragment>
            );
          })}
        </div>
      </div>
      <p className="panel-note" style={{ marginTop: "12px", fontStyle: "italic" }}>
        Warning: CWE shares can total &gt;100% since a single CVE can carry multiple weakness codes.
      </p>
    </article>
  );
}


function WeaknessAnalysisPanel({ data }: { data?: DashboardData["weaknessAnalysis"] }) {
  if (!data) return null;

  const total = data.totalRecords;
  const specificPct = total > 0 ? (data.specificCount / total) * 100 : 0;
  const noinfoPct = total > 0 ? (data.noinfoCount / total) * 100 : 0;
  const otherPct = total > 0 ? (data.otherCount / total) * 100 : 0;
  const nonePct = total > 0 ? (data.noneCount / total) * 100 : 0;

  return (
    <article className="flat-panel weakness-breakdown-panel" id="weakness-completeness">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Weakness quality classification / T12M</p>
          <h3>CWE classification completeness</h3>
        </div>
        <span>{number(total)} records</span>
      </div>
      <p className="panel-desc">
        Breakdown of weakness classification statuses for CVEs published in the trailing 12 months.
      </p>

      <div className="breakdown-bars">
        <div className="breakdown-bar-item">
          <div className="bar-info">
            <span>Specific CWE code assigned</span>
            <strong>{number(data.specificCount)} ({specificPct.toFixed(1)}%)</strong>
          </div>
          <div className="bar-bg"><div className="bar-fill specific" style={{ width: `${specificPct}%` }} /></div>
        </div>
        
        <div className="breakdown-bar-item">
          <div className="bar-info">
            <span>No information provided (NVD-CWE-noinfo)</span>
            <strong>{number(data.noinfoCount)} ({noinfoPct.toFixed(1)}%)</strong>
          </div>
          <div className="bar-bg"><div className="bar-fill noinfo" style={{ width: `${noinfoPct}%` }} /></div>
        </div>

        <div className="breakdown-bar-item">
          <div className="bar-info">
            <span>Other non-specific weakness code (NVD-CWE-Other)</span>
            <strong>{number(data.otherCount)} ({otherPct.toFixed(1)}%)</strong>
          </div>
          <div className="bar-bg"><div className="bar-fill other" style={{ width: `${otherPct}%` }} /></div>
        </div>

        <div className="breakdown-bar-item">
          <div className="bar-info">
            <span>No weakness data recorded</span>
            <strong>{number(data.noneCount)} ({nonePct.toFixed(1)}%)</strong>
          </div>
          <div className="bar-bg"><div className="bar-fill none" style={{ width: `${nonePct}%` }} /></div>
        </div>
      </div>
    </article>
  );
}


export default function Home() {
  const thresholdPercentile = dashboard.sources.epss?.thresholdPercentile;
  const topPercentText = thresholdPercentile !== undefined && thresholdPercentile !== null
    ? `approximately the top ${((1 - thresholdPercentile) * 100).toFixed(1)}%`
    : "approximately the top 4.9%";

  const maxCwe = Math.max(
    ...dashboard.topCwes.map((item) => item.recentShare ?? item.count),
    1,
  );
  const fallbackMatureWindow: DateWindow = {
    start: dashboard.risk.matureCohortStart,
    end: dashboard.risk.matureCohortEnd,
  };
  const timingComparison = dashboard.risk.kevTimingComparison;
  const additionComparison = dashboard.risk.kevAdditionComparison;
  const deadlineComparison = dashboard.risk.kevDeadlineComparison;
  const kevTimingPeriod = dateRangeLabel(
    timingComparison?.current ?? dashboard.risk.kevTimingWindow,
    fallbackMatureWindow,
  );
  const kevAdditionsPeriod = dateRangeLabel(
    additionComparison?.current ?? dashboard.risk.kevAdditionsWindow,
    fallbackMatureWindow,
  );
  const epssCohortPeriod = dateRangeLabel(
    dashboard.risk.epssCohortWindow,
    fallbackMatureWindow,
  );
  const epssScoreDate = dashboard.sources.epss?.scoreDate
    ?? dashboard.risk.epssCohortWindow?.scoreDate
    ?? null;
  const sourceUpdates = [
    { label: "CVE List", qualifier: "Updated", value: dashboard.sources.cve.latestFetch, url: dashboard.sources.cve.url },
    { label: "NVD", qualifier: "Updated", value: dashboard.sources.nvd.latestSourceUpdate, url: dashboard.sources.nvd.url },
    { label: "CISA KEV", qualifier: "Released", value: dashboard.sources.kev.released, url: dashboard.sources.kev.url },
    { label: "Anthropic CVD", qualifier: "As at", value: dashboard.sources.anthropic.asOf, url: dashboard.sources.anthropic.url },
    { label: "EPSS", qualifier: "Score date", value: epssScoreDate, url: dashboard.sources.epss?.url ?? "https://www.first.org/epss/" },
    { label: "LLM register", qualifier: "Reviewed", value: dashboard.sources.llmRegistry.lastReviewed, url: dashboard.sources.llmRegistry.url },
  ];
  const headlineLlmSource = dashboard.llmDiscovery.programReports.find(
    (report) => report.count === dashboard.llmDiscovery.value,
  )?.sourceUrl;

  return (
    <main>
      <FreshnessBanner generatedAt={dashboard.generatedAt} />
      <header className="topbar">
        <a className="brand" href="#top" aria-label="VulnSignal home">
          <span className="brand__mark" aria-hidden="true">
            {Array.from({ length: 9 }, (_, index) => <i key={index} />)}
          </span>
          <span><strong>VulnSignal</strong><small>CVE / KEV / PUBLIC SOURCES</small></span>
        </a>
        <nav aria-label="Dashboard sections">
          <a href="#reporting">Reporting</a>
          <a href="#context">Context</a>
          <a href="#kev-watch">KEV watch</a>
          <a href="#methodology">Sources</a>
        </nav>
        <div className="sync-state">
          <span className="sync-state__dot" aria-hidden="true" />
          <span><strong>SNAPSHOT ID</strong><small>{dashboard.snapshot.id}</small></span>
        </div>
      </header>

      <div className="page" id="top">
        <section className="hero">
          <div className="hero__copy">
            <p className="kicker">DAILY VULNERABILITY REPORT</p>
            <h1>Vulnerability trends.<br /><em>Exploitation signals.</em></h1>
            <p>
              Compare monthly CVE publications, CVSS severity, CISA KEV additions,
              public exploit references and EPSS probability signals. Documented LLM-assisted disclosures remain a separate evidence ledger.
            </p>
          </div>
          <div className="hero__status">
            <div><span>Snapshot built</span><strong><MetricValue tooltip="UTC time when this validated dashboard snapshot was generated">{timestampLabel(dashboard.generatedAt)}</MetricValue></strong></div>
            <div><span>Latest complete month</span><strong><MetricValue href="#reporting" tooltip="Jump to the interactive monthly and yearly report">{dateLabel(dashboard.coverage.latestCompleteMonth)}</MetricValue></strong></div>
            <div><span>CVE records covered</span><strong><MetricValue href={dashboard.sources.nvd.url} tooltip="Open the official NVD source used for CVE trend records">{number(dashboard.coverage.recordCount)}</MetricValue></strong></div>
            <div><span>Refresh schedule</span><strong><MetricValue tooltip="Normally refreshed daily. The displayed snapshot may be up to 72 hours old if an upstream source or validation step fails.">{dashboard.project.refreshSchedule || "Daily"}</MetricValue></strong></div>
          </div>
          <div className="source-snapshot" aria-label="Source dates included in this snapshot">
            <strong>Source data included</strong>
            <div>
              {sourceUpdates.map((source) => (
                <a href={source.url} key={source.label}>
                  <span>
                    {source.label}
                    {source.label === "CVE List" && (
                      <span className="telemetry-badge">
                        ({number(dashboard.sources.cve.changedRecords24h)} changes/24h)
                      </span>
                    )}
                  </span>
                  <time dateTime={source.value ?? undefined}><b>{source.qualifier}</b>{timestampLabel(source.value)}</time>
                </a>
              ))}
            </div>
          </div>
        </section>

        <WhatChanged digest={dashboard.changeDigest} cveUrl={dashboard.sources.cve.url} />

        <TrendExplorer
          monthly={dashboard.monthly}
          latestCompleteMonth={dashboard.coverage.latestCompleteMonth}
          events={dashboard.llmDiscovery.events ?? []}
          epssScoreDate={epssScoreDate}
          priorityWatch={dashboard.priorityWatch}
        />

        <section className="section" id="context">
          <div className="section-heading">
            <div><p className="eyebrow">[02] Additional context</p><h2>Additional vulnerability metrics</h2></div>
            <p>Each metric states the period and records included.</p>
          </div>

          <div className="priority-history-grid">
            <PriorityWatchPanel watch={dashboard.priorityWatch} topPercentText={topPercentText} />
            <EpssHistoryPanel history={dashboard.epssHistory} />
          </div>

          <div className="visualizations-grid" style={{ marginTop: "24px" }}>
            <CvssEpssHeatmapPanel data={dashboard.cvssEpssHeatmap} coverage={dashboard.coverage} epss={dashboard.sources.epss} />
            <SignalOverlapPanel data={dashboard.signalOverlap} cvssEpssHeatmap={dashboard.cvssEpssHeatmap} />
          </div>

          <div className="visualizations-grid" style={{ marginTop: "24px" }}>
            <KevLagHeatmapPanel data={dashboard.kevLagHeatmap} />
            <EnrichmentCompletenessPanel data={dashboard.enrichmentCompleteness} />
          </div>

          <div className="operational-matrix">
            <article>
              <span>Publication-to-KEV gap (Median)</span>
              <small>{kevTimingPeriod}</small>
              <strong>
                <MetricValue tooltip={`Median across ${number(timingComparison?.current.sample ?? dashboard.risk.kevTimingSample)} KEV-matched CVEs in mature cohort (using signed difference; negative values indicate CISA KEV listing predates NVD publication)`}>
                  {(timingComparison?.current.medianDays ?? dashboard.risk.medianDaysToKev) === null ? "—" : `${number(timingComparison?.current.medianDays ?? dashboard.risk.medianDaysToKev ?? 0)} days`}
                </MetricValue>
              </strong>
              <small style={{ display: "block", fontSize: "11px", color: "var(--muted)", marginTop: "4px", fontWeight: 600 }}>
                {number(timingComparison?.current.sample ?? dashboard.risk.kevTimingSample)} KEV-listed / {number(timingComparison?.current.matureCves ?? dashboard.risk.matureCohort)} mature CVEs
              </small>
              <DeltaTag value={timingComparison?.medianDaysChange} unit="days" />
              <p>
                Signed median gap across KEV-listed CVEs in mature cohort. Post-publication median gap: {number(timingComparison?.current.medianDaysNonNegative ?? dashboard.risk.medianDaysToKevNonNegative ?? 0)} days ({number(timingComparison?.current.prePublicationKev ?? dashboard.risk.prePublicationKev)} pre-publication listings; {percent(timingComparison?.current.prePublicationKevShare ?? dashboard.risk.prePublicationKevShare ?? null)} of sample).
              </p>
            </article>
            <article>
              <span>Publication-to-KEV gap (75th percentile)</span>
              <small>{kevTimingPeriod}</small>
              <strong>
                <MetricValue tooltip={`75th percentile across ${number(timingComparison?.current.sample ?? dashboard.risk.kevTimingSample)} KEV-matched CVEs in the mature cohort`}>
                  {(timingComparison?.current.p75Days ?? dashboard.risk.p75DaysToKev) === null ? "—" : `${number(timingComparison?.current.p75Days ?? dashboard.risk.p75DaysToKev ?? 0)} days`}
                </MetricValue>
              </strong>
              <small style={{ display: "block", fontSize: "11px", color: "var(--muted)", marginTop: "4px", fontWeight: 600 }}>
                {number(timingComparison?.current.sample ?? dashboard.risk.kevTimingSample)} KEV-listed / {number(timingComparison?.current.matureCves ?? dashboard.risk.matureCohort)} mature CVEs
              </small>
              <DeltaTag value={timingComparison?.p75DaysChange} unit="days" />
              <p>75% of matched KEV CVEs entered within this time after NVD publication.</p>
            </article>
            <article>
              <span>Mature CVE KEV entry within 90 days</span>
              <small>{kevTimingPeriod}</small>
              <strong>
                <MetricValue tooltip="Share of mature published CVEs that entered KEV within 90 days of NVD publication">
                  {percent(dashboard.risk.kevWithin90DayRate)}
                </MetricValue>
              </strong>
              <p>
                {number(dashboard.risk.kevWithin90Days)} of {number(dashboard.risk.matureCohort)} mature published CVEs. Among KEV-listed CVEs in this cohort, {percent(dashboard.risk.kevWithin90DayKevShare ?? 86.4)} entered within 90 days.
              </p>
            </article>
            <article>
              <span>KEV conversion rate</span>
              <small>Mature cohort conversion</small>
              <strong>
                <MetricValue tooltip="Comparison of KEV conversion rate for all mature CVEs vs exploit-tagged mature CVEs">
                  {percent(dashboard.risk.allCveKevConversion ?? 0.34)}
                </MetricValue>
              </strong>
              <p>
                {percent(dashboard.risk.allCveKevConversion ?? 0.34)} of all mature CVEs enter KEV, compared to {percent(dashboard.risk.exploitRefKevConversion ?? 0.0)} of CVEs with an NVD Exploit tag.
              </p>
            </article>
            <article>
              <span>Ransomware in KEV additions</span>
              <small>{kevAdditionsPeriod}</small>
              <strong><MetricValue href={dashboard.sources.kev.url} tooltip="Open the official CISA KEV catalog containing ransomware-use flags">{percent(additionComparison?.current.ransomwareShare ?? dashboard.risk.ransomwareKevShare)}</MetricValue></strong>
              <DeltaTag value={additionComparison?.ransomwareShareChangePoints} unit="points" />
              <p>{number(additionComparison?.current.ransomwareCount ?? dashboard.risk.ransomwareKevCount)} of {number(additionComparison?.current.count ?? dashboard.risk.kevAdditionsCount)} additions are known to be used in ransomware campaigns.</p>
            </article>
            <article>
              <span>KEV deadlines within 7 days</span>
              <small>{dateRangeLabel(deadlineComparison?.current, dashboard.risk.kevAdditionsWindow)}</small>
              <strong><MetricValue href={dashboard.sources.kev.url} tooltip="Open the official CISA KEV catalog containing required-action due dates">{percent(deadlineComparison?.current.within7Share ?? null)}</MetricValue></strong>
              <DeltaTag value={deadlineComparison?.within7ShareChangePoints} unit="points" />
              <p>{number(deadlineComparison?.current.within7Count ?? 0)} of {number(deadlineComparison?.current.dueWindowSample ?? 0)} additions required accelerated remediation within seven days.</p>
            </article>
            <article>
              <span>KEV additions &gt;2 years old</span>
              <small>{kevAdditionsPeriod}</small>
              <strong><MetricValue href={dashboard.sources.kev.url} tooltip="Open the official CISA KEV catalog used for this age comparison">{percent(additionComparison?.current.oldShare ?? dashboard.risk.oldKevShare)}</MetricValue></strong>
              <DeltaTag value={additionComparison?.oldShareChangePoints} unit="points" />
              <p>{number(additionComparison?.current.oldCount ?? dashboard.risk.oldKevCount)} of {number(additionComparison?.current.ageSample ?? dashboard.risk.kevAgeSample)} additions with publication dates were listed more than two years later.</p>
            </article>
            <article>
              <span>EPSS ≥ 0.10 not in CISA KEV</span>
              <small>{epssCohortPeriod} · scores {timestampLabel(epssScoreDate)}</small>
              <strong><MetricValue href="#priority-watch-panel" tooltip="Jump to the VulnSignal screening threshold candidates not listed in CISA KEV">{percent(dashboard.risk.highEpssNotInKevShare)}</MetricValue></strong>
              <p>{number(dashboard.risk.highEpssNotInKevCount)} of {number(dashboard.risk.highEpss)} CVEs meeting this project-defined threshold are not in CISA KEV. Scores are current, not historical.</p>
            </article>
          </div>

          <div className="context-grid">
            <article className="flat-panel era-card">
              <div className="panel-heading">
                <div><p className="eyebrow">Two adjacent 36-month periods</p><h3>Disclosure and publication activity</h3></div>
                <span>Published reporting trends</span>
              </div>
              <div className="era-labels">
                <div><i />EARLIER <strong>{dateLabel(dashboard.comparison.earlier.start)}–{dateLabel(dashboard.comparison.earlier.end)}</strong></div>
                <div><i />RECENT <strong>{dateLabel(dashboard.comparison.recent.start)}–{dateLabel(dashboard.comparison.recent.end)}</strong></div>
              </div>
              <ComparisonRow label="Average CVEs per month" earlier={dashboard.comparison.earlier.monthlyAverage} recent={dashboard.comparison.recent.monthlyAverage} />
              <ComparisonRow label="Critical + high share of scored CVEs" earlier={dashboard.comparison.earlier.criticalHighShare} recent={dashboard.comparison.recent.criticalHighShare} suffix="%" changeMode="points" />
              <ComparisonRow label="CVEs with public exploit references" earlier={dashboard.comparison.earlier.publicExploitShare} recent={dashboard.comparison.recent.publicExploitShare} suffix="%" changeMode="points" />
              <ComparisonRow label="Current EPSS ≥ 0.1 share (project threshold)" earlier={dashboard.comparison.earlier.epssHighShare} recent={dashboard.comparison.recent.epssHighShare} suffix="%" changeMode="points" />
              <p className="panel-note">EPSS scores use the current snapshot dated {timestampLabel(epssScoreDate)} and are grouped by CVE publication period; this is not a historical EPSS trend.</p>
              <p className="panel-note">{dashboard.comparison.note}</p>
            </article>

            <article className="flat-panel evidence-card">
              <div className="panel-heading">
                <div><p className="eyebrow">LLM disclosure evidence</p><h3>Reported LLM-assisted disclosure events</h3></div>
              </div>
              <div className="evidence-score">
                <strong><MetricValue href={headlineLlmSource} tooltip={headlineLlmSource ? "Open the first-party programme report supporting this value" : "No single linked programme report is available for this value"}>{dashboard.llmDiscovery.value === null ? "—" : `≥ ${number(dashboard.llmDiscovery.value)}`}</MetricValue></strong>
                <span>Largest CVE count reported by one programme</span>
              </div>
              <div className="evidence-ledger">
                {dashboard.llmDiscovery.programReports.map((report) => (
                  <a href={report.sourceUrl} key={report.id}>
                    <span>{dateLabel(report.published, true)}</span>
                    <strong>{report.publisher} / {report.program}</strong>
                    <em>≥ {number(report.count)} {report.metric.toLowerCase()}</em>
                    <i aria-hidden="true">↗</i>
                  </a>
                ))}
              </div>
              <p className="panel-note">{dashboard.llmDiscovery.basis}</p>
            </article>
          </div>

          <article className="flat-panel weakness-panel">
            <div className="panel-heading">
              <div><p className="eyebrow">CWE / Trailing 12 months</p><h3>Most common CWE classes</h3></div>
              <span>Share of CVEs · change vs prior 12 months</span>
            </div>
            {dashboard.cweMovers ? (
              <div className="cwe-movers" aria-label="Largest CWE share changes">
                <article>
                  <span>Largest share risers</span>
                  {dashboard.cweMovers.rising.slice(0, 2).map((item) => (
                    <a href={item.url} key={item.cwe}>
                      <strong>{item.cwe}</strong>
                      <span>{item.name}</span>
                      <em>+{Math.abs(item.changePoints ?? 0).toFixed(1)} percentage points</em>
                    </a>
                  ))}
                </article>
                <article>
                  <span>Largest share fallers</span>
                  {dashboard.cweMovers.falling.slice(0, 2).map((item) => (
                    <a href={item.url} key={item.cwe}>
                      <strong>{item.cwe}</strong>
                      <span>{item.name}</span>
                      <em>−{Math.abs(item.changePoints ?? 0).toFixed(1)} percentage points</em>
                    </a>
                  ))}
                </article>
              </div>
            ) : null}
            <div className="cwe-list">
              {dashboard.topCwes.map((item, index) => {
                const hasShare = item.recentShare !== undefined;
                const recentValue = item.recentShare ?? item.count;
                const change = item.changePoints ?? item.change ?? 0;
                const changeText = hasShare
                  ? `${change > 0 ? "+" : change < 0 ? "−" : ""}${Math.abs(change).toFixed(1)} points`
                  : change > 0
                    ? `+${number(change)}`
                    : change < 0
                      ? `−${number(Math.abs(change))}`
                      : "0";
                const changeClass = change > 0 ? "cwe-change--up" : change < 0 ? "cwe-change--down" : "cwe-change--flat";
                return (
                  <div className="cwe-row" key={item.cwe}>
                    <span>{String(index + 1).padStart(2, "0")}</span>
                    <strong><a href={item.url ?? `https://cwe.mitre.org/data/definitions/${item.cwe.replace("CWE-", "")}.html`}>{item.cwe}<small>{item.name ?? "Official CWE definition"}</small></a></strong>
                    <div title={`${number(item.count)} CVEs`}><i style={{ "--bar": `${(recentValue / maxCwe) * 100}%` } as CSSProperties} /></div>
                    <em className="cwe-count" title={`${number(item.count)} CVEs`}>{hasShare ? percent(item.recentShare ?? null) : number(item.count)}</em>
                    <span className={`cwe-change ${changeClass}`} title="Percentage-point change vs prior 12 months">{changeText}</span>
                  </div>
                );
              })}
            </div>
            <p className="panel-note" style={{ marginTop: "16px", fontStyle: "italic", borderTop: "1px solid var(--rule-strong)", paddingTop: "12px" }}>
              Warning: CWE shares can total &gt;100% since a single CVE can carry multiple weakness codes.
            </p>
          </article>

          <div className="visualizations-grid" style={{ marginTop: "24px" }}>
            <CweHeatmapPanel data={dashboard.cweHeatmap} topCwes={dashboard.topCwes} />
            <WeaknessAnalysisPanel data={dashboard.weaknessAnalysis} />
          </div>
        </section>

        <section className="section" id="kev-watch">
          <div className="section-heading">
            <div><p className="eyebrow">[03] Exploitation ledger</p><h2>Recently added to CISA KEV</h2></div>
            <p>A CISA KEV listing confirms known exploitation. An NVD exploit-tagged reference is a separate public signal.</p>
          </div>

          <article className="flat-panel kev-table-card">
            <div className="panel-heading">
              <div><p className="eyebrow">CISA / Latest additions</p><h3>KEV watch</h3></div>
              <a href={dashboard.sources.kev.url}>VIEW CISA SOURCE ↗</a>
            </div>
            <div className="table-wrap">
              <table className="kev-table">
                <thead><tr><th>Added</th><th>Vulnerability</th><th>Asset</th><th>Severity</th><th>Signals</th><th>Due</th></tr></thead>
                <tbody>
                  {dashboard.recentKev.map((item) => (
                    <tr key={item.cveId}>
                      <td data-label="Added">{dateLabel(item.dateAdded, true)}</td>
                      <td data-label="Vulnerability"><a href={`https://www.cve.org/CVERecord?id=${item.cveId}`}>{item.cveId}</a><span>{item.name}</span></td>
                      <td data-label="Asset"><strong>{item.vendor}</strong><span>{item.product}</span></td>
                      <td data-label="Severity"><span className={`severity-badge severity-badge--${item.severity.toLowerCase()}`}>{item.severity === "UNKNOWN" ? "Unscored" : `${item.severity}${item.score ? ` ${item.score}` : ""}${item.cvssVersion ? ` (${item.cvssVersion.toLowerCase()})` : ""}`}</span></td>
                      <td data-label="Signals">
                        <div className="signal-list">
                          <a
                            href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="signal signal--active"
                          >
                            Known exploited
                          </a>
                          {item.ransomware === "Known" ? (
                            <span className="signal signal--ransomware">Ransomware</span>
                          ) : null}
                          {item.publicExploitReference ? (
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${item.cveId}#vulnHyperlinksSection`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="signal"
                            >
                              Exploit ref
                            </a>
                          ) : null}
                        </div>
                      </td>
                      <td data-label="Due">{dateLabel(item.dueDate, true)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </article>
        </section>

        <section className="methodology" id="methodology">
          <div className="methodology__intro">
            <p className="eyebrow">[04] Definitions and sources</p>
            <h2>What each metric measures</h2>
            <p>CVE counts use NVD publication dates. KEV counts use CISA listing dates. Exploit references, current EPSS probabilities and LLM disclosures remain separate signals.</p>
          </div>
          <div className="method-grid">
            <article><span>01</span><h3>CVE publication</h3><p>Active NVD records are grouped by publication month; rejected records are excluded.</p></article>
            <article><span>02</span><h3>Severity</h3><p>Selects Primary assessments where available (originating from NVD or provider-level CNAs), falling back to Secondary assessments. A scored 0.0 is shown as “None”; records without a score remain “Unscored”.</p></article>
            <article><span>03</span><h3>Exploitation</h3><p>An NVD reference tagged “Exploit” indicates linked public material; it does not prove that the exploit works. Only CISA KEV entries are labelled “Known exploited”.</p></article>
            <article><span>04</span><h3>LLM evidence</h3><p>Report and reveal dates are not discovery dates. Counts from different programmes remain separate because they may overlap.</p></article>
            <article><span>05</span><h3>EPSS probability</h3><p>Current FIRST EPSS scores estimate exploitation probability over the next 30 days. Scores are grouped by CVE publication month; ≥ 0.1 is a project-defined threshold, not an official severity band. In the current snapshot, this threshold dynamically corresponds to {topPercentText} of scored CVEs.</p></article>
          </div>
          <div className="source-strip">
            <span>SOURCES</span>
            <a href={dashboard.sources.cve.url}>CVE LIST V5 ↗</a>
            <a href={dashboard.sources.nvd.url}>NVD JSON 2.0 ↗</a>
            <a href={dashboard.sources.kev.url}>CISA KEV ↗</a>
            <a href={dashboard.sources.epss?.url ?? "https://www.first.org/epss/"}>FIRST EPSS ↗</a>
            <a href={dashboard.sources.anthropic.url}>ANTHROPIC CVD ↗</a>
            <a href={dashboard.sources.llmRegistry.url}>LLM REGISTER ↗</a>
          </div>
          <aside className="project-disclaimer" id="disclaimer" aria-labelledby="disclaimer-title">
            <div>
              <span>PROJECT DISCLAIMER</span>
              <h3 id="disclaimer-title">Informational use only</h3>
            </div>
            <div>
              <p>VulnSignal is a personal, experimental project. It is not legal, compliance, security, risk-management or remediation advice, and it should not be the sole basis for operational decisions. Verify important findings against the linked original sources, vendor guidance and your own environment.</p>
              <p>Data and derived metrics may be incomplete, delayed, revised or incorrect. SHA-256 fingerprints establish which bytes were processed for traceability and reproducibility, but do not prove independent authenticity or correctness of upstream publisher data. The project is provided “as is”, without guarantees of accuracy, completeness, timeliness, availability or fitness for a particular purpose. Use it at your own risk. Source names and trademarks belong to their respective owners; inclusion does not imply affiliation, endorsement or certification. Software use remains subject to the <a href="https://github.com/llody9977/vulnsignal/blob/main/LICENSE">Apache License 2.0</a>.</p>
              <p className="project-disclaimer__nvd">{dashboard.coverage.notice}</p>
            </div>
          </aside>
        </section>
      </div>

      <footer>
        <div><strong>VulnSignal</strong><span>© 2026 <a href="https://github.com/llody9977">llody9977</a> · Apache-2.0</span></div>
        <div><a href="#disclaimer">DISCLAIMER</a><a href="https://github.com/llody9977/vulnsignal/blob/main/NOTICE">ATTRIBUTION ↗</a><a href="https://github.com/llody9977/vulnsignal">VIEW SOURCE ON GITHUB ↗</a><a href="#top">TOP ↑</a></div>
      </footer>
    </main>
  );
}
