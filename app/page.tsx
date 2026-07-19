import type { CSSProperties } from "react";
import rawDashboard from "@/data/dashboard.json";
import { TrendExplorer } from "./trend-explorer";
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

type EpssHistory = {
  threshold: number;
  semantics: string;
  modelBoundaryPolicy: string;
  points: EpssHistoryPoint[];
};

type ComparisonWindow = {
  start: string;
  end: string;
  count?: number;
  dueWindowSample?: number;
  within7Count?: number;
  within7Share?: number | null;
  under21Count?: number;
  under21Share?: number | null;
  ransomwareCount?: number;
  ransomwareShare?: number | null;
  ageSample?: number;
  oldCount?: number;
  oldShare?: number | null;
  publishedCves?: number;
  matureCves?: number;
  sample?: number;
  medianDays?: number | null;
  p75Days?: number | null;
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
          <span>{earlier === null ? "—" : `${number(earlier)}${suffix}`}</span>
        </div>
        <div
          className="comparison-bar comparison-bar--recent"
          style={{ "--bar": `${(safeRecent / max) * 100}%` } as CSSProperties}
        >
          <span>{recent === null ? "—" : `${number(recent)}${suffix}`}</span>
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
}: {
  digest?: DashboardData["changeDigest"];
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
          <strong>{number(digest.cve.distinctChanged)} CVE records changed</strong>
          <p>{number(digest.cve.newRecords)} newly published and {number(digest.cve.updatedRecords)} updated in 24 hours; categories can overlap. This is feed activity, not vulnerability incidence.</p>
        </article>
        <article>
          <span>Confirmed exploitation · latest catalog date</span>
          <strong>{number(digest.kev.additions)} KEV additions</strong>
          <p>{digest.kev.date ? `Added by CISA on ${dateLabel(digest.kev.date, true)}.` : "No dated KEV additions in this refresh."}</p>
        </article>
        <article>
          <span>EPSS threshold movement · adjacent sample</span>
          <strong>{epssText}</strong>
          <p>Uses adjacent official snapshots only when their model versions are comparable.</p>
        </article>
        <article>
          <span>Current priority watch · current snapshot</span>
          <strong>{number(digest.priority.count)} candidates</strong>
          <p>Current EPSS ≥ 0.1, published in 90 days and not listed in CISA KEV.</p>
        </article>
      </div>
    </section>
  );
}

function PriorityWatchPanel({ watch }: { watch?: PriorityWatch }) {
  const visibleItems = watch?.items.slice(0, 10) ?? [];
  return (
    <article className="flat-panel priority-watch">
      <div className="panel-heading">
        <div><p className="eyebrow">Priority watch / 90 days</p><h3>Elevated EPSS CVEs not in CISA KEV</h3></div>
        <span>{watch ? `EPSS scores ${timestampLabel(watch.window.scoreDate)}` : "Awaiting EPSS history"}</span>
      </div>
      {watch ? (
        <>
          <div className="priority-watch__summary">
            <div><span>Candidates</span><strong>{number(watch.total)}</strong></div>
            <div><span>Critical or high</span><strong>{number(watch.criticalHigh)}</strong></div>
            <div><span>Exploit reference</span><strong>{number(watch.publicExploitReferences)}</strong></div>
          </div>
          <p className="priority-watch__note">
            Published {dateLabel(watch.window.start, true)}–{dateLabel(watch.window.end, true)}. EPSS ≥ 0.1 is a project-defined current-score threshold. Not appearing in CISA KEV does not prove that exploitation has not occurred. “Yes” under exploit reference means NVD has at least one reference tagged <code>Exploit</code>; “No” means that tag is absent in this snapshot.
          </p>
          {visibleItems.length ? (
            <div className="priority-table-wrap">
              <table className="priority-table">
                <caption>Highest EPSS probabilities among CVEs published in the 90-day priority-watch window and not listed in CISA KEV</caption>
                <thead><tr><th>Vulnerability</th><th>Published</th><th>Severity</th><th>EPSS probability</th><th>Exploit reference</th></tr></thead>
                <tbody>
                  {visibleItems.map((item) => (
                    <tr key={item.cveId}>
                      <td data-label="Vulnerability"><a href={item.url}>{item.cveId}</a></td>
                      <td data-label="Published"><strong>{dateLabel(item.published, true)}</strong><span>{ageLabel(item.published, watch.window.scoreDate)}</span></td>
                      <td data-label="Severity"><span className={`severity-badge severity-badge--${item.severity.toLowerCase()}`}>{item.severity === "UNKNOWN" ? "Unscored" : `${item.severity}${item.score === null ? "" : ` ${item.score}`}`}</span>{item.cvssVersion ? <small>CVSS {item.cvssVersion}</small> : null}</td>
                      <td data-label="EPSS probability"><strong>{probability(item.epss)}</strong><span>{percentileLabel(item.epssPercentile)}</span></td>
                      <td data-label="Exploit reference">
                        <span className={`signal${item.publicExploitReference ? " signal--active" : ""}`}>{item.publicExploitReference ? "Yes" : "No"}</span>
                        <small>{item.publicExploitReference ? "NVD-tagged exploit reference" : "No NVD exploit tag in this snapshot"}</small>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {watch.items.length > visibleItems.length ? <p className="table-note">Showing the {number(visibleItems.length)} highest EPSS probabilities here. Use the “90-day priority candidates” tile breakdown to search all {number(watch.items.length)} detailed candidate rows retained in this snapshot.</p> : null}
            </div>
          ) : <p className="panel-empty">No qualifying CVEs were found in this snapshot.</p>}
        </>
      ) : <p className="panel-empty">Priority-watch data is not available in this snapshot.</p>}
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
    <article className="flat-panel epss-history">
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
            <strong>{shares.at(-1)?.toFixed(2)}%</strong>
            <small>{number(points.at(-1)?.notInKevCount ?? 0)} threshold records not in KEV</small>
          </div>
          <div className="epss-models"><span>Model versions</span>{models.map((model) => <em key={model}>{model}</em>)}</div>
          <a className="panel-source-link" href={points.at(-1)?.sourceUrl}>View latest historical source ↗</a>
          <p className="panel-note">Each point comes from its dated official EPSS snapshot. Dashed markers show model changes and lines stop at those boundaries; current scores are not applied backwards.</p>
        </>
      ) : <p className="panel-empty">Historical EPSS samples are not available in this snapshot.</p>}
    </article>
  );
}

export default function Home() {
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

  return (
    <main>
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
            <div><span>Snapshot built</span><strong>{timestampLabel(dashboard.generatedAt)}</strong></div>
            <div><span>Latest complete month</span><strong>{dateLabel(dashboard.coverage.latestCompleteMonth)}</strong></div>
            <div><span>CVE records covered</span><strong>{number(dashboard.coverage.recordCount)}</strong></div>
            <div><span>Refresh schedule</span><strong>{dashboard.project.refreshSchedule || "Daily"}</strong></div>
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

        <WhatChanged digest={dashboard.changeDigest} />

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
            <PriorityWatchPanel watch={dashboard.priorityWatch} />
            <EpssHistoryPanel history={dashboard.epssHistory} />
          </div>

          <div className="operational-matrix">
            <article>
              <span>Median time to enter KEV</span>
              <small>{kevTimingPeriod}</small>
              <strong>{(timingComparison?.current.medianDays ?? dashboard.risk.medianDaysToKev) === null ? "—" : `${number(timingComparison?.current.medianDays ?? dashboard.risk.medianDaysToKev ?? 0)} days`}</strong>
              <DeltaTag value={timingComparison?.medianDaysChange} unit="days" />
              <p>Half of {number(timingComparison?.current.sample ?? dashboard.risk.kevTimingSample)} KEV-matched CVEs were listed within this time. Already-listed records count as zero days.</p>
            </article>
            <article>
              <span>75th percentile time to KEV</span>
              <small>{kevTimingPeriod}</small>
              <strong>{(timingComparison?.current.p75Days ?? dashboard.risk.p75DaysToKev) === null ? "—" : `${number(timingComparison?.current.p75Days ?? dashboard.risk.p75DaysToKev ?? 0)} days`}</strong>
              <DeltaTag value={timingComparison?.p75DaysChange} unit="days" />
              <p>75% of the same {number(timingComparison?.current.sample ?? dashboard.risk.kevTimingSample)} matched CVEs entered KEV within this time after NVD publication.</p>
            </article>
            <article>
              <span>CISA KEV catalog</span>
              <small>Released {timestampLabel(dashboard.sources.kev.released)}</small>
              <strong>{number(dashboard.risk.catalogKev)}</strong>
              <p>Known exploited vulnerabilities currently listed by CISA.</p>
            </article>
            <article>
              <span>Severity coverage</span>
              <small>{dateLabel(dashboard.latestCompleteMonth.month)}</small>
              <strong>{percent(dashboard.latestCompleteMonth.severityCoverage)}</strong>
              <p>Share of CVEs in the latest complete month with a CVSS score.</p>
            </article>
            <article>
              <span>Ransomware in KEV additions</span>
              <small>{kevAdditionsPeriod}</small>
              <strong>{percent(additionComparison?.current.ransomwareShare ?? dashboard.risk.ransomwareKevShare)}</strong>
              <DeltaTag value={additionComparison?.ransomwareShareChangePoints} unit="points" />
              <p>{number(additionComparison?.current.ransomwareCount ?? dashboard.risk.ransomwareKevCount)} of {number(additionComparison?.current.count ?? dashboard.risk.kevAdditionsCount)} additions are known to be used in ransomware campaigns.</p>
            </article>
            <article>
              <span>KEV deadlines within 7 days</span>
              <small>{dateRangeLabel(deadlineComparison?.current, dashboard.risk.kevAdditionsWindow)}</small>
              <strong>{percent(deadlineComparison?.current.within7Share ?? null)}</strong>
              <DeltaTag value={deadlineComparison?.within7ShareChangePoints} unit="points" />
              <p>{number(deadlineComparison?.current.within7Count ?? 0)} of {number(deadlineComparison?.current.dueWindowSample ?? 0)} additions required accelerated remediation within seven days.</p>
            </article>
            <article>
              <span>KEV additions &gt;2 years old</span>
              <small>{kevAdditionsPeriod}</small>
              <strong>{percent(additionComparison?.current.oldShare ?? dashboard.risk.oldKevShare)}</strong>
              <DeltaTag value={additionComparison?.oldShareChangePoints} unit="points" />
              <p>{number(additionComparison?.current.oldCount ?? dashboard.risk.oldKevCount)} of {number(additionComparison?.current.ageSample ?? dashboard.risk.kevAgeSample)} additions with publication dates were listed more than two years later.</p>
            </article>
            <article>
              <span>EPSS ≥ 0.1 not in CISA KEV</span>
              <small>{epssCohortPeriod} · scores {timestampLabel(epssScoreDate)}</small>
              <strong>{percent(dashboard.risk.highEpssNotInKevShare)}</strong>
              <p>{number(dashboard.risk.highEpssNotInKevCount)} of {number(dashboard.risk.highEpss)} CVEs meeting this project-defined threshold are not in CISA KEV. Scores are current, not historical.</p>
            </article>
          </div>

          <div className="context-grid">
            <article className="flat-panel era-card">
              <div className="panel-heading">
                <div><p className="eyebrow">Two adjacent 36-month periods</p><h3>Change in published vulnerability reporting</h3></div>
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
                <div><p className="eyebrow">LLM disclosure evidence</p><h3>Reported minimum, not a total</h3></div>
              </div>
              <div className="evidence-score">
                <strong>{dashboard.llmDiscovery.value === null ? "—" : `≥ ${number(dashboard.llmDiscovery.value)}`}</strong>
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
          </article>
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
            <article><span>02</span><h3>Severity</h3><p>Primary CVSS assessments are used where available. A scored 0.0 is shown as “None”; records without a score remain “Unscored”.</p></article>
            <article><span>03</span><h3>Exploitation</h3><p>An NVD reference tagged “Exploit” indicates linked public material; it does not prove that the exploit works. Only CISA KEV entries are labelled “Known exploited”.</p></article>
            <article><span>04</span><h3>LLM evidence</h3><p>Report and reveal dates are not discovery dates. Counts from different programmes remain separate because they may overlap.</p></article>
            <article><span>05</span><h3>EPSS probability</h3><p>Current FIRST EPSS scores estimate exploitation probability over the next 30 days. Scores are grouped by CVE publication month; ≥ 0.1 is a project-defined threshold, not an official severity band.</p></article>
          </div>
          <div className="source-strip">
            <span>SOURCES</span>
            <a href={dashboard.sources.cve.url}>CVE LIST V5 ↗</a>
            <a href={dashboard.sources.nvd.url}>NVD JSON 2.0 ↗</a>
            <a href={dashboard.sources.kev.url}>CISA KEV ↗</a>
            <a href={dashboard.sources.epss?.url ?? "https://www.first.org/epss/"}>FIRST EPSS ↗</a>
            <a href={dashboard.sources.anthropic.url}>ANTHROPIC CVD ↗</a>
            <a href={dashboard.sources.llmRegistry.url}>LLM REGISTER ↗</a>
            <em>{dashboard.coverage.notice}</em>
          </div>
        </section>
      </div>

      <footer>
        <div><strong>VulnSignal</strong><span>Daily vulnerability trends from public sources.</span></div>
        <div><a href="https://github.com/llody9977/vulnsignal">VIEW SOURCE ON GITHUB ↗</a><a href="#top">TOP ↑</a></div>
      </footer>
    </main>
  );
}
