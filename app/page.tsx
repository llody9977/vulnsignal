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

type DashboardData = {
  generatedAt: string;
  snapshot: {
    id: string;
    generatedAt: string;
    inputCount: number;
    inputFingerprintSha256: string;
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
  topCwes: { cwe: string; count: number }[];
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

export default function Home() {
  const maxCwe = Math.max(...dashboard.topCwes.map((item) => item.count), 1);
  const sourceUpdates = [
    { label: "CVE List", qualifier: "Updated", value: dashboard.sources.cve.latestFetch, url: dashboard.sources.cve.url },
    { label: "NVD", qualifier: "Updated", value: dashboard.sources.nvd.latestSourceUpdate, url: dashboard.sources.nvd.url },
    { label: "CISA KEV", qualifier: "Released", value: dashboard.sources.kev.released, url: dashboard.sources.kev.url },
    { label: "Anthropic CVD", qualifier: "As at", value: dashboard.sources.anthropic.asOf, url: dashboard.sources.anthropic.url },
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
            <p className="kicker">DAILY CVE AND KEV REPORT</p>
            <h1>CVE, KEV and LLM disclosures.<br /><em>One timeline.</em></h1>
            <p>
              Compare monthly CVE publications, CVSS severity, CISA KEV additions,
              CVEs with public exploit references and documented LLM-assisted disclosures.
            </p>
          </div>
          <div className="hero__status">
            <div><span>Snapshot built</span><strong>{timestampLabel(dashboard.generatedAt)}</strong></div>
            <div><span>Latest complete month</span><strong>{dateLabel(dashboard.coverage.latestCompleteMonth)}</strong></div>
            <div><span>CVE records covered</span><strong>{number(dashboard.coverage.recordCount)}</strong></div>
            <div><span>Refresh schedule</span><strong>Daily at 17:17 SGT</strong></div>
          </div>
          <div className="source-snapshot" aria-label="Source dates included in this snapshot">
            <strong>Source data included</strong>
            <div>
              {sourceUpdates.map((source) => (
                <a href={source.url} key={source.label}>
                  <span>{source.label}</span>
                  <time dateTime={source.value ?? undefined}><b>{source.qualifier}</b>{timestampLabel(source.value)}</time>
                </a>
              ))}
            </div>
          </div>
        </section>

        <TrendExplorer
          monthly={dashboard.monthly}
          latestCompleteMonth={dashboard.coverage.latestCompleteMonth}
          events={dashboard.llmDiscovery.events ?? []}
        />

        <section className="section" id="context">
          <div className="section-heading">
            <div><p className="eyebrow">[02] Additional context</p><h2>Additional vulnerability metrics</h2></div>
            <p>Each metric states the period and records included.</p>
          </div>

          <div className="operational-matrix">
            <article><span>Median time to enter KEV</span><strong>{dashboard.risk.medianDaysToKev === null ? "—" : `${number(dashboard.risk.medianDaysToKev)} days`}</strong><p>Half of the {number(dashboard.risk.kevTimingSample)} KEV-matched CVEs in the mature cohort were listed within this time. The {number(dashboard.risk.prePublicationKev)} already-listed records count as zero days.</p></article>
            <article><span>75th percentile time to KEV</span><strong>{dashboard.risk.p75DaysToKev === null ? "—" : `${number(dashboard.risk.p75DaysToKev)} days`}</strong><p>75% of the same {number(dashboard.risk.kevTimingSample)} KEV-matched CVEs were listed within this time, measured from NVD publication.</p></article>
            <article><span>Added to KEV within 90 days</span><strong>{percent(dashboard.risk.kevWithin90DayRate)}</strong><p>Of CVEs published {dateLabel(dashboard.risk.matureCohortStart)} to {dateLabel(dashboard.risk.matureCohortEnd)}, {number(dashboard.risk.kevWithin90Days)} of {number(dashboard.risk.matureCohort)} entered KEV within 90 days.</p></article>
            <article><span>CISA KEV catalog</span><strong>{number(dashboard.risk.catalogKev)}</strong><p>Known exploited vulnerabilities currently listed by CISA.</p></article>
            <article><span>CVE records changed in 24 hours</span><strong>{number(dashboard.sources.cve.changedRecords24h)}</strong><p>CVE List records added or updated in the 24 hours before this snapshot.</p></article>
            <article><span>CVEs with severity scores</span><strong>{percent(dashboard.latestCompleteMonth.severityCoverage)}</strong><p>Share of the latest complete month with a CVSS score.</p></article>
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
              <ComparisonRow label="Added to KEV within 90 days" earlier={dashboard.comparison.earlier.kevWithin90DayRate} recent={dashboard.comparison.recent.kevWithin90DayRate} suffix="%" changeMode="points" />
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
              <span>CVEs published in the past 12 months</span>
            </div>
            <div className="cwe-list">
              {dashboard.topCwes.map((item, index) => (
                <div className="cwe-row" key={item.cwe}>
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <strong>{item.cwe}</strong>
                  <div><i style={{ "--bar": `${(item.count / maxCwe) * 100}%` } as CSSProperties} /></div>
                  <em>{number(item.count)}</em>
                </div>
              ))}
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
                      <td data-label="Severity"><span className={`severity-badge severity-badge--${item.severity.toLowerCase()}`}>{item.severity === "UNKNOWN" ? "Unscored" : `${item.severity}${item.score ? ` ${item.score}` : ""}`}</span></td>
                      <td data-label="Signals"><div className="signal-list"><span className="signal signal--active">Known exploited</span>{item.ransomware === "Known" ? <span className="signal signal--ransomware">Ransomware</span> : null}{item.publicExploitReference ? <span className="signal">Exploit ref</span> : null}</div></td>
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
            <p>CVE counts use NVD publication dates. KEV counts use CISA listing dates. Exploit references and LLM disclosures are shown as separate evidence.</p>
          </div>
          <div className="method-grid">
            <article><span>01</span><h3>CVE publication</h3><p>We group active NVD records by publication month and exclude rejected records.</p></article>
            <article><span>02</span><h3>Severity</h3><p>The dashboard uses primary CVSS assessments where available. Records without a score remain marked “Unscored”.</p></article>
            <article><span>03</span><h3>Exploitation</h3><p>An NVD reference tagged “Exploit” indicates linked public material; it does not prove that the exploit works. Only CISA KEV entries are labelled “Known exploited”.</p></article>
            <article><span>04</span><h3>LLM evidence</h3><p>Report and reveal dates are not discovery dates. Counts from different programmes remain separate because they may overlap.</p></article>
          </div>
          <div className="source-strip">
            <span>SOURCES</span>
            <a href={dashboard.sources.cve.url}>CVE LIST V5 ↗</a>
            <a href={dashboard.sources.nvd.url}>NVD JSON 2.0 ↗</a>
            <a href={dashboard.sources.kev.url}>CISA KEV ↗</a>
            <a href={dashboard.sources.anthropic.url}>ANTHROPIC CVD ↗</a>
            <a href={dashboard.sources.llmRegistry.url}>LLM REGISTER ↗</a>
            <em>{dashboard.coverage.notice}</em>
          </div>
        </section>
      </div>

      <footer>
        <div><strong>VulnSignal</strong><span>Daily CVE, KEV and exploit trends from public sources.</span></div>
        <div><a href="https://github.com/llody9977/vulnsignal">VIEW SOURCE ON GITHUB ↗</a><a href="#top">TOP ↑</a></div>
      </footer>
    </main>
  );
}
