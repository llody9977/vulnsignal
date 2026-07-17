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
    causalityNote: string;
    pre: WindowMetrics;
    post: WindowMetrics;
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
    publicExploitReference: boolean;
  }[];
};

const dashboard = rawDashboard as DashboardData;

function number(value: number) {
  return new Intl.NumberFormat("en").format(value);
}

function percent(value: number | null) {
  return value === null ? "—" : `${value.toFixed(1)}%`;
}

function dateLabel(value: string, includeDay = false) {
  const date = new Date(`${value.length === 7 ? `${value}-01` : value}T00:00:00Z`);
  return new Intl.DateTimeFormat("en", {
    month: "short",
    year: "numeric",
    ...(includeDay ? { day: "numeric" } : {}),
    timeZone: "UTC",
  }).format(date);
}

function ComparisonRow({
  label,
  pre,
  post,
  suffix = "",
  changeMode = "relative",
}: {
  label: string;
  pre: number | null;
  post: number | null;
  suffix?: string;
  changeMode?: "relative" | "points";
}) {
  const safePre = pre ?? 0;
  const safePost = post ?? 0;
  const max = Math.max(safePre, safePost, 1);
  const ratio = safePre ? ((safePost - safePre) / safePre) * 100 : null;
  const pointDifference = post !== null && pre !== null ? post - pre : null;
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
          style={{ "--bar": `${(safePre / max) * 100}%` } as CSSProperties}
        >
          <span>{pre === null ? "—" : `${number(pre)}${suffix}`}</span>
        </div>
        <div
          className="comparison-bar comparison-bar--post"
          style={{ "--bar": `${(safePost / max) * 100}%` } as CSSProperties}
        >
          <span>{post === null ? "—" : `${number(post)}${suffix}`}</span>
        </div>
      </div>
    </div>
  );
}

export default function Home() {
  const generated = new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(dashboard.generatedAt));
  const maxCwe = Math.max(...dashboard.topCwes.map((item) => item.count), 1);

  return (
    <main>
      <header className="topbar">
        <a className="brand" href="#top" aria-label="VulnSignal home">
          <span className="brand__mark" aria-hidden="true">
            {Array.from({ length: 9 }, (_, index) => <i key={index} />)}
          </span>
          <span><strong>VulnSignal</strong><small>CVE / KEV / LLM evidence</small></span>
        </a>
        <nav aria-label="Dashboard sections">
          <a href="#reporting">Reporting</a>
          <a href="#context">Context</a>
          <a href="#kev-watch">KEV watch</a>
          <a href="#methodology">Sources</a>
        </nav>
        <div className="sync-state">
          <span className="sync-state__dot" aria-hidden="true" />
          <span><strong>UPDATED DAILY</strong><small>{generated}</small></span>
        </div>
      </header>

      <div className="page" id="top">
        <section className="hero">
          <div className="hero__copy">
            <p className="kicker">VULNERABILITY SIGNAL REPORT / DAILY</p>
            <h1>One timeline.<br /><em>Every signal.</em></h1>
            <p>
              Filter CVE publication, severity, CISA KEV, exploit references, and
              documented LLM evidence on a shared monthly grid.
            </p>
          </div>
          <div className="hero__status">
            <div><span>Latest source data</span><strong>{dateLabel(dashboard.coverage.asOf, true)}</strong></div>
            <div><span>Latest complete month</span><strong>{dateLabel(dashboard.coverage.latestCompleteMonth)}</strong></div>
            <div><span>CVE records covered</span><strong>{number(dashboard.coverage.recordCount)}</strong></div>
            <div><span>Refresh schedule</span><strong>Daily on GitHub</strong></div>
          </div>
        </section>

        <TrendExplorer
          monthly={dashboard.monthly}
          latestCompleteMonth={dashboard.coverage.latestCompleteMonth}
          events={dashboard.llmDiscovery.events ?? []}
        />

        <section className="section" id="context">
          <div className="section-heading">
            <div><p className="eyebrow">[02] Additional context</p><h2>Operational vulnerability context.</h2></div>
            <p>Definitions and comparison populations are shown with each metric.</p>
          </div>

          <div className="operational-matrix">
            <article><span>Median time to KEV</span><strong>{dashboard.risk.medianDaysToKev === null ? "—" : `${number(dashboard.risk.medianDaysToKev)} days`}</strong><p>Among CVEs published {dateLabel(dashboard.risk.matureCohortStart)}–{dateLabel(dashboard.risk.matureCohortEnd)} that later entered KEV, half were added within this many days of NVD publication.</p></article>
            <article><span>75% of KEV-listed CVEs added within</span><strong>{dashboard.risk.p75DaysToKev === null ? "—" : `${number(dashboard.risk.p75DaysToKev)} days`}</strong><p>Among that same KEV-matched cohort, three quarters entered CISA’s catalog within this many days.</p></article>
            <article><span>Added to KEV within 90 days</span><strong>{percent(dashboard.risk.kevWithin90DayRate)}</strong><p>{number(dashboard.risk.kevWithin90Days)} of {number(dashboard.risk.matureCohort)} CVEs with a full 90-day observation window.</p></article>
            <article><span>CISA KEV catalog</span><strong>{number(dashboard.risk.catalogKev)}</strong><p>Known exploited vulnerabilities currently listed by CISA.</p></article>
            <article><span>CVE records changed (24h)</span><strong>{number(dashboard.sources.cve.changedRecords24h)}</strong><p>CVE List records added or updated in the past day.</p></article>
            <article><span>CVEs with severity scores</span><strong>{percent(dashboard.latestCompleteMonth.severityCoverage)}</strong><p>Share of the latest complete month with a CVSS score.</p></article>
          </div>

          <div className="context-grid">
            <article className="flat-panel era-card">
              <div className="panel-heading">
                <div><p className="eyebrow">36 months before + after</p><h3>Before and after ChatGPT launched</h3></div>
                <span>Comparison only / not causal</span>
              </div>
              <div className="era-labels">
                <div><i />PRE <strong>{dateLabel(dashboard.comparison.pre.start)}–{dateLabel(dashboard.comparison.pre.end)}</strong></div>
                <div><i />POST <strong>{dateLabel(dashboard.comparison.post.start)}–{dateLabel(dashboard.comparison.post.end)}</strong></div>
              </div>
              <ComparisonRow label="Average CVEs / month" pre={dashboard.comparison.pre.monthlyAverage} post={dashboard.comparison.post.monthlyAverage} />
              <ComparisonRow label="Critical + high share" pre={dashboard.comparison.pre.criticalHighShare} post={dashboard.comparison.post.criticalHighShare} suffix="%" changeMode="points" />
              <ComparisonRow label="CVEs with public exploit references" pre={dashboard.comparison.pre.publicExploitShare} post={dashboard.comparison.post.publicExploitShare} suffix="%" changeMode="points" />
              <ComparisonRow label="KEV within 90 days" pre={dashboard.comparison.pre.kevWithin90DayRate} post={dashboard.comparison.post.kevWithin90DayRate} suffix="%" changeMode="points" />
              <ComparisonRow label="Median days to KEV" pre={dashboard.comparison.pre.medianDaysToKev} post={dashboard.comparison.post.medianDaysToKev} />
              <p className="panel-note">{dashboard.comparison.causalityNote}</p>
            </article>

            <article className="flat-panel evidence-card">
              <div className="panel-heading">
                <div><p className="eyebrow">LLM / Evidence ledger</p><h3>Reported minimum, not prevalence</h3></div>
              </div>
              <div className="evidence-score">
                <strong>{dashboard.llmDiscovery.value === null ? "—" : `≥ ${number(dashboard.llmDiscovery.value)}`}</strong>
                <span>largest documented program count</span>
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
              <div><p className="eyebrow">CWE / Trailing 12 months</p><h3>Weakness concentration</h3></div>
              <span>Published CVEs / top classes</span>
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
            <div><p className="eyebrow">[03] Exploitation ledger</p><h2>Recently confirmed exploitation.</h2></div>
            <p>KEV membership is kept distinct from a public exploit-reference signal.</p>
          </div>

          <article className="flat-panel kev-table-card">
            <div className="panel-heading">
              <div><p className="eyebrow">CISA / Latest additions</p><h3>KEV watch</h3></div>
              <a href={dashboard.sources.kev.url}>OPEN SOURCE ↗</a>
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
            <p className="eyebrow">[04] Method / provenance</p>
            <h2>Each line says what it knows.</h2>
            <p>CVE is publication, KEV is catalog addition, exploit is a tagged public reference, and LLM is a first-party report or public-ID reveal event.</p>
          </div>
          <div className="method-grid">
            <article><span>01</span><h3>CVE publication</h3><p>Active NVD records grouped by NVD published timestamp. Rejected records are excluded.</p></article>
            <article><span>02</span><h3>Severity</h3><p>Primary CVSS assessments are preferred. Unscored records remain visible and never become “low.”</p></article>
            <article><span>03</span><h3>Exploitation</h3><p>NVD exploit-tagged references indicate public material. CISA KEV alone is labeled known exploited.</p></article>
            <article><span>04</span><h3>LLM evidence</h3><p>Timeline points use report or reveal dates. They are not discovery dates, and non-deduplicated program totals are not summed.</p></article>
          </div>
          <div className="source-strip">
            <span>PRIMARY / SOURCES</span>
            <a href={dashboard.sources.cve.url}>CVE LIST V5 ↗</a>
            <a href={dashboard.sources.nvd.url}>NVD JSON 2.0 ↗</a>
            <a href={dashboard.sources.kev.url}>CISA KEV ↗</a>
            <em>{dashboard.coverage.notice}</em>
          </div>
        </section>
      </div>

      <footer>
        <div><strong>VulnSignal</strong><span>Evidence-led vulnerability trend intelligence.</span></div>
        <div><span>SCHEMA / V1</span><span>GITHUB / DAILY</span><a href="#top">TOP ↑</a></div>
      </footer>
    </main>
  );
}
