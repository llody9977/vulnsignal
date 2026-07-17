import type { CSSProperties } from "react";
import rawDashboard from "@/data/dashboard.json";

type MonthPoint = {
  month: string;
  published: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  none: number;
  unknown: number;
  severityCoverage: number | null;
  publicExploitReferences: number;
  kevAdded: number;
  partial: boolean;
};

type WindowMetrics = {
  start: string;
  end: string;
  published: number;
  monthlyAverage: number;
  scored: number;
  severityCoverage: number | null;
  criticalHigh: number;
  criticalHighShare: number | null;
  publicExploitReferences: number;
  publicExploitShare: number | null;
  eventualKev: number;
  eventualKevShare: number | null;
  matureCohort: number;
  kevWithin90Days: number;
  kevWithin90DayRate: number | null;
  medianDaysToKev: number | null;
  p75DaysToKev: number | null;
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
    publishedDelta: number | null;
    criticalHigh: number;
    criticalHighShare: number | null;
    severityCoverage: number | null;
    kevAdded: number;
    kevAddedDelta: number | null;
    publicExploitReferences: number;
    publicExploitDelta: number | null;
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
    qualifier: string;
    verifiedCount: number;
    status: string;
    coverage: string;
    label: string;
    methodologyVersion: string;
    basis: string | null;
    programReports: { publisher: string; program: string; metric: string; count: number; sourceUrl: string }[];
  };
  comparison: {
    event: string;
    cutover: string;
    windowMonths: number;
    causalityNote: string;
    pre: WindowMetrics;
    post: WindowMetrics;
  };
  trend: MonthPoint[];
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

function compact(value: number) {
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

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

function signed(value: number | null) {
  if (value === null) return "No prior baseline";
  return `${value > 0 ? "+" : ""}${value.toFixed(1)}% vs prior month`;
}

function changeTone(value: number | null, inverse = false) {
  if (value === null || value === 0) return "neutral";
  const favorable = inverse ? value < 0 : value > 0;
  return favorable ? "up" : "down";
}

type PlotPoint = { x: number; y: number; value: number };

function plotPoints(values: number[]): PlotPoint[] {
  const highest = Math.max(...values, 1);
  return values.map((value, index) => ({
    x: values.length === 1 ? 50 : (index / (values.length - 1)) * 100,
    y: 92 - (value / highest) * 78,
    value,
  }));
}

function CssLine({ values, tone = "mint", compact: isCompact = false }: { values: number[]; tone?: "mint" | "amber" | "rose"; compact?: boolean }) {
  const points = plotPoints(values);
  const aspect = isCompact ? 3.1 : 2.6;
  return (
    <div className={`css-line ${isCompact ? "css-line--compact" : ""}`} aria-hidden="true">
      {points.slice(0, -1).map((point, index) => {
        const next = points[index + 1];
        const dx = next.x - point.x;
        const dy = next.y - point.y;
        const adjustedDy = dy / aspect;
        const length = Math.sqrt(dx * dx + adjustedDy * adjustedDy);
        const angle = Math.atan2(dy, dx * aspect) * (180 / Math.PI);
        return (
          <span
            className={`css-line__segment css-line__segment--${tone}`}
            key={`${point.x}-${point.y}`}
            style={{
              "--x": `${point.x}%`,
              "--y": `${point.y}%`,
              "--length": `${length}%`,
              "--angle": `${angle}deg`,
            } as CSSProperties}
          />
        );
      })}
      {points.map((point, index) => (
        <span
          className={`css-line__point css-line__point--${tone}`}
          key={`${point.value}-${index}`}
          style={{ "--x": `${point.x}%`, "--y": `${point.y}%` } as CSSProperties}
        />
      ))}
    </div>
  );
}

function Delta({ value, inverse = false }: { value: number | null; inverse?: boolean }) {
  return <span className={`delta delta--${changeTone(value, inverse)}`}>{signed(value)}</span>;
}

function MetricCard({
  eyebrow,
  value,
  detail,
  delta,
  values,
  tone = "mint",
  inverse = false,
  className = "",
}: {
  eyebrow: string;
  value: string;
  detail: string;
  delta?: number | null;
  values: number[];
  tone?: "mint" | "amber" | "rose";
  inverse?: boolean;
  className?: string;
}) {
  return (
    <article className={`metric-card metric-card--${tone} ${className}`}>
      <div className="metric-card__head">
        <span>{eyebrow}</span>
        <span className="metric-card__period">complete month</span>
      </div>
      <div className="metric-card__value">{value}</div>
      <p>{detail}</p>
      <CssLine values={values} tone={tone} compact />
      {delta !== undefined ? <Delta value={delta} inverse={inverse} /> : <span className="delta delta--neutral">12-month signal</span>}
    </article>
  );
}

function TrendPanel({
  title,
  value,
  detail,
  values,
  tone,
}: {
  title: string;
  value: string;
  detail: string;
  values: number[];
  tone: "mint" | "amber";
}) {
  const points = dashboard.trend;
  return (
    <div className="trend-panel">
      <div className="trend-panel__copy">
        <div>
          <span className="eyebrow">{title}</span>
          <strong>{value}</strong>
        </div>
        <p>{detail}</p>
      </div>
      <div className="trend-panel__chart" role="img" aria-label={`${title} over the last 24 complete months`}>
        <div className="chart-grid" />
        <CssLine values={values} tone={tone} />
      </div>
      <div className="chart-axis" aria-hidden="true">
        <span>{dateLabel(points[0].month)}</span>
        <span>{dateLabel(points[Math.floor(points.length / 2)].month)}</span>
        <span>{dateLabel(points[points.length - 1].month)}</span>
      </div>
    </div>
  );
}

function ComparisonRow({ label, pre, post, suffix = "" }: { label: string; pre: number | null; post: number | null; suffix?: string }) {
  const safePre = pre ?? 0;
  const safePost = post ?? 0;
  const max = Math.max(safePre, safePost, 1);
  const ratio = safePre ? ((safePost - safePre) / safePre) * 100 : null;
  return (
    <div className="comparison-row">
      <div className="comparison-row__label">
        <span>{label}</span>
        <span>{ratio === null ? "—" : `${ratio > 0 ? "+" : ""}${ratio.toFixed(1)}%`}</span>
      </div>
      <div className="comparison-bars">
        <div className="comparison-bar comparison-bar--pre" style={{ "--bar": `${(safePre / max) * 100}%` } as CSSProperties}>
          <span>{pre === null ? "—" : `${number(safePre)}${suffix}`}</span>
        </div>
        <div className="comparison-bar comparison-bar--post" style={{ "--bar": `${(safePost / max) * 100}%` } as CSSProperties}>
          <span>{post === null ? "—" : `${number(safePost)}${suffix}`}</span>
        </div>
      </div>
    </div>
  );
}

export default function Home() {
  const latest = dashboard.latestCompleteMonth;
  const trend = dashboard.trend;
  const lastTwelve = trend.slice(-12);
  const severityTotal = latest.published || 1;
  const latestPoint = trend[trend.length - 1];
  const severityStops = [
    { label: "Critical", value: latestPoint.critical, color: "#ff5f6d" },
    { label: "High", value: latestPoint.high, color: "#ff9f43" },
    { label: "Medium", value: latestPoint.medium, color: "#f1d15b" },
    { label: "Low", value: latestPoint.low, color: "#3fd8a2" },
    { label: "None", value: latestPoint.none, color: "#8dc9b3" },
    { label: "Unscored", value: latestPoint.unknown, color: "#d9dee7" },
  ];
  let cursor = 0;
  const conic = severityStops.map((item) => {
    const start = cursor;
    cursor += (item.value / severityTotal) * 100;
    return `${item.color} ${start}% ${cursor}%`;
  }).join(", ");
  const maxCwe = Math.max(...dashboard.topCwes.map((item) => item.count), 1);
  const generated = new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(dashboard.generatedAt));

  return (
    <main>
      <header className="topbar">
        <a className="brand" href="#top" aria-label="VulnSignal home">
          <span className="brand__mark" aria-hidden="true"><i /><i /><i /></span>
          <span><strong>VulnSignal</strong><small>CVE + KEV intelligence</small></span>
        </a>
        <nav aria-label="Dashboard sections">
          <a href="#overview">Overview</a>
          <a href="#era-shift">Era shift</a>
          <a href="#kev-watch">KEV watch</a>
          <a href="#methodology">Methodology</a>
        </nav>
        <div className="sync-state">
          <span className="sync-state__dot" aria-hidden="true" />
          <span><strong>Sources synced</strong><small>{generated}</small></span>
        </div>
      </header>

      <div className="page" id="top">
        <section className="hero">
          <div className="hero__copy">
            <p className="kicker"><span>Daily vulnerability signal</span> / Official public sources</p>
            <h1>See the shift.<br /><em>Prioritize the risk.</em></h1>
            <p className="hero__lede">Trend intelligence across published CVEs, severity, exploit evidence, and CISA-confirmed exploitation—without blurring what each signal means.</p>
          </div>
          <div className="hero__meta">
            <div><span>Data through</span><strong>{dateLabel(dashboard.coverage.asOf, true)}</strong></div>
            <div><span>Latest complete month</span><strong>{dateLabel(latest.month)}</strong></div>
            <div><span>Coverage</span><strong>{dateLabel(dashboard.coverage.start)} → now</strong></div>
          </div>
        </section>

        <section className="section" id="overview">
          <div className="section-heading">
            <div><p className="eyebrow">01 / Executive signal</p><h2>Latest complete month</h2></div>
            <p>Comparable monthly metrics with incomplete current-month data excluded.</p>
          </div>

          <div className="metric-grid">
            <MetricCard
              eyebrow="CVEs published"
              value={number(latest.published)}
              detail={`${number(dashboard.coverage.recordCount)} CVEs in dashboard coverage`}
              delta={latest.publishedDelta}
              values={lastTwelve.map((item) => item.published)}
            />
            <MetricCard
              eyebrow="Critical + high"
              value={number(latest.criticalHigh)}
              detail={`${percent(latest.criticalHighShare)} of scored · ${percent(latest.severityCoverage)} scored`}
              values={lastTwelve.map((item) => item.critical + item.high)}
              tone="rose"
            />
            <MetricCard
              eyebrow="KEV additions"
              value={number(latest.kevAdded)}
              detail={`${number(dashboard.risk.catalogKev)} confirmed exploited CVEs in catalog`}
              delta={latest.kevAddedDelta}
              values={lastTwelve.map((item) => item.kevAdded)}
              tone="amber"
              inverse
            />
            <MetricCard
              eyebrow="Public exploit refs"
              value={number(latest.publicExploitReferences)}
              detail="CVE references tagged exploit; not proof of active use"
              delta={latest.publicExploitDelta}
              values={lastTwelve.map((item) => item.publicExploitReferences)}
              tone="amber"
              inverse
            />
            <MetricCard
              eyebrow="Added to KEV ≤90d"
              value={percent(dashboard.risk.kevWithin90DayRate)}
              detail={`${number(dashboard.risk.kevWithin90Days)} of ${number(dashboard.risk.matureCohort)} mature cohort CVEs`}
              values={lastTwelve.map((item) => item.kevAdded)}
              tone="rose"
            />
            <MetricCard
              eyebrow="LLM-assisted CVEs"
              value={dashboard.llmDiscovery.value === null ? "N/A" : `≥${number(dashboard.llmDiscovery.value)}`}
              detail={`First-party lower bound · ${number(dashboard.llmDiscovery.verifiedCount)} public CVE IDs`}
              values={lastTwelve.map(() => 0)}
              className="metric-card--hatched"
            />
          </div>

          <div className="analytics-grid">
            <article className="card card--wide trend-card">
              <div className="card-heading">
                <div><p className="eyebrow">24 complete months</p><h3>Volume and confirmed exploitation</h3></div>
                <p>Separate scales preserve the shape of each signal.</p>
              </div>
              <TrendPanel
                title="Published CVEs / month"
                value={compact(trend.reduce((sum, item) => sum + item.published, 0))}
                detail="24-month total"
                values={trend.map((item) => item.published)}
                tone="mint"
              />
              <TrendPanel
                title="KEV additions / month"
                value={number(trend.reduce((sum, item) => sum + item.kevAdded, 0))}
                detail="CISA-confirmed exploited"
                values={trend.map((item) => item.kevAdded)}
                tone="amber"
              />
            </article>

            <article className="card severity-card">
              <div className="card-heading"><div><p className="eyebrow">Severity mix</p><h3>{dateLabel(latest.month)}</h3></div></div>
              <div className="severity-visual">
                <div className="severity-ring" style={{ background: `conic-gradient(${conic})` }} role="img" aria-label={`Severity mix for ${dateLabel(latest.month)}`}>
                  <div><strong>{percent(latest.severityCoverage)}</strong><span>scored</span></div>
                </div>
                <div className="severity-legend">
                  {severityStops.map((item) => (
                    <div key={item.label}><span style={{ background: item.color }} /><em>{item.label}</em><strong>{number(item.value)}</strong></div>
                  ))}
                </div>
              </div>
              <p className="card-note">Unscored stays visible. Missing CVSS data is never treated as low severity.</p>
            </article>
          </div>
        </section>

        <section className="section" id="era-shift">
          <div className="section-heading">
            <div><p className="eyebrow">02 / Era comparison</p><h2>Before and after public ChatGPT</h2></div>
            <p>Equal 36-month windows around 30 November 2022.</p>
          </div>

          <div className="era-grid">
            <article className="card era-card">
              <div className="era-labels">
                <div><span className="era-dot era-dot--pre" />Pre-event<strong>{dateLabel(dashboard.comparison.pre.start)}–{dateLabel(dashboard.comparison.pre.end)}</strong></div>
                <div><span className="era-dot era-dot--post" />Post-event<strong>{dateLabel(dashboard.comparison.post.start)}–{dateLabel(dashboard.comparison.post.end)}</strong></div>
              </div>
              <ComparisonRow label="Average CVEs / month" pre={dashboard.comparison.pre.monthlyAverage} post={dashboard.comparison.post.monthlyAverage} />
              <ComparisonRow label="Critical + high share" pre={dashboard.comparison.pre.criticalHighShare} post={dashboard.comparison.post.criticalHighShare} suffix="%" />
              <ComparisonRow label="Public exploit ref share" pre={dashboard.comparison.pre.publicExploitShare} post={dashboard.comparison.post.publicExploitShare} suffix="%" />
              <ComparisonRow label="KEV within 90 days" pre={dashboard.comparison.pre.kevWithin90DayRate} post={dashboard.comparison.post.kevWithin90DayRate} suffix="%" />
              <ComparisonRow label="Median days to KEV" pre={dashboard.comparison.pre.medianDaysToKev} post={dashboard.comparison.post.medianDaysToKev} />
            </article>

            <aside className="card interpretation-card">
              <p className="eyebrow">Read this carefully</p>
              <h3>Era marker ≠ attribution</h3>
              <p>{dashboard.comparison.causalityNote}</p>
              <div className="interpretation-card__facts">
                <div><span>CVE program growth</span><strong>Confounder</strong></div>
                <div><span>NVD enrichment lag</span><strong>Coverage shift</strong></div>
                <div><span>KEV launched in 2021</span><strong>Catalog effect</strong></div>
              </div>
              <a href="#methodology">Open methodology <span aria-hidden="true">↗</span></a>
            </aside>
          </div>
        </section>

        <section className="section" id="kev-watch">
          <div className="section-heading">
            <div><p className="eyebrow">03 / Exploitation watch</p><h2>What defenders should see next</h2></div>
            <p>Known exploitation, timing, and weakness concentration.</p>
          </div>

          <div className="risk-grid">
            <article className="card timing-card">
              <div className="card-heading"><div><p className="eyebrow">NVD published → CISA added</p><h3>Time to KEV catalog entry</h3></div></div>
              <div className="timing-values">
                <div><strong>{dashboard.risk.medianDaysToKev ?? "—"}</strong><span>median days</span></div>
                <div><strong>{dashboard.risk.p75DaysToKev ?? "—"}</strong><span>75th percentile</span></div>
              </div>
              <p className="card-note">Measured on mature publication cohorts only, reducing right-censoring in recent CVEs.</p>
            </article>

            <article className="card cwe-card">
              <div className="card-heading"><div><p className="eyebrow">Trailing 12 months</p><h3>Top weakness classes</h3></div></div>
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
          </div>

          <article className="card kev-table-card">
            <div className="card-heading">
              <div><p className="eyebrow">CISA KEV / latest additions</p><h3>Recently confirmed exploitation</h3></div>
              <a href={dashboard.sources.kev.url}>Open CISA catalog <span aria-hidden="true">↗</span></a>
            </div>
            <div className="table-wrap">
              <table>
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
            <p className="eyebrow">04 / Methodology & provenance</p>
            <h2>Clear labels beat false precision.</h2>
            <p>Every metric keeps its evidence class visible: publication, score, public exploit reference, or confirmed exploitation.</p>
          </div>
          <div className="method-grid">
            <article><span>01</span><h3>CVE publication</h3><p>Monthly counts use the NVD published timestamp for active records. The CVE Program change log is checked independently for source freshness.</p></article>
            <article><span>02</span><h3>Severity coverage</h3><p>One published CVSS assessment is selected deterministically. Unscored records remain a separate denominator.</p></article>
            <article><span>03</span><h3>Exploit evidence</h3><p>A reference tagged “exploit” indicates public exploit material. Only KEV membership is labeled known exploited.</p></article>
            <article><span>04</span><h3>LLM discovery</h3><p>Source feeds do not standardize discovery method. The headline is a first-party reported minimum; ID-level evidence stays in a curated registry.</p></article>
            <div className="program-reports">
              <span>First-party LLM program reports · counts are not summed</span>
              {dashboard.llmDiscovery.programReports.map((report) => (
                <a href={report.sourceUrl} key={`${report.publisher}-${report.program}`}>
                  <strong>{number(report.count)}</strong>
                  <span><em>{report.publisher} · {report.program}</em>{report.metric}</span>
                  <i aria-hidden="true">↗</i>
                </a>
              ))}
            </div>
          </div>
          <div className="source-strip">
            <span>Primary sources</span>
            <a href={dashboard.sources.cve.url}>CVE List V5 ↗</a>
            <a href={dashboard.sources.nvd.url}>NVD JSON 2.0 ↗</a>
            <a href={dashboard.sources.kev.url}>CISA KEV ↗</a>
            <em>{dashboard.coverage.notice}</em>
          </div>
        </section>
      </div>

      <footer>
        <div><strong>VulnSignal</strong><span>Evidence-led vulnerability trend intelligence.</span></div>
        <div><span>Dataset schema v1</span><span>Updated daily by GitHub Actions</span><a href="#top">Back to top ↑</a></div>
      </footer>
    </main>
  );
}
