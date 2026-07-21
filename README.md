# VulnSignal

[![Refresh vulnerability data](https://github.com/llody9977/vulnsignal/actions/workflows/data-refresh.yml/badge.svg)](https://github.com/llody9977/vulnsignal/actions/workflows/data-refresh.yml)
[![Deploy dashboard](https://github.com/llody9977/vulnsignal/actions/workflows/pages.yml/badge.svg)](https://github.com/llody9977/vulnsignal/actions/workflows/pages.yml)
[![Continuous integration](https://github.com/llody9977/vulnsignal/actions/workflows/ci.yml/badge.svg)](https://github.com/llody9977/vulnsignal/actions/workflows/ci.yml)
[![CodeQL](https://github.com/llody9977/vulnsignal/actions/workflows/codeql.yml/badge.svg)](https://github.com/llody9977/vulnsignal/actions/workflows/codeql.yml)

I built VulnSignal as a personal project to examine trends in published vulnerability records, CISA KEV additions, public exploit-reference signals and selected LLM-assisted disclosure reports.

**Live dashboard:** [llody9977.github.io/vulnsignal](https://llody9977.github.io/vulnsignal/)

[![VulnSignal — CVE, KEV and LLM disclosures on one timeline](public/og.png)](https://llody9977.github.io/vulnsignal/)

## What it shows

- Year, month and aligned year-on-year views of CVEs published by NVD.
- Drill-down sheets for every headline tile, showing the exact denominator, selected-period monthly breakdown and relevant source limitations.
- Monthly CVSS severity as counts or shares, CISA KEV additions, NVD exploit-tagged references and current EPSS signals.
- Exact monthly values alongside the chart, including separate CVSS `NONE` and unscored records.
- A searchable 90-day priority watch for recent CVEs with current EPSS scores at or above the project threshold that are not yet in KEV; every candidate row in the current cohort is retained.
- Official historical EPSS snapshots, sampled monthly, with model-version boundaries kept visible.
- A short change digest that says exactly whether each item covers the previous 24 hours, the latest KEV release or two official EPSS snapshots.
- Source dates, a snapshot ID and content fingerprints for the inputs used to build each release.
- Median and 75th-percentile time to KEV for an explicitly stated mature cohort.
- Ransomware use, accelerated remediation deadlines and the age of KEV additions over comparable 12-month windows.
- Trailing-12-month CWE shares and the largest share movers, with official CWE names and links.
- First-party LLM-assisted disclosure events shown as separate reported minimums, not a combined discovery total.

## Why I built it

The upstream sources answer different questions and mature at different speeds. NVD publication volume measures published records rather than the underlying incidence of vulnerable software. Recent exploit-reference counts can also appear lower while NVD continues enriching those records. Changes in CNA participation and reporting processes may increase publication counts even when the underlying security environment has not changed at the same rate.

VulnSignal brings these signals together while reducing known measurement artefacts:

- Recent exploit-reference months remain visible but are marked as enriching. Comparisons are withheld until the selected periods contain mature data.
- KEV timing is calculated only for CVEs with a complete observation period.
- KEV-addition measures use their own latest-12-month window rather than borrowing the CVE maturity cohort.
- Current EPSS screening and historical EPSS movement are kept separate. One groups today's scores by CVE publication month; the other reads the score that FIRST published on each sampled date.
- LLM programme claims remain separate because the disclosed sets may overlap and the public sources do not support reliable deduplication.

## Scope and limitations

VulnSignal is a daily analytical snapshot, not a real-time advisory or an organisation-specific patch queue. The priority watch is a screening list, not a replacement for asset exposure, business impact and compensating-control checks. An EPSS score is an estimate of exploitation probability, not severity. Absence from KEV does not mean absence of exploitation. Publication growth also does not necessarily mean that software is becoming vulnerable at the same rate, and an NVD reference tagged `Exploit` does not prove that linked code works.

CVE, NVD and KEV do not reliably record how a vulnerability was discovered. The LLM timeline therefore contains only reviewed first-party programme reports or public CVE-ID releases. A blank month means that the registry has no recorded disclosure event; it does not mean zero LLM-assisted discoveries. Programme counts are never added together unless overlaps can be removed reliably.

The optional `--as-of` value is a report cutoff, not a complete historical archive. It excludes later NVD publications and KEV events, while source freshness, NVD severity, CWE, exploit-reference and current EPSS fields still reflect the downloaded source snapshots. The dataset build time remains the actual time when the report was generated.

## Disclaimer

VulnSignal is a personal, experimental project provided for general information only. It is not legal, compliance, security, risk-management or remediation advice, and it should not be used as the sole basis for operational decisions. Important findings should be checked against the linked original sources, vendor guidance and the user's own environment.

Data and derived metrics may be incomplete, delayed, revised or incorrect. The project is provided “as is”, without guarantees of accuracy, completeness, timeliness, availability or fitness for a particular purpose. Use it at your own risk. No service level, response time, uninterrupted refresh schedule or continuing availability is promised. Source names and trademarks belong to their respective owners; their inclusion does not imply affiliation, endorsement or certification.

The software is released under the [Apache License 2.0](LICENSE), which contains the applicable warranty and liability terms.

## Licence and attribution

VulnSignal is free to use, modify and redistribute under the Apache License 2.0. Redistributions and derivative works must comply with the licence, retain applicable copyright and attribution notices, state significant changes, and include the attribution from [NOTICE](NOTICE) in a permitted readable form.

Copyright 2026 [llody9977](https://github.com/llody9977). See [AUTHORS.md](AUTHORS.md) for the project authorship and AI-assistance disclosure. The use of OpenAI Codex as a development assistant does not change the attribution and licence requirements for this repository.

## Data sources and freshness

VulnSignal downloads directly from official and first-party public sources. Downloaded source archives are cached for validation and repeatable processing; the aggregate generated from them is committed as `data/dashboard.json`.

| Source | Dashboard use | Official endpoint |
| --- | --- | --- |
| CVE Program, CVE List V5 | Source freshness and records changed during the previous 24 hours | [CVE List downloads](https://www.cve.org/Downloads) and [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) |
| NIST National Vulnerability Database | Published CVEs, CVSS severity, CWE and references tagged as exploits | [NVD JSON 2.0 data feeds](https://nvd.nist.gov/vuln/data-feeds) |
| CISA Known Exploited Vulnerabilities | Known-exploited membership, catalogue additions, remediation due dates and ransomware-use labels | [CISA KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) |
| FIRST EPSS | Current exploitation-probability scores and monthly samples from official historical score files | [FIRST EPSS data and statistics](https://www.first.org/epss/data_stats), [current CSV feed](https://epss.empiricalsecurity.com/epss_scores-current.csv.gz) and [historical score repository](https://github.com/empiricalsec/epss_scores) |
| MITRE Common Weakness Enumeration | Official names and definition links for the CWE rows selected for display | [MITRE CWE](https://cwe.mitre.org/) and [CWE REST API](https://cwe-api.mitre.org/) |
| Anthropic coordinated disclosure | Machine-readable programme minimum and public CVE identifiers for Claude Mythos Preview findings | [Anthropic CVD payload](https://red.anthropic.com/2026/cvd/data/payload.json) |
| Curated LLM evidence register | Reviewed first-party programme claims, including OpenAI Aardvark | [`data/llm-discovery-evidence.json`](data/llm-discovery-evidence.json) |

The page distinguishes the dashboard build time from upstream source dates. For EPSS, it records the model version and `score_date` from the downloaded feed. The refresh rejects stale or structurally invalid EPSS data rather than labelling the dashboard build time as the EPSS update time.

Every NVD yearly feed is checked against the SHA-256 value in its official META file. The pipeline calculates content fingerprints for the CVE List delta, CISA KEV, FIRST EPSS, Anthropic payload and curated LLM register. A fingerprint identifies the exact input used; it is not independent proof that an upstream source is complete or free from later revisions.

This product uses NVD data feeds and is not endorsed or certified by the NVD.

## How to interpret the metrics

| Metric | Meaning and limitation |
| --- | --- |
| Published CVEs | Active NVD records grouped by publication month; rejected records are excluded. This measures publication activity, not vulnerability incidence. |
| Severity | Primary assessments are preferred over secondary assessments. Within that class, versions are checked in order: CVSS v4.0, v3.1, v3.0, then v2. Scores are not maximised. CVSS `NONE` (0.0) is kept separate from records without a score. |
| Public exploit reference | The NVD record has a reference tagged `Exploit`. Raw recent counts remain visible and marked as enriching; comparisons are withheld when either selected period lacks mature data. |
| KEV | CISA has placed the CVE in its Known Exploited Vulnerabilities catalogue. This confirms known exploitation and is distinct from an NVD exploit-tagged reference. |
| Time to KEV | Median and 75th-percentile days from NVD publication to CISA listing, calculated for KEV-matched records in the displayed mature cohort. Calculations retain the signed difference (listings that predate NVD publication retain negative values). |
| Current EPSS ≥ 0.1 | A project-defined threshold applied to the current FIRST EPSS snapshot. Monthly and 36-month groups use each CVE's NVD publication month, so they are not historical EPSS scores as they stood in those months. |
| Priority watch | NVD-published CVEs from the latest 90 days with current EPSS ≥ 0.1 and no CISA KEV listing in the downloaded catalogue. Every qualifying row is retained for the tile drill-down. It is a focused screening list, not a recommended remediation queue or patch priority list, and not proof of exploitability or a complete patch order. |
| Historical EPSS | Counts from official historical EPSS snapshots sampled at month end, plus the current score date. Model versions are shown because scores on different model versions are not strictly like-for-like. |
| Accelerated KEV deadline | The share of KEV additions whose CISA due date is no more than seven days after `dateAdded`, compared with the previous 12-month window. The denominator is the additions that carry a usable due date on or after `dateAdded`, and it is shown alongside the share. |
| What changed | Source-specific activity with an explicit clock: CVE List records in the previous 24 hours, additions on the latest KEV catalogue date, and EPSS threshold crossings between sampled official score files. These are update signals, not incident counts. |
| Common CWE classes | Each CVE contributes once to every distinct valid CWE assigned in NVD. The dashboard compares shares of published CVEs, because raw counts are affected by changes in total publication volume. |
| Earlier versus recent | Two adjacent 36-month publication periods ending at the latest complete month. This compares publication, severity, matured exploit-reference and current-snapshot EPSS signals; it does not measure an LLM discovery rate. |
| LLM evidence | Sparse first-party programme report or public-CVE-ID release events. Dates are disclosure dates rather than discovery dates, and programme totals are not summed. |

## Data pipeline

```mermaid
flowchart LR
  CVE["CVE List V5 delta log"] --> Sync["Python aggregation and validation"]
  NVD["NVD JSON 2.0 feeds"] --> Sync
  KEV["CISA KEV JSON"] --> Sync
  EPSS["FIRST EPSS current and historical CSV"] --> Sync
  CWE["MITRE CWE REST API"] --> Sync
  Evidence["Curated LLM evidence"] --> Sync
  Anthropic["Anthropic CVD payload"] --> Sync
  Sync --> Dataset["data/dashboard.json"]
  Dataset --> App["Static dashboard"]
  App --> Pages["GitHub Pages"]
```

`app/page.tsx` imports the generated dataset directly. The daily workflow downloads and validates the inputs in a read-only job, runs the complete test suite and produces the GitHub Pages export. Only the final publication job receives permission to commit `data/dashboard.json`, and only when the validated output differs. The Pages workflow also checks the current clock and refuses to deploy a dashboard, CVE List, NVD or EPSS snapshot beyond its freshness limit. If a download, freshness check or reconciliation fails, the last successful snapshot remains published.

The committed JSON is the complete validated aggregate used by the page, not an append-only copy of every upstream record. Git history keeps earlier dashboard snapshots, while the Actions cache reuses verified source archives to make later refreshes faster. Each daily run still reconciles the aggregate against the authoritative inputs instead of trusting yesterday's totals and adding a delta blindly.

## GitHub automation

- `Refresh vulnerability data` runs daily at 09:17 UTC (17:17 SGT) and can also be started manually. It refreshes CVE, NVD, CISA KEV, FIRST EPSS and first-party LLM evidence before validating the aggregate.
- `Deploy VulnSignal to GitHub Pages` runs after successful `CI` checks on a `main` code push, after a successful data refresh, or when started manually. The successful-refresh trigger is necessary because a commit made with the workflow token does not start another workflow automatically.
- `Continuous integration` checks data and evidence contracts, linting, tests, the static Pages export and high-severity dependency advisories for pull requests and pushes to `main`.
- `CodeQL` scans the JavaScript/TypeScript and Python code. Dependabot checks npm and GitHub Actions updates each week.

Workflows are read-only by default. The repository allows only GitHub-owned Actions, and every Action is pinned to a full commit SHA.

## Development

Requirements:

- Node.js 22.23.1 or a later 22.x release
- Python 3.11 or later

```bash
npm ci
npm run dev
```

The committed dataset lets the dashboard start without downloading the upstream feeds. The first full refresh downloads the yearly NVD archives and can take 30 minutes or more. Later runs reuse verified cached inputs where appropriate.

```bash
npm run data:sync
npm run evidence:check
npm run data:check
```

To include publication data before 2019:

```bash
python3 scripts/sync_vulnerability_data.py --from-year 2010
```

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start the development dashboard. |
| `npm run data:sync` | Pull official sources and rebuild `data/dashboard.json`. |
| `npm run evidence:check` | Validate the curated LLM register against its JSON Schema. |
| `npm run data:check` | Validate the generated dataset without network access. |
| `npm run data:check:freshness` | Apply the deployment-time freshness gates to the generated dataset. |
| `npm run lint` | Run static checks. |
| `npm test` | Build the app and run application and pipeline tests. |
| `npm run check` | Run the full local verification suite. |
| `npm run build:pages` | Produce the static GitHub Pages site in `out/`. |

## Project layout and hosting

```text
app/                                Dashboard UI
data/dashboard.json                 Generated aggregate consumed by the UI
data/llm-discovery-evidence.json    Curated evidence register
data/llm-discovery-evidence.schema.json  Register contract
scripts/sync_vulnerability_data.py  Source ingestion and aggregation
tests/                              Application and pipeline tests
.github/workflows/                  CI, CodeQL, daily refresh and GitHub Pages deployment
```

GitHub Pages is the only public deployment target. This keeps the hosting path and dependency surface small for a personal project.

I maintain VulnSignal as a personal project, so changes may not follow a fixed support timetable. Issues and focused pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) before changing metric definitions or source handling, and [SECURITY.md](SECURITY.md) for private vulnerability reporting. VulnSignal is released under the [Apache License 2.0](LICENSE); redistribution must preserve the attribution in [NOTICE](NOTICE).
