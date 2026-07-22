# VulnSignal Metric Dictionary

This document defines the formal metrics, formulas, numerators, denominators, date semantics, censoring policies, source fields, and known biases for all analytical indicators rendered in the **VulnSignal** vulnerability dashboard.

---

## Summary of Core Metrics

### 1. Published CVE Count (`cvePublicationCount`)
* **Formula**: `count(active_nvd_records where start_date <= published <= end_date)`
* **Numerator**: Active (non-rejected) NVD CVE records published in the window.
* **Denominator**: N/A (absolute count).
* **Date Semantics**: NVD publication date (`cve.published`).
* **Censoring Policy**: Excludes `REJECTED` CVEs; incomplete current month is marked as `(Partial)`.
* **Known Biases**: Increases when CNA reporting activity grows, regardless of true software vulnerability prevalence.

### 2. CVSS Base Severity Distribution (`severityShare`)
* **Formula**: `count(published_cves where severity == band) / count(scored_published_cves)`
* **Numerator**: Published CVEs assigned a specific CVSS base severity band (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
* **Denominator**: All CVSS-scored published CVEs in window.
* **Date Semantics**: NVD publication date.
* **Censoring Policy**: Prefers primary assessment over secondary; hierarchy: `v4.0` &rarr; `v3.1` &rarr; `v3.0` &rarr; `v2`. Scores of `0.0` are assigned to `NONE`; records without CVSS remain `UNKNOWN`/Unscored.
* **Known Biases**: Different CVSS versions use different baseline distributions and are not directly comparable.

### 3. Public Exploit Reference Share (`publicExploitShare`)
* **Formula**: `count(mature_published_cves with Exploit tag) / count(mature_published_cves)`
* **Numerator**: CVEs with at least one NVD reference tagged with type `Exploit`.
* **Denominator**: Mature published CVEs (`published <= snapshot_date - 180 days`).
* **Date Semantics**: NVD publication date.
* **Censoring Policy**: Requires 180-day maturity window to avoid CNA tag ingestion lag. Comparison is withheld if either period lacks mature data.
* **Known Biases**: Tags indicate linked public material on NVD references; they do not verify exploit validity or execution capability.

### 4. Median Publication-to-KEV Gap (`medianPublicationToKevGap`)
* **Formula**: `median((cisa_kev.dateAdded - nvd_cve.published).days for cve in mature_cohort if cve in KEV)`
* **Numerator**: Signed day difference between NVD publication date and CISA KEV `dateAdded`.
* **Denominator**: KEV-listed CVEs in mature cohort (`kevTimingSample / matureCohort`).
* **Date Semantics**: NVD publication date (`cve.published`) and CISA KEV listing date (`dateAdded`).
* **Censoring Policy**: Calculated only for mature cohort (`published <= snapshot_date - 90 days`) to prevent right-censoring bias. Retains signed difference (negative values indicate pre-publication KEV listing).
* **Known Biases**: **Selected-outcome metric** computed ONLY among KEV-listed CVEs; it does not measure the time-to-KEV for unlisted CVEs.

### 5. Post-Publication Median Gap to KEV (`nonNegativePublicationToKevGap`)
* **Formula**: `median((dateAdded - published).days for cve in mature_cohort if cve in KEV and (dateAdded - published).days >= 0)`
* **Numerator**: Non-negative day differences for KEV listings added on or after NVD publication date.
* **Denominator**: Post-publication KEV-listed CVEs in mature cohort.
* **Date Semantics**: NVD publication date and CISA KEV listing date.
* **Censoring Policy**: Excludes pre-publication KEV cases where `dateAdded` predates NVD publication.

### 6. Share of Mature Published CVEs Entering KEV within 90 Days (`kevWithin90DayRate`)
* **Formula**: `count(mature_cves listed in KEV within 90 days of publication) / count(mature_published_cves)`
* **Numerator**: Mature published CVEs with `(dateAdded - published).days <= 90`.
* **Denominator**: All mature published CVEs (`published <= snapshot_date - 90 days`).
* **Date Semantics**: NVD publication date and CISA KEV `dateAdded`.
* **Censoring Policy**: Excludes CVEs published in the latest 90 days to prevent right-censoring bias.

### 7. All-CVE KEV Conversion Rate (`allCveKevConversionRate`)
* **Formula**: `count(mature_published_cves in KEV) / count(mature_published_cves)`
* **Numerator**: Mature published CVEs listed in CISA KEV.
* **Denominator**: All mature published CVEs.
* **Date Semantics**: NVD publication date.
* **Known Biases**: Baseline conversion rate for any published vulnerability to enter KEV.

### 8. Exploit-Reference Tagged KEV Conversion Rate (`exploitRefKevConversionRate`)
* **Formula**: `count(mature_exploit_ref_cves in KEV) / count(mature_exploit_ref_cves)`
* **Numerator**: Mature published CVEs with NVD Exploit tag that are listed in CISA KEV.
* **Denominator**: All mature published CVEs with NVD Exploit reference tag.
* **Date Semantics**: NVD publication date.
* **Known Biases**: Demonstrates the increased likelihood of KEV listing when a public exploit reference tag is present.

### 9. EPSS Screening Watch (`epssScreeningWatch`)
* **Formula**: Active NVD CVEs published in latest 90 days with current EPSS &ge; 0.10 and not listed in CISA KEV.
* **Numerator**: CVEs meeting screening criteria.
* **Denominator**: N/A (full list retained for tile inspection).
* **Date Semantics**: CVE published in latest 90 days; EPSS current snapshot date.
* **Known Biases**: A project-defined analytical screening list based solely on current EPSS and KEV status; **NOT** an asset-specific remediation order or patch priority queue.
