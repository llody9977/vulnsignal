# Contributing to VulnSignal

Thanks for helping make vulnerability reporting more transparent and
reproducible. Contributions to the dashboard, ingestion pipeline,
documentation, tests, and evidence methodology are welcome.

## Set up a development environment

Requirements:

- Node.js 22.13 or later
- Python 3.11 or later

```bash
npm ci
npm run data:check
npm run dev
```

Create a focused branch, keep unrelated changes out of the pull request, and
explain any user-visible or methodological decision in the description.

## Validate a change

Run the full suite before opening a pull request:

```bash
npm run check
```

For documentation-only changes, at minimum run `npm run data:check` and verify
that Markdown links and examples are accurate.

## Data and methodology changes

- Do not commit `.cache/`; it contains reproducible upstream downloads.
- Do not hand-edit `data/dashboard.json`. Change the aggregation code, add a
  test, and regenerate the dataset with `npm run data:sync`.
- Prefer an issuing authority or original publisher over mirrors and derived
  APIs. Explain provenance, update frequency, licensing or attribution, and
  failure behavior when proposing a new source.
- Preserve source uncertainty. Missing severity is not low severity, an NVD
  `Exploit` reference is not equivalent to CISA KEV membership, and a KEV entry
  does not show that every product configuration is exploitable.
- Avoid silently changing denominators, date windows, CVSS selection, or cohort
  maturity rules. Add tests and document the old and new interpretations.

## LLM-discovery evidence

CVE, NVD, and KEV do not reliably identify the discovery method. Do not infer
LLM participation from publication dates, descriptions, author names, or a
general statement that a team uses AI.

For CVE-level evidence, a proposal should identify the CVE, link to a primary
source, quote or precisely summarize the relevant claim, and show that an LLM
participated in finding that specific vulnerability. Vendor advisories,
researcher reports, and first-party technical disclosures are preferred.
Secondary reporting can help locate evidence but is not sufficient by itself
for `verified` status.

A first-party program aggregate can be tracked as a documented lower bound
when individual CVE identifiers are not published, but it must remain separate
from CVE-level records. State the unit exactly and do not treat a combined
CVEs-and-GHSAs figure as a CVE count.

The registry is intentionally curated and non-exhaustive. Absence from it must
never be presented as evidence that a vulnerability was not LLM-assisted.

## Pull request checklist

- The change has a narrow, descriptive title.
- Tests cover new behavior or explain why no test is needed.
- Generated data is included only when pipeline behavior changed or a refresh
  is intentionally part of the pull request.
- User-facing metric definitions and caveats remain accurate.
- No credentials, private vulnerability information, or downloaded source
  archives are included.

By contributing, you agree that your contribution is licensed under the MIT
License in this repository.
