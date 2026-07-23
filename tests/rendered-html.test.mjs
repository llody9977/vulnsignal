import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render() {
  return readFile(new URL("../out/index.html", import.meta.url), "utf8");
}

test("static export renders the VulnSignal intelligence dashboard", async () => {
  const html = await render();
  assert.match(html, /<title>VulnSignal — CVE, KEV and EPSS Exploitation Signals<\/title>/i);
  assert.match(html, /Vulnerability trends\./);
  assert.match(html, /Exploitation signals\./);
  assert.match(html, /Interactive report/);
  assert.match(html, /Compare years/);
  assert.match(html, /Relative trend/);
  assert.match(html, /Actual counts/);
  assert.match(html, /Baseline:/);
  assert.match(html, /Monthly values by indicator/);
  assert.match(html, /CVE, KEV, exploit and EPSS trends/);
  assert.match(html, /SNAPSHOT ID/);
  assert.match(html, /VS-\d{8}-\d{4}Z/);
  assert.match(html, /Source data included/);
  assert.match(html, /What changed/);
  assert.match(html, /feed activity, not vulnerability incidence/);
  assert.match(html, /Confirmed exploitation · CISA KEV/);
  assert.doesNotMatch(html, /Confirmed exploitation · latest catalog date/);
  assert.match(html, /Critical \+ high share/);
  assert.match(html, /Disclosure and publication activity/);
  assert.match(html, /does not measure an LLM discovery rate/);
  assert.match(html, /Publication-to-KEV gap \(Median\)/);
  assert.match(html, /Publication-to-KEV gap \(75th percentile\)/);
  assert.match(html, /KEV deadlines within 7 days/);
  assert.match(html, /90-day EPSS screening watch/);
  assert.doesNotMatch(html, /View breakdown/);
  assert.equal((html.match(/indicator-cell__value-link/g) ?? []).length, 6);
  assert.equal((html.match(/aria-haspopup="dialog"/g) ?? []).length, 6);
  assert.match(html, /metric-value--link/);
  assert.match(html, /metric-value--info/);
  assert.match(html, /data-tooltip="UTC time when this validated dashboard snapshot was generated"/);
  assert.match(html, /href="#priority-watch-table"/);
  assert.match(html, /id="indicator-drilldown"/);
  assert.match(html, /aria-labelledby="indicator-drilldown-title"/);
  assert.match(html, /VulnSignal screening candidates not in CISA KEV/);
  assert.match(html, /Exploit reference<\/th>/);
  assert.match(html, /NVD-tagged exploit reference/);
  assert.match(html, /No NVD exploit tag in this snapshot/);
  assert.match(html, /EPSS threshold history/);
  assert.match(html, /current scores are not applied backwards/i);
  assert.match(html, /Largest share risers/);
  assert.match(html, /cwe\.mitre\.org\/data\/definitions/);
  assert.match(html, /Recently added to CISA KEV/);
  assert.match(html, /CVE List V5/i);
  assert.match(html, /NVD JSON 2\.0/);
  assert.match(html, /CISA/);
  assert.match(html, /Reported LLM-assisted disclosure events/);
  assert.match(html, /LLM disclosure events/);
  assert.match(html, /does not mean zero LLM-assisted discoveries/);
  assert.match(html, /recent records are still being enriched/);
  assert.match(html, /None \(CVSS 0\.0\)/);
  assert.match(html, /project-defined threshold/);
  assert.match(html, /current, not historical/i);
  assert.match(html, /FIRST EPSS/i);
  assert.match(html, /Informational use only/);
  assert.match(html, /not legal, compliance, security, risk-management or remediation advice/i);
  assert.match(html, /provided “as is”/i);
  assert.match(html, /Apache License 2\.0/);
  assert.match(html, /© 2026/);
  assert.match(html, /llody9977/);
  assert.match(html, />ATTRIBUTION ↗</);
  assert.match(html, /This product uses NVD data feeds and is not endorsed or certified by the NVD/);
  assert.match(html, /href="#disclaimer"/);
  assert.match(html, /chart-point--event/);
  assert.match(html, /≥ 28/);
  assert.match(html, /Counts from different programmes remain separate/);
  assert.doesNotMatch(html, /LLM CVE evidence disclosed/);
  assert.doesNotMatch(html, /Reported LLM-assisted CVEs/);
  assert.doesNotMatch(html, /Higher reported minimum|Lower reported minimum/);
  assert.doesNotMatch(html, /Before and after ChatGPT|Every signal|recommended GitHub repository/i);
  assert.doesNotMatch(html, /T2K \/ P50|T2K \/ P75/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|Starter Project/i);
});

test("project disclaimer, attribution, and security policy are documented", async () => {
  const [readme, security, license, notice, authors] = await Promise.all([
    readFile(new URL("../README.md", import.meta.url), "utf8"),
    readFile(new URL("../SECURITY.md", import.meta.url), "utf8"),
    readFile(new URL("../LICENSE", import.meta.url), "utf8"),
    readFile(new URL("../NOTICE", import.meta.url), "utf8"),
    readFile(new URL("../AUTHORS.md", import.meta.url), "utf8"),
  ]);

  assert.match(readme, /## Disclaimer/);
  assert.match(readme, /No service level, response time, uninterrupted refresh schedule or continuing availability is promised/);
  assert.match(readme, /## Licence and attribution/);
  assert.match(readme, /Apache License 2\.0/);
  assert.match(license, /Apache License/);
  assert.match(license, /Version 2\.0, January 2004/);
  assert.match(notice, /Copyright 2026 llody9977/);
  assert.match(authors, /OpenAI Codex has assisted/);
  assert.doesNotMatch(readme, /MIT Licence/);
  assert.match(security, /Reports are reviewed when time permits, and I may not reply to every report/);
  assert.match(security, /does not promise an acknowledgement, response, remediation or disclosure timeline/);
  assert.doesNotMatch(security, /acknowledge a report within seven days/i);
});

test("project metadata and generated dataset are repo-ready", async () => {
  const [packageText, datasetText, evidenceText] = await Promise.all([
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../data/dashboard.json", import.meta.url), "utf8"),
    readFile(new URL("../data/llm-discovery-evidence.json", import.meta.url), "utf8"),
  ]);
  const packageJson = JSON.parse(packageText);
  const dataset = JSON.parse(datasetText);
  const evidence = JSON.parse(evidenceText);

  assert.equal(packageJson.name, "vulnsignal");
  assert.equal(packageJson.version, "1.0.0");
  assert.equal(packageJson.license, "Apache-2.0");
  assert.match(packageJson.author, /llody9977/);
  assert.ok(packageJson.scripts["data:sync"]);
  assert.ok(packageJson.scripts["build:pages"]);
  assert.equal(dataset.schemaVersion, 2);
  assert.match(dataset.snapshot.id, /^VS-\d{8}-\d{4}Z$/);
  assert.equal(dataset.snapshot.generatedAt, dataset.generatedAt);
  assert.equal(dataset.snapshot.inputCount, dataset.snapshot.inputs.length);
  assert.match(dataset.snapshot.inputFingerprintSha256, /^[a-f0-9]{64}$/);
  assert.ok(dataset.snapshot.inputs.some((input) => input.id === "llm-evidence-register"));
  assert.ok(dataset.coverage.recordCount > 1_000);
  assert.ok(dataset.monthly.length >= 24);
  assert.ok(dataset.recentKev.length > 0);
  assert.ok(dataset.llmDiscovery.value >= 28);
  assert.equal(dataset.llmDiscovery.qualifier, "documented_lower_bound");
  assert.ok(dataset.llmDiscovery.events.length >= 3);
  assert.ok(dataset.llmDiscovery.events.some((event) => event.kind === "public_id_revealed"));
  assert.ok(dataset.llmDiscovery.events.some((event) => event.kind === "program_report"));
  assert.equal(dataset.comparison.method, "adjacent_rolling_windows");
  assert.ok(dataset.comparison.earlier.start);
  assert.ok(dataset.comparison.recent.end);
  assert.ok(Number.isInteger(dataset.risk.prePublicationKev));
  assert.ok(dataset.sources.cve.latestFetch);
  assert.ok(dataset.sources.nvd.latestSourceUpdate);
  assert.ok(dataset.sources.kev.released);
  assert.ok(dataset.sources.anthropic.asOf);
  assert.ok(dataset.sources.llmRegistry.lastReviewed);
  assert.ok(dataset.sources.llmRegistry.programmeSources.some((source) => source.publisher === "OpenAI"));
  assert.equal(dataset.priorityWatch.window.days, 90);
  assert.equal(dataset.priorityWatch.window.threshold, dataset.sources.epss.projectThreshold);
  assert.equal(dataset.priorityWatch.itemsCompleteness, "all_candidates");
  assert.equal(dataset.priorityWatch.items.length, dataset.priorityWatch.total);
  assert.ok(dataset.priorityWatch.items.every((item) => item.epss >= dataset.priorityWatch.window.threshold));
  assert.ok(dataset.epssHistory.points.length >= 1);
  assert.equal(dataset.epssHistory.threshold, dataset.sources.epss.projectThreshold);
  assert.ok(dataset.epssHistory.points.every((point) => point.sourceUrl && point.modelVersion));
  assert.ok(dataset.risk.kevDeadlineComparison.current.within7Share >= 0);
  assert.ok(dataset.topCwes.every((item) => item.name && item.url));
  assert.ok(dataset.cweMovers.rising.length > 0);
  assert.ok(dataset.cweMovers.falling.length > 0);
  assert.equal(dataset.changeDigest.priority.count, dataset.priorityWatch.total);
  assert.equal(evidence.coverage, "curated_non_exhaustive");
  assert.ok(evidence.lastReviewed);
  assert.equal(evidence.headlineMinimum.cveCount, 28);
  assert.deepEqual(evidence.records, []);
});
