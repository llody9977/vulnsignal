import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the VulnSignal intelligence dashboard", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>VulnSignal — CVE &amp; KEV Trend Intelligence<\/title>/i);
  assert.match(html, /One timeline/);
  assert.match(html, /Interactive report/);
  assert.match(html, /Year vs year/);
  assert.match(html, /Relative trend/);
  assert.match(html, /Actual counts/);
  assert.match(html, /51\.6% higher than Jan–Jun 2025/);
  assert.match(html, /Baseline: 23,650/);
  assert.match(html, /All indicators, one time grid/);
  assert.match(html, /Before and after ChatGPT launched/);
  assert.match(html, /Median time to KEV/);
  assert.match(html, /Apr 2025/);
  assert.match(html, /Mar 2026/);
  assert.match(html, /that later entered KEV/);
  assert.match(html, /75% of KEV-listed CVEs added within/);
  assert.match(html, /Recently confirmed exploitation/);
  assert.match(html, /CVE List V5/i);
  assert.match(html, /NVD JSON 2\.0/);
  assert.match(html, /CISA/);
  assert.match(html, /Reported minimum, not prevalence/);
  assert.match(html, /LLM points mark first-party report or reveal dates/);
  assert.doesNotMatch(html, /T2K \/ P50|T2K \/ P75/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|Starter Project/i);
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
  assert.ok(packageJson.scripts["data:sync"]);
  assert.ok(packageJson.scripts["build:pages"]);
  assert.equal(dataset.schemaVersion, 1);
  assert.ok(dataset.coverage.recordCount > 1_000);
  assert.ok(dataset.monthly.length >= 24);
  assert.ok(dataset.recentKev.length > 0);
  assert.ok(dataset.llmDiscovery.value >= 28);
  assert.equal(dataset.llmDiscovery.qualifier, "documented_lower_bound");
  assert.ok(dataset.llmDiscovery.events.length >= 3);
  assert.ok(dataset.llmDiscovery.events.some((event) => event.kind === "public_id_revealed"));
  assert.ok(dataset.llmDiscovery.events.some((event) => event.kind === "program_report"));
  assert.equal(evidence.coverage, "curated_non_exhaustive");
  assert.equal(evidence.headlineMinimum.cveCount, 28);
  assert.deepEqual(evidence.records, []);
});
