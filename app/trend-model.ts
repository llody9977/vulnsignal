export type MonthPoint = {
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

export type LlmEvidenceEvent = {
  kind: "public_id_revealed" | "program_report";
  date: string;
  dateSemantics: string;
  coverage: string;
  count?: number;
  cveIds?: string[];
  publisher?: string;
  program?: string;
  reportedMinimum?: number;
  sourceUrl?: string;
};

export type PeriodSummary = {
  published: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  none: number;
  unknown: number;
  scored: number;
  criticalHigh: number;
  criticalHighShare: number | null;
  severityCoverage: number | null;
  publicExploitReferences: number;
  publicExploitShare: number | null;
  kevAdded: number;
  llmEvidence: number;
  monthlyAverage: number;
  peakMonth: MonthPoint | null;
  momentum: number | null;
};

export function percentage(numerator: number, denominator: number) {
  if (!denominator) return null;
  return Math.round((numerator / denominator) * 1000) / 10;
}

export function change(current: number, previous: number) {
  if (!previous) return null;
  return Math.round(((current - previous) / previous) * 1000) / 10;
}

export function completeMonths(monthly: MonthPoint[], latestCompleteMonth: string) {
  return monthly.filter(
    (point) => !point.partial && point.month <= latestCompleteMonth,
  );
}

export function availableYears(monthly: MonthPoint[], latestCompleteMonth: string) {
  return Array.from(
    new Set(
      completeMonths(monthly, latestCompleteMonth).map((point) =>
        Number(point.month.slice(0, 4)),
      ),
    ),
  ).sort((a, b) => a - b);
}

export function monthsForYear(
  monthly: MonthPoint[],
  year: number,
  latestCompleteMonth: string,
) {
  return completeMonths(monthly, latestCompleteMonth).filter(
    (point) => Number(point.month.slice(0, 4)) === year,
  );
}

export function rollingMonths(
  monthly: MonthPoint[],
  endMonth: string,
  latestCompleteMonth: string,
  count = 12,
) {
  const complete = completeMonths(monthly, latestCompleteMonth);
  const endIndex = complete.findIndex((point) => point.month === endMonth);
  if (endIndex < 0) return [];
  return complete.slice(Math.max(0, endIndex - count + 1), endIndex + 1);
}

export function matchedYearPoints(
  monthly: MonthPoint[],
  firstYear: number,
  secondYear: number,
  latestCompleteMonth: string,
) {
  const first = monthsForYear(monthly, firstYear, latestCompleteMonth);
  const second = monthsForYear(monthly, secondYear, latestCompleteMonth);
  const monthCap = Math.min(
    Math.max(...first.map((point) => Number(point.month.slice(5, 7))), 0),
    Math.max(...second.map((point) => Number(point.month.slice(5, 7))), 0),
  );
  return {
    first: first.filter(
      (point) => Number(point.month.slice(5, 7)) <= monthCap,
    ),
    second: second.filter(
      (point) => Number(point.month.slice(5, 7)) <= monthCap,
    ),
    monthCap,
  };
}

export function llmEvidenceForMonth(
  month: string,
  events: LlmEvidenceEvent[],
) {
  const matching = events.filter((event) => event.date.slice(0, 7) === month);
  const publicIds = matching
    .filter((event) => event.kind === "public_id_revealed")
    .reduce(
      (total, event) => total + (event.count ?? event.cveIds?.length ?? 0),
      0,
    );
  const reportedMinimum = Math.max(
    ...matching
      .filter((event) => event.kind === "program_report")
      .map((event) => event.reportedMinimum ?? 0),
    0,
  );
  return Math.max(publicIds, reportedMinimum);
}

export function summarizePeriod(
  points: MonthPoint[],
  events: LlmEvidenceEvent[],
): PeriodSummary {
  const totals = points.reduce(
    (summary, point) => {
      summary.published += point.published;
      summary.critical += point.critical;
      summary.high += point.high;
      summary.medium += point.medium;
      summary.low += point.low;
      summary.none += point.none;
      summary.unknown += point.unknown;
      summary.publicExploitReferences += point.publicExploitReferences;
      summary.kevAdded += point.kevAdded;
      return summary;
    },
    {
      published: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      none: 0,
      unknown: 0,
      publicExploitReferences: 0,
      kevAdded: 0,
    },
  );
  const scored =
    totals.critical + totals.high + totals.medium + totals.low + totals.none;
  const criticalHigh = totals.critical + totals.high;
  const peakMonth = points.reduce<MonthPoint | null>(
    (peak, point) => (!peak || point.published > peak.published ? point : peak),
    null,
  );
  const llmEvidence = Math.max(
    ...points.map((point) => llmEvidenceForMonth(point.month, events)),
    0,
  );
  const lastThree = points.slice(-3);
  const priorThree = points.slice(-6, -3);
  const lastAverage = lastThree.length
    ? lastThree.reduce((sum, point) => sum + point.published, 0) /
      lastThree.length
    : 0;
  const priorAverage = priorThree.length
    ? priorThree.reduce((sum, point) => sum + point.published, 0) /
      priorThree.length
    : 0;

  return {
    ...totals,
    scored,
    criticalHigh,
    criticalHighShare: percentage(criticalHigh, scored),
    severityCoverage: percentage(scored, totals.published),
    publicExploitShare: percentage(
      totals.publicExploitReferences,
      totals.published,
    ),
    llmEvidence,
    monthlyAverage: points.length
      ? Math.round((totals.published / points.length) * 10) / 10
      : 0,
    peakMonth,
    momentum: priorAverage ? change(lastAverage, priorAverage) : null,
  };
}
