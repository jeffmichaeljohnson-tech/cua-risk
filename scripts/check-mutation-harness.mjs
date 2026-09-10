#!/usr/bin/env node
/**
 * Refuse a generated-mutant report that the harness did not actually produce.
 *
 * WHY THIS EXISTS
 *
 * A mutation score is a measurement, and a measurement tool can be wrong in two
 * ways. It can crash, which is loud and harmless. Or it can return a number,
 * which is neither.
 *
 * Upgrading vitest 2 to 5 did the second. Stryker's vitest runner declares
 * `vitest: ">=2.0.0"`, so it installed and ran happily, and reported this
 * package at 12.38% where the same commit measured 94.93% one version earlier.
 * Whole files came back 0.00% with every mutant "surviving" while all 817 tests
 * passed. Proven on a single mutant by hand: Stryker called an unanchored-regex
 * mutation SURVIVED, and applying that exact mutation to the source fails 37
 * tests. The tests catch it. The harness was not running them.
 *
 * Nothing errored. A scheduled job would have published 12% for a package whose
 * real score is 94%, and the only reason anyone noticed is that somebody went
 * back to check whether a published number still described what ships.
 *
 * THE CHECK
 *
 * The curated set in `mutations.json` is the second witness. Every mutation in
 * it is committed, runnable, and proven caught by `mutation-runner.mjs` — which
 * invokes the test command as a subprocess and therefore cannot be fooled by a
 * broken test-runner integration. So the files it names are files whose tests
 * demonstrably catch mutations.
 *
 * If a generated report says one of those files killed NOTHING, the two
 * witnesses disagree, and the curated one is the one that ran the tests. That is
 * a harness failure, not a coverage result, and the report is refused rather
 * than published.
 *
 * This is the same rule the mutation runner already applies to itself: a verdict
 * you cannot show your work for is not a verdict. FAIL is not UNKNOWN, and a
 * number you cannot substantiate is worse than no number.
 *
 * USAGE
 *   node scripts/check-mutation-harness.mjs <stryker-report.json> <mutations.json>
 *
 * EXIT CODES
 *   0  the report is consistent with the curated set
 *   1  they disagree — the harness is suspect, do not publish the score
 *   2  UNKNOWN: a file could not be read or parsed, so nothing was checked
 */
import { readFileSync } from 'node:fs';

/** Files named by the curated mutation set. Each provably has tests that catch a mutation. */
export function curatedFiles(mutations) {
  const specs = Array.isArray(mutations) ? mutations : (mutations?.mutations ?? []);
  return [...new Set(specs.map((m) => m?.file).filter((f) => typeof f === 'string' && f.length > 0))];
}

/**
 * Per-file kill tallies from a Stryker JSON report.
 *
 * `NoCoverage` is counted as not-killed on purpose. In the broken case it is
 * exactly what a mutant gets when the harness ran no tests against it, so
 * folding it into "killed" would hide the failure this check exists to find.
 */
export function tallies(report) {
  const out = {};
  for (const [path, entry] of Object.entries(report?.files ?? {})) {
    const mutants = entry?.mutants ?? [];
    if (mutants.length === 0) continue;
    const killed = mutants.filter((m) => m.status === 'Killed' || m.status === 'Timeout').length;
    out[path] = { total: mutants.length, killed };
  }
  return out;
}

/** Does `reportPath` refer to the same file as the curated spec's `file`? */
export function samePath(reportPath, curatedPath) {
  const norm = (s) => String(s).replace(/\\/g, '/').replace(/^\.\//, '');
  const a = norm(reportPath);
  const b = norm(curatedPath);
  return a === b || a.endsWith('/' + b) || b.endsWith('/' + a);
}

export function verify(report, mutations) {
  const files = curatedFiles(mutations);
  if (files.length === 0) {
    return { code: 2, why: 'the curated set names no files, so there is nothing to check the report against' };
  }
  const tally = tallies(report);
  if (Object.keys(tally).length === 0) {
    return { code: 2, why: 'the report contains no mutants, so no measurement was made' };
  }

  const disagreements = [];
  let checked = 0;
  for (const curated of files) {
    const match = Object.entries(tally).find(([p]) => samePath(p, curated));
    // A curated file absent from the report is not a disagreement: the report
    // may deliberately scope `mutate` to a subset.
    if (!match) continue;
    checked += 1;
    const [path, { total, killed }] = match;
    if (killed === 0) {
      disagreements.push(
        `${path}: the report kills 0 of ${total} mutants, but the curated set proves this file's tests catch one`,
      );
    }
  }

  if (checked === 0) {
    return { code: 2, why: 'no curated file appears in the report, so the two could not be compared' };
  }
  if (disagreements.length > 0) {
    return {
      code: 1,
      why: 'the generated report disagrees with the curated set, which DID run the tests:\n  - '
        + disagreements.join('\n  - ')
        + '\nThis is a harness failure, not a coverage result. Do not publish this score.',
      checked,
    };
  }
  return { code: 0, why: `report agrees with the curated set on all ${checked} file(s) they share`, checked };
}

function main(argv) {
  const [reportFile, mutationsFile] = argv;
  if (!reportFile || !mutationsFile) {
    console.error('usage: check-mutation-harness.mjs <stryker-report.json> <mutations.json>');
    return 2;
  }
  let report, mutations;
  try {
    report = JSON.parse(readFileSync(reportFile, 'utf8'));
  } catch (e) {
    console.error(`UNKNOWN — could not read the report at ${reportFile}: ${e.message}`);
    return 2;
  }
  try {
    mutations = JSON.parse(readFileSync(mutationsFile, 'utf8'));
  } catch (e) {
    console.error(`UNKNOWN — could not read the curated set at ${mutationsFile}: ${e.message}`);
    return 2;
  }
  const r = verify(report, mutations);
  const label = r.code === 0 ? 'OK' : r.code === 1 ? 'HARNESS SUSPECT' : 'UNKNOWN';
  console[r.code === 0 ? 'log' : 'error'](`${label} — ${r.why}`);
  return r.code;
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  process.exit(main(process.argv.slice(2)));
}
