#!/usr/bin/env node
/**
 * Tests for the harness-sanity guard.
 *
 * The guard's whole value is that it refuses a number rather than publishing a
 * wrong one, so the half that must not fire is the larger half here: a low score
 * is a legitimate result and must pass, and only a curated file catching NOTHING
 * is treated as the harness lying.
 */
import { verify, curatedFiles, tallies, samePath } from './check-mutation-harness.mjs';

let pass = 0;
let fail = 0;
const t = (name, fn) => {
  try {
    fn();
    pass += 1;
    console.log(`  ok    ${name}`);
  } catch (e) {
    fail += 1;
    console.log(`  FAIL  ${name}\n        ${e.message}`);
  }
};
const assert = (cond, msg) => {
  if (!cond) throw new Error(msg);
};

/** A report shape matching Stryker's JSON reporter, with `n` mutants of which `k` are Killed. */
const fileEntry = (n, k) => ({
  mutants: Array.from({ length: n }, (_, i) => ({ status: i < k ? 'Killed' : 'Survived' })),
});

console.log('\nAGREEMENT — a healthy report passes');

t('a report that catches mutants in every curated file is accepted', () => {
  const report = { files: { 'src/a.ts': fileEntry(10, 9), 'src/b.ts': fileEntry(10, 4) } };
  const r = verify(report, [{ file: 'src/a.ts' }, { file: 'src/b.ts' }]);
  assert(r.code === 0, `expected 0, got ${r.code}: ${r.why}`);
});

t('a LOW score is a result, not a harness failure', () => {
  // The guard must not become a score floor by the back door. One catch out of a
  // hundred is a bad suite and a true measurement; only ZERO is suspect.
  const report = { files: { 'src/a.ts': fileEntry(100, 1) } };
  const r = verify(report, [{ file: 'src/a.ts' }]);
  assert(r.code === 0, `a 1% score must pass, got ${r.code}: ${r.why}`);
});

t('a Timeout counts as caught', () => {
  const report = { files: { 'src/a.ts': { mutants: [{ status: 'Timeout' }, { status: 'Survived' }] } } };
  assert(verify(report, [{ file: 'src/a.ts' }]).code === 0, 'a timeout is evidence the tests ran');
});

console.log('\nDISAGREEMENT — the case this exists for');

t('a curated file that catches NOTHING is refused', () => {
  const report = { files: { 'src/a.ts': fileEntry(151, 0) } };
  const r = verify(report, [{ file: 'src/a.ts' }]);
  assert(r.code === 1, `expected 1, got ${r.code}`);
  assert(/catches 0 of 151/.test(r.why), `the refusal must name the tally, got: ${r.why}`);
  assert(/src\/a\.ts/.test(r.why), 'the refusal must name the file');
});

t('NoCoverage is NOT folded into caught', () => {
  // In the real failure a mutant the harness never tested came back NoCoverage.
  // Counting it as caught would hide exactly this defect.
  const report = { files: { 'src/a.ts': { mutants: [{ status: 'NoCoverage' }, { status: 'NoCoverage' }] } } };
  assert(verify(report, [{ file: 'src/a.ts' }]).code === 1, 'all-NoCoverage must be refused');
});

t('one healthy file does not excuse a dead one', () => {
  const report = { files: { 'src/a.ts': fileEntry(10, 9), 'src/b.ts': fileEntry(20, 0) } };
  const r = verify(report, [{ file: 'src/a.ts' }, { file: 'src/b.ts' }]);
  assert(r.code === 1, 'a single disagreement is enough to refuse the report');
  assert(/src\/b\.ts/.test(r.why) && !/src\/a\.ts:/.test(r.why), 'only the offending file is named');
});

console.log('\nUNKNOWN — could not compare, which is not the same as agreeing');

t('an empty report is UNKNOWN, never OK', () => {
  assert(verify({ files: {} }, [{ file: 'src/a.ts' }]).code === 2, 'no mutants means no measurement');
});

t('an empty curated set is UNKNOWN, never OK', () => {
  assert(verify({ files: { 'src/a.ts': fileEntry(5, 5) } }, []).code === 2, 'nothing to compare against');
});

t('a report sharing no file with the curated set is UNKNOWN', () => {
  // A scoped `mutate` legitimately produces this. It must not read as agreement.
  const report = { files: { 'src/z.ts': fileEntry(10, 0) } };
  assert(verify(report, [{ file: 'src/a.ts' }]).code === 2, 'no overlap means no verdict');
});

t('a curated file absent from a scoped report is skipped, not failed', () => {
  const report = { files: { 'src/a.ts': fileEntry(10, 9) } };
  const r = verify(report, [{ file: 'src/a.ts' }, { file: 'src/not-in-report.ts' }]);
  assert(r.code === 0 && r.checked === 1, `expected one file checked, got ${r.checked}`);
});

console.log('\nHELPERS');

t('curatedFiles reads both the bare-array and wrapped spec shapes', () => {
  assert(curatedFiles([{ file: 'a' }, { file: 'a' }, { file: 'b' }]).length === 2, 'duplicates collapse');
  assert(curatedFiles({ mutations: [{ file: 'c' }] })[0] === 'c', 'wrapped shape is read');
  assert(curatedFiles([{ name: 'no file' }]).length === 0, 'entries without a file are ignored');
});

t('tallies ignores files with no mutants', () => {
  const out = tallies({ files: { 'src/a.ts': { mutants: [] }, 'src/b.ts': fileEntry(3, 1) } });
  assert(!('src/a.ts' in out) && out['src/b.ts'].caught === 1, 'an empty file is not a zero-catch file');
});

t('samePath matches across leading ./ and path depth, and rejects a near-miss', () => {
  assert(samePath('src/detect/detect.ts', 'src/detect/detect.ts'), 'identical');
  assert(samePath('./src/a.ts', 'src/a.ts'), 'leading ./');
  assert(samePath('/w/repo/src/a.ts', 'src/a.ts'), 'absolute report path');
  assert(!samePath('src/other.ts', 'src/a.ts'), 'a different file must not match');
  assert(!samePath('src/xa.ts', 'src/a.ts'), 'a suffix that is not a path segment must not match');
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
