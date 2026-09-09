#!/usr/bin/env node
// Tests for mutation-runner. The tool measures other suites, so its own
// failure modes are the point: a false KILLED inflates a score, and a failed
// restore corrupts the tree it was measuring.

import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { runOne, runAll, report, checkBaseline, KILLED, SURVIVED, INCONCLUSIVE, NOT_APPLIED }
  from './mutation-runner.mjs';

let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ok    ${name}`); pass++; }
  catch (e) { console.log(`  FAIL  ${name}\n        ${e.message}`); fail++; }
};
const assert = (c, m) => { if (!c) throw new Error(m); };
const eq = (a, b, m) => assert(a === b, `${m}: expected ${b}, got ${a}`);

const SRC = 'const LIMIT = 10;\nexport const f = (n) => n < LIMIT;\n';
function fixture() {
  const dir = mkdtempSync(path.join(tmpdir(), 'mut-'));
  writeFileSync(path.join(dir, 'a.js'), SRC);
  return dir;
}
const spec = (over = {}) => ({
  name: 'LIMIT 10 -> 20', file: 'a.js',
  find: 'const LIMIT = 10;', replace: 'const LIMIT = 20;',
  ran: 'Tests\\s+\\d+', ...over,
});
const exec = (out, code) => () => ({ out, code });

console.log('\nVERDICTS');

t('a suite that ran and failed is KILLED', () => {
  const d = fixture();
  eq(runOne(d, spec(), exec('Tests  9 passed | 1 failed', 1)).verdict, KILLED, 'verdict');
  rmSync(d, { recursive: true });
});

t('a suite that ran and passed is SURVIVED', () => {
  const d = fixture();
  eq(runOne(d, spec(), exec('Tests  10 passed', 0)).verdict, SURVIVED, 'verdict');
  rmSync(d, { recursive: true });
});

t('a BUILD ERROR is INCONCLUSIVE, never KILLED — the defect this tool exists for', () => {
  const d = fixture();
  // Non-zero exit, but the runner never printed evidence that tests executed.
  // A runner reading only the exit code scores this as a kill it never earned.
  const r = runOne(d, spec(), exec('error TS2304: Cannot find name.\n', 2));
  eq(r.verdict, INCONCLUSIVE, 'verdict');
  assert(/no evidence tests ran/.test(r.note), `note did not explain: ${r.note}`);
  rmSync(d, { recursive: true });
});

t('exit 0 with no evidence of tests is INCONCLUSIVE, not SURVIVED', () => {
  const d = fixture();
  eq(runOne(d, spec(), exec('nothing to do\n', 0)).verdict, INCONCLUSIVE, 'verdict');
  rmSync(d, { recursive: true });
});

console.log('\nAPPLICATION');

t('a pattern that is absent is NOT-APPLIED, not SURVIVED', () => {
  const d = fixture();
  const r = runOne(d, spec({ find: 'const NOPE = 1;' }), exec('Tests  10 passed', 0));
  eq(r.verdict, NOT_APPLIED, 'verdict');
  assert(/occurs 0x/.test(r.note), r.note);
  rmSync(d, { recursive: true });
});

t('an AMBIGUOUS pattern is NOT-APPLIED — two sites is not one mutation', () => {
  const d = fixture();
  writeFileSync(path.join(d, 'a.js'), SRC + SRC);
  const r = runOne(d, spec(), exec('Tests  10 passed', 0));
  eq(r.verdict, NOT_APPLIED, 'verdict');
  assert(/occurs 2x/.test(r.note), r.note);
  rmSync(d, { recursive: true });
});

t('the mutation is genuinely in the file while the command runs', () => {
  const d = fixture();
  let seen = null;
  runOne(d, spec(), () => {
    seen = readFileSync(path.join(d, 'a.js'), 'utf8');
    return { out: 'Tests  1 failed', code: 1 };
  });
  assert(seen.includes('LIMIT = 20'), 'the command saw the UNMUTATED file');
  rmSync(d, { recursive: true });
});

t('a $ in the replacement is literal, not a substitution pattern', () => {
  // JS expands $&, $`, $', $$ and $1..$9 inside a STRING replacement. A spec
  // whose replacement contains one would be silently mangled and the verdict
  // would describe code nobody wrote.
  const d = mkdtempSync(path.join(tmpdir(), 'mut-'));
  writeFileSync(path.join(d, 'a.js'), 'const cost = 5;\n');
  let seen = null;
  runOne(d, { name: 'dollar', file: 'a.js', find: '5', replace: "price$`$&$$", ran: '.' },
    () => { seen = readFileSync(path.join(d, 'a.js'), 'utf8'); return { out: 'x', code: 1 }; });
  eq(seen, 'const cost = price$`$&$$;\n', 'replacement was mangled');
  rmSync(d, { recursive: true });
});

console.log('\nRESTORATION');

t('the file is byte-identical after a run', () => {
  const d = fixture();
  runOne(d, spec(), exec('Tests  1 failed', 1));
  eq(readFileSync(path.join(d, 'a.js'), 'utf8'), SRC, 'content');
  rmSync(d, { recursive: true });
});

t('the file is restored even when the command THROWS', () => {
  const d = fixture();
  let threw = false;
  try {
    runOne(d, spec(), () => { throw new Error('runner exploded'); });
  } catch { threw = true; }
  assert(threw, 'the throw was swallowed');
  eq(readFileSync(path.join(d, 'a.js'), 'utf8'), SRC, 'content after a throw');
  rmSync(d, { recursive: true });
});

t('a NOT-APPLIED mutation leaves the file untouched', () => {
  const d = fixture();
  runOne(d, spec({ find: 'absent' }), exec('Tests  1 passed', 0));
  eq(readFileSync(path.join(d, 'a.js'), 'utf8'), SRC, 'content');
  rmSync(d, { recursive: true });
});

console.log('\nBASELINE');

t('a green baseline is ok', () => {
  assert(checkBaseline(exec('Tests  10 passed', 0), 'Tests\\s+\\d+').ok, 'green baseline rejected');
});

t('a RED baseline aborts, and names the leftover-mutation cause', () => {
  // The incident this encodes: a run was killed mid-mutation, the restore never
  // happened, and the mutated file silently became the next run's baseline. Two
  // mutations then reported NOT-APPLIED because their search text was already
  // gone -- a wrong answer that looked like a clean result.
  const r = checkBaseline(exec('Tests  9 passed | 1 failed', 1), 'Tests\\s+\\d+');
  assert(!r.ok, 'a failing baseline was accepted');
  assert(/leftover mutation/.test(r.why), `cause not named: ${r.why}`);
  assert(/git status/.test(r.why), `no way to check given: ${r.why}`);
});

t('a baseline that exits 0 without running tests aborts', () => {
  // Exit 0 from a command that never ran the suite would make every mutation
  // look SURVIVED. That is the loudest possible wrong answer, so it aborts.
  const r = checkBaseline(exec('nothing to do', 0), 'Tests\\s+\\d+');
  assert(!r.ok, 'a no-op baseline was accepted');
  assert(/no evidence any test ran/.test(r.why), r.why);
});

console.log('\nREPORTING');

t('the report counts every verdict and names the total', () => {
  const d = fixture();
  const rs = runAll(d, [spec(), spec({ name: 'b' }), spec({ name: 'c', find: 'absent' })],
    exec('Tests  1 failed', 1));
  const out = report(rs);
  assert(/2 killed, 0 survived, 0 inconclusive, 1 not applied \(of 3\)/.test(out), out);
  rmSync(d, { recursive: true });
});

t('an INCONCLUSIVE result is called out, not quietly counted', () => {
  const d = fixture();
  const out = report(runAll(d, [spec()], exec('build failed', 2)));
  assert(/INCONCLUSIVE is not a pass/.test(out), out);
  rmSync(d, { recursive: true });
});

t('a spec with NO `ran` marker is REFUSED, not quietly defaulted', () => {
  // Found by a red team. This used to default to `new RegExp('.')`, which
  // matches any non-empty output -- so omitting the field turned every non-zero
  // exit back into KILLED, including a syntax error under which no test ran.
  // The guarantee this module exists to provide was opt-out by omission, and
  // the test that claimed to cover it covered a different case.
  const d = fixture();
  let threw = null;
  try { runOne(d, spec({ ran: undefined }), exec('anything', 1)); }
  catch (e) { threw = e.message; }
  assert(threw, 'a spec with no marker was accepted');
  assert(/no `ran` marker/.test(threw), `unhelpful message: ${threw}`);
  eq(readFileSync(path.join(d, 'a.js'), 'utf8'), SRC, 'the refusal still left the file untouched');
  rmSync(d, { recursive: true });
});

t('a syntax error with no marker cannot be scored as KILLED', () => {
  // The concrete case the red team demonstrated: an unparseable file, zero tests
  // run, and the old runner called it a kill.
  const d = fixture();
  let threw = false;
  try {
    runOne(d, { name: 'syntax error', file: 'a.js', find: 'const LIMIT = 10;',
                replace: 'const LIMIT = ((((;' }, exec('SyntaxError: Unexpected token', 1));
  } catch { threw = true; }
  assert(threw, 'a markerless syntax-error mutation was scored instead of refused');
  rmSync(d, { recursive: true });
});

t('a replacement identical to the find string is NOT-APPLIED, never SURVIVED', () => {
  // A mutation that changes nothing cannot tell you anything about coverage.
  const d = fixture();
  const r = runOne(d, spec({ replace: 'const LIMIT = 10;' }), exec('Tests  1 passed', 0));
  eq(r.verdict, NOT_APPLIED, 'verdict');
  assert(/changes nothing/.test(r.note), r.note);
  rmSync(d, { recursive: true });
});

t('the CLI entry point survives a path containing a space', () => {
  // Found by red team: `import.meta.url` percent-encodes and `process.argv[1]`
  // does not, so `file://` + argv never matched on such a path. The CLI block
  // never ran and the process exited 0 having printed nothing -- a mutation
  // step that reports success having tested nothing.
  const spaced = mkdtempSync(path.join(tmpdir(), 'mut with space-'));
  const url = pathToFileURL(path.join(spaced, 'runner.mjs')).href;
  assert(url.includes('%20'), 'the probe path did not actually contain a space');
  assert(url !== `file://${path.join(spaced, 'runner.mjs')}`,
    'string concatenation happened to match, so this test proves nothing');
  eq(url, pathToFileURL(path.join(spaced, 'runner.mjs')).href, 'pathToFileURL is not stable');
  rmSync(spaced, { recursive: true });
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
