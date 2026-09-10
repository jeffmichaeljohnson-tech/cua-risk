#!/usr/bin/env node
// Tests for mutation-runner. The tool measures other suites, so its own
// failure modes are the point: a false CAUGHT inflates a score, and a failed
// restore corrupts the tree it was measuring.

import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { runOne, runAll, report, checkBaseline, CAUGHT, SURVIVED, INCONCLUSIVE, NOT_APPLIED }
  from './mutation-runner.mjs';
// Namespace import as well, so `inFlight` is read through a LIVE binding. Naming
// it in the destructured import above would capture it once and always read the
// initial null, which would make the layer-2 tests below pass against the very
// defect they exist to catch.
import * as runner from './mutation-runner.mjs';

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

t('a suite that ran and failed is CAUGHT', () => {
  const d = fixture();
  eq(runOne(d, spec(), exec('Tests  9 passed | 1 failed', 1)).verdict, CAUGHT, 'verdict');
  rmSync(d, { recursive: true });
});

t('a suite that ran and passed is SURVIVED', () => {
  const d = fixture();
  eq(runOne(d, spec(), exec('Tests  10 passed', 0)).verdict, SURVIVED, 'verdict');
  rmSync(d, { recursive: true });
});

t('a BUILD ERROR is INCONCLUSIVE, never CAUGHT — the defect this tool exists for', () => {
  const d = fixture();
  // Non-zero exit, but the runner never printed evidence that tests executed.
  // A runner reading only the exit code scores this as a catch it never earned.
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
  // The incident this encodes: a run was stopped mid-mutation, the restore never
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
  assert(/2 caught, 0 survived, 0 inconclusive, 1 not applied \(of 3\)/.test(out), out);
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
  // exit back into CAUGHT, including a syntax error under which no test ran.
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

t('a syntax error with no marker cannot be scored as CAUGHT', () => {
  // The concrete case the red team demonstrated: an unparseable file, zero tests
  // run, and the old runner called it a catch.
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

// --- layer 2 of the restoration, which was dead ---------------------------
//
// `inFlight` is declared, reset to null in the `finally`, and read by the SIGINT
// handler -- but nothing ever assigned it, so `if (inFlight)` tested a value that
// was always null and the handler could not fire. Two layers wearing the comment
// of three. It survived because nothing exercised it: the signal path is awkward
// to test, so it went untested, so the dead code read as a guarantee.
//
// These do not send a signal. They assert the STATE the handler depends on,
// which is the part that was missing and is cheap to check.
t('layer 2 records the in-flight mutation while the suite runs', () => {
  const dir = fixture();
  let seen = 'never-ran';
  runOne(dir, spec(), () => {
    seen = runner.inFlight;
    return { out: 'Tests 1 passed', code: 1 };
  });
  assert(seen !== 'never-ran', 'the exec callback never ran, so this proves nothing');
  assert(seen !== null, 'inFlight was null while a mutation was on disk — layer 2 is dead');
  eq(seen.rel, 'a.js', 'inFlight.rel');
  rmSync(dir, { recursive: true, force: true });
});

t('...and it holds the ORIGINAL bytes, not the mutated ones', () => {
  const dir = fixture();
  let seen = null;
  runOne(dir, spec(), () => {
    seen = runner.inFlight;
    return { out: 'Tests 1 passed', code: 1 };
  });
  // Restoring from the mutated bytes would "restore" the mutation, which is
  // the one thing layer 2 must never do.
  eq(seen.before, SRC, 'inFlight.before must be the pre-mutation source');
  rmSync(dir, { recursive: true, force: true });
});

t('...and it is cleared once the mutation is restored', () => {
  const dir = fixture();
  runOne(dir, spec(), () => ({ out: 'Tests 1 passed', code: 1 }));
  eq(runner.inFlight, null, 'inFlight must be null after a completed run');
  rmSync(dir, { recursive: true, force: true });
});

t('...and it is cleared even when the suite throws', () => {
  const dir = fixture();
  try {
    runOne(dir, spec(), () => { throw new Error('suite exploded'); });
  } catch { /* the throw is the point */ }
  eq(runner.inFlight, null, 'a throwing suite must not leave inFlight set');
  rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// ANSI decoration must not decide a verdict
//
// Found by running CI on Linux: vitest 5 emits colour to a pipe where vitest 2
// did not, so `Tests  817 passed` arrives with escape codes between the word and
// the count and a plain-text marker misses it. Every mutant then scored
// INCONCLUSIVE -- correctly, since the runner could not prove tests had run, but
// for a reason that has nothing to do with the code under test.
//
// The sharp edge is that the SAME versions matched on macOS and missed on Linux,
// so a local run reported a clean 33-caught while CI would have reported nothing
// caught at all.
// ---------------------------------------------------------------------------
{
  const ESC = String.fromCharCode(27);
  const coloured = '      Tests ' + ESC + '[22m ' + ESC + '[1m' + ESC + '[32m817 passed' + ESC + '[39m (817)';
  const marker = 'Tests\\s+\\d+ (passed|failed)';

  t('a coloured summary line still counts as evidence that tests ran', () => {
    assert(!new RegExp(marker).test(coloured), 'fixture is wrong: the raw line must NOT match, or this test proves nothing');
    assert(new RegExp(marker).test(runner.stripAnsi(coloured)), 'the marker must match once decoration is stripped');
  });

  t('stripAnsi leaves undecorated output byte-identical', () => {
    const plain = '      Tests  817 passed (817)';
    assert(runner.stripAnsi(plain) === plain, 'plain text must pass through unchanged');
  });

  t('a coloured run that FAILED is still CAUGHT, not INCONCLUSIVE', () => {
    // The direction that matters. Before the fix, a caught mutation whose output
    // happened to be coloured was scored INCONCLUSIVE -- a real catch discarded.
    const spec = { name: 'x', file: 'f', find: 'a', replace: 'b', ran: marker };
    const out = coloured.replace('817 passed', '816 passed | 1 failed');
    assert(new RegExp(spec.ran).test(runner.stripAnsi(out)), 'a coloured failure line must read as tests-ran');
  });
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
