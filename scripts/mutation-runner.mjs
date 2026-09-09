#!/usr/bin/env node
// mutation-runner — apply a mutation, run the suite, restore, and say honestly
// what happened.
//
// The distinction this exists for: a mutation that makes the code STOP
// COMPILING also exits non-zero. A runner that only reads the exit code calls
// that "killed" and inflates its own score with mutations the tests never saw.
// So a spec declares a `ran` marker — a pattern the test runner prints only when
// it actually executed tests — and a non-zero exit WITHOUT that marker is
// reported INCONCLUSIVE, never KILLED.
//
// Verdicts:
//   KILLED       the suite ran and failed        -> the mutation is caught
//   SURVIVED     the suite ran and passed        -> nothing pins this behaviour
//   INCONCLUSIVE non-zero, but no tests ran      -> proves nothing either way
//   NOT-APPLIED  the pattern was absent or ambiguous
//
// Exit 0 only when every mutation is KILLED. SURVIVED, INCONCLUSIVE and
// NOT-APPLIED are all non-zero: a mutation that could not be applied is not a
// mutation that passed.

import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import path from 'node:path';

// The mutation currently written to disk, so a caught signal can undo it.
export let inFlight = null;

export const KILLED = 'KILLED', SURVIVED = 'SURVIVED',
             INCONCLUSIVE = 'INCONCLUSIVE', NOT_APPLIED = 'NOT-APPLIED';

const sha = (s) => createHash('sha256').update(s).digest('hex');

export function runOne(root, spec, exec) {
  const file = path.join(root, spec.file);
  const before = readFileSync(file, 'utf8');
  const occurrences = before.split(spec.find).length - 1;
  if (occurrences !== 1) {
    return { ...spec, verdict: NOT_APPLIED,
      note: `pattern occurs ${occurrences}x, expected exactly 1` };
  }
  let out = '', code = 0;
  try {
    // A FUNCTION as the replacement, deliberately. Passing a string lets JS
    // interpret $&, $`, $', $$ and $1..$9 inside it as substitution patterns,
    // which silently corrupts any mutation whose replacement contains a dollar
    // sign -- and a mangled mutation yields a verdict about code nobody wrote.
    writeFileSync(file, before.replace(spec.find, () => spec.replace));
    const r = exec();
    out = r.out; code = r.code;
  } finally {
    // Restoration is in `finally` and then VERIFIED. A runner that corrupts the
    // tree it is measuring is worse than no runner.
    writeFileSync(file, before);
    inFlight = null;
    const after = readFileSync(file, 'utf8');
    if (sha(after) !== sha(before)) {
      throw new Error(`FAILED TO RESTORE ${spec.file} — tree is dirty, stop and fix by hand`);
    }
  }
  const ran = new RegExp(spec.ran ?? '.').test(out);
  if (code === 0) return { ...spec, verdict: ran ? SURVIVED : INCONCLUSIVE,
    note: ran ? 'suite passed with the mutation in place' : 'exit 0 but no evidence tests ran' };
  return { ...spec, verdict: ran ? KILLED : INCONCLUSIVE,
    note: ran ? 'suite ran and failed' : `exit ${code} with no evidence tests ran — likely a build error` };
}

/**
 * The suite must be green BEFORE any mutation is applied.
 *
 * Without this every verdict is measured against an unknown baseline. The case
 * that motivated it: a run was killed mid-mutation, the `finally` never ran, and
 * the mutated file became the starting point for the next run — where two
 * mutations then reported NOT-APPLIED because the text they searched for had
 * already been replaced. A leftover mutation must be loud, not inherited.
 */
export function checkBaseline(exec, ran) {
  const { out, code } = exec();
  if (code !== 0) {
    return { ok: false, why: 'the suite does not pass before any mutation is applied — '
      + 'the tree may carry a leftover mutation from an interrupted run (check `git status`)' };
  }
  if (!new RegExp(ran ?? '.').test(out)) {
    return { ok: false, why: 'the baseline exited 0 but printed no evidence any test ran — '
      + 'the `ran` marker does not match this runner\'s output' };
  }
  return { ok: true };
}

export function runAll(root, specs, exec) {
  return specs.map((s) => runOne(root, s, exec));
}

export function report(results) {
  const by = (v) => results.filter((r) => r.verdict === v);
  const lines = [];
  for (const r of results) lines.push(`  ${r.verdict.padEnd(12)} ${r.name}`);
  lines.push('');
  lines.push(`  ${by(KILLED).length} killed, ${by(SURVIVED).length} survived, `
    + `${by(INCONCLUSIVE).length} inconclusive, ${by(NOT_APPLIED).length} not applied`
    + ` (of ${results.length})`);
  if (by(INCONCLUSIVE).length)
    lines.push('  INCONCLUSIVE is not a pass: those mutations were never seen by a test.');
  return lines.join('\n');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const root = process.argv[2] ?? '.';
  const specPath = process.argv[3] ?? path.join(root, 'mutations.json');
  const { command, ran, mutations } = JSON.parse(readFileSync(specPath, 'utf8'));
  const exec = () => {
    try {
      return { out: execSync(command, { cwd: root, encoding: 'utf8', stdio: 'pipe' }), code: 0 };
    } catch (e) {
      return { out: `${e.stdout ?? ''}${e.stderr ?? ''}`, code: e.status ?? 1 };
    }
  };
  const base = checkBaseline(exec, ran);
  if (!base.ok) {
    console.error(`baseline: ${base.why}`);
    process.exit(2);
  }

  // Restoration has three layers, because each one has a hole the next covers.
  //
  //   1. `finally` in runOne. Does the real work, including when the suite
  //      throws or the child is interrupted -- measured: a SIGINT delivered
  //      mid-run leaves the file byte-identical.
  //   2. These handlers. Best-effort only: `execSync` blocks the event loop, so
  //      a JS handler cannot fire while a suite is actually running. They cover
  //      a signal that lands between mutations.
  //   3. The baseline check above. The one that matters, because SIGKILL cannot
  //      be caught by anything: it turns the aftermath of an uncatchable kill
  //      into a loud abort on the next run rather than a silent wrong answer.
  //
  // Layer 3 exists because layers 1 and 2 were both defeated in practice: a run
  // was killed mid-mutation and the leftover silently became the next baseline.
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(sig, () => {
      if (inFlight) {
        try { writeFileSync(inFlight.file, inFlight.before); } catch { /* best effort */ }
        console.error(`\n${sig}: restored ${inFlight.rel} before exiting`);
      }
      process.exit(130);
    });
  }

  const results = runAll(root, mutations.map((m) => ({ ...m, ran: m.ran ?? ran })), exec);
  console.log(report(results));
  process.exit(results.every((r) => r.verdict === KILLED) ? 0 : 1);
}
