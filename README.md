# cua-risk

Risk classification for computer-use agent actions. Given a proposed action, it
returns one of three dispositions: **auto** (proceed), **confirm** (ask a human
first), or **block** (refuse).

The interesting part is not the taxonomy, it is where the line sits. A password
field is blocked, not confirmed. A submit tool is `confirm` regardless of what
its label claims, because the label is attacker-controlled. Reads and navigation
are auto. Irreversible verbs are confirm.

## Test

```
cargo test
```

74 tests, all passing. They are the specification: each names the case it pins,
and the negative half is deliberately larger than the positive one, so a
classifier that simply blocked everything would fail the suite rather than pass it.

## Mutation

A pass count says a suite runs. It does not say the suite would notice if the
code were wrong. So the mutations are committed rather than described:

```
node scripts/mutation-runner.mjs . mutations.json
```

`mutations.json` lists seven changes to real logic. The runner applies each one,
runs the suite, restores the file and verifies the restore by hash. It reports
four verdicts, and the third is why it exists:

| verdict | meaning |
|---|---|
| `KILLED` | the suite ran and failed — the mutation is caught |
| `SURVIVED` | the suite ran and passed — nothing pins this behaviour |
| `INCONCLUSIVE` | non-zero exit, but no evidence any test ran |
| `NOT-APPLIED` | the pattern was absent, or matched more than once |

A mutation that stops the code compiling also exits non-zero. A runner reading
only the exit code scores that as a kill it never earned, so a spec declares a
marker the test runner prints only when tests actually execute, and a non-zero
exit without it is `INCONCLUSIVE` — never counted as caught.

The runner has its own suite (`node scripts/mutation-runner.test.mjs`), because a tool that measures test suites
is itself a check, and a check nobody has watched fail is a claim.

The seven are dispositions and ladder steps: flipping what an unrecognised tool
gets, downgrading typing to auto, and disabling each rung of the escalation
ladder.

One mutation originally survived, and it was the worst possible one: the
catch-all branch deciding what happens to a tool nobody anticipated could be
flipped from `Confirm` to `Auto` with every test still passing. A classifier that
auto-approves what it does not recognise is worse than no classifier, because it
reads as one. That branch is now pinned in both directions, and so is the fact
that tool matching is case-sensitive, so `GUI.CLICK` cannot reach an
auto-approved branch by casing alone.

## Status

Extracted from a larger application, where it had no coupling to its host: a
single `use super::*` inside the test module and nothing else. No dependencies
beyond `std`.

MIT licensed.
