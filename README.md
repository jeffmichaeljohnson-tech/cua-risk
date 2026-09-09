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

94 tests, all passing. They are the specification: each names the case it pins.

The property that matters is that neither degenerate classifier can pass. Both
were measured rather than asserted -- by replacing every entry point with a
constant and running the suite:

| classifier | result |
|---|---|
| block everything | **53 of 94 fail** |
| approve everything | **69 of 94 fail** |

So the suite constrains the answer from both sides. An earlier version of this
paragraph claimed the negative half was deliberately larger than the positive
one; that was never measured and it is not true.

## Mutation

A pass count says a suite runs. It does not say the suite would notice if the
code were wrong. So the mutations are committed rather than described:

```
node scripts/mutation-runner.mjs . mutations.json
```

`mutations.json` lists sixteen changes to real logic. The runner applies each one,
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

They are dispositions, ladder steps and label handling: flipping what an
unrecognised tool gets, downgrading typing to auto, disabling each rung of the
escalation ladder, and removing the label fold described below.

One mutation originally survived, and it was the worst possible one: the
catch-all branch deciding what happens to a tool nobody anticipated could be
flipped from `Confirm` to `Auto` with every test still passing. A classifier that
auto-approves what it does not recognise is worse than no classifier, because it
reads as one. That branch is now pinned in both directions, and so is the fact
that tool matching is case-sensitive, so `GUI.CLICK` cannot reach an
auto-approved branch by casing alone.

## Labels are not ASCII

A label reaches this code from the DOM on the web, and from whatever string an
application publishes through the accessibility API on the desktop. Both are
attacker-controlled where it counts, and every marker table here is ASCII.

Measured before it was fixed: `browser_click` on a control labelled `Send`
returned `Confirm`, and the same click on `Sеnd` -- with U+0435 CYRILLIC SMALL
LETTER IE, which renders identically -- returned `Auto`. Worse, `browser_type`
into a field labelled with fullwidth `ＯＴＰ code` returned `Auto` where the ASCII
spelling is a hard `Blocked`. Because every label rule only ever ESCALATES, a
missed match fails in the permissive direction and nothing reports it.

`fold_label` now folds three mechanical classes toward ASCII -- fullwidth forms,
the Cyrillic and Greek letters that render as Latin ones, and non-ASCII spaces
and dashes -- and deletes zero-width and bidi format characters outright, since
they render as nothing and would otherwise break a keyword invisibly.

**It is not a UTS #39 confusable skeleton and it is not complete.** No fold is.
The design therefore never rests on it: `browser_submit` confirms whatever its
label says, an unrecognised tool defaults to `Confirm`, and the fold only adds
escalations on top. Both properties are pinned by tests that use a homoglyph the
fold does not carry. The residual exposure is worth naming rather than hiding: a
generic `browser_click` or `browser_type` has no tool-name signal, so for those
the label is the only evidence there is.

## Status

Extracted from a larger application, where it had no coupling to its host: a
single `use super::*` inside the test module and nothing else. No dependencies
beyond `std`.

MIT licensed.
