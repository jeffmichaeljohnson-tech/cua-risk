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

115 tests, all passing. They are the specification: each names the case it pins.

The property that matters is that neither degenerate classifier can pass. Both
were measured rather than asserted -- by replacing every entry point with a
constant and running the suite:

| classifier | result |
|---|---|
| block everything | **60 of 115 fail** |
| approve everything | **76 of 115 fail** |

So the suite constrains the answer from both sides. An earlier version of this
paragraph claimed the negative half was deliberately larger than the positive
one; that was never measured and it is not true.

## Mutation

A pass count says a suite runs. It does not say the suite would notice if the
code were wrong. So the mutations are committed rather than described:

```
node scripts/mutation-runner.mjs . mutations.json
```

`mutations.json` lists twenty-five changes to real logic. The runner applies each one,
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

Measured before any of it was fixed: `browser_click` on a control labelled `Send`
returned `Confirm`, and the same click on `Sеnd` — with U+0435 CYRILLIC SMALL
LETTER IE, which renders identically — returned `Auto`. `browser_type` into a
field labelled with fullwidth `ＯＴＰ code` returned `Auto` where the ASCII
spelling is a hard `Blocked`. Because every label rule only ever ESCALATES, a
missed match fails in the permissive direction and nothing reports it.

There are two mechanisms, and the second exists because the first can never be
finished.

### 1. The fold, which has one rule

> A character is folded when it is **invisible**, or when it renders as an ASCII
> character in a different typeface. A character that renders as something
> visibly different is left alone.

So `Ｓｅｎｄ`, `𝐒𝐞𝐧𝐝`, `Ѕепd` and `Se<ZWSP>nd` all fold to `send`, while `Sénd`
does not — an accented vowel is a glyph a reader can see, and folding it would
silently rewrite non-English labels.

Two consequences of stating the rule that way rather than accumulating cases:

- **The invisible set is a Unicode property, not a list.** It is
  `Default_Ignorable_Code_Point` — the definition of "a character a conforming
  renderer draws nothing for". The previous hand-picked list covered zero-width
  spaces and bidi controls and missed `U+034F COMBINING GRAPHEME JOINER`, so
  `Se<CGJ>nd` reached `Auto`. Asking Unicode what counts as invisible has an
  authoritative answer; asking which invisible characters I happened to think of
  does not.
- **Combining marks are deliberately NOT stripped.** Stripping them would fold
  the decomposed spelling of `Sénd` and leave the precomposed one, so the same
  label would classify two ways depending on which normalisation form it arrived
  in. A test pins that both reach the same tier.

Mathematical Alphanumeric Symbols fold too (`𝐒𝐞𝐧𝐝`, `𝕊𝕖𝕟𝕕`, `𝚂𝚎𝚗𝚍`) — the most
casually available spoof there is, since social platforms hand them out as a
styling affordance. The block is thirteen 26-letter runs per case, so the mapping
is arithmetic; the explicit arm beside it is the holes, glyphs Unicode had
already assigned in Letterlike Symbols. Without those, `ℛ` fails to fold while
its neighbours in the same word succeed, which is worse than not folding at all.

### 2. The shape detector, which is what makes the fold's completeness stop mattering

No fold is ever complete, and a security control resting on one is resting on an
enumeration. So `label_is_suspicious` reads the **raw** label — before folding,
because folding is what erases the evidence — and asks a question that needs no
table: *does an ASCII letter sit directly against a Cyrillic or Greek letter, or
against an invisible character?*

It reads the element's ROLE the same way. On the web that is the DOM's `role`
attribute, as page-authored as the label, and it gates a hard `Blocked` rather
than an escalation. Leaving it out was a real gap and a mutation is what surfaced
it: `is_credential_target` folds the role before matching `securetextfield`, but
no test pinned that fold, so the mutation removing it SURVIVED. A legitimate role
is always plain ASCII, so reading it costs nothing.

That is the shape of every mixed-script spoof, whether or not the fold knows the
particular codepoint. The two mechanisms are complementary by construction:

| spoof | example | caught by |
|---|---|---|
| whole-script | `Ѕепԁ` — every letter swapped, no ASCII left | the fold |
| mixed-script | `Sеnd` — one letter swapped | the detector |
| invisible | `Se<CGJ>nd` | both |
| typeface | `𝐒𝐞𝐧𝐝` | the fold |

A suspicious label never lowers a tier. It raises `Auto` to `Confirm`, which
costs one human glance at a label the classifier is telling you it could not read
with confidence.

**The must-not-fire half is the larger one, and it is a fairness constraint as
much as a usability one.** Only Cyrillic and Greek are treated as confusable,
because they are the scripts that share letterforms with Latin. A label mixing
ASCII with CJK, Arabic or Hebrew is an ordinary bilingual label, and flagging it
would penalise every non-English interface for no security gain. Adjacency rather
than same-word co-occurrence is what keeps `α-version` and `Ω Reset` quiet: a
real label puts the Greek letter beside punctuation or a space, a spoof puts it
inside the word. `Отправить`, `送信`, `Wi-Fi設定`, `café` and its decomposed
spelling all classify exactly as they would in English.

### What is still not covered, stated plainly

This is **not** a UTS #39 confusable skeleton; the full table is larger than a
zero-dependency crate should carry. Precomposed accented Latin is not folded, by
the rule above. And nothing here rests on either mechanism in any case: the tool
name decides first wherever a tool name carries the meaning (`browser_submit`
confirms whatever its label says), and an unrecognised tool defaults to
`Confirm`. Tests pin both of those using a homoglyph the fold does not carry.

### One test worth reading

`every_letter_a_marker_depends_on_is_accounted_for` derives its alphabet from the
marker tables themselves, then requires every letter to have either a folded
look-alike fixture or an explicit declaration that Cyrillic and Greek offer none.
Remove a fixture and it fails naming the letter and what to do about it. A
companion test keeps the exemption list honest, so it cannot become a place to
hide letters.

It carries a control, and the control is not decoration: a derivation that read
nothing — a renamed const, a filter that excludes everything — would iterate an
empty set and pass, which is the exact shape of a sweep that scanned zero files
and reported no findings. The test asserts the alphabet actually came back before
trusting anything it says, and that assertion was driven red by breaking the
derivation on purpose.

Getting the hard-block markers under that check is why `password`, `cvv`, `sudo`,
`filevault` and the rest were lifted out of the function bodies into consts. Five
marker tables were already consts and these were inline literals, so the tables
behind the most consequential answer this crate gives — a BLOCK, not an
escalation — were the only ones the check could not see.

## Status

Extracted from a larger application, where it had no coupling to its host: a
single `use super::*` inside the test module and nothing else. No dependencies
beyond `std`.

MIT licensed.
