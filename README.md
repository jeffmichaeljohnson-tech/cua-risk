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

The suite is **mutation-tested**. Flipping a disposition, disabling the
escalation ladder, or downgrading a credential field to a mere confirmation are
all caught.

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
