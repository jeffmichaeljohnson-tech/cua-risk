# Security Policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository —
**Security → Advisories → Report a vulnerability**, or go straight to
[`../../security/advisories/new`](../../security/advisories/new). That channel is
private between you and the maintainer, and it is the only one that stays private.

**Please do not open a public issue for a suspected vulnerability.** If private
reporting is not available to you, open an issue saying only that you have a
security report and asking for a private channel. No details in the issue.

This project is maintained by one person, not a team with an on-call rotation. A
realistic expectation: acknowledgement within a week, an assessment within two.
If a report is valid, the fix and the advisory are published together, and you
are credited unless you ask not to be.

There is no bounty. Saying so plainly is more useful than leaving you to guess.

## Supported versions

The default branch is the only supported version. This project has not cut a
release series, so there is nothing to backport to.

## Threat model — read this before deciding whether you have a finding

This crate **classifies an action; it does not enforce anything.** It takes a
description of what an agent is about to do and returns a tier: `Auto`,
`Confirm`, or `Blocked`. Nothing here intercepts a syscall, sandboxes a process,
or prevents an action. A caller that receives `Blocked` and proceeds anyway has
not defeated this crate — it never had a say. **The enforcement boundary belongs
to the caller, and this crate is one input to it, not a substitute for a
sandbox.**

With that boundary stated, the failures that matter here are all in one
direction.

**In scope — a permissive misclassification.** Anything that makes the crate
return a *lower* tier than the action deserves is the vulnerability this code
exists to prevent. Concretely:

- A label crafted so it reads as one thing to a human and matches as another —
  or matches nothing. Unicode confusables, invisible characters, fullwidth and
  Mathematical Alphanumeric forms, mixed-script text. A real one has already
  happened here: a fullwidth one-time-code label bypassed a hard block, not
  merely an escalation, and it failed permissively and silently.
- An element role or tool name that routes an action around a rule it should
  have met — including an unrecognised value falling through to a permissive
  default rather than a restrictive one.
- A cross-application or cross-origin action that keeps the tier it would have
  had within one application.
- Anything that makes a credential, payment, two-factor or privilege-elevation
  target read as ordinary.

**Out of scope.**

- **An over-restrictive verdict is not a vulnerability.** If the crate returns
  `Confirm` for something you consider routine, that is a tuning question. Open
  a normal issue; it is still worth reporting, just not privately.
- **The marker tables are non-exhaustive by design and this is documented.** A
  new application or label that is not yet recognised is a gap to fill, not a
  bypass — unless the *mechanism* by which it is missed is general.
- Resource exhaustion from a pathologically large label.
- The behaviour of whatever produced the `ActionContext`. This crate trusts its
  input struct; if an attacker controls that directly, they control the answer,
  and the boundary you need is upstream of here.

**Standing properties, so you can tell a defect from a design choice.** The
crate has no dependencies beyond `std`, declares `#![forbid(unsafe_code)]`,
performs no I/O, opens no network connection, reads no environment variable, and
never logs. Any observed behaviour to the contrary is a finding on its own.
