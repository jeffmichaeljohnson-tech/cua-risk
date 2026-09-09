//! Tier 0/1/2 risk classifier for gui.* actions.
//!
//! Called BEFORE every gui.* dispatch to determine whether the action
//! can proceed automatically, requires confirmation, or is blocked.
//!
//! Classification rules from PRD-COMPUTER-USE.md S3.1.

/// Risk tier for a gui.* action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Read-only or non-destructive. Proceeds without confirmation.
    Auto,
    /// Show intent and require approval before dispatch.
    Confirm,
    /// Never autonomous. Agent must hand control to the human.
    Blocked,
}

/// The KIND of outward write a `browser_*` action is about to perform.
///
/// The tier answers "does this need the human's confirmation?"; it does NOT say
/// *what sort of thing* is about to happen. Before this existed, every
/// non-credential outward act — submitting a form, publishing a post, sending an
/// email — collapsed into one undifferentiated `Confirm`, so the confirm card
/// could only say "approve this action" with no way to tell the operator whether
/// they were about to email a stranger or save a draft. The class is the missing
/// noun on the card.
///
/// This is ADVISORY: it never changes the tier, so a misread label still stops
/// for confirmation — it only changes the WORDS the card renders. New variants
/// must be justified by verbs that actually appear in the label tables below; a
/// class with no verb behind it would be a promise the classifier cannot keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteClass {
    /// Submitting/saving a form or document (submit, save, upload, apply, …).
    DocumentWrite,
    /// Publishing or broadcasting to a social surface (post, publish, follow,
    /// connect, invite, …) — content or a connection request that others see.
    SocialPost,
    /// Sending an email (the label names mail explicitly).
    EmailSend,
}

/// The full verdict for a `browser_*` action: the risk [`Tier`] plus, when the
/// action is an irreversible outward write, the [`WriteClass`] naming what kind.
///
/// Returned as one value (rather than two positional returns) so a caller cannot
/// accidentally pair the tier of one action with the class of another, and so
/// the JSON the confirm card reads carries both from a single source.
///
/// `class` is `Some` ONLY when `tier == Confirm` and the trusted label names a
/// recognizable kind. It is deliberately `None` for:
/// - `Auto` actions — nothing outward is happening, so there is nothing to name;
/// - `Blocked` credential/2FA/payment hard-blocks — a takeover is NOT a "write"
///   and must never be dressed up as one (see the credential test);
/// - an irreversible act whose label names no known kind — still `Confirm`, but
///   the card falls back to a generic phrasing rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebVerdict {
    pub tier: Tier,
    pub class: Option<WriteClass>,
}

/// Context assembled from the gui.* call arguments and session state,
/// passed to [`classify`] before every dispatch.
pub struct ActionContext<'a> {
    pub tool: &'a str,
    pub element_label: Option<&'a str>,
    pub element_role: Option<&'a str>,
    pub app_bundle_id: Option<&'a str>,
    pub allowed_apps: &'a [String],
}

/// Classify a voice-dictation insert's risk tier.
///
/// Dictation types the user's spoken words into whatever macOS field is
/// focused. It is low-friction by design (Auto for normal fields) but
/// preserves hard safety blocks for sensitive apps and credential fields.
///
/// Unlike [`classify`], dictation does NOT apply cross-app escalation
/// (the user explicitly invoked dictation at the focused field) and does
/// NOT escalate for messaging apps (dictating into a compose field is
/// the core allowed use case).
pub fn classify_dictation(ctx: &ActionContext<'_>) -> Tier {
    // Hard-block: sensitive app (1Password, Keychain, banking/crypto).
    if is_sensitive_target(ctx.app_bundle_id, None) {
        return Tier::Blocked;
    }

    // Hard-block: credential / secure input field.
    if is_credential_target(ctx) {
        return Tier::Blocked;
    }

    Tier::Auto
}

/// Classify an action's risk tier.
///
/// The classifier runs BEFORE any cua-driver call. There is no code
/// path that bypasses this gate.
pub fn classify(ctx: &ActionContext<'_>) -> Tier {
    // Hard-block: sensitive app, regardless of tool or label.
    if let Some(bid) = ctx.app_bundle_id {
        if is_sensitive_app(bid) {
            return Tier::Blocked;
        }
    }

    let base = base_tier(ctx);

    // Tier 2 category check (password fields, payment, messaging apps, etc.)
    if is_tier2_context(ctx) {
        return apply_cross_app_escalation(Tier::Blocked, ctx);
    }

    // Dynamic escalation for gui.click based on element label.
    let label_tier = if ctx.tool == "gui.click" {
        label_tier(ctx.element_label)
    } else {
        base
    };

    let effective = max_tier(base, label_tier);

    // Same rule as the web path, for the same reason: an accessibility label is
    // whatever string the frontmost application chose to publish. A label with
    // the shape of a spoof is raised to at least Confirm -- never lowered.
    let effective = if action_is_spoof_shaped(ctx.element_label, ctx.element_role) {
        max_tier(effective, Tier::Confirm)
    } else {
        effective
    };

    apply_cross_app_escalation(effective, ctx)
}

// ---------------------------------------------------------------------------
// Web (browser_*) irreversibility tier map
// ---------------------------------------------------------------------------

/// Context for classifying a Hermes `browser_*` action. As with [`classify`],
/// tier decisions key ONLY on trusted metadata (the element role/label the
/// sidecar resolved from the page snapshot) — never on agent-supplied claims,
/// so a lying agent cannot omit a field's secure role to downgrade a hard block.
pub struct WebActionContext<'a> {
    /// The browser tool name (`browser_navigate`, `browser_click`,
    /// `browser_type`, `browser_press`, `browser_snapshot`, `browser_scroll`, …).
    pub tool: &'a str,
    pub element_role: Option<&'a str>,
    pub element_label: Option<&'a str>,
}

/// Irreversible action verbs on the web: a control whose label matches escalates
/// a browser action to [`Tier::Confirm`] (secondary confirmation).
const WEB_IRREVERSIBLE_VERBS: &[&str] = &[
    "submit",
    "send",
    "post",
    "apply",
    "purchase",
    "buy",
    "order",
    "checkout",
    "place order",
    "pay",
    "delete",
    "remove",
    "publish",
    "confirm",
    // connection-request shapes
    "connect",
    "add friend",
    "follow",
    "send request",
    "connection request",
    "invite",
];

/// Label markers that name an EMAIL send. Kept narrow on purpose: an email
/// compose button often just says "Send", which is indistinguishable from a chat
/// or a form submit by label alone, so we only claim `EmailSend` when the label
/// itself says "email". Claiming it on a bare "Send" would put a confident, wrong
/// noun on the card — worse than saying nothing.
const WEB_EMAIL_MARKERS: &[&str] = &["email", "e-mail"];

/// Label markers that name a SOCIAL post or connection request. Covers both
/// publishing content (post, publish, tweet, share) and the connection-request
/// shapes already in [`WEB_IRREVERSIBLE_VERBS`] (follow, connect, add friend,
/// invite) — from the operator's seat those are the same kind of act: something
/// other people will see happen under his name.
const WEB_SOCIAL_MARKERS: &[&str] = &[
    "post",
    "publish",
    "tweet",
    "retweet",
    "share",
    "follow",
    "add friend",
    "connect",
    "send request",
    "connection request",
    "invite",
];

/// Label markers that name a DOCUMENT/form write. The broadest bucket, so it is
/// checked LAST — a label that also matched email or social should read as those
/// first (e.g. "Email this post" is an email, not a document).
const WEB_DOCUMENT_MARKERS: &[&str] = &["submit", "save", "upload", "create", "update", "apply"];

/// Name the KIND of write a label describes, or `None` when it names none.
///
/// Single source of truth for the class, shared by the advisory [`classify_web`]
/// and the managed-browser verdict (which re-derives it from the SERVER-read
/// label, never the agent's claim). Keeping it in one function is what keeps the
/// two paths from drifting: if the card ever named an act differently depending
/// on which browser engine was live, the operator's trust in the noun would be
/// worth nothing.
///
/// Checked most-specific first (email → social → document) so an overlapping
/// label resolves to its more telling kind rather than the generic document
/// bucket. Case-insensitive and substring-based, matching how the tier itself
/// reads labels.
/// The write class for an act, label AND tool considered — the one rule.
///
/// [`web_write_class`] reads the label alone. This adds the floor that a bare
/// `browser_submit` is a document write even when its label names nothing: the
/// tool itself is the evidence, because submitting a form commits something.
///
/// **It exists because that floor was written three times and had already
/// drifted.** The managed verdict applied it; the confirm CARD did not, so a
/// bare submit produced a verdict saying `document_write` beside a card that
/// named no kind at all — the two disagreeing about the same act, which is
/// exactly what deriving it from one helper was supposed to prevent. A test
/// carried a fourth copy and therefore could not catch the drift: it asserted
/// its own re-implementation rather than the code that ships.
///
/// Every path that needs a class calls THIS. If a new tool earns a floor, it
/// earns it here, once.
pub fn write_class_for(tool: &str, label: Option<&str>) -> Option<WriteClass> {
    web_write_class(label)
        .or_else(|| (tool == "browser_submit").then_some(WriteClass::DocumentWrite))
}

pub fn web_write_class(label: Option<&str>) -> Option<WriteClass> {
    let l = match label {
        Some(l) if !l.trim().is_empty() => fold_label(l),
        _ => return None,
    };
    if WEB_EMAIL_MARKERS.iter().any(|m| l.contains(m)) {
        return Some(WriteClass::EmailSend);
    }
    if WEB_SOCIAL_MARKERS.iter().any(|m| l.contains(m)) {
        return Some(WriteClass::SocialPost);
    }
    if WEB_DOCUMENT_MARKERS.iter().any(|m| l.contains(m)) {
        return Some(WriteClass::DocumentWrite);
    }
    None
}

/// Two-factor / one-time-code field markers. Combined with credential and
/// payment detection, these are the hard-block (human-takeover) categories on
/// the web — never granted away.
const WEB_2FA_MARKERS: &[&str] = &[
    "2fa",
    "two-factor",
    "two factor",
    "2-step",
    "one-time",
    "one time code",
    "otp",
    "verification code",
    "authenticator",
    "security code",
];

fn is_web_2fa_target(ctx: &WebActionContext<'_>) -> bool {
    if let Some(label) = ctx.element_label {
        let l = fold_label(label);
        if WEB_2FA_MARKERS.iter().any(|m| l.contains(m)) {
            return true;
        }
    }
    false
}

fn web_label_is_irreversible(label: Option<&str>) -> bool {
    match label {
        Some(l) if !l.trim().is_empty() => {
            let l = fold_label(l);
            WEB_IRREVERSIBLE_VERBS.iter().any(|v| l.contains(v))
        }
        _ => false,
    }
}

/// Classify a `browser_*` action's risk tier AND its write class under the grant
/// plane.
///
/// - **Auto (reversible under grant):** navigate, read/snapshot, scroll, fill a
///   normal field, and a non-committal click. These proceed silently once a
///   standing grant covers the domain. Class is `None` — nothing outward.
/// - **Confirm (irreversible → secondary confirmation):** submit / send / post /
///   apply / purchase / delete / connection-request, detected by the trusted
///   element label. The [`WriteClass`] names the kind for the card; it stays
///   `None` when the label names no recognizable kind (still Confirm).
/// - **Blocked (hard block → human takeover):** typing into a credential,
///   payment, or 2FA field. Never autonomous, even under a grant. Class is
///   `None` — a takeover is not a write and must not be rendered as one.
pub fn classify_web(ctx: &WebActionContext<'_>) -> WebVerdict {
    // Build a shared ActionContext so the credential/payment field detector
    // (role- and label-based) is reused verbatim from the gui path.
    let cred_ctx = ActionContext {
        tool: ctx.tool,
        element_label: ctx.element_label,
        element_role: ctx.element_role,
        app_bundle_id: None,
        allowed_apps: &[],
    };

    // Hard block: credential / payment / 2FA field. These route to human
    // takeover and are never granted away. Return BEFORE deriving any class:
    // the class must never be computed for a hard-block, or a field labelled
    // "Submit password" would be dressed up as a DocumentWrite instead of the
    // takeover it is. This early return is what pins the credential test.
    if is_credential_target(&cred_ctx) || is_web_2fa_target(ctx) {
        return WebVerdict {
            tier: Tier::Blocked,
            class: None,
        };
    }

    // Irreversible when an actuating tool carries an irreversible verb, OR the
    // tool is browser_submit (a form submission is irreversible by construction
    // regardless of label). One predicate so the class is derived in exactly one
    // place below.
    let actuating = matches!(
        ctx.tool,
        "browser_click" | "browser_press" | "browser_type" | "browser_submit"
    );
    let irreversible =
        (actuating && web_label_is_irreversible(ctx.element_label)) || ctx.tool == "browser_submit";

    if irreversible {
        // Name the kind from the same trusted label the tier keyed on. A bare
        // browser_submit (no label, or a label that names no kind) is a
        // form/document write by construction, so it floors at DocumentWrite
        // rather than leaving the card with a nameless "confirm".
        let class = web_write_class(ctx.element_label)
            .or_else(|| (ctx.tool == "browser_submit").then_some(WriteClass::DocumentWrite));
        return WebVerdict {
            tier: Tier::Confirm,
            class,
        };
    }

    // An UNRECOGNISED tool falls to Confirm, never to Auto.
    //
    // This mirrors `base_tier`'s catch-all, and it was missing here. The web
    // path used to end in a bare `Auto`, so any tool not named above -- a new
    // `browser_evaluate`, a `browser_download`, a rename of `browser_submit` to
    // `browser_submitForm`, or the same name in different case -- was
    // auto-approved. The two entry points disagreed about the most consequential
    // decision either of them makes.
    //
    // The list is the one this function's own doc comment names as reversible.
    // Adding a tool is a deliberate act; forgetting to add one costs a
    // confirmation, not a silent action.
    let reversible = matches!(
        ctx.tool,
        "browser_navigate"
            | "browser_read"
            | "browser_snapshot"
            | "browser_scroll"
            | "browser_click"
            | "browser_press"
            | "browser_type"
    );

    // A label the classifier cannot claim to have READ does not get the
    // permissive answer. `reversible` above says the TOOL is reversible; it says
    // nothing about what the control does, and for a generic click or keystroke
    // the label is the only evidence there is. When that label has the shape of
    // a spoof, the honest verdict is one human glance, not silence.
    //
    // This is the arm that makes the fold's completeness stop being
    // load-bearing: a mixed-script label escalates here whether or not
    // `fold_label` happens to know the codepoint that was swapped in.
    let tier = if reversible && !action_is_spoof_shaped(ctx.element_label, ctx.element_role) {
        Tier::Auto
    } else {
        Tier::Confirm
    };

    WebVerdict { tier, class: None }
}

// ---------------------------------------------------------------------------
// Base tier by tool name
// ---------------------------------------------------------------------------

fn base_tier(ctx: &ActionContext<'_>) -> Tier {
    match ctx.tool {
        "gui.snapshot" | "gui.list_apps" | "gui.list_windows" | "gui.launch_app" | "gui.scroll"
        | "gui.screenshot" => Tier::Auto,
        "gui.click" => Tier::Auto, // escalated dynamically by label
        "gui.type" | "gui.key" => Tier::Confirm,
        _ => Tier::Confirm, // unknown tools default to confirm
    }
}

// ---------------------------------------------------------------------------
// Label folding
// ---------------------------------------------------------------------------

/// Does Unicode say a conforming renderer draws NOTHING for this character?
///
/// This is the `Default_Ignorable_Code_Point` property, transcribed. It is used
/// instead of a hand-picked list because a hand-picked list is what let
/// `U+034F COMBINING GRAPHEME JOINER` through: the enumerated set here covered
/// zero-width spaces and bidi controls, and CGJ is neither, yet it renders as
/// nothing just the same. Asking "what does Unicode call invisible" is a
/// question with an authoritative answer; asking "which invisible characters
/// did I think of" is not.
fn is_default_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'                  // SOFT HYPHEN
            | '\u{034f}'            // COMBINING GRAPHEME JOINER
            | '\u{061c}'            // ARABIC LETTER MARK
            | '\u{115f}'..='\u{1160}' // HANGUL CHOSEONG/JUNGSEONG FILLER
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}' // MONGOLIAN selectors + vowel separator
            | '\u{200b}'..='\u{200f}' // ZWSP, ZWNJ, ZWJ, LRM, RLM
            | '\u{202a}'..='\u{202e}' // bidi embedding / override
            | '\u{2060}'..='\u{206f}' // word joiner, invisible operators, isolates
            | '\u{3164}'            // HANGUL FILLER
            | '\u{fe00}'..='\u{fe0f}' // VARIATION SELECTOR-1..16
            | '\u{feff}'            // ZERO WIDTH NO-BREAK SPACE (BOM)
            | '\u{ffa0}'            // HALFWIDTH HANGUL FILLER
            | '\u{fff0}'..='\u{fff8}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}' // tags and variation selectors supplement
    )
}

/// The ASCII letter a Mathematical Alphanumeric Symbol renders as, if any.
///
/// `𝐒𝐞𝐧𝐝`, `𝕊𝕖𝕟𝕕` and `𝚂𝚎𝚗𝚍` are read by every human as `Send`; they are the
/// most casually available spoof there is, because social platforms hand them
/// out as a styling affordance. The block is thirteen 26-letter runs per case,
/// so the mapping is arithmetic rather than a table -- except that Unicode had
/// already assigned some of those glyphs in Letterlike Symbols and left holes in
/// the runs. Those are the explicit arm below; without it `ℋ`, `ℝ` and `ℯ` fold
/// to nothing while their neighbours in the same word fold correctly, which is a
/// worse failure than not folding the block at all.
fn math_alphanumeric_to_ascii(c: char) -> Option<char> {
    const UPPER_RUNS: [u32; 13] = [
        0x1d400, 0x1d434, 0x1d468, 0x1d49c, 0x1d4d0, 0x1d504, 0x1d538, 0x1d56c, 0x1d5a0, 0x1d5d4,
        0x1d608, 0x1d63c, 0x1d670,
    ];
    const LOWER_RUNS: [u32; 13] = [
        0x1d41a, 0x1d44e, 0x1d482, 0x1d4b6, 0x1d4ea, 0x1d51e, 0x1d552, 0x1d586, 0x1d5ba, 0x1d5ee,
        0x1d622, 0x1d656, 0x1d68a,
    ];
    let cp = c as u32;
    for start in UPPER_RUNS {
        if (start..start + 26).contains(&cp) {
            return char::from_u32(u32::from(b'A') + (cp - start));
        }
    }
    for start in LOWER_RUNS {
        if (start..start + 26).contains(&cp) {
            return char::from_u32(u32::from(b'a') + (cp - start));
        }
    }
    // The holes: glyphs that belong to the runs above but live in Letterlike
    // Symbols because they were encoded before the block existed.
    Some(match c {
        '\u{210e}' => 'h',
        '\u{212c}' => 'B',
        '\u{2130}' => 'E',
        '\u{2131}' => 'F',
        '\u{210b}' | '\u{210c}' | '\u{210d}' => 'H',
        '\u{2110}' | '\u{2111}' => 'I',
        '\u{2112}' => 'L',
        '\u{2133}' => 'M',
        '\u{211b}' | '\u{211c}' | '\u{211d}' => 'R',
        '\u{212f}' => 'e',
        '\u{210a}' => 'g',
        '\u{2134}' => 'o',
        '\u{212d}' | '\u{2102}' => 'C',
        '\u{2115}' => 'N',
        '\u{2119}' => 'P',
        '\u{211a}' => 'Q',
        '\u{2128}' | '\u{2124}' => 'Z',
        '\u{2145}' => 'D',
        '\u{2146}' => 'd',
        '\u{2147}' => 'e',
        '\u{2148}' => 'i',
        '\u{2149}' => 'j',
        _ => return None,
    })
}

/// Is this a letter from a script whose characters are routinely mistaken for
/// Latin ones? Cyrillic and Greek only -- the two scripts that share letterforms
/// with Latin. CJK, Arabic, Hebrew and the rest are NOT here, deliberately: they
/// look nothing like Latin letters, so a label mixing them with ASCII is an
/// ordinary bilingual label rather than a spoof, and flagging it would penalise
/// every non-English interface for no security gain.
fn is_latin_confusable_script(c: char) -> bool {
    matches!(
        c,
        '\u{0370}'..='\u{03ff}'     // Greek and Coptic
            | '\u{0400}'..='\u{04ff}' // Cyrillic
            | '\u{0500}'..='\u{052f}' // Cyrillic Supplement
            | '\u{1f00}'..='\u{1fff}' // Greek Extended
            | '\u{2de0}'..='\u{2dff}' // Cyrillic Extended-A
            | '\u{a640}'..='\u{a69f}' // Cyrillic Extended-B
    )
}

/// Does this label have the SHAPE of a spoof, whatever its specific codepoints?
///
/// This is the check that makes [`fold_label`]'s completeness stop being
/// load-bearing, and it is the answer to the obvious objection that no fold can
/// enumerate every confusable. It reads the RAW label -- before folding, because
/// folding is precisely what erases the evidence -- and asks a question that
/// needs no table: **does an ASCII letter sit directly against a Cyrillic or
/// Greek letter, or against an invisible character?**
///
/// That is the shape of every mixed-script spoof, including the ones this
/// crate's fold does not know:
///
/// ```text
///   "Send"          ascii only                  -> not suspicious
///   "Sеnd"          ascii + Cyrillic е          -> SUSPICIOUS
///   "Se<CGJ>nd"     ascii + invisible           -> SUSPICIOUS
///   "Отправить"     one script, no ascii        -> not suspicious
///   "Send Отправить" two words, each pure       -> not suspicious
///   "Wi-Fi設定"      ascii + CJK                 -> not suspicious
///   "café"          precomposed Latin           -> not suspicious
///   "cafe" + U+0301 decomposed Latin            -> not suspicious
/// ```
///
/// Adjacency rather than same-word co-occurrence is what keeps `α-version` and
/// `Ω Reset` quiet: a legitimate label puts a Greek letter beside a separator or
/// a space, a spoof puts it inside the word. And a genuine bilingual label keeps
/// its scripts in separate words, which is why the two-word case above is silent.
///
/// A suspicious label never lowers a tier -- it can only raise `Auto` to
/// `Confirm`, which costs one human glance at a label the classifier is telling
/// you it could not read with confidence.
/// Either of the two attacker-authored strings having the shape of a spoof is
/// enough to withhold the permissive answer.
///
/// The ROLE is here because leaving it out was a real gap, and a mutation is what
/// surfaced it: `is_credential_target` folds the role before matching
/// `securetextfield`, but no test pinned that fold and the detector never looked
/// at the role at all. On the web the role is the DOM's `role` attribute -- as
/// page-authored as the label, and it gates a hard BLOCK rather than an
/// escalation. A legitimate role is always plain ASCII, so this direction costs
/// nothing.
fn action_is_spoof_shaped(label: Option<&str>, role: Option<&str>) -> bool {
    label_is_suspicious(label) || label_is_suspicious(role)
}

fn label_is_suspicious(label: Option<&str>) -> bool {
    let label = match label {
        Some(l) if !l.trim().is_empty() => l,
        _ => return false,
    };
    let risky = |c: char| is_latin_confusable_script(c) || is_default_ignorable(c);
    let mut prev: Option<char> = None;
    for cur in label.chars() {
        if let Some(p) = prev {
            if (p.is_ascii_alphabetic() && risky(cur)) || (risky(p) && cur.is_ascii_alphabetic()) {
                return true;
            }
        }
        prev = Some(cur);
    }
    false
}

/// Fold a free-text label toward ASCII before matching a marker against it.
///
/// Every marker table in this file is ASCII. A label is not: on the web it comes
/// from the DOM, and on the desktop from whatever string an application chooses
/// to publish through the accessibility API. Both are attacker-controlled in the
/// case that matters. Plain `to_lowercase` leaves a label that a person reads as
/// `Send` but that no ASCII marker matches, and because every label rule here
/// only ever ESCALATES, a missed match silently returns the permissive answer.
///
/// The fold has ONE rule, and everything in it follows from that rule:
///
/// > A character is folded when it is INVISIBLE, or when it renders as an ASCII
/// > character in a different typeface. A character that renders as something
/// > visibly different is left alone.
///
/// So `Ｓｅｎｄ` (fullwidth), `𝐒𝐞𝐧𝐝` (mathematical bold), `Ѕепd` (Cyrillic
/// look-alikes) and `Se<ZWSP>nd` all fold to `send` -- while `Sénd` does not.
/// An accented vowel is a glyph a reader can see, and folding it would silently
/// rewrite non-English labels. Drawing the line at visibility rather than at
/// convenience is also what keeps the two Unicode normalisation forms of `Sénd`
/// behaving identically, which an ad-hoc "strip the combining marks" rule would
/// not: it would fold the decomposed spelling and leave the precomposed one, so
/// the same label would classify two different ways depending on where it came
/// from.
///
/// Invisible characters are DELETED rather than mapped, because they render as
/// nothing: a human sees `Send` where the bytes say `Se<ZWSP>nd`, and no marker
/// can match across the break. The set is not hand-picked -- it is Unicode's own
/// `Default_Ignorable_Code_Point` property (see [`is_default_ignorable`]), which
/// is the definition of "a character a conforming renderer draws nothing for".
/// That widening is not cosmetic: the previous enumerated list covered
/// zero-width spaces and bidi controls but missed `U+034F COMBINING GRAPHEME
/// JOINER`, and `Se<CGJ>nd` reached `Auto` on a `browser_click`.
///
/// **This is still not a UTS #39 confusable skeleton.** The full confusables
/// table is larger than a zero-dependency crate should carry, and no fold is
/// ever finished. What changed is that the fold is no longer the only thing
/// standing between an attacker-authored label and a tier. [`label_is_suspicious`]
/// reads the RAW label and escalates whenever ASCII sits directly against
/// Cyrillic, Greek or an invisible character -- the shape every one of these
/// spoofs has, whether or not this table knows the particular codepoint. The two
/// are complementary by construction: the fold catches the WHOLE-script spoof
/// (`Ѕепԁ`, every letter swapped, no ASCII left to be adjacent to), the detector
/// catches the MIXED-script one (`Sеnd`, a single letter swapped). Neither alone
/// is complete; the pair is what makes completeness stop being load-bearing.
///
/// Nothing here rests on the fold in any case: the tool name decides first
/// wherever a tool name carries the meaning (`browser_submit` confirms whatever
/// its label says) and an unrecognised tool defaults to `Confirm`.
fn fold_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let folded = match ch {
            // Invisible: renders as nothing, so it must not be able to break a
            // keyword. Decided by Unicode's property, not by an enumeration.
            c if is_default_ignorable(c) => continue,

            // Fullwidth ASCII: an exact one-to-one mapping.
            '\u{ff01}'..='\u{ff5e}' => char::from_u32(ch as u32 - 0xff01 + 0x21).unwrap_or(ch),

            // Mathematical Alphanumeric Symbols and the Letterlike glyphs that
            // belong with them: a different typeface for an ASCII letter.
            c if math_alphanumeric_to_ascii(c).is_some() => {
                math_alphanumeric_to_ascii(c).unwrap_or(ch)
            }

            // Spaces that are not U+0020.
            '\u{00a0}' | '\u{2000}'..='\u{200a}' | '\u{202f}' | '\u{205f}' | '\u{3000}' => ' ',

            // Dashes that are not U+002D.
            '\u{2010}'..='\u{2015}' | '\u{2212}' | '\u{fe58}' | '\u{fe63}' => '-',

            // Cyrillic letters that render as Latin ones.
            '\u{0430}' => 'a',
            '\u{0410}' => 'A',
            '\u{0432}' => 'b',
            '\u{0412}' => 'B',
            '\u{0441}' => 'c',
            '\u{0421}' => 'C',
            '\u{0501}' => 'd',
            '\u{0435}' => 'e',
            '\u{0415}' => 'E',
            '\u{04bb}' => 'h',
            '\u{041d}' => 'H',
            '\u{0456}' => 'i',
            '\u{0406}' => 'I',
            '\u{0458}' => 'j',
            '\u{0408}' => 'J',
            '\u{043a}' => 'k',
            '\u{041a}' => 'K',
            '\u{043c}' => 'm',
            '\u{041c}' => 'M',
            '\u{043e}' => 'o',
            '\u{041e}' => 'O',
            '\u{0440}' => 'p',
            '\u{0420}' => 'P',
            '\u{051b}' => 'q',
            '\u{0455}' => 's',
            '\u{0405}' => 'S',
            '\u{0442}' => 't',
            '\u{0422}' => 'T',
            '\u{0475}' => 'v',
            '\u{0474}' => 'V',
            '\u{051d}' => 'w',
            '\u{0445}' => 'x',
            '\u{0425}' => 'X',
            '\u{0443}' => 'y',
            '\u{0423}' => 'Y',

            // Greek letters that render as Latin ones.
            '\u{03b1}' => 'a',
            '\u{0391}' => 'A',
            '\u{0392}' => 'B',
            '\u{03b5}' => 'e',
            '\u{0395}' => 'E',
            '\u{0397}' => 'H',
            '\u{03b9}' => 'i',
            '\u{0399}' => 'I',
            '\u{03ba}' => 'k',
            '\u{039a}' => 'K',
            '\u{039c}' => 'M',
            '\u{03bd}' => 'v',
            '\u{039d}' => 'N',
            '\u{03bf}' => 'o',
            '\u{039f}' => 'O',
            '\u{03c1}' => 'p',
            '\u{03a1}' => 'P',
            '\u{03c4}' => 't',
            '\u{03a4}' => 'T',
            '\u{03c5}' => 'u',
            '\u{03a5}' => 'Y',
            '\u{03c7}' => 'x',
            '\u{03a7}' => 'X',
            '\u{0396}' => 'Z',

            other => other,
        };
        out.push(folded);
    }
    // Lowercase LAST: folding first means a fullwidth or Cyrillic capital
    // reaches the ASCII lowercaser as an ASCII capital.
    out.to_lowercase()
}

// ---------------------------------------------------------------------------
// Label-based tier for gui.click
// ---------------------------------------------------------------------------

/// Action verbs that escalate gui.click to Tier 1.
const ACTION_VERBS: &[&str] = &[
    "submit", "send", "post", "delete", "buy", "order", "publish", "confirm", "install",
];

/// Labels that escalate gui.click to Tier 2.
const TIER2_LABELS: &[&str] = &["empty trash", "erase", "permanently delete"];

/// File operation labels that escalate to Tier 1.
const FILE_OP_LABELS: &[&str] = &["save as", "move to trash", "export"];

fn label_tier(label: Option<&str>) -> Tier {
    let label = match label {
        Some(l) if !l.trim().is_empty() => fold_label(l),
        _ => return Tier::Auto,
    };

    // Tier 2 labels first (more restrictive).
    for pattern in TIER2_LABELS {
        if label.contains(pattern) {
            return Tier::Blocked;
        }
    }

    // Action verb check (Tier 1).
    for verb in ACTION_VERBS {
        if label.contains(verb) {
            return Tier::Confirm;
        }
    }

    // File operation labels (Tier 1).
    for op in FILE_OP_LABELS {
        if label.contains(op) {
            return Tier::Confirm;
        }
    }

    Tier::Auto
}

// ---------------------------------------------------------------------------
// Tier 2 contextual checks
// ---------------------------------------------------------------------------

/// Detects whether the focused element is a credential/password/payment/sudo
/// field, by role or label. Shared by [`is_tier2_context`] (for general gui.*
/// gating) and [`classify_dictation`] (for dictation safety blocks).
/// Accessibility ROLES that name a secret-bearing field outright.
const CREDENTIAL_ROLES: &[&str] = &["securetextfield", "password"];

/// Label markers for a credential field.
const CREDENTIAL_MARKERS: &[&str] = &["password", "credential", "passphrase"];

/// Label markers for a payment field.
const PAYMENT_MARKERS: &[&str] = &["credit card", "card number", "cvv", "payment"];

/// Label markers for an authorisation prompt.
const SUDO_MARKERS: &[&str] = &["sudo", "administrator password"];

/// Is this action pointed at a credential, payment or authorisation field?
///
/// The markers were inline string literals until they were lifted here. That was
/// not tidying: five other marker tables in this file are consts, and
/// `every_letter_a_marker_depends_on_is_accounted_for` derives its alphabet from
/// the consts. So the tables the fold most needs to protect -- the ones behind a
/// hard BLOCK rather than an escalation -- were the only ones that test could not
/// see. Being a const is what puts a marker under that check.
fn is_credential_target(ctx: &ActionContext<'_>) -> bool {
    if let Some(role) = ctx.element_role {
        let r = fold_label(role);
        if CREDENTIAL_ROLES.iter().any(|m| r.contains(m)) {
            return true;
        }
    }

    if let Some(label) = ctx.element_label {
        let l = fold_label(label);
        return CREDENTIAL_MARKERS
            .iter()
            .chain(PAYMENT_MARKERS)
            .chain(SUDO_MARKERS)
            .any(|m| l.contains(m));
    }

    false
}

/// Label markers for a system security setting.
const SECURITY_SETTING_MARKERS: &[&str] = &["filevault", "firewall", "gatekeeper"];

/// Label markers for sending inside a messaging app.
const MESSAGING_MARKERS: &[&str] = &["send", "post", "reply"];

fn is_tier2_context(ctx: &ActionContext<'_>) -> bool {
    // Credential / secure field detection (shared helper).
    if is_credential_target(ctx) {
        return true;
    }

    // Security settings (not credential fields per se, but Tier 2 for gui.*).
    if let Some(label) = ctx.element_label {
        let l = fold_label(label);
        if SECURITY_SETTING_MARKERS.iter().any(|m| l.contains(m)) {
            return true;
        }
    }

    // Messaging apps: "Send" in mail/messages/slack = Tier 2.
    if let Some(bid) = ctx.app_bundle_id {
        if is_messaging_app(bid) {
            if let Some(label) = ctx.element_label {
                let l = fold_label(label);
                if MESSAGING_MARKERS.iter().any(|m| l.contains(m)) {
                    return true;
                }
            }
            // gui.type in a messaging app is also Tier 2 (composing a message).
            if ctx.tool == "gui.type" {
                return true;
            }
        }
    }

    // Keychain access window detection by bundle id.
    if let Some(bid) = ctx.app_bundle_id {
        if bid == "com.apple.keychainaccess" {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Sensitive-app suppression list (Tier 2 hard-block)
// ---------------------------------------------------------------------------

/// Bundle ID substrings for banking/financial apps.
const BANKING_SUBSTRINGS: &[&str] = &[
    "chase",
    "bofa",
    "wellsfargo",
    "paypal",
    "venmo",
    "zelle",
    "schwab",
    "fidelity",
    "vanguard",
    "etrade",
    "robinhood",
    "coinbase",
    "binance",
    "kraken",
    "metamask",
    "ledger",
    "trezor",
    "phantom",
];

fn is_sensitive_app(bundle_id: &str) -> bool {
    let bid = bundle_id.to_lowercase();

    // 1Password variants.
    if bid.starts_with("com.agilebits.onepassword") {
        return true;
    }

    // Keychain Access.
    if bid == "com.apple.keychainaccess" {
        return true;
    }

    // Banking/crypto heuristic.
    for substr in BANKING_SUBSTRINGS {
        if bid.contains(substr) {
            return true;
        }
    }

    false
}

/// Returns true if the target app is sensitive, matching by bundle id OR by
/// display name. Used by `gui.snapshot` to suppress the accessibility tree of
/// a sensitive app: the AX tree leaks credentials (vault entries, field labels)
/// even when the screenshot itself is suppressed, and the bundle id is not yet
/// resolved at pre-snapshot classification time. The display-name check is the
/// catch-all for window-id / frontmost-app snapshots where only the parsed
/// `Application:` header is available.
pub fn is_sensitive_target(bundle_id: Option<&str>, app_name: Option<&str>) -> bool {
    if let Some(bid) = bundle_id {
        if is_sensitive_app(bid) {
            return true;
        }
    }
    if let Some(name) = app_name {
        let n = fold_label(name);
        if n.contains("1password") || n.contains("keychain access") {
            return true;
        }
        for substr in BANKING_SUBSTRINGS {
            if n.contains(substr) {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Messaging app detection
// ---------------------------------------------------------------------------

const MESSAGING_BUNDLES: &[&str] = &[
    "com.apple.mail",
    "com.apple.MobileSMS",       // Messages
    "com.apple.iChat",           // Messages (legacy)
    "com.tinyspeck.slackmacgap", // Slack
    "com.microsoft.Outlook",
    "com.microsoft.teams",
    "com.readdle.smartemail", // Spark
    "com.freron.MailMate",
    "com.hnc.Discord",
    "ru.keepcoder.Telegram",
    "org.whispersystems.signal-desktop",
    "com.twitter.twitter-mac",
    "com.facebook.archon", // Messenger
];

fn is_messaging_app(bundle_id: &str) -> bool {
    let bid = bundle_id.to_lowercase();
    for known in MESSAGING_BUNDLES {
        if bid == known.to_lowercase() {
            return true;
        }
    }
    // Heuristic: bundle contains "mail" or "messenger" or "chat".
    if bid.contains("mail") || bid.contains("messenger") || bid.contains("chat") {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Cross-app escalation (PRD D8)
// ---------------------------------------------------------------------------

fn apply_cross_app_escalation(tier: Tier, ctx: &ActionContext<'_>) -> Tier {
    if ctx.allowed_apps.is_empty() {
        return tier;
    }

    // An UNRESOLVED app escalates, exactly as a non-allowlisted one does.
    //
    // This used to `return tier`, which fails open at the worst moment: an agent
    // that cannot tell which app is frontmost is least sure what it is about to
    // touch, and was being treated as though it were inside the allowlist. The
    // allowlist means "these apps are known"; an unknown app is not one of them,
    // and neither is no app at all.
    let current_app = match ctx.app_bundle_id {
        Some(bid) => bid,
        None => return escalate_one_level(tier),
    };

    let in_allowlist = ctx
        .allowed_apps
        .iter()
        .any(|a| a.eq_ignore_ascii_case(current_app));

    if in_allowlist {
        return tier;
    }

    escalate_one_level(tier)
}

/// One rung up the ladder, defined once.
///
/// This was written out twice — at the unresolved-app return and at the
/// not-in-allowlist fall-through — which is two places for one decision to drift
/// apart, and it made the ladder ambiguous to pin: a mutation aimed at it
/// matched both sites and could be applied to neither.
fn escalate_one_level(tier: Tier) -> Tier {
    match tier {
        Tier::Auto => Tier::Confirm,
        Tier::Confirm => Tier::Blocked,
        Tier::Blocked => Tier::Blocked,
    }
}

fn max_tier(a: Tier, b: Tier) -> Tier {
    match (a, b) {
        (Tier::Blocked, _) | (_, Tier::Blocked) => Tier::Blocked,
        (Tier::Confirm, _) | (_, Tier::Confirm) => Tier::Confirm,
        _ => Tier::Auto,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_for(tool: &'static str) -> ActionContext<'static> {
        ActionContext {
            tool,
            element_label: None,
            element_role: None,
            app_bundle_id: None,
            allowed_apps: &[],
        }
    }

    // -- An unrecognised tool must fail CLOSED --
    //
    // Found by mutation: flipping the catch-all arm of `base_tier` from
    // `Tier::Confirm` to `Tier::Auto` left all 72 tests passing. That arm is the
    // single most consequential line here — it decides what happens to a tool
    // nobody anticipated — and nothing pinned it. A classifier that auto-approves
    // what it does not recognise is worse than no classifier, because it reads
    // as one.

    #[test]
    fn unknown_tools_default_to_confirm_never_auto() {
        for tool in &[
            "gui.frobnicate",
            "gui.download_file",
            "shell.exec",
            "",
            "gui.click.extra",
        ] {
            assert_eq!(
                classify(&ctx_for(tool)),
                Tier::Confirm,
                "unrecognised tool {tool:?} must not be Auto"
            );
        }
    }

    #[test]
    fn tool_matching_is_case_sensitive_so_casing_is_not_a_bypass() {
        // "GUI.CLICK" is not "gui.click". If matching were ever loosened to be
        // case-insensitive, an auto-approved tool name could be reached by
        // casing alone; this pins that it cannot.
        assert_eq!(classify(&ctx_for("GUI.CLICK")), Tier::Confirm);
        assert_eq!(classify(&ctx_for("GUI.SNAPSHOT")), Tier::Confirm);
        assert_eq!(classify(&ctx_for("gui.snapshot")), Tier::Auto);
    }

    // -- Tier 0 tools are Auto --

    #[test]
    fn tier0_tools_are_auto() {
        for tool in &[
            "gui.snapshot",
            "gui.list_apps",
            "gui.list_windows",
            "gui.launch_app",
            "gui.scroll",
            "gui.screenshot",
        ] {
            assert_eq!(classify(&ctx_for(tool)), Tier::Auto, "tool {tool}");
        }
    }

    // -- gui.type and gui.key are Tier 1 --

    #[test]
    fn gui_type_is_confirm() {
        assert_eq!(classify(&ctx_for("gui.type")), Tier::Confirm);
    }

    #[test]
    fn gui_key_is_confirm() {
        assert_eq!(classify(&ctx_for("gui.key")), Tier::Confirm);
    }

    // -- gui.click: navigation (no action verb) is Auto --

    #[test]
    fn click_navigation_is_auto() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Documents"),
            element_role: Some("button"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Auto);
    }

    // -- Every Tier 1 action-verb triggers Confirm on gui.click --

    #[test]
    fn click_action_verb_submit() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Submit Form"),
            element_role: Some("button"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    #[test]
    fn click_action_verb_send() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Send Message"),
            element_role: Some("button"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    #[test]
    fn click_action_verb_post() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Post Update"),
            element_role: Some("button"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    #[test]
    fn click_action_verb_delete() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Delete Item"),
            element_role: Some("button"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    #[test]
    fn click_action_verb_buy() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Buy Now"),
            element_role: Some("button"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    #[test]
    fn click_action_verb_order() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Place Order"),
            element_role: Some("button"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    #[test]
    fn click_action_verb_publish() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Publish Article"),
            element_role: Some("button"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    #[test]
    fn click_action_verb_confirm() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Confirm Purchase"),
            element_role: Some("button"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    #[test]
    fn click_action_verb_install() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Install App"),
            element_role: Some("button"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    #[test]
    fn action_verb_case_insensitive() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("SUBMIT"),
            element_role: None,
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    #[test]
    fn action_verb_substring_match() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Resubmit Report"),
            element_role: None,
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    // -- File operation labels escalate to Tier 1 --

    #[test]
    fn click_save_as_is_confirm() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Save As..."),
            element_role: Some("menuitem"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    #[test]
    fn click_move_to_trash_is_confirm() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Move to Trash"),
            element_role: Some("menuitem"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    #[test]
    fn click_export_is_confirm() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Export PDF"),
            element_role: Some("menuitem"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    // -- Tier 2 categories --

    #[test]
    fn password_field_by_role_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.type",
            element_label: None,
            element_role: Some("AXSecureTextField"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn password_field_by_label_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.type",
            element_label: Some("Enter Password"),
            element_role: Some("textfield"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn payment_field_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.type",
            element_label: Some("Credit Card Number"),
            element_role: Some("textfield"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn send_in_mail_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Send"),
            element_role: Some("button"),
            app_bundle_id: Some("com.apple.mail"),
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn type_in_slack_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.type",
            element_label: Some("Message #general"),
            element_role: Some("textfield"),
            app_bundle_id: Some("com.tinyspeck.slackmacgap"),
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn empty_trash_label_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Empty Trash"),
            element_role: Some("menuitem"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn keychain_access_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.snapshot",
            element_label: None,
            element_role: None,
            app_bundle_id: Some("com.apple.keychainaccess"),
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn sudo_prompt_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.type",
            element_label: Some("Enter sudo password"),
            element_role: Some("securetextfield"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn filevault_label_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Turn On FileVault"),
            element_role: Some("button"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn firewall_label_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Firewall Options"),
            element_role: Some("button"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    // -- Sensitive-app suppression list --

    #[test]
    fn onepassword_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.snapshot",
            element_label: None,
            element_role: None,
            app_bundle_id: Some("com.agilebits.onepassword7"),
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn onepassword_8_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.list_windows",
            element_label: None,
            element_role: None,
            app_bundle_id: Some("com.agilebits.onepassword8"),
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn chase_banking_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Account Details"),
            element_role: Some("button"),
            app_bundle_id: Some("com.chase.sig.ios"),
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn coinbase_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.snapshot",
            element_label: None,
            element_role: None,
            app_bundle_id: Some("com.coinbase.wallet"),
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn metamask_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.snapshot",
            element_label: None,
            element_role: None,
            app_bundle_id: Some("io.metamask.desktop"),
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn paypal_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Transfer"),
            element_role: Some("button"),
            app_bundle_id: Some("com.paypal.here"),
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    // -- Cross-app escalation (PRD D8) --

    #[test]
    fn cross_app_snapshot_escalates_auto_to_confirm() {
        let allowed = vec!["com.figma.Desktop".to_string()];
        let ctx = ActionContext {
            tool: "gui.snapshot",
            element_label: None,
            element_role: None,
            app_bundle_id: Some("com.apple.Safari"),
            allowed_apps: &allowed,
        };
        assert_eq!(classify(&ctx), Tier::Confirm);
    }

    #[test]
    fn cross_app_click_submit_escalates_confirm_to_blocked() {
        let allowed = vec!["com.figma.Desktop".to_string()];
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Submit"),
            element_role: Some("button"),
            app_bundle_id: Some("com.apple.Safari"),
            allowed_apps: &allowed,
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    #[test]
    fn in_allowlist_no_escalation() {
        let allowed = vec!["com.figma.Desktop".to_string()];
        let ctx = ActionContext {
            tool: "gui.snapshot",
            element_label: None,
            element_role: None,
            app_bundle_id: Some("com.figma.Desktop"),
            allowed_apps: &allowed,
        };
        assert_eq!(classify(&ctx), Tier::Auto);
    }

    #[test]
    fn empty_allowlist_no_escalation() {
        let ctx = ActionContext {
            tool: "gui.snapshot",
            element_label: None,
            element_role: None,
            app_bundle_id: Some("com.apple.Safari"),
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Auto);
    }

    #[test]
    fn allowlist_case_insensitive() {
        let allowed = vec!["COM.FIGMA.DESKTOP".to_string()];
        let ctx = ActionContext {
            tool: "gui.snapshot",
            element_label: None,
            element_role: None,
            app_bundle_id: Some("com.figma.Desktop"),
            allowed_apps: &allowed,
        };
        assert_eq!(classify(&ctx), Tier::Auto);
    }

    #[test]
    fn cross_app_blocked_stays_blocked() {
        let allowed = vec!["com.figma.Desktop".to_string()];
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Empty Trash"),
            element_role: Some("menuitem"),
            app_bundle_id: Some("com.apple.Finder"),
            allowed_apps: &allowed,
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    // -- Edge cases --

    #[test]
    fn no_label_click_is_auto() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: None,
            element_role: None,
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Auto);
    }

    #[test]
    fn empty_label_click_is_auto() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some(""),
            element_role: None,
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Auto);
    }

    #[test]
    fn gatekeeper_label_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: Some("Gatekeeper Settings"),
            element_role: Some("button"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify(&ctx), Tier::Blocked);
    }

    // -----------------------------------------------------------------------
    // is_sensitive_target -- gui.snapshot AX-tree leak guard (CRITICAL fix)
    // -----------------------------------------------------------------------

    #[test]
    fn sensitive_target_by_bundle_id() {
        assert!(is_sensitive_target(
            Some("com.agilebits.onepassword7"),
            None
        ));
        assert!(is_sensitive_target(Some("com.apple.keychainaccess"), None));
        assert!(is_sensitive_target(Some("com.chase.mobile"), None));
    }

    #[test]
    fn sensitive_target_by_display_name() {
        // The bundle id is unknown (window-id / frontmost snapshot), but the
        // parsed `Application:` header reveals the app. This is the catch-all.
        assert!(is_sensitive_target(None, Some("1Password")));
        assert!(is_sensitive_target(None, Some("Keychain Access")));
        assert!(is_sensitive_target(None, Some("Coinbase")));
        assert!(is_sensitive_target(None, Some("Robinhood")));
    }

    #[test]
    fn non_sensitive_target_allowed() {
        assert!(!is_sensitive_target(
            Some("com.apple.finder"),
            Some("Finder")
        ));
        assert!(!is_sensitive_target(None, Some("Calendar")));
        assert!(!is_sensitive_target(None, None));
    }

    // -----------------------------------------------------------------------
    // classify_dictation — voice dictation risk gate
    // -----------------------------------------------------------------------

    #[test]
    fn dictate_into_textedit_is_auto() {
        let ctx = ActionContext {
            tool: "gui.dictate",
            element_label: None,
            element_role: Some("AXTextArea"),
            app_bundle_id: Some("com.apple.TextEdit"),
            allowed_apps: &[],
        };
        assert_eq!(classify_dictation(&ctx), Tier::Auto);
    }

    #[test]
    fn dictate_into_slack_compose_is_auto() {
        let ctx = ActionContext {
            tool: "gui.dictate",
            element_label: Some("Message #general"),
            element_role: Some("AXTextField"),
            app_bundle_id: Some("com.tinyspeck.slackmacgap"),
            allowed_apps: &[],
        };
        assert_eq!(classify_dictation(&ctx), Tier::Auto);
    }

    #[test]
    fn dictate_into_1password_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.dictate",
            element_label: None,
            element_role: None,
            app_bundle_id: Some("com.agilebits.onepassword8"),
            allowed_apps: &[],
        };
        assert_eq!(classify_dictation(&ctx), Tier::Blocked);
    }

    #[test]
    fn dictate_into_secure_text_field_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.dictate",
            element_label: None,
            element_role: Some("AXSecureTextField"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify_dictation(&ctx), Tier::Blocked);
    }

    #[test]
    fn dictate_into_password_label_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.dictate",
            element_label: Some("Enter Password"),
            element_role: Some("AXTextField"),
            app_bundle_id: None,
            allowed_apps: &[],
        };
        assert_eq!(classify_dictation(&ctx), Tier::Blocked);
    }

    #[test]
    fn dictate_into_banking_app_is_blocked() {
        let ctx = ActionContext {
            tool: "gui.dictate",
            element_label: None,
            element_role: None,
            app_bundle_id: Some("com.chase.mobile"),
            allowed_apps: &[],
        };
        assert_eq!(classify_dictation(&ctx), Tier::Blocked);
    }

    // -----------------------------------------------------------------------
    // classify_web — browser_* irreversibility tier map (grant plane)
    // -----------------------------------------------------------------------

    // -- The web path fails CLOSED, exactly as the gui path does --
    //
    // Found by a red team. `classify_web` used to end in a bare `Tier::Auto`, so
    // any tool it did not name was auto-approved: a new `browser_evaluate`, a
    // `browser_download`, a rename of `browser_submit`, or the same name in
    // different case. `base_tier` has had a `_ => Confirm` catch-all all along,
    // and the README tells the story of pinning it. The other entry point did
    // the opposite and nothing noticed, because no mutation was ever aimed here.

    #[test]
    fn unknown_web_tools_default_to_confirm_never_auto() {
        for tool in &[
            "browser_evaluate",
            "browser_run_js",
            "browser_download",
            "browser_file_upload",
            "browser_drag",
            "browser_select_option",
            "browser_frobnicate",
            "shell.exec",
            "",
            "gui.type",
        ] {
            assert_eq!(
                classify_web(&web_ctx(tool, None)).tier,
                Tier::Confirm,
                "unrecognised web tool {tool:?} must not be Auto"
            );
        }
    }

    #[test]
    fn web_tool_matching_is_case_sensitive_so_casing_is_not_a_bypass() {
        // "BROWSER_CLICK" is not "browser_click". If matching were ever loosened
        // to be case-insensitive, casing alone would reach an auto-approved arm.
        assert_eq!(
            classify_web(&web_ctx("BROWSER_CLICK", None)).tier,
            Tier::Confirm
        );
        assert_eq!(
            classify_web(&web_ctx("Browser_Navigate", None)).tier,
            Tier::Confirm
        );
        assert_eq!(
            classify_web(&web_ctx("browser_navigate", None)).tier,
            Tier::Auto
        );
    }

    #[test]
    fn the_reversible_web_tools_are_still_auto() {
        // The must-not-fire half. A catch-all that swept everything into Confirm
        // would pass the two tests above and be useless, so this pins the other
        // direction: the documented reversible set stays Auto.
        for tool in &[
            "browser_navigate",
            "browser_read",
            "browser_snapshot",
            "browser_scroll",
            "browser_click",
            "browser_press",
            "browser_type",
        ] {
            assert_eq!(
                classify_web(&web_ctx(tool, None)).tier,
                Tier::Auto,
                "reversible web tool {tool:?} should not need a confirmation"
            );
        }
    }

    #[test]
    fn an_unresolved_app_escalates_rather_than_being_treated_as_allowlisted() {
        let allow = vec!["com.apple.Safari".to_string()];
        // The allowlist means "these apps are known". No app at all is not one
        // of them, and an agent that cannot resolve the frontmost app is exactly
        // when it is least sure what it is touching.
        let ctx = ActionContext {
            tool: "gui.click",
            element_label: None,
            element_role: None,
            app_bundle_id: None,
            allowed_apps: &allow,
        };
        assert_eq!(classify(&ctx), Tier::Confirm);

        // Control: the same action inside the allowlist is not escalated.
        let known = ActionContext {
            tool: "gui.click",
            element_label: None,
            element_role: None,
            app_bundle_id: Some("com.apple.Safari"),
            allowed_apps: &allow,
        };
        assert_eq!(classify(&known), Tier::Auto);
    }

    fn web_ctx(tool: &'static str, label: Option<&'static str>) -> WebActionContext<'static> {
        WebActionContext {
            tool,
            element_role: None,
            element_label: label,
        }
    }

    #[test]
    fn web_reads_and_navigation_are_auto() {
        for tool in &[
            "browser_navigate",
            "browser_snapshot",
            "browser_read",
            "browser_scroll",
        ] {
            assert_eq!(
                classify_web(&web_ctx(tool, None)).tier,
                Tier::Auto,
                "tool {tool}"
            );
        }
    }

    #[test]
    fn web_fill_normal_field_is_auto() {
        // Typing into an ordinary field is reversible under grant.
        let ctx = WebActionContext {
            tool: "browser_type",
            element_role: Some("textbox"),
            element_label: Some("Search"),
        };
        assert_eq!(classify_web(&ctx).tier, Tier::Auto);
    }

    #[test]
    fn web_non_committal_click_is_auto() {
        let ctx = web_ctx("browser_click", Some("Home"));
        assert_eq!(classify_web(&ctx).tier, Tier::Auto);
    }

    #[test]
    fn web_irreversible_verbs_are_confirm() {
        for verb in &[
            "Submit",
            "Send",
            "Post",
            "Apply Now",
            "Purchase",
            "Buy Now",
            "Place Order",
            "Checkout",
            "Delete Account",
            "Publish",
            "Confirm Order",
            "Connect",
            "Add Friend",
            "Follow",
            "Send Request",
        ] {
            let ctx = web_ctx("browser_click", Some(verb));
            assert_eq!(classify_web(&ctx).tier, Tier::Confirm, "verb {verb}");
        }
    }

    #[test]
    fn web_submit_tool_is_confirm_regardless_of_label() {
        let ctx = web_ctx("browser_submit", None);
        assert_eq!(classify_web(&ctx).tier, Tier::Confirm);
    }

    #[test]
    fn web_press_enter_on_submit_label_is_confirm() {
        let ctx = web_ctx("browser_press", Some("Send Message"));
        assert_eq!(classify_web(&ctx).tier, Tier::Confirm);
    }

    #[test]
    fn web_password_field_is_blocked() {
        let ctx = WebActionContext {
            tool: "browser_type",
            element_role: Some("AXSecureTextField"),
            element_label: Some("Password"),
        };
        assert_eq!(classify_web(&ctx).tier, Tier::Blocked);
    }

    #[test]
    fn web_payment_field_is_blocked() {
        let ctx = WebActionContext {
            tool: "browser_type",
            element_role: Some("textbox"),
            element_label: Some("Credit Card Number"),
        };
        assert_eq!(classify_web(&ctx).tier, Tier::Blocked);
    }

    #[test]
    fn web_2fa_field_is_blocked() {
        for label in &[
            "One-Time Code",
            "Verification Code",
            "Authenticator code",
            "2FA code",
            "OTP",
        ] {
            let ctx = WebActionContext {
                tool: "browser_type",
                element_role: Some("textbox"),
                element_label: Some(label),
            };
            assert_eq!(classify_web(&ctx).tier, Tier::Blocked, "2fa label {label}");
        }
    }

    #[test]
    fn web_hard_block_wins_over_irreversible_verb() {
        // A field that is BOTH a credential field and carries an action verb
        // must hard-block (takeover), never merely confirm.
        let ctx = WebActionContext {
            tool: "browser_type",
            element_role: Some("AXSecureTextField"),
            element_label: Some("Submit password"),
        };
        assert_eq!(classify_web(&ctx).tier, Tier::Blocked);
    }

    // -----------------------------------------------------------------------
    // WriteClass — the named write class the confirm card renders (A1).
    //
    // The tier says "confirm"; the class says WHAT KIND, so the card can name
    // the act ("send an email") instead of an undifferentiated "confirm". These
    // pin: (1) each class is produced by a representative verb; (2) an
    // irreversible verb with no class still gets its TIER right (no regression);
    // (3) a credential/2FA hard-block is NEVER reclassified as a write.
    // -----------------------------------------------------------------------

    #[test]
    fn web_class_document_write_from_submit() {
        // "Submit Form" is an irreversible form write → Confirm + DocumentWrite.
        let v = classify_web(&web_ctx("browser_click", Some("Submit Form")));
        assert_eq!(v.tier, Tier::Confirm);
        assert_eq!(v.class, Some(WriteClass::DocumentWrite));
    }

    #[test]
    fn web_class_social_post_from_post() {
        // "Post Update" → Confirm + SocialPost. Social is checked before the
        // generic document bucket, so the "update" substring does not shadow it.
        let v = classify_web(&web_ctx("browser_click", Some("Post Update")));
        assert_eq!(v.tier, Tier::Confirm);
        assert_eq!(v.class, Some(WriteClass::SocialPost));
    }

    #[test]
    fn web_class_email_send_from_email_label() {
        // "Send Email" → Confirm + EmailSend. The label must say "email"; a bare
        // "Send" is deliberately left classless (see the no-class test) because
        // it cannot be told apart from a chat or a form submit.
        let v = classify_web(&web_ctx("browser_click", Some("Send Email")));
        assert_eq!(v.tier, Tier::Confirm);
        assert_eq!(v.class, Some(WriteClass::EmailSend));
    }

    #[test]
    fn web_class_connection_request_is_social() {
        // Connection-request shapes read as social from the operator's seat —
        // something other people see happen under his name.
        for verb in &["Follow", "Add Friend", "Connect", "Send Request", "Invite"] {
            let v = classify_web(&web_ctx("browser_click", Some(verb)));
            assert_eq!(v.tier, Tier::Confirm, "verb {verb} tier");
            assert_eq!(v.class, Some(WriteClass::SocialPost), "verb {verb} class");
        }
    }

    #[test]
    fn web_bare_submit_tool_floors_at_document_write() {
        // A browser_submit with no label is a form/document write by
        // construction, so it names DocumentWrite rather than a nameless confirm.
        let v = classify_web(&web_ctx("browser_submit", None));
        assert_eq!(v.tier, Tier::Confirm);
        assert_eq!(v.class, Some(WriteClass::DocumentWrite));
    }

    #[test]
    fn web_irreversible_verb_with_no_class_still_confirms() {
        // NO-REGRESSION GUARD: a commerce verb ("Buy Now") is irreversible, so
        // the TIER must still be Confirm — but it names no document/social/email
        // kind, so the class is honestly None (the card falls back to generic
        // phrasing rather than guessing). If class derivation ever leaked into
        // the tier decision, this verb would misclassify.
        let v = classify_web(&web_ctx("browser_click", Some("Buy Now")));
        assert_eq!(v.tier, Tier::Confirm, "buy is still irreversible");
        assert_eq!(v.class, None, "buy names no write class");
    }

    #[test]
    fn web_credential_hard_block_is_not_reclassified_as_write() {
        // The label "Submit password" contains "submit" (a DocumentWrite marker),
        // but the field is a credential field → it MUST hard-block with class
        // None. The class must never be derived for a hard-block; this is the
        // falsifier for the credential path.
        let v = classify_web(&WebActionContext {
            tool: "browser_type",
            element_role: Some("AXSecureTextField"),
            element_label: Some("Submit password"),
        });
        assert_eq!(v.tier, Tier::Blocked);
        assert_eq!(v.class, None, "a credential takeover is not a write");
    }

    #[test]
    fn web_2fa_hard_block_is_not_reclassified_as_write() {
        // Same guarantee for a 2FA field even if its label carried a write verb.
        let v = classify_web(&WebActionContext {
            tool: "browser_type",
            element_role: Some("textbox"),
            element_label: Some("Submit one-time code"),
        });
        assert_eq!(v.tier, Tier::Blocked);
        assert_eq!(v.class, None);
    }

    #[test]
    fn web_auto_action_has_no_class() {
        // A reversible read/navigate names no write — nothing outward happens.
        let v = classify_web(&web_ctx("browser_click", Some("Home")));
        assert_eq!(v.tier, Tier::Auto);
        assert_eq!(v.class, None);
    }

    #[test]
    fn web_write_class_helper_maps_representatives_and_none() {
        // The class function is the ONE source both the advisory and managed
        // paths call; pin it directly so a marker-table edit is caught here.
        assert_eq!(
            web_write_class(Some("Submit")),
            Some(WriteClass::DocumentWrite)
        );
        assert_eq!(
            web_write_class(Some("Publish Article")),
            Some(WriteClass::SocialPost)
        );
        assert_eq!(
            web_write_class(Some("Send Email")),
            Some(WriteClass::EmailSend)
        );
        assert_eq!(web_write_class(Some("Checkout")), None);
        assert_eq!(web_write_class(Some("   ")), None);
        assert_eq!(web_write_class(None), None);
    }
}

#[cfg(test)]
mod fold_tests {
    use super::*;

    fn web(tool: &'static str, label: &'static str) -> WebActionContext<'static> {
        WebActionContext {
            tool,
            element_role: None,
            element_label: Some(label),
        }
    }

    fn desk(tool: &'static str, label: &'static str) -> ActionContext<'static> {
        ActionContext {
            tool,
            element_label: Some(label),
            element_role: None,
            app_bundle_id: None,
            allowed_apps: &[],
        }
    }

    // -- the reproduced bypasses ------------------------------------------

    #[test]
    fn cyrillic_e_in_send_still_escalates_a_generic_click() {
        // U+0435 renders as ASCII 'e'. Before the fold this returned Auto.
        assert_eq!(
            classify_web(&web("browser_click", "S\u{0435}nd")).tier,
            Tier::Confirm
        );
        assert_eq!(
            classify_web(&web("browser_click", "Send")).tier,
            Tier::Confirm
        );
    }

    #[test]
    fn fullwidth_otp_field_is_still_hard_blocked() {
        // A hard block, not merely an escalation. Before the fold: Auto.
        assert_eq!(
            classify_web(&web("browser_type", "\u{ff2f}\u{ff34}\u{ff30} code")).tier,
            Tier::Blocked
        );
    }

    #[test]
    fn a_zero_width_space_cannot_break_a_keyword() {
        assert_eq!(
            classify_web(&web("browser_click", "Se\u{200b}nd")).tier,
            Tier::Confirm
        );
    }

    #[test]
    fn a_soft_hyphen_cannot_break_a_keyword() {
        assert_eq!(
            classify_web(&web("browser_click", "De\u{00ad}lete")).tier,
            Tier::Confirm
        );
    }

    #[test]
    fn a_non_breaking_space_and_a_unicode_dash_still_match_one_time() {
        assert_eq!(
            classify_web(&web("browser_type", "one\u{2011}time code")).tier,
            Tier::Blocked
        );
    }

    #[test]
    fn greek_omicron_in_a_password_label_still_hard_blocks_on_the_desktop() {
        assert_eq!(
            classify(&desk("gui.type", "Passw\u{03bf}rd")),
            Tier::Blocked
        );
        assert_eq!(classify(&desk("gui.type", "Password")), Tier::Blocked);
    }

    #[test]
    fn a_folded_tier2_desktop_label_still_blocks() {
        assert_eq!(
            classify(&desk("gui.click", "\u{0415}mpty Trash")),
            Tier::Blocked
        );
    }

    // -- the fold must not INVENT a match ---------------------------------

    #[test]
    fn an_ordinary_benign_label_is_unaffected() {
        assert_eq!(
            classify_web(&web("browser_click", "Cancel")).tier,
            Tier::Auto
        );
        assert_eq!(
            classify_web(&web("browser_click", "Back to results")).tier,
            Tier::Auto
        );
    }

    #[test]
    fn folding_does_not_manufacture_a_keyword_from_unrelated_text() {
        // Cyrillic that does NOT look Latin must pass through untouched, so a
        // label in another language cannot be folded into an English verb.
        assert_eq!(
            classify_web(&web(
                "browser_click",
                "\u{0416}\u{0443}\u{0440}\u{043d}\u{0430}\u{043b}"
            ))
            .tier,
            Tier::Auto
        );
    }

    // The original of this test used a Cyrillic-swapped "Rеad more" and asserted
    // Auto, conflating two separate promises. They are stated apart now, because
    // the second deliberately changed: a folded letter must not MANUFACTURE a
    // marker match, but a label carrying one is still spoof-SHAPED and no longer
    // earns silence.
    #[test]
    fn folding_a_benign_ascii_label_does_not_manufacture_a_marker_match() {
        assert_eq!(
            classify_web(&web("browser_click", "Read more")).tier,
            Tier::Auto
        );
        assert_eq!(
            classify_web(&web("browser_click", "Preferences")).tier,
            Tier::Auto
        );
    }

    #[test]
    fn a_cyrillic_swapped_label_is_escalated_even_when_it_matches_no_marker() {
        // "Rеad more" names no irreversible verb even after folding. It is still
        // a label whose bytes and whose rendering disagree, which is the whole
        // signal -- a legitimate "Read more" has no reason to carry a Cyrillic е.
        assert_eq!(
            classify_web(&web("browser_click", "R\u{0435}ad more")).tier,
            Tier::Confirm
        );
    }

    // -- the fold is not what holds the line ------------------------------

    #[test]
    fn the_tool_name_decides_even_when_the_label_evades_the_fold() {
        // A homoglyph this table does not carry. The TOOL still confirms, which
        // is the property that must not depend on the fold being complete.
        assert_eq!(
            classify_web(&web("browser_submit", "\u{a4d0}\u{a4f4}nd")).tier,
            Tier::Confirm
        );
    }

    #[test]
    fn an_unrecognised_web_tool_still_defaults_to_confirm() {
        assert_eq!(
            classify_web(&web("browser_evaluate", "anything")).tier,
            Tier::Confirm
        );
    }

    // -- fold_label directly ----------------------------------------------

    #[test]
    fn fold_label_maps_fullwidth_to_ascii_and_lowercases_after() {
        assert_eq!(fold_label("\u{ff33}\u{ff25}\u{ff2e}\u{ff24}"), "send");
    }

    #[test]
    fn fold_label_leaves_plain_ascii_alone_apart_from_case() {
        assert_eq!(fold_label("Send Now"), "send now");
    }

    #[test]
    fn fold_label_deletes_rather_than_maps_zero_width_characters() {
        assert_eq!(fold_label("a\u{200b}b"), "ab");
        assert_eq!(fold_label("a\u{feff}b"), "ab");
    }

    #[test]
    fn fold_label_is_idempotent() {
        let once = fold_label("S\u{0435}\u{200b}nd\u{2011}now");
        assert_eq!(fold_label(&once), once);
    }
}

#[cfg(test)]
mod spoof_shape_tests {
    use super::*;
    use std::collections::BTreeSet;

    fn web(tool: &'static str, label: &'static str) -> WebActionContext<'static> {
        WebActionContext {
            tool,
            element_role: None,
            element_label: Some(label),
        }
    }

    fn desk(tool: &'static str, label: &'static str) -> ActionContext<'static> {
        ActionContext {
            tool,
            element_label: Some(label),
            element_role: None,
            app_bundle_id: None,
            allowed_apps: &[],
        }
    }

    // -- the bypass that motivated all of this -----------------------------

    #[test]
    fn a_combining_grapheme_joiner_no_longer_buys_silence() {
        // U+034F renders as nothing. Before the Default_Ignorable widening this
        // reached Auto: the enumerated delete-set covered zero-width spaces and
        // bidi controls, and CGJ is neither.
        assert_eq!(
            classify_web(&web("browser_click", "Se\u{034f}nd")).tier,
            Tier::Confirm
        );
        assert_eq!(fold_label("Se\u{034f}nd"), "send");
    }

    #[test]
    fn the_other_invisible_characters_the_enumerated_list_missed() {
        for label in [
            "Se\u{180e}nd",  // MONGOLIAN VOWEL SEPARATOR
            "Se\u{fe0f}nd",  // VARIATION SELECTOR-16
            "Se\u{115f}nd",  // HANGUL CHOSEONG FILLER
            "Se\u{3164}nd",  // HANGUL FILLER
            "Se\u{2066}nd",  // LEFT-TO-RIGHT ISOLATE
            "Se\u{e0001}nd", // LANGUAGE TAG
        ] {
            assert_eq!(fold_label(label), "send", "not folded: {label:?}");
        }
    }

    #[test]
    fn mathematical_alphanumerics_fold_to_the_letters_they_render_as() {
        assert_eq!(fold_label("\u{1d412}\u{1d41e}\u{1d427}\u{1d41d}"), "send"); // bold
        assert_eq!(fold_label("\u{1d54a}\u{1d556}\u{1d55f}\u{1d555}"), "send"); // double-struck
        assert_eq!(fold_label("\u{1d682}\u{1d68e}\u{1d697}\u{1d68d}"), "send"); // monospace
        assert_eq!(fold_label("\u{1d5e6}\u{1d5f2}\u{1d5fb}\u{1d5f1}"), "send"); // sans bold
    }

    #[test]
    fn the_letterlike_holes_fold_with_their_own_runs() {
        // Script capital R lives at U+211B, not in the 1D49C run, because it was
        // encoded before the block existed. Folding the run but not the holes
        // would leave one letter of a word un-normalised.
        assert_eq!(fold_label("\u{211b}"), "r");
        assert_eq!(fold_label("\u{210e}"), "h");
        assert_eq!(fold_label("\u{2115}"), "n");
        assert_eq!(fold_label("\u{212f}"), "e");
    }

    #[test]
    fn a_math_styled_send_button_does_not_reach_auto() {
        assert_eq!(
            classify_web(&web(
                "browser_click",
                "\u{1d412}\u{1d41e}\u{1d427}\u{1d41d}"
            ))
            .tier,
            Tier::Confirm
        );
    }

    // -- the detector, which is what makes the fold non-load-bearing --------

    #[test]
    fn a_mixed_script_label_escalates_even_when_the_fold_does_not_know_the_codepoint() {
        // U+A64B CYRILLIC SMALL LETTER MONOGRAPH UK is NOT in the homoglyph map,
        // deliberately: this asserts the detector alone carries the case. If a
        // future map addition covers it, the assertion still holds -- which is
        // the point of having two independent mechanisms.
        assert!(!matches!(fold_label("\u{a64b}").chars().next(), Some(c) if c.is_ascii()));
        assert_eq!(
            classify_web(&web("browser_click", "S\u{a64b}nd")).tier,
            Tier::Confirm
        );
    }

    #[test]
    fn suspicion_applies_on_the_desktop_path_too() {
        assert_eq!(
            classify(&desk("gui.click", "R\u{0435}ad more")),
            Tier::Confirm
        );
        assert_eq!(classify(&desk("gui.click", "Read more")), Tier::Auto);
    }

    #[test]
    fn suspicion_never_lowers_a_tier() {
        // A hard block stays a hard block; the escalation is one-directional.
        assert_eq!(
            classify_web(&web("browser_type", "P\u{0430}ssword")).tier,
            Tier::Blocked
        );
        assert_eq!(
            classify_web(&web("browser_submit", "\u{0405}end")).tier,
            Tier::Confirm
        );
    }

    // -- the must-NOT-fire half, which is the larger one --------------------

    #[test]
    fn a_single_script_non_latin_label_is_not_suspicious() {
        // Penalising every non-English interface would be a real cost for no
        // security gain, so one script and no ASCII is silent.
        for label in [
            "\u{041e}\u{0442}\u{043f}\u{0440}\u{0430}\u{0432}\u{0438}\u{0442}\u{044c}",
            "\u{9001}\u{4fe1}",
            "\u{0625}\u{0631}\u{0633}\u{0627}\u{0644}",
        ] {
            assert!(!label_is_suspicious(Some(label)), "fired on {label:?}");
        }
    }

    #[test]
    fn a_bilingual_label_keeps_its_scripts_in_separate_words_and_is_silent() {
        assert!(!label_is_suspicious(Some(
            "Send \u{041e}\u{0442}\u{043f}\u{0440}\u{0430}\u{0432}\u{0438}\u{0442}\u{044c}"
        )));
    }

    #[test]
    fn ascii_beside_cjk_is_an_ordinary_label_not_a_spoof() {
        // CJK shares no letterforms with Latin, so mixing is never a spoof.
        assert!(!label_is_suspicious(Some("Wi-Fi\u{8a2d}\u{5b9a}")));
        assert_eq!(
            classify_web(&web("browser_click", "Wi-Fi\u{8a2d}\u{5b9a}")).tier,
            Tier::Auto
        );
    }

    #[test]
    fn both_normalisation_forms_of_an_accented_label_behave_the_same() {
        // The invariant that decided where the fold stops. A "strip the
        // combining marks" rule would fold the decomposed spelling and leave the
        // precomposed one, so the SAME label would classify two ways depending
        // on which normalisation form it happened to arrive in.
        //
        // Note what is asserted and what is not. The two fold to different
        // STRINGS -- they were different strings to begin with and the fold
        // leaves both alone, so string equality was never the claim, and
        // asserting it here failed against correct code while this test was
        // being written. The claim is behavioural: every marker is ASCII, so
        // neither form matches one, and both reach the same tier.
        let precomposed = "Caf\u{e9}";
        let decomposed = "Cafe\u{301}";
        assert_eq!(
            classify_web(&web("browser_click", "Caf\u{e9}")).tier,
            classify_web(&web("browser_click", "Cafe\u{301}")).tier
        );
        assert!(!label_is_suspicious(Some(precomposed)));
        assert!(!label_is_suspicious(Some(decomposed)));
        // And neither is mistaken for the ASCII spelling.
        assert_ne!(fold_label(precomposed), "cafe");
        assert_ne!(fold_label(decomposed), "cafe");
    }

    #[test]
    fn a_greek_letter_beside_a_separator_is_not_a_spoof() {
        // Adjacency rather than same-word co-occurrence is what keeps these
        // quiet: a real label puts the Greek letter next to punctuation or a
        // space, a spoof puts it inside the word.
        assert!(!label_is_suspicious(Some("\u{03b1}-version")));
        assert!(!label_is_suspicious(Some("\u{03a9} Reset")));
        assert!(label_is_suspicious(Some("v\u{03b5}rsion")));
    }

    #[test]
    fn a_confusable_at_the_start_of_a_word_is_caught_too() {
        // Adjacency is checked in both directions. A one-directional scan would
        // pass every test above, because in all of them the ASCII letter comes
        // first -- so this is the case that pins the second clause.
        assert!(label_is_suspicious(Some("\u{0405}end")));
        assert!(label_is_suspicious(Some("\u{200b}Send")));
    }

    #[test]
    fn a_spoofed_role_is_caught_the_same_way_a_spoofed_label_is() {
        // The role is the DOM's `role` attribute on the web -- as page-authored
        // as the label, and it gates a hard BLOCK. A mutation dropping the fold
        // from the role check SURVIVED until these two existed.
        let cred = |role: &'static str| WebActionContext {
            tool: "browser_type",
            element_role: Some(role),
            element_label: Some("Card"),
        };
        assert_eq!(classify_web(&cred("securetextfield")).tier, Tier::Blocked);
        // Cyrillic е inside the role name: folds back, so it still blocks.
        assert_eq!(
            classify_web(&cred("securet\u{0435}xtfield")).tier,
            Tier::Blocked
        );
        // And a role the fold does NOT know still refuses the permissive answer,
        // because the shape alone is enough.
        assert_ne!(
            classify_web(&WebActionContext {
                tool: "browser_click",
                element_role: Some("butt\u{a64b}n"),
                element_label: Some("Next"),
            })
            .tier,
            Tier::Auto
        );
    }

    #[test]
    fn an_ordinary_ascii_role_is_never_treated_as_spoofed() {
        for role in ["button", "textfield", "AXButton", "link", "checkbox"] {
            assert!(!label_is_suspicious(Some(role)), "fired on {role:?}");
        }
    }

    #[test]
    fn an_empty_or_absent_label_is_not_suspicious() {
        assert!(!label_is_suspicious(None));
        assert!(!label_is_suspicious(Some("")));
        assert!(!label_is_suspicious(Some("   ")));
    }

    #[test]
    fn plain_ascii_labels_are_never_suspicious() {
        for label in ["Send", "Cancel", "Read more", "Wi-Fi", "e-mail", "2-step"] {
            assert!(!label_is_suspicious(Some(label)), "fired on {label:?}");
        }
    }

    // -- forcing function: coverage derived from the marker tables ----------

    /// One documented look-alike per ASCII letter, used to prove the fold
    /// normalises the letters the markers actually depend on.
    fn look_alike(c: char) -> Option<char> {
        Some(match c {
            'a' => '\u{0430}',
            'b' => '\u{0432}',
            'c' => '\u{0441}',
            'd' => '\u{0501}',
            'e' => '\u{0435}',
            'h' => '\u{04bb}',
            'i' => '\u{0456}',
            'j' => '\u{0458}',
            'k' => '\u{043a}',
            'm' => '\u{043c}',
            'o' => '\u{043e}',
            'p' => '\u{0440}',
            'q' => '\u{051b}',
            's' => '\u{0455}',
            't' => '\u{0442}',
            'u' => '\u{03c5}',
            'v' => '\u{0475}',
            'w' => '\u{051d}',
            'x' => '\u{0445}',
            'y' => '\u{0443}',
            _ => return None,
        })
    }

    /// Letters for which Cyrillic and Greek offer no ordinary look-alike. Being
    /// on this list is a CLAIM, checked by the test below -- not a way to opt a
    /// letter out.
    const LETTERS_WITH_NO_LOOK_ALIKE: &[char] = &['f', 'g', 'l', 'n', 'r', 'z'];

    fn marker_alphabet() -> BTreeSet<char> {
        let mut out = BTreeSet::new();
        for table in [
            WEB_IRREVERSIBLE_VERBS,
            WEB_EMAIL_MARKERS,
            WEB_SOCIAL_MARKERS,
            WEB_DOCUMENT_MARKERS,
            WEB_2FA_MARKERS,
            ACTION_VERBS,
            TIER2_LABELS,
            FILE_OP_LABELS,
            // The hard-block tables. These are the reason the markers were
            // lifted out of the function bodies: a BLOCK is the most
            // consequential answer this crate gives, and its markers were the
            // only ones this check could not see.
            CREDENTIAL_ROLES,
            CREDENTIAL_MARKERS,
            PAYMENT_MARKERS,
            SUDO_MARKERS,
            SECURITY_SETTING_MARKERS,
            MESSAGING_MARKERS,
        ] {
            for marker in table {
                for c in marker.chars().filter(|c| c.is_ascii_alphabetic()) {
                    out.insert(c);
                }
            }
        }
        out
    }

    #[test]
    fn every_letter_a_marker_depends_on_is_accounted_for() {
        // Derived from the marker tables rather than hand-listed. What it proves
        // is a coverage CLAIM: every letter the markers actually depend on is
        // either folded from a documented look-alike, or explicitly declared to
        // have none in Cyrillic and Greek.
        let alphabet = marker_alphabet();

        // The control, and it is not decoration. A derivation that read nothing
        // -- a renamed const, a filter that excludes everything -- would iterate
        // an empty set and pass, which is the exact shape of a sweep that
        // scanned zero files and reported no findings. Assert the derivation
        // actually reached the tables before trusting anything it says.
        assert!(
            alphabet.len() >= 20,
            "the marker alphabet came back with only {} letters, which means the \
             derivation stopped reading the tables rather than that the tables \
             shrank: {alphabet:?}",
            alphabet.len()
        );

        for letter in alphabet {
            match look_alike(letter) {
                Some(k) => assert_eq!(
                    fold_label(&k.to_string()),
                    letter.to_string(),
                    "the marker tables depend on '{letter}' and its look-alike \
                     U+{:04X} does not fold to it",
                    k as u32
                ),
                None => assert!(
                    LETTERS_WITH_NO_LOOK_ALIKE.contains(&letter),
                    "the marker tables gained '{letter}' and there is no look-alike \
                     fixture for it: add one to look_alike(), or -- after checking \
                     that Cyrillic and Greek really offer none -- declare it in \
                     LETTERS_WITH_NO_LOOK_ALIKE"
                ),
            }
        }
    }

    #[test]
    fn the_no_look_alike_list_is_honest() {
        // A letter cannot sit on the exemption list while a fixture exists for
        // it, or the list would become a place to hide gaps.
        for c in LETTERS_WITH_NO_LOOK_ALIKE {
            assert!(
                look_alike(*c).is_none(),
                "'{c}' is declared to have no look-alike but look_alike() returns one"
            );
        }
    }
}
