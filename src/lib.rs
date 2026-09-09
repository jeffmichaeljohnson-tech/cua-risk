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
        Some(l) if !l.trim().is_empty() => l.to_lowercase(),
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
        let l = label.to_lowercase();
        if WEB_2FA_MARKERS.iter().any(|m| l.contains(m)) {
            return true;
        }
    }
    false
}

fn web_label_is_irreversible(label: Option<&str>) -> bool {
    match label {
        Some(l) if !l.trim().is_empty() => {
            let l = l.to_lowercase();
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

    WebVerdict {
        tier: if reversible {
            Tier::Auto
        } else {
            Tier::Confirm
        },
        class: None,
    }
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
        Some(l) if !l.trim().is_empty() => l.to_lowercase(),
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
fn is_credential_target(ctx: &ActionContext<'_>) -> bool {
    // Password/credential field detection by role.
    if let Some(role) = ctx.element_role {
        let r = role.to_lowercase();
        if r.contains("securetextfield") || r.contains("password") {
            return true;
        }
    }

    // Password/credential field detection by label.
    if let Some(label) = ctx.element_label {
        let l = label.to_lowercase();
        if l.contains("password") || l.contains("credential") || l.contains("passphrase") {
            return true;
        }
        // Payment field.
        if l.contains("credit card")
            || l.contains("card number")
            || l.contains("cvv")
            || l.contains("payment")
        {
            return true;
        }
        // Sudo prompt.
        if l.contains("sudo") || l.contains("administrator password") {
            return true;
        }
    }

    false
}

fn is_tier2_context(ctx: &ActionContext<'_>) -> bool {
    // Credential / secure field detection (shared helper).
    if is_credential_target(ctx) {
        return true;
    }

    // Security settings (not credential fields per se, but Tier 2 for gui.*).
    if let Some(label) = ctx.element_label {
        let l = label.to_lowercase();
        if l.contains("filevault") || l.contains("firewall") || l.contains("gatekeeper") {
            return true;
        }
    }

    // Messaging apps: "Send" in mail/messages/slack = Tier 2.
    if let Some(bid) = ctx.app_bundle_id {
        if is_messaging_app(bid) {
            if let Some(label) = ctx.element_label {
                let l = label.to_lowercase();
                if l.contains("send") || l.contains("post") || l.contains("reply") {
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
        let n = name.to_lowercase();
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
