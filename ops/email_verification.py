"""Deterministic, provider-agnostic selection of signup/login verification email.

This module is the single authority for deciding *whether a given inbox message is
the verification message this run is waiting for*, and for extracting the one-time
secret it carries. It performs no I/O so every decision is reproducible and unit
testable.

Why this exists as its own boundary
-----------------------------------
An autonomous signup accepts a one-time code or magic link from an inbox and then
types it into a live provider page. That makes the inbox an *untrusted input
channel*: anyone can send mail to the connected address. Four independent bindings
must therefore hold before a secret is used, and each is checked here:

1. **Recency** — the message must be inside an explicit freshness window measured
   from the provider's own receive timestamp, not from a search query the mail
   provider may silently ignore.
2. **Recipient** — the message must have been delivered to the exact address this
   run signed up with (plus-tag aware), so another run's or another app's
   verification can never be consumed.
3. **Sender** — the sending domain must be inside the reviewed domain set for the
   app when the caller requires it.
4. **Link host** — a magic link must be HTTPS and its host must be inside the same
   reviewed host set, so a look-alike link in a spoofed email cannot be opened.

Gmail query semantics that motivated the design
-----------------------------------------------
Gmail's relative age operators accept only ``d`` (day), ``m`` (**month**) and
``y`` (year) - hours are not a supported unit, and ``m`` is *not* minutes. See
Google's "Refine searches in Gmail" reference:
https://support.google.com/mail/answer/7190 (content rephrased for compliance with
licensing restrictions). A query such as ``newer_than:1h`` is therefore not a valid
one-hour bound, and ``newer_than:30m`` silently means thirty *months*. Any
short-lived freshness bound must consequently be enforced in code against the
message timestamp; the server-side query may only ever be a coarse, valid
pre-filter. Gmail's own documentation also states that ``internalDate`` is the
epoch-millisecond receive time that determines inbox ordering and is more reliable
than the ``Date`` header
(https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages),
which is why ordering here is numeric over parsed timestamps rather than
lexicographic over provider strings.

Secret handling
---------------
Extracted codes and links are secrets with a very short useful life. They are
returned wrapped in ``SecretStr`` and are never placed on the value-free
``VerificationEvidence`` projection that callers log, persist, or return over an
API. Evidence carries a host, a code length, and identifiers only.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import getaddresses, parsedate_to_datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr

VerificationPurpose = Literal[
    "signup_confirmation",
    "login_verification",
    "email_otp",
]
VerificationSecretKind = Literal["link", "code"]
RecipientBindingStatus = Literal["exact", "canonical", "tag_conflict", "no_match"]

# Google treats these mail domains as dot-insensitive, so "a.b@gmail.com" and
# "ab@gmail.com" are the same mailbox. Applying that rule to any other domain
# would be wrong: for a non-Google domain the dots are significant, and folding
# them would let a DIFFERENT mailbox satisfy the recipient binding.
_DOT_INSENSITIVE_DOMAINS = frozenset({"gmail.com", "googlemail.com"})

# A message dated in the future is either clock skew or an attempt to win the
# newest-first ordering. A small tolerance is allowed; beyond it the message is
# rejected rather than trusted.
DEFAULT_CLOCK_SKEW_SECONDS = 300
# Hard ceiling on how old a one-time verification message may be. A caller may
# request less, never more, so a stale code can never be revived.
MAX_VERIFICATION_AGE_SECONDS = 3_600

_MAX_ADDRESS_LENGTH = 320
_MAX_LINK_LENGTH = 2_048
_MAX_SCAN_LENGTH = 200_000

# --- one-time code heuristics -------------------------------------------------
# Cue words a genuine one-time code sits next to. Word-bounded so "pin" does not
# match inside "shipping" and "code" does not match inside "encoded". Used both as
# the presence gate and for proximity scoring.
_OTP_CUE = re.compile(
    r"\b(?:one[\s-]?time|verification|verify|security|confirmation|confirm|access|"
    r"log[\s-]?in|login|sign[\s-]?in|authentication|auth|passcode|otp|pin|code)\b",
    re.IGNORECASE,
)
# A numeric code: 4-8 digits, optionally split once by a single space or hyphen
# ("123-456", "123 456"); never embedded in a longer number, word, URL, path,
# decimal, or version. A trailing sentence period is allowed (the code may end a
# sentence), but a "." or "-" or "/" FOLLOWED BY A DIGIT is not (that is a
# decimal/version/IP/path, not a code).
_OTP_CANDIDATE = re.compile(r"(?<![\w./-])(\d{3}[\s-]\d{3}|\d{4,8})(?![\w]|[./-]\d)")
# An alphanumeric code, trusted ONLY when directly attached to an explicit cue word.
# The cue is case-insensitive; the code stays uppercase-only so it cannot match a
# lowercase prose word.
_OTP_ALNUM_NEAR = re.compile(r"(?i:code|otp|passcode|pin)\b[^0-9A-Za-z]{0,12}([A-Z0-9]{5,8})\b")
_OTP_YEARISH = re.compile(r"^(?:19|20)\d{2}$")
_OTP_MAX_CUE_DISTANCE = 60

# --- verification link heuristics ---------------------------------------------
# A sign-in/confirmation email is one whose subject/body is about confirming a
# login, device, or new account.
_VERIFICATION_EMAIL_KEYWORDS = (
    "verify",
    "verification",
    "confirm",
    "sign in",
    "sign-in",
    "log in",
    "login",
    "new device",
    "new login",
    "activate",
    "authenticate",
    "secure your account",
    "it's you",
    "it is you",
    "complete your registration",
    "complete your signup",
    "complete your sign up",
    "finish setting up",
    "welcome to",
)
# URL tokens that mark the actual sign-in/verification link (not a footer link).
_VERIFICATION_LINK_HINTS = (
    "notification-station",
    "notifications/cta",
    "/cta/",
    "deliverymethod",
    "login-verify",
    "login_verify",
    "verify-email",
    "verify_email",
    "email-verification",
    "confirm-email",
    "confirm_email",
    "activate-account",
    "verification",
    "verify",
    "confirm",
    "secure-login",
    "signin",
    "sign-in",
    "one-time",
    "onetime",
    "magiclink",
    "magic-link",
    "activate",
    "sso",
    "auth",
    "token",
)
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+", re.IGNORECASE)
# Footer/marketing links to ignore when several URLs are present.
_LINK_STOPWORDS = (
    "unsubscribe",
    "privacy",
    "/legal",
    "terms",
    "help.",
    "/help",
    "support.",
    "cookie",
    "preferences",
    "manage-preferences",
)
# Static assets and open/click tracking that are never the sign-in link.
_LINK_ASSET_MARKERS = (
    "hsappstatic.net",
    "/emailimages/",
    "hubspotlinks.com",
    "/cto/",
    "sib.googleusercontent",
    "list-manage",
    "/track",
    "/open?",
    "pixel",
)
_ASSET_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".css",
    ".ico",
    ".woff",
    ".woff2",
    ".webp",
)


class VerificationEvidence(BaseModel):
    """Value-free projection of one accepted verification message.

    Everything here is safe to log, persist in a checkpoint, put in a ledger
    receipt, or return over the API. The secret itself is deliberately absent:
    only its kind, its length (for a code) and its host (for a link) appear.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )

    purpose: VerificationPurpose
    verification_kind: VerificationSecretKind
    message_id: str = Field(min_length=1, max_length=200)
    sender_domain: str = Field(default="", max_length=253)
    recipient_binding: RecipientBindingStatus
    sender_reviewed: bool
    received_at_ms: int = Field(ge=0)
    age_seconds: int = Field(ge=0)
    link_host: str = Field(default="", max_length=253)
    code_length: int = Field(default=0, ge=0, le=8)


@dataclass(frozen=True, slots=True)
class VerificationCandidate:
    """One inbox message being considered.

    ``subject`` and ``body`` may contain the one-time secret, so an instance of
    this class must stay inside the trusted process that read the inbox: never log
    it, never persist it, never place it on a workflow state or API model.
    """

    message_id: str
    sender: str
    recipients: tuple[str, ...]
    received_at: object
    subject: str
    body: str


@dataclass(frozen=True, slots=True)
class ResolvedVerification:
    """An accepted verification message and its secret."""

    secret: SecretStr
    evidence: VerificationEvidence


@dataclass(frozen=True, slots=True)
class VerificationDecision:
    """The outcome of examining every candidate, with a stable reason code."""

    resolved: ResolvedVerification | None
    reason_code: str
    examined: int = 0
    rejections: tuple[str, ...] = field(default=())

    @property
    def is_resolved(self) -> bool:
        return self.resolved is not None


@dataclass(frozen=True, slots=True)
class CanonicalAddress:
    """A parsed email address plus the comparable canonical form."""

    address: str
    local: str
    tag: str
    domain: str
    canonical_local: str


def canonical_address(value: object) -> CanonicalAddress | None:
    """Parse one address into its comparable canonical form, or ``None``.

    Returns ``None`` for anything that is not a single, syntactically safe
    address. The plus-tag is separated out because a signup identity is normally a
    tagged alias, and the tag is what distinguishes one provider's verification
    mail from another's.
    """

    if not isinstance(value, str):
        return None
    raw = value.strip().strip("<>").casefold()
    if not raw or len(raw) > _MAX_ADDRESS_LENGTH or raw.count("@") != 1:
        return None
    if any(character in raw for character in "\r\n\x00 \t"):
        return None
    local, domain = raw.split("@", 1)
    domain = domain.rstrip(".")
    if not local or not domain or "." not in domain or domain.startswith("."):
        return None
    tag = ""
    if "+" in local:
        local_base, tag = local.split("+", 1)
    else:
        local_base = local
    if not local_base:
        return None
    canonical_local = local_base
    if domain in _DOT_INSENSITIVE_DOMAINS:
        canonical_local = canonical_local.replace(".", "")
        if not canonical_local:
            return None
    return CanonicalAddress(
        address=f"{local}@{domain}",
        local=local,
        tag=tag,
        domain=domain,
        canonical_local=canonical_local,
    )


def parse_addresses(values: Sequence[object]) -> tuple[CanonicalAddress, ...]:
    """Parse a header-ish collection of addresses, dropping unparsable entries.

    Accepts the shapes a mail provider actually returns: a bare address, a
    ``Name <addr>`` display form, or a comma-separated header value.
    """

    raw: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip():
            raw.append(value)
    if not raw:
        return ()
    parsed: list[CanonicalAddress] = []
    for _display_name, address in getaddresses(raw):
        canonical = canonical_address(address)
        if canonical is not None and canonical.address not in {item.address for item in parsed}:
            parsed.append(canonical)
    return tuple(parsed)


def bind_recipient(
    expected: CanonicalAddress,
    observed: Sequence[CanonicalAddress],
) -> RecipientBindingStatus:
    """Decide whether a message was delivered to the run's signup identity.

    ``exact`` — an observed recipient carries the same mailbox *and* the same
    plus-tag; this is the strongest binding.
    ``canonical`` — an observed recipient is the same mailbox with no tag at all.
    Some providers strip the tag when they send, so this is accepted.
    ``tag_conflict`` — the same mailbox appeared but with a *different* tag, i.e.
    the message belongs to another signup. Rejected.
    ``no_match`` — no observed recipient is this mailbox.

    Note that a mail API does not perform the alias expansion the Gmail web UI
    does, so comparison is done on parsed addresses rather than by trusting a
    server-side ``to:`` filter.
    """

    conflict = False
    canonical_match = False
    for address in observed:
        if address.domain != expected.domain:
            continue
        if address.canonical_local != expected.canonical_local:
            continue
        if address.tag == expected.tag:
            return "exact"
        if not address.tag:
            canonical_match = True
        else:
            conflict = True
    if canonical_match:
        return "canonical"
    return "tag_conflict" if conflict else "no_match"


def parse_received_at_ms(value: object) -> int | None:
    """Parse a provider receive timestamp into epoch milliseconds (UTC).

    Handles every shape these payloads use in practice: epoch milliseconds, epoch
    seconds, an ISO-8601 string (``Z`` or offset), and an RFC-2822 ``Date`` header.
    Returns ``None`` when the value cannot be understood, which callers must treat
    as a rejection rather than as "very old" or "very new" - an unparsable
    timestamp must never be allowed to satisfy a freshness bound.
    """

    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _epoch_number_to_ms(float(value))
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw.isdigit():
        return _epoch_number_to_ms(float(raw))
    iso_candidate = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
    try:
        parsed = datetime.fromisoformat(iso_candidate)
    except ValueError:
        parsed = None
    if parsed is None:
        try:
            parsed = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.astimezone(UTC).timestamp() * 1000)


def _epoch_number_to_ms(value: float) -> int | None:
    """Interpret a numeric epoch as seconds or milliseconds, bounded to sane years.

    Bounds keep an absurd value (0, or a nanosecond epoch) from being accepted as
    a plausible receive time.
    """

    if value <= 0:
        return None
    # 1e12 ms is 2001; a value below that as ms would be implausible for mail, so
    # treat a small magnitude as seconds instead.
    milliseconds = value if value >= 1e11 else value * 1000
    if not 9.46e11 <= milliseconds <= 4.10e12:  # ~2000-01-01 .. ~2100-01-01
        return None
    return int(milliseconds)


def sender_domain_of(value: object) -> str:
    """Return the lowercased sender domain, or ``""`` when it cannot be parsed."""

    canonical = canonical_address(value)
    if canonical is not None:
        return canonical.domain
    if not isinstance(value, str):
        return ""
    match = re.search(r"@([A-Za-z0-9.-]+)", value)
    return match.group(1).rstrip(".").casefold() if match else ""


def host_matches(host: str, patterns: Sequence[str]) -> bool:
    """Match a host against exact names and left-edge ``*.parent`` wildcards.

    A wildcard matches strict subdomains and the parent itself, mirroring the
    browser host policy so the email boundary and the navigation boundary cannot
    disagree about what "reviewed" means.
    """

    normalized = host.rstrip(".").casefold()
    if not normalized:
        return False
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern:
            continue
        candidate = pattern.rstrip(".").casefold()
        if candidate.startswith("*."):
            parent = candidate[2:]
            if normalized == parent or normalized.endswith(f".{parent}"):
                return True
        elif normalized == candidate:
            return True
    return False


def extract_verification_code(subject: str, body: str) -> str | None:
    """Extract a one-time verification code from a verification email.

    Deterministic and local by design: a code is a short-lived secret and is never
    sent to a language model. Hardened against false positives - a numeric
    candidate is accepted only when it sits near a verification cue, subject-line
    codes are strongly preferred, split codes ("123-456") are normalized, and
    4-digit years or repeated-digit runs are rejected. Returns ``None`` rather
    than guessing when no candidate is clearly a code.
    """

    text = f"{subject}\n{body}"[:_MAX_SCAN_LENGTH]
    cue_positions = [match.start() for match in _OTP_CUE.finditer(text)]
    if not cue_positions:
        return None
    # An alphanumeric code attached to an explicit cue word wins outright.
    alnum = _OTP_ALNUM_NEAR.search(text)
    if alnum and not alnum.group(1).isdigit():
        return alnum.group(1)
    subject_boundary = len(subject) + 1
    best: str | None = None
    best_distance = 10**9
    for match in _OTP_CANDIDATE.finditer(text):
        normalized = re.sub(r"[\s-]", "", match.group(1))
        if not _plausible_numeric_code(normalized):
            continue
        distance = min(abs(match.start() - position) for position in cue_positions)
        if match.start() < subject_boundary:
            distance = min(distance, 15)  # subject codes frequently stand alone
        if distance < best_distance:
            best, best_distance = normalized, distance
    # Require the winning candidate to be reasonably near a cue; otherwise decline.
    if best is not None and best_distance <= _OTP_MAX_CUE_DISTANCE:
        return best
    return None


def _plausible_numeric_code(normalized: str) -> bool:
    if not normalized.isdigit() or not 4 <= len(normalized) <= 8:
        return False
    if len(normalized) == 4 and _OTP_YEARISH.match(normalized):
        return False  # a bare 4-digit year is almost never an issued one-time code
    if len(set(normalized)) == 1:
        return False  # 0000 / 111111: implausible as an issued code
    return True


def looks_like_verification_email(subject: str, body: str) -> bool:
    """Whether the message reads like a sign-in/confirmation email at all."""

    text = f"{subject}\n{body}"[:_MAX_SCAN_LENGTH].casefold()
    return any(keyword in text for keyword in _VERIFICATION_EMAIL_KEYWORDS)


def extract_verification_link(
    subject: str,
    body: str,
    *,
    allowed_host_patterns: Sequence[str] = (),
    require_reviewed_host: bool = False,
) -> str | None:
    """Extract a sign-in/confirmation magic link, optionally host-restricted.

    Returns the most likely verification URL and never a static asset, tracking
    pixel, or marketing/footer link. Only messages that read like a sign-in
    confirmation are considered, so ordinary mail is ignored.

    When ``require_reviewed_host`` is set, a candidate is additionally required to
    be HTTPS, free of embedded credentials, and hosted inside
    ``allowed_host_patterns``. That combination is what makes a link from a
    spoofed message unusable: even a perfectly worded email cannot direct the
    agent off the reviewed hosts for the app.
    """

    if not looks_like_verification_email(subject, body):
        return None
    # HTML bodies may still be entity-encoded; normalize the common ampersand.
    normalized = body.replace("&amp;", "&")[:_MAX_SCAN_LENGTH]
    candidates: list[str] = []
    for match in _URL_RE.finditer(normalized):
        url = match.group(0).rstrip(".,);]}'\"")
        if len(url) > _MAX_LINK_LENGTH:
            continue
        lowered = url.casefold()
        if any(stop in lowered for stop in _LINK_STOPWORDS):
            continue
        if any(marker in lowered for marker in _LINK_ASSET_MARKERS):
            continue
        if lowered.split("?", 1)[0].endswith(_ASSET_SUFFIXES):
            continue
        if require_reviewed_host and not is_safe_verification_link(url, allowed_host_patterns):
            continue
        candidates.append(url)
    if not candidates:
        return None
    # Prefer a URL whose path/query clearly marks it as the sign-in link.
    for url in candidates:
        if any(hint in url.casefold() for hint in _VERIFICATION_LINK_HINTS):
            return url
    # Otherwise fall back to the first real (non-asset, non-footer) link.
    return candidates[0]


def is_safe_verification_link(url: str, allowed_host_patterns: Sequence[str]) -> bool:
    """Whether a URL may be opened: HTTPS, credential-free, reviewed host."""

    if not isinstance(url, str) or not url or len(url) > _MAX_LINK_LENGTH:
        return False
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    if parsed.username or parsed.password:
        return False
    return host_matches(parsed.hostname, allowed_host_patterns)


def link_host(url: str) -> str:
    """Return only a link's host, so a token-bearing path is never surfaced."""

    try:
        return (urlsplit(url).hostname or "").rstrip(".").casefold()
    except ValueError:
        return ""


def select_verification(
    candidates: Sequence[VerificationCandidate],
    *,
    purpose: VerificationPurpose,
    expected_recipient: str,
    now_ms: int,
    max_age_seconds: int,
    allowed_host_patterns: Sequence[str] = (),
    reviewed_sender_patterns: Sequence[str] = (),
    require_reviewed_sender: bool = True,
    require_reviewed_link_host: bool = True,
    prefer_link: bool = True,
    consumed_message_ids: Sequence[str] = (),
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> VerificationDecision:
    """Pick the newest message that satisfies every binding, or refuse.

    Candidates are examined newest-first by parsed receive time. The first one
    that passes recency, recipient, sender, and secret-extraction checks wins.
    Anything ambiguous or unverifiable is rejected with a stable reason code
    instead of being used, because the consequence of a wrong choice is typing an
    attacker-supplied code or opening an attacker-supplied link.
    """

    expected = canonical_address(expected_recipient)
    if expected is None:
        return VerificationDecision(
            resolved=None, reason_code="verification_expected_recipient_invalid"
        )
    if max_age_seconds <= 0 or max_age_seconds > MAX_VERIFICATION_AGE_SECONDS:
        return VerificationDecision(resolved=None, reason_code="verification_age_bound_invalid")
    if require_reviewed_sender and not reviewed_sender_patterns:
        return VerificationDecision(
            resolved=None, reason_code="verification_reviewed_sender_set_missing"
        )
    if require_reviewed_link_host and not allowed_host_patterns:
        return VerificationDecision(
            resolved=None, reason_code="verification_reviewed_host_set_missing"
        )

    consumed = {str(item) for item in consumed_message_ids if item}
    ordered = _order_newest_first(candidates)
    rejections: list[str] = []

    for received_at_ms, candidate in ordered:
        message_id = str(candidate.message_id or "").strip()
        if not message_id:
            rejections.append("verification_message_id_missing")
            continue
        if message_id in consumed:
            rejections.append("verification_already_consumed")
            continue
        if received_at_ms is None:
            rejections.append("verification_timestamp_unparsable")
            continue
        age_ms = now_ms - received_at_ms
        if age_ms < -clock_skew_seconds * 1000:
            rejections.append("verification_message_future_dated")
            continue
        age_seconds = max(0, age_ms // 1000)
        if age_seconds > max_age_seconds:
            # Newest-first ordering means every remaining candidate is older.
            rejections.append("verification_message_stale")
            break
        binding = bind_recipient(expected, parse_addresses(candidate.recipients))
        if binding == "tag_conflict":
            rejections.append("verification_recipient_tag_conflict")
            continue
        if binding == "no_match":
            rejections.append("verification_recipient_mismatch")
            continue
        domain = sender_domain_of(candidate.sender)
        sender_reviewed = bool(domain) and host_matches(domain, reviewed_sender_patterns)
        if require_reviewed_sender and not sender_reviewed:
            rejections.append("verification_sender_not_reviewed")
            continue

        resolved = _extract_secret(
            candidate,
            purpose=purpose,
            prefer_link=prefer_link,
            allowed_host_patterns=allowed_host_patterns,
            require_reviewed_link_host=require_reviewed_link_host,
            message_id=message_id,
            sender_domain=domain,
            binding=binding,
            sender_reviewed=sender_reviewed,
            received_at_ms=received_at_ms,
            age_seconds=int(age_seconds),
        )
        if resolved is None:
            rejections.append("verification_secret_absent")
            continue
        return VerificationDecision(
            resolved=resolved,
            reason_code="verification_resolved",
            examined=len(ordered),
            rejections=tuple(rejections),
        )

    return VerificationDecision(
        resolved=None,
        reason_code=rejections[0] if rejections else "verification_message_not_found",
        examined=len(ordered),
        rejections=tuple(rejections),
    )


def _order_newest_first(
    candidates: Sequence[VerificationCandidate],
) -> tuple[tuple[int | None, VerificationCandidate], ...]:
    """Sort candidates by parsed receive time, newest first, unparsable last.

    Ordering is numeric on purpose. Sorting provider timestamp *strings*
    lexicographically silently misorders the moment two payload shapes appear
    (epoch seconds beside epoch milliseconds, or an ISO string beside either),
    which would let an older message be treated as the newest one.
    """

    stamped = [(parse_received_at_ms(item.received_at), item) for item in candidates]
    return tuple(
        sorted(
            stamped,
            key=lambda entry: (entry[0] is None, -(entry[0] or 0)),
        )
    )


def _extract_secret(
    candidate: VerificationCandidate,
    *,
    purpose: VerificationPurpose,
    prefer_link: bool,
    allowed_host_patterns: Sequence[str],
    require_reviewed_link_host: bool,
    message_id: str,
    sender_domain: str,
    binding: RecipientBindingStatus,
    sender_reviewed: bool,
    received_at_ms: int,
    age_seconds: int,
) -> ResolvedVerification | None:
    """Extract the link or code, preferring whichever the caller asked for."""

    subject = candidate.subject if isinstance(candidate.subject, str) else ""
    body = candidate.body if isinstance(candidate.body, str) else ""

    def _link() -> ResolvedVerification | None:
        url = extract_verification_link(
            subject,
            body,
            allowed_host_patterns=allowed_host_patterns,
            require_reviewed_host=require_reviewed_link_host,
        )
        if url is None:
            return None
        if require_reviewed_link_host and not is_safe_verification_link(url, allowed_host_patterns):
            return None
        return ResolvedVerification(
            secret=SecretStr(url),
            evidence=VerificationEvidence(
                purpose=purpose,
                verification_kind="link",
                message_id=message_id[:200],
                sender_domain=sender_domain[:253],
                recipient_binding=binding,
                sender_reviewed=sender_reviewed,
                received_at_ms=received_at_ms,
                age_seconds=age_seconds,
                link_host=link_host(url)[:253],
            ),
        )

    def _code() -> ResolvedVerification | None:
        code = extract_verification_code(subject, body)
        if code is None:
            return None
        return ResolvedVerification(
            secret=SecretStr(code),
            evidence=VerificationEvidence(
                purpose=purpose,
                verification_kind="code",
                message_id=message_id[:200],
                sender_domain=sender_domain[:253],
                recipient_binding=binding,
                sender_reviewed=sender_reviewed,
                received_at_ms=received_at_ms,
                age_seconds=age_seconds,
                code_length=len(code),
            ),
        )

    first, second = (_link, _code) if prefer_link else (_code, _link)
    return first() or second()


def gmail_freshness_query(
    *,
    now: datetime,
    max_age_seconds: int,
    recipient: str | None = None,
    sender_domain: str | None = None,
) -> str:
    """Build a VALID coarse Gmail pre-filter for a short freshness window.

    Gmail's relative age operators support only day, month, and year units, so an
    hour-scale bound cannot be expressed server-side; ``newer_than:1h`` is not a
    one-hour filter and ``newer_than:30m`` means thirty months. This therefore
    emits a documented ``after:YYYY/MM/DD`` bound with a one-day safety margin
    (covering time-zone interpretation of the date) and leaves the real,
    short-lived bound to be enforced in code against each message's own receive
    timestamp.
    """

    if max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be positive")
    span_days = max(1, (max_age_seconds + 86_399) // 86_400)
    cutoff = now.astimezone(UTC) - timedelta(days=span_days + 1)
    parts = [f"after:{cutoff.strftime('%Y/%m/%d')}"]
    if recipient:
        parsed = canonical_address(recipient)
        if parsed is None:
            raise ValueError("recipient is not a valid address")
        parts.append(f"to:{parsed.address}")
    if sender_domain:
        domain = sender_domain.strip().lstrip("@").rstrip(".").casefold()
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", domain) or "." not in domain:
            raise ValueError("sender_domain is not a valid domain")
        parts.append(f"from:{domain}")
    return " ".join(parts)


__all__ = [
    "DEFAULT_CLOCK_SKEW_SECONDS",
    "MAX_VERIFICATION_AGE_SECONDS",
    "CanonicalAddress",
    "RecipientBindingStatus",
    "ResolvedVerification",
    "VerificationCandidate",
    "VerificationDecision",
    "VerificationEvidence",
    "VerificationPurpose",
    "VerificationSecretKind",
    "bind_recipient",
    "canonical_address",
    "extract_verification_code",
    "extract_verification_link",
    "gmail_freshness_query",
    "host_matches",
    "is_safe_verification_link",
    "link_host",
    "looks_like_verification_email",
    "parse_addresses",
    "parse_received_at_ms",
    "select_verification",
    "sender_domain_of",
]
