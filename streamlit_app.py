"""Internal debugging ledger for the local Phase 0/1/2 workflow."""

from __future__ import annotations

import hashlib
import html
import json
import os
from pathlib import Path
from typing import Any, Literal, cast

import streamlit as st
from pydantic import ValidationError

from ops.cli import create_dry_run, get_run_status, get_run_timeline
from ops.models import CompanyProfile, OperationsRequest, validate_vault_reference
from ops.redaction import install_redacting_filter

ROOT = Path(__file__).resolve().parent
SNAPSHOT_MANIFEST = ROOT / "data" / "p1" / "SNAPSHOT.json"
UNCONFIGURED_WORK_EMAIL_REF = "vault://company/work_email/unconfigured"

# Streamlit configures logging during startup, after package import. This
# idempotent call ensures those handlers receive the application redactor too.
install_redacting_filter()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_snapshot_provenance() -> dict[str, Any]:
    """Load and verify the immutable P1 snapshot manifest."""

    try:
        manifest = json.loads(SNAPSHOT_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"available": False, "verified": False}

    expected = {
        "results_sha256": ROOT / "data" / "p1" / "results.json",
        "coverage_sha256": ROOT / "data" / "p1" / "composio_coverage.json",
    }
    verified = all(
        path.is_file() and manifest.get(key) == _sha256(path) for key, path in expected.items()
    )
    return {
        "available": True,
        "verified": verified,
        "source_repository": manifest.get("source_repository", "Unavailable"),
        "source_commit": manifest.get("source_commit", "Unavailable"),
        "results_sha256": manifest.get("results_sha256", "Unavailable"),
        "coverage_sha256": manifest.get("coverage_sha256", "Unavailable"),
        "copied_at": manifest.get("copied_at", "Unavailable"),
    }


def _short(value: Any, size: int = 12) -> str:
    text = str(value)
    return f"{text[:size]}…" if len(text) > size else text


def _html(value: Any) -> str:
    """Escape dynamic ledger text before inserting it into styled HTML."""

    return html.escape(str(value), quote=True)


def _work_email_reference_default() -> str:
    """Return only a validated reference; raw invalid environment values stay hidden."""

    candidate = os.getenv("COMPANY_WORK_EMAIL_REF")
    if candidate is None:
        return UNCONFIGURED_WORK_EMAIL_REF
    try:
        return validate_vault_reference(candidate.strip())
    except ValueError:
        return UNCONFIGURED_WORK_EMAIL_REF


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        fields = sorted({".".join(str(part) for part in error["loc"]) for error in exc.errors()})
        return f"Please review: {', '.join(fields)}."
    return "The local ledger could not complete that operation. Check the CLI doctor output."


st.set_page_config(
    page_title="Operations Ledger · Composio",
    page_icon="◒",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
<style>
    :root {
        --paper: #f3eddf;
        --paper-deep: #e7dcc7;
        --ink: #17211d;
        --ink-soft: #47504a;
        --amber: #b45f18;
        --amber-pale: #efd4a9;
        --line: rgba(23, 33, 29, 0.18);
        --quiet: rgba(255, 252, 245, 0.58);
    }

    .stApp {
        color: var(--ink);
        background-color: var(--paper);
        background-image:
            linear-gradient(rgba(23, 33, 29, 0.025) 1px, transparent 1px),
            radial-gradient(circle at 88% 9%, rgba(180, 95, 24, 0.10), transparent 26rem);
        background-size: 100% 31px, 100% 100%;
    }

    [data-testid="stHeader"] { background: transparent; }
    [data-testid="stAppViewContainer"] > .main { background: transparent; }
    [data-testid="stMainBlockContainer"] {
        max-width: 1180px;
        padding: 3.4rem 3.2rem 5rem;
    }

    html, body, [class*="st-"] {
        font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
    }

    h1, h2, h3, .ledger-display {
        font-family: "Iowan Old Style", "Baskerville", "Times New Roman", serif !important;
        font-weight: 500 !important;
        letter-spacing: -0.035em !important;
        color: var(--ink) !important;
    }

    h2 { font-size: clamp(1.65rem, 3vw, 2.6rem) !important; }
    p, label, [data-testid="stCaptionContainer"] { color: var(--ink-soft); }

    .ledger-hero {
        position: relative;
        padding: 0.5rem 0 2.8rem;
        animation: ledger-reveal 520ms cubic-bezier(.22,.75,.2,1) both;
    }

    .ledger-kicker {
        margin-bottom: 1.15rem;
        color: var(--amber);
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.17em;
        text-transform: uppercase;
    }

    .ledger-title {
        max-width: 820px;
        margin: 0;
        font-family: "Iowan Old Style", "Baskerville", "Times New Roman", serif;
        font-size: clamp(3.15rem, 7.2vw, 6.8rem);
        font-weight: 500;
        line-height: 0.86;
        letter-spacing: -0.065em;
        text-wrap: balance;
    }

    .ledger-deck {
        max-width: 650px;
        margin: 1.7rem 0 0 18%;
        color: var(--ink-soft);
        font-family: "Iowan Old Style", "Baskerville", "Times New Roman", serif;
        font-size: 1.24rem;
        line-height: 1.5;
    }

    .ledger-rule {
        border: 0;
        border-top: 1px solid var(--ink);
        margin: 0.5rem 0 2.4rem;
    }

    .ledger-stamp {
        display: inline-flex;
        align-items: center;
        gap: 0.55rem;
        padding: 0.48rem 0.72rem;
        border: 1px solid var(--ink);
        border-radius: 999px;
        color: var(--ink);
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.1em;
        text-transform: uppercase;
    }

    .ledger-stamp::before {
        width: 0.48rem;
        height: 0.48rem;
        border-radius: 50%;
        background: var(--amber);
        content: "";
    }

    .ledger-index {
        color: var(--amber);
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.14em;
        text-transform: uppercase;
    }

    .ledger-card {
        min-height: 11rem;
        padding: 1.25rem 1.3rem;
        border-top: 2px solid var(--ink);
        background: var(--quiet);
    }

    .ledger-card--future {
        border-top-color: var(--amber);
        background: rgba(239, 212, 169, 0.24);
    }

    .ledger-card h3 {
        margin: 1.55rem 0 0.5rem;
        font-size: 1.5rem;
    }

    .ledger-card p {
        margin: 0;
        font-size: 0.78rem;
        line-height: 1.55;
    }

    .ledger-meta {
        padding: 0.85rem 0;
        border-bottom: 1px solid var(--line);
    }

    .ledger-meta strong {
        display: block;
        margin-bottom: 0.25rem;
        color: var(--ink);
        font-family: "Iowan Old Style", "Baskerville", "Times New Roman", serif;
        font-size: 1.1rem;
        font-weight: 600;
    }

    .ledger-meta span { color: var(--ink-soft); font-size: 0.72rem; }
    .ledger-code { overflow-wrap: anywhere; font-size: 0.68rem; }

    [data-testid="stForm"] {
        padding: 1.65rem !important;
        border: 1px solid var(--ink) !important;
        border-radius: 0 !important;
        background: rgba(255, 252, 245, 0.62);
        box-shadow: 10px 10px 0 rgba(180, 95, 24, 0.11);
    }

    [data-baseweb="input"] > div,
    [data-baseweb="textarea"] > div,
    [data-baseweb="select"] > div {
        border-color: var(--line) !important;
        border-radius: 0 !important;
        background: rgba(255,255,255,0.38) !important;
    }

    .stButton button,
    [data-testid="stFormSubmitButton"] button {
        min-height: 2.8rem;
        border: 1px solid var(--ink) !important;
        border-radius: 0 !important;
        background: var(--ink) !important;
        color: var(--paper) !important;
        font-weight: 700 !important;
        letter-spacing: 0.035em;
        transition: transform 150ms ease, box-shadow 150ms ease;
    }

    .stButton button:hover,
    [data-testid="stFormSubmitButton"] button:hover {
        transform: translate(-2px, -2px);
        box-shadow: 4px 4px 0 var(--amber);
    }

    button:focus-visible, input:focus-visible, textarea:focus-visible {
        outline: 3px solid var(--amber) !important;
        outline-offset: 2px;
    }

    .ledger-event {
        display: grid;
        grid-template-columns: 5.5rem 1fr;
        gap: 1rem;
        padding: 1rem 0;
        border-top: 1px solid var(--line);
    }

    .ledger-event__mark {
        color: var(--amber);
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
    }

    .ledger-event__copy { color: var(--ink); font-size: 0.79rem; }

    @keyframes ledger-reveal {
        from { opacity: 0; transform: translateY(14px); }
        to { opacity: 1; transform: translateY(0); }
    }

    @media (max-width: 760px) {
        [data-testid="stMainBlockContainer"] { padding: 2.2rem 1.15rem 4rem; }
        .ledger-deck { margin-left: 0; }
        .ledger-title { font-size: clamp(3rem, 17vw, 5.2rem); }
    }

    @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
            scroll-behavior: auto !important;
            animation-duration: 0.01ms !important;
            animation-iteration-count: 1 !important;
            transition-duration: 0.01ms !important;
        }
    }
</style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    """
<header class="ledger-hero">
  <div class="ledger-kicker">Composio / internal debugging desk / phase 0–2</div>
  <h1 class="ledger-title">Access work,<br>without the theatre.</h1>
  <p class="ledger-deck">A quiet, auditable ledger for verifying the immutable P1 snapshot and its deterministic access route. It records local dry runs only; it does not contact vendors or operate browsers.</p>
</header>
<hr class="ledger-rule">
""",
    unsafe_allow_html=True,
)

stamp_col, note_col = st.columns([1, 2.45], vertical_alignment="center")
with stamp_col:
    st.markdown('<span class="ledger-stamp">Local only</span>', unsafe_allow_html=True)
with note_col:
    st.caption(
        "Phase boundary — verified P1 lookup and deterministic routing are active. "
        "Browser, HITL, email, and provider execution remain deliberately unavailable."
    )

st.write("")
st.markdown('<div class="ledger-index">01 / source register</div>', unsafe_allow_html=True)
st.header("The research this ledger inherits")

provenance = load_snapshot_provenance()
source_col, commit_col, lock_col = st.columns([1.45, 1, 0.9])
with source_col:
    st.markdown(
        f"""<div class="ledger-meta"><strong>P1 snapshot</strong><span>{_html(provenance.get("source_repository", "Unavailable"))}</span></div>""",
        unsafe_allow_html=True,
    )
with commit_col:
    st.markdown(
        f"""<div class="ledger-meta"><strong>{_html(_short(provenance.get("source_commit", "Unavailable")))}</strong><span>source commit</span></div>""",
        unsafe_allow_html=True,
    )
with lock_col:
    integrity_label = (
        "Hashes verified" if provenance.get("verified") else "Verification unavailable"
    )
    st.markdown(
        f"""<div class="ledger-meta"><strong>{integrity_label}</strong><span>copied {_html(provenance.get("copied_at", "Unavailable"))}</span></div>""",
        unsafe_allow_html=True,
    )

with st.expander("Snapshot provenance details"):
    st.markdown(
        f"""
<strong>Results SHA-256</strong><br>
<span class="ledger-code">{_html(provenance.get("results_sha256", "Unavailable"))}</span>

<strong>Coverage SHA-256</strong><br>
<span class="ledger-code">{_html(provenance.get("coverage_sha256", "Unavailable"))}</span>
""",
        unsafe_allow_html=True,
    )

st.write("")
st.write("")
st.markdown('<div class="ledger-index">02 / intake</div>', unsafe_allow_html=True)
st.header("Open a dry-run entry")
st.caption(
    "The intake stores references and operational context—never passwords, tokens, keys, or email contents."
)

with st.form("dry_run_intake", clear_on_submit=False):
    form_left, form_right = st.columns([1, 1])
    with form_left:
        app_name = st.text_input("App name", placeholder="Example App")
        legal_name = st.text_input(
            "Company legal name",
            value=os.getenv("COMPANY_LEGAL_NAME", "Composio"),
        )
        website = st.text_input(
            "Company website",
            value=os.getenv("COMPANY_WEBSITE", "https://composio.dev"),
        )
    with form_right:
        work_email_ref = st.text_input(
            "Work email vault reference",
            value=_work_email_reference_default(),
            help="A vault:// reference only. Do not paste an email password or token.",
        )
        scope_policy = st.selectbox(
            "Requested scope policy",
            options=("maximum", "recommended", "minimum"),
        )
        callback_urls_text = st.text_area(
            "Callback URLs",
            placeholder="https://example.com/oauth/callback\nOne URL per line",
            height=68,
        )

    use_case = st.text_area(
        "Operational use case",
        value="Evaluate documented API access for integration readiness.",
        height=92,
    )
    st.checkbox("Dry run — no external actions", value=True, disabled=True)
    submitted = st.form_submit_button("Record local run", use_container_width=True)

if submitted:
    try:
        request = OperationsRequest(
            app_name=app_name,
            company=CompanyProfile(
                legal_name=legal_name,
                website=website,
                work_email_ref=work_email_ref,
                use_case=use_case,
                callback_urls=[
                    item.strip() for item in callback_urls_text.splitlines() if item.strip()
                ],
            ),
            requested_scope_policy=cast(
                Literal["minimum", "recommended", "maximum"],
                scope_policy,
            ),
            dry_run=True,
        )
        created_run = create_dry_run(request)
        st.session_state["active_run_id"] = created_run["run_id"]
        st.success(f"Local run recorded: {created_run['run_id']}")
    except (OSError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
        st.error(_safe_error(exc))

st.write("")
st.write("")
st.markdown('<div class="ledger-index">03 / live register</div>', unsafe_allow_html=True)
st.header("Run status & sanitized timeline")

lookup_col, action_col = st.columns([3, 1], vertical_alignment="bottom")
with lookup_col:
    lookup_run_id = st.text_input(
        "Run ID",
        value=st.session_state.get("active_run_id", ""),
        placeholder="run_…",
    )
with action_col:
    load_run = st.button("Load run", use_container_width=True)

if load_run and lookup_run_id:
    st.session_state["active_run_id"] = lookup_run_id.strip()

active_run_id = st.session_state.get("active_run_id")
if active_run_id:
    try:
        active_run = get_run_status(active_run_id)
        timeline = get_run_timeline(active_run_id) if active_run else []
        if active_run:
            run_col, mode_col, route_col = st.columns(3)
            run_col.metric(
                "State", str(active_run.get("status", "unknown")).replace("_", " ").title()
            )
            mode_col.metric("Mode", "Local dry run")
            route_col.metric("Access route", active_run.get("access_route") or "Not researched")
            st.caption(
                f"{active_run.get('app_name', 'Unknown app')} · {active_run.get('run_id')} · external actions: false"
            )

            if timeline:
                for index, event in enumerate(timeline, start=1):
                    payload = event.get("payload") or {}
                    summary = (
                        payload.get("status", "recorded")
                        if isinstance(payload, dict)
                        else "recorded"
                    )
                    st.markdown(
                        f"""<div class="ledger-event"><div class="ledger-event__mark">{index:02d} / {_html(str(event.get("event_type", "event")).replace("_", " "))}</div><div class="ledger-event__copy">{_html(summary)} · {_html(event.get("created_at") or "timestamp recorded locally")}</div></div>""",
                        unsafe_allow_html=True,
                    )
            else:
                st.info("No audit events have been recorded for this run.")
        else:
            st.warning("No local run matches that ID.")
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        st.error(_safe_error(exc))
else:
    st.info("Record a dry run or enter a run ID to inspect the local ledger.")

st.write("")
st.write("")
st.markdown('<div class="ledger-index">04 / phase register</div>', unsafe_allow_html=True)
st.header("What is—and is not—operational")

phase_one, phase_browser, phase_email, phase_output = st.columns(4)
with phase_one:
    st.markdown(
        """<div class="ledger-card"><span class="ledger-index">Available now</span><h3>Verified routing</h3><p>Strict contracts, snapshot integrity, deterministic access classification, encrypted vault boundary, and sanitized audit storage.</p></div>""",
        unsafe_allow_html=True,
    )
with phase_browser:
    st.markdown(
        """<div class="ledger-card ledger-card--future"><span class="ledger-index">Unavailable · later phase</span><h3>Browser</h3><p>No session is started, no portal is visited, and no credential page is inspected in Phase 0/1.</p></div>""",
        unsafe_allow_html=True,
    )
with phase_email:
    st.markdown(
        """<div class="ledger-card ledger-card--future"><span class="ledger-index">Unavailable · later phase</span><h3>Email</h3><p>No vendor is contacted. Thread polling and controlled outreach remain explicit future capabilities.</p></div>""",
        unsafe_allow_html=True,
    )
with phase_output:
    st.markdown(
        """<div class="ledger-card ledger-card--future"><span class="ledger-index">Unavailable · later phase</span><h3>Output</h3><p>No IntegratorBundle exists until researched access and referenced credentials are truthfully available.</p></div>""",
        unsafe_allow_html=True,
    )

st.write("")
st.caption("INTERNAL OPERATIONS LEDGER · PHASE 0/1/2 · NO EXTERNAL PROVIDER ACTIONS")
