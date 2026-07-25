"""HTML for every scenario the Phase 4 browser suite exercises.

Kept separate from the server so the markup is reviewable on its own. Each page is
minimal and deliberate: it exists to make ONE harness behaviour observable.

Nothing here is a real credential. ``FAKE_API_TOKEN`` is a fixed 40-hex string
chosen to match the reviewed Pipedrive capture pattern so the deterministic
capture path can be tested without a vendor account.
"""

from __future__ import annotations

# --- Test constants (obviously fake, never real credentials) -------------------
ACCEPTED_EMAIL = "ops@example.test"
ACCEPTED_PASSWORD = "local-test-password-not-real"  # pragma: allowlist secret
OTP_CODE = "483920"
FAKE_API_TOKEN = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"  # pragma: allowlist secret
MAGIC_LINK_PATH = "/magic-confirm"

# Injected into pages that must attempt an off-domain request. The host is
# substituted at serve time so the third-party origin's real port is used.
_THIRD_PARTY_PLACEHOLDER = "__THIRD_PARTY__"


def _doc(title: str, body: str, *, head: str = "") -> str:
    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>{title}</title>{head}</head><body>{body}</body></html>"
    )


# --- Authentication -----------------------------------------------------------
LOGIN = _doc(
    "Sign in",
    "<h1>Sign in</h1>"
    "<form action='/login' method='post'>"
    "<label for='email'>Email</label>"
    "<input id='email' type='email' name='email' autocomplete='username'>"
    "<label for='password'>Password</label>"
    "<input id='password' type='password' name='password' autocomplete='current-password'>"
    "<button type='submit'>Sign in</button>"
    "</form>",
)

EMAIL_FIRST = _doc(
    "Sign in",
    "<h1>Sign in</h1>"
    "<form action='/email-first' method='post'>"
    "<label for='email'>Email</label>"
    "<input id='email' type='email' name='email' autocomplete='username'>"
    "<button type='submit'>Continue</button>"
    "</form>",
)

PASSWORD_STEP = _doc(
    "Enter password",
    "<h1>Enter your password</h1>"
    "<form action='/login' method='post'>"
    "<input type='hidden' name='email' value='ops@example.test'>"
    "<label for='password'>Password</label>"
    "<input id='password' type='password' name='password' autocomplete='current-password'>"
    "<button type='submit'>Log in</button>"
    "</form>",
)

WRONG_PASSWORD = _doc(
    "Sign in",
    "<h1>Sign in</h1>"
    "<p class='error' role='alert'>Your password is incorrect. Please try again.</p>"
    "<form action='/login' method='post'>"
    "<input type='email' name='email' autocomplete='username'>"
    "<input type='password' name='password' autocomplete='current-password'>"
    "<button type='submit'>Sign in</button>"
    "</form>",
)

OTP_SINGLE = _doc(
    "Verify",
    "<h1>Check your email</h1>"
    "<p>Enter the 6-digit verification code we sent you.</p>"
    "<form action='/otp-single' method='post'>"
    "<label for='otp'>Verification code</label>"
    "<input id='otp' name='otp' autocomplete='one-time-code' inputmode='numeric'>"
    "<button type='submit'>Verify</button>"
    "</form>",
)

OTP_MULTIPLE = _doc(
    "Verify",
    "<h1>Check your email</h1>"
    "<p>Enter the 6-digit verification code we sent you.</p>"
    "<form action='/otp-multiple' method='post'>"
    + "".join(
        f"<input name='code{index}' inputmode='numeric' maxlength='1' "
        f"aria-label='Digit {index + 1}'>"
        for index in range(6)
    )
    + "<button type='submit'>Verify</button></form>",
)

MAGIC_LINK_SENT = _doc(
    "Check your email",
    "<h1>Check your email</h1><p>We emailed you a sign-in link. Open it to finish signing in.</p>",
)

ACCOUNT_SELECTION = _doc(
    "Choose an account",
    "<h1>Choose an account</h1>"
    "<p>Select which workspace to continue with.</p>"
    "<button name='account' value='personal'>Personal workspace</button>"
    "<button name='account' value='team'>Team workspace</button>",
)

CAPTCHA_GATE = _doc(
    "Verify you are human",
    "<h1>Verify you are human</h1>"
    "<div class='g-recaptcha' data-sitekey='local-test'></div>"
    "<iframe title='reCAPTCHA challenge' src='/captcha-frame'></iframe>"
    "<button type='button'>I am not a robot</button>",
)

CAPTCHA_FRAME = _doc(
    "reCAPTCHA",
    "<p>Select every square containing a traffic light.</p><button>Verify</button>",
)

MFA_GATE = _doc(
    "Two-factor authentication",
    "<h1>Two-factor authentication</h1>"
    "<p>Approve the request in your authenticator app, then continue.</p>"
    "<button type='button'>I approved it</button>",
)

# --- Post-login application ---------------------------------------------------
HOME = _doc(
    "Home",
    "<h1>Welcome back</h1><nav><a href='/settings'>Settings</a> <a href='/spa'>Workspace</a></nav>",
)

SETTINGS = _doc(
    "Settings",
    "<h1>Settings</h1>"
    "<nav><a href='/developers'>Developers</a> <a href='/settings/api'>API</a></nav>",
)

DEVELOPERS = _doc(
    "Developers",
    "<h1>Developers</h1><p>Build integrations.</p><a href='/settings/api'>API</a>",
)

# The reviewed credential-management page. The token is a FAKE 40-hex value that
# matches the reviewed capture pattern, in a read-only input, behind a heading the
# capture spec requires.
CREDENTIAL_PAGE = _doc(
    "API",
    "<h1>API</h1>"
    "<h2>Your personal API token</h2>"
    f"<input name='api_token' readonly value='{FAKE_API_TOKEN}'>"
    "<button type='button'>Regenerate token</button>",
)

# A near-miss credential page: right shape, WRONG heading. Capture must refuse it.
CREDENTIAL_PAGE_WRONG_HEADING = _doc(
    "Billing",
    f"<h1>Billing</h1><input name='api_token' readonly value='{FAKE_API_TOKEN}'>",
)

# A near-miss token: too short for the reviewed pattern, so a PARTIAL regex match
# must not be accepted (this is why capture requires fullmatch).
CREDENTIAL_PAGE_PARTIAL_TOKEN = _doc(
    "API",
    "<h1>API</h1><h2>Your personal API token</h2><input name='api_token' readonly value='a1b2c3'>",
)

# --- SPA navigation (history API, no document request) -------------------------
SPA = _doc(
    "Workspace",
    "<h1 id='view-title'>Overview</h1>"
    "<nav>"
    "<button id='go-members' type='button'>Members</button>"
    "<button id='go-api' type='button'>API settings</button>"
    "</nav>"
    "<div id='view'>Overview content</div>",
    head=(
        "<script>"
        "function render(name, title, body){"
        " history.pushState({}, '', name);"
        " document.getElementById('view-title').textContent = title;"
        " document.getElementById('view').textContent = body;"
        "}"
        "window.addEventListener('DOMContentLoaded', function(){"
        " document.getElementById('go-members').addEventListener('click', function(){"
        "  render('/spa/members', 'Members', 'Members content'); });"
        " document.getElementById('go-api').addEventListener('click', function(){"
        "  setTimeout(function(){ render('/spa/api', 'API settings',"
        "   'Your personal API token lives here'); }, 250); });"
        "});"
        "</script>"
    ),
)

# --- Frames -------------------------------------------------------------------
IFRAME_LOGIN = _doc(
    "Sign in",
    "<h1>Sign in</h1><p>Authentication is handled in the frame below.</p>"
    "<iframe title='Login frame' name='login-frame' src='/iframe-login-inner'></iframe>",
)

IFRAME_LOGIN_INNER = _doc(
    "Login frame",
    "<form action='/login' method='post'>"
    "<input type='email' name='email' autocomplete='username'>"
    "<input type='password' name='password' autocomplete='current-password'>"
    "<button type='submit'>Sign in</button>"
    "</form>",
)

# --- Popup OAuth --------------------------------------------------------------
POPUP_OAUTH = _doc(
    "Connect",
    "<h1>Connect your account</h1><button id='open-oauth' type='button'>Continue with SSO</button>",
    head=(
        "<script>"
        "window.addEventListener('DOMContentLoaded', function(){"
        " document.getElementById('open-oauth').addEventListener('click', function(){"
        "  window.open('/oauth-popup', 'oauth', 'width=500,height=600'); });"
        "});"
        "</script>"
    ),
)

OAUTH_POPUP = _doc(
    "Authorize",
    "<h1>Authorize access</h1><p>Grant read access to your workspace.</p>"
    "<button type='button'>Authorize</button>",
)

# --- Ambiguous / awkward controls ---------------------------------------------
DUPLICATE_BUTTONS = _doc(
    "Duplicate controls",
    "<h1>Duplicate controls</h1>"
    "<section><h2>Personal</h2><button type='button' data-testid='save-personal'>Save</button>"
    "</section>"
    "<section><h2>Team</h2><button type='button' data-testid='save-team'>Save</button></section>",
)

HIDDEN_CONTROLS = _doc(
    "Hidden controls",
    "<h1>Hidden controls</h1>"
    "<button type='button' style='display:none'>Hidden by display</button>"
    "<button type='button' hidden>Hidden attribute</button>"
    "<div style='visibility:hidden'><button type='button'>Hidden by visibility</button></div>"
    "<button type='button'>Visible control</button>",
)

DISABLED_CONTROLS = _doc(
    "Disabled controls",
    "<h1>Disabled controls</h1>"
    "<button type='button' disabled>Disabled control</button>"
    "<input name='locked' disabled value='locked'>"
    "<button type='button'>Enabled control</button>",
)

OFFSCREEN_CONTROLS = _doc(
    "Offscreen controls",
    "<h1>Offscreen controls</h1>"
    "<div style='height:3000px'>Scroll down</div>"
    "<button id='far-below' type='button'>Far below control</button>",
)

FORM_CONTROLS = _doc(
    "Form controls",
    "<h1>Form controls</h1>"
    "<form action='/form-controls' method='post'>"
    "<label for='plan'>Plan</label>"
    "<select id='plan' name='plan'>"
    "<option value='free'>Free</option>"
    "<option value='pro'>Pro</option>"
    "<option value='enterprise'>Enterprise</option>"
    "</select>"
    "<label for='agree'>Agree</label>"
    "<input id='agree' type='checkbox' name='agree'>"
    "<button type='submit'>Save</button>"
    "</form>",
)

# --- Dialogs -----------------------------------------------------------------
DIALOGS = _doc(
    "Dialogs",
    "<h1>Dialogs</h1>"
    "<button id='do-alert' type='button'>Show alert</button>"
    "<button id='do-confirm' type='button'>Show confirm</button>"
    "<button id='do-prompt' type='button'>Show prompt</button>"
    "<p id='outcome'>none</p>",
    head=(
        "<script>"
        "window.addEventListener('DOMContentLoaded', function(){"
        " var out = document.getElementById('outcome');"
        " document.getElementById('do-alert').addEventListener('click', function(){"
        "  window.alert('Saved'); out.textContent = 'alert-done'; });"
        " document.getElementById('do-confirm').addEventListener('click', function(){"
        "  out.textContent = window.confirm('Delete this?') ? 'confirm-true' : 'confirm-false'; });"
        " document.getElementById('do-prompt').addEventListener('click', function(){"
        "  var v = window.prompt('Name?'); out.textContent = 'prompt-' + (v === null ? 'null' : v);"
        " });"
        "});"
        "</script>"
    ),
)

# --- Downloads ---------------------------------------------------------------
DOWNLOADS = _doc(
    "Downloads",
    "<h1>Downloads</h1>"
    "<a id='safe-download' href='/download/report.csv' download>Download report</a>"
    "<a id='key-download' href='/download/id_rsa' download>Download private key</a>"
    "<a id='exe-download' href='/download/setup.exe' download>Download installer</a>",
)

# --- Off-domain requests (the security surface) -------------------------------
# Each of these attempts a request to the SEPARATE third-party origin. The
# third-party server records every hit, so a blocked request is provable.
OFF_DOMAIN_FETCH = _doc(
    "Off-domain fetch",
    "<h1>Off-domain fetch</h1><p id='fetch-state'>idle</p>"
    "<button id='do-fetch' type='button'>Send beacon</button>",
    head=(
        "<script>"
        "window.addEventListener('DOMContentLoaded', function(){"
        " document.getElementById('do-fetch').addEventListener('click', function(){"
        f"  fetch('{_THIRD_PARTY_PLACEHOLDER}/beacon', {{mode: 'no-cors'}})"
        "   .then(function(){ document.getElementById('fetch-state').textContent = 'sent'; })"
        "   .catch(function(){ document.getElementById('fetch-state').textContent = 'blocked'; });"
        " });"
        "});"
        "</script>"
    ),
)

OFF_DOMAIN_SCRIPT = _doc(
    "Off-domain script",
    "<h1>Off-domain script</h1><p id='script-state'>idle</p>",
    head=f"<script src='{_THIRD_PARTY_PLACEHOLDER}/analytics.js'></script>",
)

OFF_DOMAIN_IMAGE = _doc(
    "Off-domain image",
    "<h1>Off-domain image</h1>"
    f"<img id='pixel' alt='tracking pixel' src='{_THIRD_PARTY_PLACEHOLDER}/pixel.png'>",
)

OFF_DOMAIN_LINK = _doc(
    "Off-domain link",
    "<h1>Off-domain link</h1>"
    f"<a id='leave' href='{_THIRD_PARTY_PLACEHOLDER}/elsewhere'>Go to third party</a>",
)

# --- Error and timing surfaces ------------------------------------------------
SLOW_PAGE = _doc("Slow", "<h1>Slow page</h1><p>This response was delayed.</p>")
NOT_FOUND = _doc("Not found", "<h1>Not found</h1><p>No such page.</p>")
SERVER_ERROR = _doc("Server error", "<h1>Server error</h1><p>Something broke.</p>")

# A page whose renderer can be crashed on demand, to prove a browser crash is
# reported as a TYPED failure rather than an opaque exception.
CRASH_PAGE = _doc(
    "Crash",
    "<h1>Crash test</h1><p>Navigating to chrome://crash terminates this renderer.</p>",
)


def substitute_third_party(html: str, third_party_origin: str) -> str:
    """Point off-domain markup at the real third-party origin."""

    return html.replace(_THIRD_PARTY_PLACEHOLDER, third_party_origin)


__all__ = [
    "ACCEPTED_EMAIL",
    "ACCEPTED_PASSWORD",
    "ACCOUNT_SELECTION",
    "CAPTCHA_FRAME",
    "CAPTCHA_GATE",
    "CRASH_PAGE",
    "CREDENTIAL_PAGE",
    "CREDENTIAL_PAGE_PARTIAL_TOKEN",
    "CREDENTIAL_PAGE_WRONG_HEADING",
    "DEVELOPERS",
    "DIALOGS",
    "DISABLED_CONTROLS",
    "DOWNLOADS",
    "DUPLICATE_BUTTONS",
    "EMAIL_FIRST",
    "FAKE_API_TOKEN",
    "FORM_CONTROLS",
    "HIDDEN_CONTROLS",
    "HOME",
    "IFRAME_LOGIN",
    "IFRAME_LOGIN_INNER",
    "LOGIN",
    "MAGIC_LINK_PATH",
    "MAGIC_LINK_SENT",
    "MFA_GATE",
    "NOT_FOUND",
    "OAUTH_POPUP",
    "OFFSCREEN_CONTROLS",
    "OFF_DOMAIN_FETCH",
    "OFF_DOMAIN_IMAGE",
    "OFF_DOMAIN_LINK",
    "OFF_DOMAIN_SCRIPT",
    "OTP_CODE",
    "OTP_MULTIPLE",
    "OTP_SINGLE",
    "PASSWORD_STEP",
    "POPUP_OAUTH",
    "SERVER_ERROR",
    "SETTINGS",
    "SLOW_PAGE",
    "SPA",
    "WRONG_PASSWORD",
    "substitute_third_party",
]
