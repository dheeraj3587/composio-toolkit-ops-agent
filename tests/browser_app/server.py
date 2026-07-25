"""Two-origin loopback HTTP server for the Phase 4 browser suite.

Why a real server instead of Playwright route fulfilment: the security tests must
prove that the production guard blocked an off-domain request. If the test itself
fulfils every request, nothing is proven. Here the third-party origin is a genuinely
separate HTTP server that RECORDS every request it receives, so "the beacon never
arrived" is an observation rather than an assumption.

Both servers bind to 127.0.0.1 on an ephemeral port and serve only in-memory
content. No credentials, no external network, no vendor account.
"""

from __future__ import annotations

import json
import shutil
import ssl
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from tests.browser_app import pages
from tests.browser_app.pages import (
    ACCEPTED_EMAIL,
    ACCEPTED_PASSWORD,
    FAKE_API_TOKEN,
    MAGIC_LINK_PATH,
    OTP_CODE,
)
from tests.browser_app.tls import SelfSignedCert, generate_self_signed_cert

# How long the deliberately slow route stalls before responding.
SLOW_RESPONSE_SECONDS = 2.0

# RFC 2606 reserved `.example` names: guaranteed never to resolve on the public
# internet, yet accepted by the production host guard (which rejects bare IPs and
# loopback). Chromium maps them to 127.0.0.1 via --host-resolver-rules.
VENDOR_HOST = "app.vendor-test.example"
THIRD_PARTY_HOST = "tracker.thirdparty-test.example"

# A real, minimal 1x1 transparent PNG, so an <img> request is a genuine image
# fetch that the guard must classify as a passive resource.
_ONE_BY_ONE_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"  # pragma: allowlist secret
    "1f15c4890000000b49444154789c6360000200000500017a5eab3f0000"  # pragma: allowlist secret
    "000049454e44ae426082"
)


@dataclass
class RequestLog:
    """Thread-safe record of requests a server received."""

    _paths: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, path: str) -> None:
        with self._lock:
            self._paths.append(path)

    @property
    def paths(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._paths)

    def hit(self, needle: str) -> bool:
        """Whether any recorded path contains ``needle``."""

        return any(needle in path for path in self.paths)

    def clear(self) -> None:
        with self._lock:
            self._paths.clear()


class _Handler(BaseHTTPRequestHandler):
    """Base handler: silent logging, no server banner leakage."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Silence stderr access logs (they would pollute pytest output)."""

    def version_string(self) -> str:
        return "browser-test-app"

    def _send(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "text/html; charset=utf-8",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Deterministic tests need no caching anywhere.
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html: str, *, status: int = 200) -> None:
        origin = getattr(self.server, "third_party_origin", "")
        self._send(pages.substitute_third_party(html, origin).encode(), status=status)

    def _redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode() if length else ""
        return {key: values[0] for key, values in parse_qs(raw).items()}


class _VendorHandler(_Handler):
    """The application under automation."""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        log: RequestLog = self.server.request_log  # type: ignore[attr-defined]
        log.record(self.path)

        routes = {
            "/": pages.HOME,
            "/login": pages.LOGIN,
            "/email-first": pages.EMAIL_FIRST,
            "/password": pages.PASSWORD_STEP,
            "/bad-login": pages.WRONG_PASSWORD,
            "/otp-single": pages.OTP_SINGLE,
            "/otp-multiple": pages.OTP_MULTIPLE,
            "/magic-sent": pages.MAGIC_LINK_SENT,
            "/account-selection": pages.ACCOUNT_SELECTION,
            "/captcha": pages.CAPTCHA_GATE,
            "/captcha-frame": pages.CAPTCHA_FRAME,
            "/mfa": pages.MFA_GATE,
            "/home": pages.HOME,
            "/settings": pages.SETTINGS,
            "/developers": pages.DEVELOPERS,
            "/settings/api": pages.CREDENTIAL_PAGE,
            "/settings/billing-token": pages.CREDENTIAL_PAGE_WRONG_HEADING,
            "/settings/api-partial": pages.CREDENTIAL_PAGE_PARTIAL_TOKEN,
            "/spa": pages.SPA,
            "/spa/members": pages.SPA,
            "/spa/api": pages.SPA,
            "/iframe-login": pages.IFRAME_LOGIN,
            "/iframe-login-inner": pages.IFRAME_LOGIN_INNER,
            "/popup-oauth": pages.POPUP_OAUTH,
            "/oauth-popup": pages.OAUTH_POPUP,
            "/duplicate-buttons": pages.DUPLICATE_BUTTONS,
            "/hidden-controls": pages.HIDDEN_CONTROLS,
            "/disabled-controls": pages.DISABLED_CONTROLS,
            "/offscreen-controls": pages.OFFSCREEN_CONTROLS,
            "/form-controls": pages.FORM_CONTROLS,
            "/dialogs": pages.DIALOGS,
            "/downloads": pages.DOWNLOADS,
            "/off-domain-fetch": pages.OFF_DOMAIN_FETCH,
            "/off-domain-script": pages.OFF_DOMAIN_SCRIPT,
            "/off-domain-image": pages.OFF_DOMAIN_IMAGE,
            "/off-domain-link": pages.OFF_DOMAIN_LINK,
            "/crash": pages.CRASH_PAGE,
        }

        if path == MAGIC_LINK_PATH:
            # Opening the emailed link completes sign-in.
            self._redirect("/home")
            return
        if path == "/slow":
            time.sleep(SLOW_RESPONSE_SECONDS)
            self._html(pages.SLOW_PAGE)
            return
        if path == "/status/404":
            self._html(pages.NOT_FOUND, status=404)
            return
        if path == "/status/500":
            self._html(pages.SERVER_ERROR, status=500)
            return
        if path.startswith("/download/"):
            self._serve_download(path.rsplit("/", 1)[-1])
            return
        if path in routes:
            self._html(routes[path])
            return
        self._html(pages.NOT_FOUND, status=404)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        log: RequestLog = self.server.request_log  # type: ignore[attr-defined]
        # Record the PATH only: a form post carries the test password, and writing
        # it into a log the tests then assert over would defeat the purpose.
        log.record(path)
        form = self._form()

        if path == "/login":
            email = form.get("email", "")
            password = form.get("password", "")
            if email == ACCEPTED_EMAIL and password == ACCEPTED_PASSWORD:
                self._redirect("/home")
            else:
                self._redirect("/bad-login")
            return
        if path == "/email-first":
            self._redirect("/password" if form.get("email") else "/email-first")
            return
        if path in {"/otp-single", "/otp-multiple"}:
            submitted = form.get("otp") or "".join(
                form.get(f"code{index}", "") for index in range(6)
            )
            self._redirect("/home" if submitted == OTP_CODE else "/otp-single")
            return
        if path == "/form-controls":
            self._redirect("/home")
            return
        self._html(pages.NOT_FOUND, status=404)

    def _serve_download(self, filename: str) -> None:
        """Serve a download. Content is inert placeholder text, never a real key."""

        payloads = {
            "report.csv": (b"app,status\npipedrive,ok\n", "text/csv"),
            "id_rsa": (b"NOT-A-REAL-KEY-test-placeholder\n", "application/octet-stream"),
            "setup.exe": (b"MZ-test-placeholder\n", "application/octet-stream"),
        }
        body, content_type = payloads.get(filename, (b"", "application/octet-stream"))
        self._send(
            body,
            content_type=content_type,
            extra_headers={"Content-Disposition": f"attachment; filename={filename}"},
        )


class _ThirdPartyHandler(_Handler):
    """A separate origin that exists only to be blocked.

    Every request is recorded, so a test can assert an off-domain request never
    arrived. It never serves application content.
    """

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        log: RequestLog = self.server.request_log  # type: ignore[attr-defined]
        log.record(self.path)
        if path == "/pixel.png":
            self._send(_ONE_BY_ONE_PNG, content_type="image/png")
            return
        if path == "/analytics.js":
            self._send(
                b"window.__thirdPartyScriptRan = true;",
                content_type="application/javascript",
            )
            return
        if path == "/beacon":
            self._send(json.dumps({"received": True}).encode(), content_type="application/json")
            return
        self._send(b"<h1>Third party</h1>")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        log: RequestLog = self.server.request_log  # type: ignore[attr-defined]
        log.record(self.path)
        self._send(b"{}", content_type="application/json")


@dataclass(frozen=True, slots=True)
class BrowserTestApp:
    """Handles for a running two-origin test application."""

    vendor_origin: str
    third_party_origin: str
    vendor_host: str
    third_party_host: str
    vendor_port: int
    third_party_port: int
    vendor_log: RequestLog
    third_party_log: RequestLog

    def url(self, path: str) -> str:
        return f"{self.vendor_origin}{path}"

    def third_party_url(self, path: str) -> str:
        return f"{self.third_party_origin}{path}"

    @property
    def host_patterns(self) -> tuple[str, ...]:
        """The reviewed allowlist for this app: the vendor host ONLY.

        Deliberately real-looking hostnames rather than ``127.0.0.1``: the
        production guard REJECTS loopback and private IPs outright
        (``validate_allowed_domains`` raises "private or special IP domains are not
        allowed"), so an IP-based test app could never be allowlisted and the tests
        would prove nothing about host matching.
        """

        return (self.vendor_host,)

    @property
    def resolver_rules(self) -> str:
        """Chromium ``--host-resolver-rules`` mapping both names to loopback.

        This is what lets the test use ``.example`` hostnames — which the guard
        accepts — while every packet still stays on 127.0.0.1.
        """

        return f"MAP {self.vendor_host} 127.0.0.1,MAP {self.third_party_host} 127.0.0.1"

    @property
    def launch_args(self) -> list[str]:
        """Chromium args for the test app (loopback mapping + sandbox off in CI)."""

        return [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            f"--host-resolver-rules={self.resolver_rules}",
            # The test cert is self-signed; trusting it for these two hosts only is
            # narrower than disabling certificate checks globally.
            "--ignore-certificate-errors",
        ]


def _start(
    handler: type[_Handler], ssl_context: ssl.SSLContext | None
) -> tuple[ThreadingHTTPServer, threading.Thread, RequestLog]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    if ssl_context is not None:
        # TLS matters: the production host guard requires https, so a plain-HTTP
        # app would be refused before the host logic ran and the security tests
        # would pass without proving anything.
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    log = RequestLog()
    server.request_log = log  # type: ignore[attr-defined]
    server.third_party_origin = ""  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, log


@contextmanager
def browser_test_app(*, use_tls: bool = True) -> Iterator[BrowserTestApp]:
    """Run the vendor and third-party origins for the duration of a test.

    Defaults to HTTPS so the real allowlist path is exercised. ``use_tls=False``
    exists only for tests that specifically assert plain HTTP is refused.
    """

    certificate: SelfSignedCert | None = None
    context: ssl.SSLContext | None = None
    if use_tls:
        certificate = generate_self_signed_cert()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate.cert_path, certificate.key_path)

    scheme = "https" if use_tls else "http"
    vendor, vendor_thread, vendor_log = _start(_VendorHandler, context)
    third_party, third_party_thread, third_party_log = _start(_ThirdPartyHandler, context)
    vendor_port = int(vendor.server_address[1])
    third_party_port = int(third_party.server_address[1])
    # Distinct HOSTS, not merely distinct ports: the host policy matches on host.
    # These are RFC 2606 `.example` names (never resolvable on the public internet)
    # mapped to loopback by Chromium's resolver rules, because the production guard
    # refuses loopback/private IPs and so could never allowlist 127.0.0.1.
    vendor_authority = f"{VENDOR_HOST}:{vendor_port}"
    third_party_authority = f"{THIRD_PARTY_HOST}:{third_party_port}"
    third_party_origin = f"{scheme}://{third_party_authority}"
    vendor.third_party_origin = third_party_origin  # type: ignore[attr-defined]

    try:
        yield BrowserTestApp(
            vendor_origin=f"{scheme}://{vendor_authority}",
            third_party_origin=third_party_origin,
            vendor_host=VENDOR_HOST,
            third_party_host=THIRD_PARTY_HOST,
            vendor_port=vendor_port,
            third_party_port=third_party_port,
            vendor_log=vendor_log,
            third_party_log=third_party_log,
        )
    finally:
        for server, thread in ((vendor, vendor_thread), (third_party, third_party_thread)):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        if certificate is not None:
            shutil.rmtree(certificate.directory, ignore_errors=True)


__all__ = [
    "ACCEPTED_EMAIL",
    "ACCEPTED_PASSWORD",
    "FAKE_API_TOKEN",
    "MAGIC_LINK_PATH",
    "OTP_CODE",
    "SLOW_RESPONSE_SECONDS",
    "BrowserTestApp",
    "RequestLog",
    "browser_test_app",
]
