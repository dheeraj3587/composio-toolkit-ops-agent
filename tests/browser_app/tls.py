"""A throwaway self-signed certificate for the local test app.

This matters more than it looks. The production host guard requires
``scheme == "https"`` (see ``ops.browser_worker.is_allowed_browser_url``), so a
plain-HTTP test app would be rejected by the guard for the WRONG reason: every
"off-domain request blocked" assertion would pass without the host logic ever
being consulted, and the tests would prove nothing.

Serving real TLS on loopback makes the tests exercise the actual code path. The
key never leaves the process, the certificate lives for hours, and Chromium is
launched with ``ignore_https_errors`` for these tests only, so no trust store is
modified anywhere.
"""

from __future__ import annotations

import datetime
import ipaddress
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class SelfSignedCert:
    """Paths to a freshly generated certificate/key pair."""

    cert_path: Path
    key_path: Path
    directory: Path


def generate_self_signed_cert() -> SelfSignedCert:
    """Mint a short-lived cert covering ``localhost`` and ``127.0.0.1``.

    Covers both RFC 2606 ``.example`` hostnames the test app serves, because the
    app deliberately runs two ORIGINS so host-based policy decisions are genuinely
    exercised. 127.0.0.1 is included so direct-IP probes still work.
    """

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        # Deliberately short-lived: this is test material, not infrastructure.
        .not_valid_after(now + datetime.timedelta(hours=6))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("app.vendor-test.example"),
                    x509.DNSName("tracker.thirdparty-test.example"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    directory = Path(tempfile.mkdtemp(prefix="browser-test-tls-"))
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            # No passphrase: it is an ephemeral test key, and a passphrase here
            # would be a second secret with nothing to protect.
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    # Owner-only, out of habit and because it costs nothing.
    cert_path.chmod(0o600)
    key_path.chmod(0o600)
    return SelfSignedCert(cert_path=cert_path, key_path=key_path, directory=directory)


__all__ = ["SelfSignedCert", "generate_self_signed_cert"]
