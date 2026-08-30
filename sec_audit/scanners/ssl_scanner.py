import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List
from ..models import Finding, Severity, Category
from ..config import DEFAULT_TIMEOUT


class SSLScanner:
    """
    Analyzes SSL/TLS certificate validity, expiry, SAN names, and protocol versions.
    """

    def __init__(self, target_url: str, timeout: int = DEFAULT_TIMEOUT):
        self.target_url = target_url
        self.timeout = timeout

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(self.target_url)

        if parsed.scheme.lower() != "https":
            findings.append(
                Finding(
                    title="Website Not Using HTTPS by Default",
                    category=Category.SSL_TLS.value,
                    severity=Severity.HIGH,
                    description=f"The URL {self.target_url} uses unencrypted HTTP communication. Data transmitted in cleartext can be intercepted or manipulated.",
                    remediation="Install an SSL/TLS certificate (e.g. Let's Encrypt) and enforce HTTPS redirection on your web server.",
                    location=self.target_url,
                    cwe_id="CWE-319",
                    reference="https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                )
            )
            return findings

        hostname = parsed.hostname
        port = parsed.port or 443

        if not hostname:
            return findings

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    tls_version = ssock.version()
                    cipher = ssock.cipher()

                    # Re-get parsed certificate dict with verification enabled to check certificate validity
                    verify_context = ssl.create_default_context()
                    is_valid = True
                    verification_error = None
                    try:
                        with socket.create_connection((hostname, port), timeout=self.timeout) as vsock:
                            with verify_context.wrap_socket(vsock, server_hostname=hostname) as vssock:
                                parsed_cert = vssock.getpeercert()
                    except Exception as ve:
                        is_valid = False
                        verification_error = str(ve)
                        parsed_cert = None

                    # Check TLS Protocol Version
                    if tls_version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                        findings.append(
                            Finding(
                                title=f"Outdated TLS Protocol Version ({tls_version})",
                                category=Category.SSL_TLS.value,
                                severity=Severity.HIGH,
                                description=f"The server negotiated {tls_version}, which is deprecated and contains known cryptographic weaknesses (POODLE, BEAST, etc.).",
                                evidence=f"Protocol: {tls_version}, Cipher: {cipher[0] if cipher else 'N/A'}",
                                remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 on your server. Enable only TLS 1.2 and TLS 1.3.",
                                location=f"{hostname}:{port}",
                                cwe_id="CWE-326",
                                reference="https://ssl-config.mozilla.org/",
                            )
                        )

                    # Check Certificate Verification
                    if not is_valid and verification_error:
                        findings.append(
                            Finding(
                                title="SSL Certificate Verification Failed (Untrusted / Self-Signed)",
                                category=Category.SSL_TLS.value,
                                severity=Severity.HIGH,
                                description=f"The certificate presented by {hostname} failed validation. Reason: {verification_error}",
                                evidence=verification_error,
                                remediation="Deploy a valid SSL/TLS certificate issued by a trusted Certificate Authority (CA).",
                                location=f"{hostname}:{port}",
                                cwe_id="CWE-295",
                                reference="https://cwe.mitre.org/data/definitions/295.html",
                            )
                        )

                    # Check Expiry Date if cert was parsed
                    if parsed_cert and "notAfter" in parsed_cert:
                        not_after_str = parsed_cert["notAfter"]
                        # Example format: 'May 25 12:00:00 2025 GMT'
                        try:
                            expiry_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            days_remaining = (expiry_date - now).days

                            if days_remaining < 0:
                                findings.append(
                                    Finding(
                                        title="SSL Certificate Expired",
                                        category=Category.SSL_TLS.value,
                                        severity=Severity.CRITICAL,
                                        description=f"The SSL/TLS certificate expired on {not_after_str} ({abs(days_remaining)} days ago). Browsers will block access.",
                                        evidence=f"Expiry Date: {not_after_str}",
                                        remediation="Immediately renew and deploy your SSL/TLS certificate.",
                                        location=f"{hostname}:{port}",
                                        cwe_id="CWE-298",
                                    )
                                )
                            elif days_remaining <= 14:
                                findings.append(
                                    Finding(
                                        title=f"SSL Certificate Expiring Soon ({days_remaining} Days Remaining)",
                                        category=Category.SSL_TLS.value,
                                        severity=Severity.HIGH if days_remaining <= 7 else Severity.MEDIUM,
                                        description=f"The SSL/TLS certificate will expire on {not_after_str}.",
                                        evidence=f"Days remaining: {days_remaining}",
                                        remediation="Renew your SSL certificate before it expires to prevent service disruption.",
                                        location=f"{hostname}:{port}",
                                        cwe_id="CWE-298",
                                    )
                                )
                        except Exception:
                            pass

        except Exception as e:
            findings.append(
                Finding(
                    title="SSL/TLS Handshake Error",
                    category=Category.SSL_TLS.value,
                    severity=Severity.MEDIUM,
                    description=f"Unable to complete SSL handshake with {hostname}:{port}. Error: {str(e)}",
                    remediation="Check server port configuration and firewall rules for port 443.",
                    location=f"{hostname}:{port}",
                )
            )

        return findings
