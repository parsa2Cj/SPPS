"""
HTTP Methods and Advanced CORS Misconfiguration Scanner
"""

import requests
from typing import List
from ..models import Finding, Severity, Category
from ..config import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT


class CORSMethodsScanner:
    """
    Tests for dangerous enabled HTTP methods (e.g. TRACE) and dangerous CORS misconfigurations.
    """

    def __init__(self, target_url: str, timeout: int = DEFAULT_TIMEOUT):
        self.target_url = target_url
        self.timeout = timeout
        self.headers = {"User-Agent": DEFAULT_USER_AGENT}

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Test TRACE method (XST - Cross Site Tracing)
        try:
            resp_trace = requests.request(
                "TRACE",
                self.target_url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp_trace.status_code == 200 and "message/http" in resp_trace.headers.get("Content-Type", ""):
                findings.append(
                    Finding(
                        title="Dangerous HTTP TRACE Method Enabled (XST)",
                        category=Category.HTTP_METHODS_CORS.value,
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        description="HTTP TRACE method is enabled on the server. Attackers can exploit this via Cross-Site Tracing (XST) to bypass HttpOnly cookie protections.",
                        evidence=f"HTTP TRACE -> 200 OK",
                        remediation="Disable HTTP TRACE method in your web server configuration (e.g. TraceEnable off in Apache).",
                        location=f"{self.target_url} (HTTP TRACE)",
                        cwe_id="CWE-16",
                        reference="https://owasp.org/www-community/attacks/Cross_Site_Tracing",
                    )
                )
        except Exception:
            pass

        # 2. Test Advanced CORS Reflection (Arbitrary Origin Reflection with Credentials)
        test_origins = [
            "https://attacker-evil-domain.com",
            "null",
        ]

        for test_origin in test_origins:
            try:
                cors_headers = {
                    "User-Agent": DEFAULT_USER_AGENT,
                    "Origin": test_origin,
                    "Access-Control-Request-Method": "POST",
                }
                resp_cors = requests.options(
                    self.target_url,
                    headers=cors_headers,
                    timeout=self.timeout,
                    verify=False,
                )

                allow_origin = resp_cors.headers.get("Access-Control-Allow-Origin")
                allow_creds = resp_cors.headers.get("Access-Control-Allow-Credentials", "").lower()

                if allow_origin == test_origin and allow_creds == "true":
                    findings.append(
                        Finding(
                            title=f"Critical CORS Vulnerability: Dynamic Origin Reflection with Credentials ({test_origin})",
                            category=Category.HTTP_METHODS_CORS.value,
                            severity=Severity.CRITICAL,
                            cvss_score=8.8,
                            description=f"The server dynamically reflects untrusted Origin '{test_origin}' and enables Access-Control-Allow-Credentials: true. Malicious websites can make authenticated API requests and read private user data.",
                            evidence=f"Origin: {test_origin}\nAccess-Control-Allow-Origin: {allow_origin}\nAccess-Control-Allow-Credentials: true",
                            remediation="Implement a strict whitelist of trusted origin domains instead of reflecting arbitrary origins with credentials.",
                            location="CORS Policy -> Preflight OPTIONS",
                            cwe_id="CWE-942",
                            reference="https://portswigger.net/web-security/cors",
                        )
                    )
                    break
            except Exception:
                continue

        return findings
