import requests
from typing import List, Optional
from ..models import Finding, Severity, Category
from ..config import SECURITY_HEADERS_RULES, LEAKED_SERVER_HEADERS, DEFAULT_TIMEOUT, DEFAULT_USER_AGENT
from ..remediation.fix_generator import FixGenerator
from .csp_evaluator import CSPEvaluator


class HeaderScanner:
    """
    Audits HTTP response headers, Cookie security flags, CORS, and runs deep CSP analysis.
    """

    def __init__(self, target_url: str, timeout: int = DEFAULT_TIMEOUT):
        self.target_url = target_url
        self.timeout = timeout
        self.headers = {"User-Agent": DEFAULT_USER_AGENT}

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            response = requests.get(
                self.target_url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
        except requests.exceptions.RequestException as e:
            findings.append(
                Finding(
                    title="Failed to Connect to Target URL",
                    category=Category.HEADERS.value,
                    severity=Severity.CRITICAL,
                    cvss_score=9.0,
                    description=f"Could not connect to {self.target_url}. Error: {str(e)}",
                    remediation="Verify that the target server is running, the URL is valid, and network connectivity is established.",
                    location=self.target_url,
                )
            )
            return findings

        resp_headers = response.headers

        # 1. Check Missing Security Headers & attach fix snippets
        for header, rule in SECURITY_HEADERS_RULES.items():
            if header not in resp_headers:
                severity = Severity(rule["severity"])
                if header == "Strict-Transport-Security" and not self.target_url.startswith("https://"):
                    severity = Severity.LOW
                    desc = f"{rule['description']} (Note: The tested target URL uses HTTP. HSTS requires HTTPS)."
                else:
                    desc = rule["description"]

                findings.append(
                    Finding(
                        title=rule["title"],
                        category=Category.HEADERS.value,
                        severity=severity,
                        cvss_score=rule.get("cvss"),
                        description=desc,
                        remediation=rule["remediation"],
                        location=f"HTTP Headers -> {header}",
                        cwe_id=rule.get("cwe"),
                        reference=rule.get("reference"),
                        fix_snippet=FixGenerator.get_header_fix(header),
                    )
                )
            elif header == "Content-Security-Policy":
                # Deep CSP Evaluation
                csp_val = resp_headers["Content-Security-Policy"]
                evaluator = CSPEvaluator(csp_val, self.target_url)
                findings.extend(evaluator.evaluate())

        # 2. Check Information Leakage Headers
        leaked = []
        for header in LEAKED_SERVER_HEADERS:
            if header in resp_headers:
                val = resp_headers[header]
                leaked.append(f"{header}: {val}")

        if leaked:
            findings.append(
                Finding(
                    title="Server Version & Technology Information Disclosure",
                    category=Category.HEADERS.value,
                    severity=Severity.LOW,
                    cvss_score=3.1,
                    description="The server leaks internal technology/version details in response headers, which assists attackers in reconnaissance.",
                    evidence="\n".join(leaked),
                    remediation="Configure your web server (Nginx, Apache, IIS, Express, etc.) to suppress server tokens and remove 'Server' / 'X-Powered-By' headers.",
                    location="HTTP Response Headers",
                    cwe_id="CWE-200",
                    reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                )
            )

        # 3. Check CORS Wildcard Configuration
        cors_origin = resp_headers.get("Access-Control-Allow-Origin")
        if cors_origin == "*":
            findings.append(
                Finding(
                    title="Overly Permissive CORS Policy (Wildcard '*')",
                    category=Category.HEADERS.value,
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description="The Access-Control-Allow-Origin header is set to wildcard '*', allowing any external domain to read cross-origin responses.",
                    evidence=f"Access-Control-Allow-Origin: {cors_origin}",
                    remediation="Restrict CORS origin to trusted domains rather than wildcard '*' unless explicitly intended for public APIs.",
                    location="HTTP Headers -> Access-Control-Allow-Origin",
                    cwe_id="CWE-942",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                )
            )

        # 4. Check Cookie Security Flags (Secure, HttpOnly, SameSite)
        set_cookie_headers = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw, "headers") else []
        if not set_cookie_headers and "Set-Cookie" in resp_headers:
            set_cookie_headers = [resp_headers["Set-Cookie"]]

        for cookie_str in set_cookie_headers:
            cookie_parts = [p.strip() for p in cookie_str.split(";")]
            cookie_name = cookie_parts[0].split("=")[0] if cookie_parts else "cookie"
            cookie_lower = cookie_str.lower()

            issues = []
            if "httponly" not in cookie_lower:
                issues.append("Missing 'HttpOnly' flag (vulnerable to XSS cookie theft)")
            if "secure" not in cookie_lower:
                issues.append("Missing 'Secure' flag (cookie transmitted over plain HTTP)")
            if "samesite" not in cookie_lower:
                issues.append("Missing 'SameSite' attribute (vulnerable to CSRF)")

            if issues:
                findings.append(
                    Finding(
                        title=f"Insecure Cookie Configuration for '{cookie_name}'",
                        category=Category.HEADERS.value,
                        severity=Severity.MEDIUM if "httponly" not in cookie_lower else Severity.LOW,
                        cvss_score=5.0 if "httponly" not in cookie_lower else 3.0,
                        description=f"Cookie '{cookie_name}' is set without optimal security attributes: " + ", ".join(issues),
                        evidence=cookie_str,
                        remediation="Ensure all sensitive cookies have 'Secure', 'HttpOnly', and 'SameSite=Lax' (or 'Strict') attributes configured.",
                        location=f"Set-Cookie: {cookie_name}",
                        cwe_id="CWE-614",
                        reference="https://owasp.org/www-community/controls/SecureFlag",
                    )
                )

        return findings
