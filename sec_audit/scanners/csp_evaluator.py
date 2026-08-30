"""
Deep Content-Security-Policy (CSP) Analyzer and Evaluator
"""

from typing import List, Dict
from ..models import Finding, Severity, Category


class CSPEvaluator:
    """
    Parses and evaluates Content-Security-Policy (CSP) headers for security weaknesses,
    such as 'unsafe-inline', 'unsafe-eval', missing object-src, or wildcards.
    """

    def __init__(self, csp_header_value: str, target_url: str):
        self.csp_value = csp_header_value.strip()
        self.target_url = target_url

    def evaluate(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self.csp_value:
            return findings

        # Parse directives into a dictionary
        directives: Dict[str, List[str]] = {}
        raw_directives = self.csp_value.split(";")
        for raw_d in raw_directives:
            parts = raw_d.strip().split()
            if parts:
                name = parts[0].lower()
                values = [v.lower() for v in parts[1:]]
                directives[name] = values

        # 1. Check for 'unsafe-inline' in script-src / default-src
        script_src = directives.get("script-src", directives.get("default-src", []))
        if "'unsafe-inline'" in script_src:
            findings.append(
                Finding(
                    title="CSP Contains 'unsafe-inline' in script-src",
                    category=Category.CSP.value,
                    severity=Severity.HIGH,
                    cvss_score=7.1,
                    description="The Content-Security-Policy allows 'unsafe-inline' scripts, which significantly weakens XSS protection by permitting execution of inline scripts and event handlers.",
                    evidence=f"script-src: {' '.join(script_src)}",
                    remediation="Remove 'unsafe-inline' and use cryptographic nonces (nonce-...) or SHA-256 hashes for legitimate inline scripts.",
                    location=f"CSP -> script-src",
                    cwe_id="CWE-1021",
                    reference="https://content-security-policy.com/unsafe-inline/",
                )
            )

        # 2. Check for 'unsafe-eval' in script-src
        if "'unsafe-eval'" in script_src:
            findings.append(
                Finding(
                    title="CSP Contains 'unsafe-eval' in script-src",
                    category=Category.CSP.value,
                    severity=Severity.MEDIUM,
                    cvss_score=5.5,
                    description="The CSP policy allows string-to-code execution (eval, Function constructor, setTimeout with string), increasing vulnerability to code injection.",
                    evidence=f"script-src: {' '.join(script_src)}",
                    remediation="Refactor application code to eliminate dynamic eval() calls and remove 'unsafe-eval' from CSP.",
                    location="CSP -> script-src",
                    cwe_id="CWE-95",
                    reference="https://content-security-policy.com/unsafe-eval/",
                )
            )

        # 3. Check for wildcard '*' in script-src or default-src
        if "*" in script_src:
            findings.append(
                Finding(
                    title="CSP Uses Wildcard '*' in script-src",
                    category=Category.CSP.value,
                    severity=Severity.HIGH,
                    cvss_score=7.4,
                    description="Using a wildcard '*' in script-src allows loading scripts from ANY external domain on the internet.",
                    evidence=f"script-src: {' '.join(script_src)}",
                    remediation="Replace wildcard '*' with specific trusted origin domains or 'self'.",
                    location="CSP -> script-src",
                    cwe_id="CWE-1021",
                )
            )

        # 4. Check for missing object-src
        if "object-src" not in directives:
            if "default-src" not in directives or directives["default-src"] != ["'none'"]:
                findings.append(
                    Finding(
                        title="CSP Missing 'object-src' Directive",
                        category=Category.CSP.value,
                        severity=Severity.MEDIUM,
                        cvss_score=4.8,
                        description="Missing object-src directive allows loading legacy Flash/Java/ActiveX plugins or SVG object embeddings.",
                        evidence=f"Directives: {', '.join(directives.keys())}",
                        remediation="Add \"object-src 'none';\" to your Content-Security-Policy.",
                        location="CSP -> object-src",
                        cwe_id="CWE-1021",
                    )
                )

        # 5. Check for missing frame-ancestors or base-uri
        if "frame-ancestors" not in directives:
            findings.append(
                Finding(
                    title="CSP Missing 'frame-ancestors' Directive",
                    category=Category.CSP.value,
                    severity=Severity.LOW,
                    cvss_score=3.5,
                    description="Without frame-ancestors, the site may be framed by external malicious pages if X-Frame-Options is also missing.",
                    remediation="Add \"frame-ancestors 'self';\" or \"frame-ancestors 'none';\" to your CSP.",
                    location="CSP -> frame-ancestors",
                    cwe_id="CWE-1021",
                )
            )

        if "base-uri" not in directives:
            findings.append(
                Finding(
                    title="CSP Missing 'base-uri' Directive",
                    category=Category.CSP.value,
                    severity=Severity.LOW,
                    cvss_score=3.0,
                    description="Missing base-uri directive allows injection of <base> tags that alter relative URL resolution.",
                    remediation="Add \"base-uri 'self';\" to your CSP header.",
                    location="CSP -> base-uri",
                    cwe_id="CWE-1021",
                )
            )

        return findings
