"""
Automated unit tests for SecAudit 2.0 Enterprise
"""

import os
import tempfile
import unittest
from sec_audit.models import ScanResult, Severity, Category, Finding
from sec_audit.scanners.sast_scanner import SASTScanner
from sec_audit.scanners.iac_scanner import IaCScanner
from sec_audit.scanners.license_scanner import LicenseScanner
from sec_audit.scanners.csp_evaluator import CSPEvaluator
from sec_audit.remediation.fix_generator import FixGenerator
from sec_audit.reporting.json_reporter import JSONReporter
from sec_audit.reporting.html_reporter import HTMLReporter
from sec_audit.reporting.sarif_reporter import SARIFReporter


class TestSecAudit2(unittest.TestCase):

    def test_sast_scanner_secrets_and_injection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_code_path = os.path.join(tmpdir, "vulnerable.py")
            with open(sample_code_path, "w", encoding="utf-8") as f:
                f.write(
                    """
# OpenAI Key
openai_key = "sk-1234567890abcdef1234567890abcdef"

# Dangerous deserialization
import pickle
pickle.loads(b"data")

# DOM XSS / React
# dangerouslySetInnerHTML={{ __html: user_input }}
"""
                )

            scanner = SASTScanner(tmpdir)
            findings = scanner.scan()

            self.assertTrue(len(findings) >= 2)
            titles = [f.title for f in findings]
            self.assertTrue(any("OpenAI" in t for t in titles))
            self.assertTrue(any("Deserialization" in t for t in titles))

    def test_iac_dockerfile_audit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dockerfile_path = os.path.join(tmpdir, "Dockerfile")
            with open(dockerfile_path, "w", encoding="utf-8") as f:
                f.write(
                    """FROM node:latest
ENV DB_PASSWORD=my_hardcoded_pass123
CMD ["npm", "start"]
"""
                )

            scanner = IaCScanner(tmpdir)
            findings = scanner.scan()

            self.assertTrue(len(findings) >= 2)
            titles = [f.title for f in findings]
            self.assertTrue(any("latest" in t.lower() for t in titles))
            self.assertTrue(any("ENV" in t or "Secret" in t for t in titles))

    def test_csp_evaluator(self):
        weak_csp = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *;"
        evaluator = CSPEvaluator(weak_csp, "https://example.com")
        findings = evaluator.evaluate()

        self.assertTrue(len(findings) >= 3)
        titles = [f.title for f in findings]
        self.assertTrue(any("unsafe-inline" in t for t in titles))
        self.assertTrue(any("unsafe-eval" in t for t in titles))
        self.assertTrue(any("Wildcard" in t for t in titles))

    def test_fix_generator(self):
        nginx_fix = FixGenerator.get_header_fix("Strict-Transport-Security")
        self.assertIsNotNone(nginx_fix)
        self.assertIn("nginx", nginx_fix)
        self.assertIn("max-age=31536000", nginx_fix["nginx"])

    def test_sarif_export(self):
        res = ScanResult(target_url="https://example.com")
        res.findings.append(
            Finding(
                title="Missing HSTS",
                category="Headers",
                severity=Severity.HIGH,
                description="Test desc",
                remediation="Test fix",
                cwe_id="CWE-319",
                location="index.js:10",
            )
        )
        res.calculate_score()

        with tempfile.TemporaryDirectory() as tmpdir:
            sarif_file = os.path.join(tmpdir, "results.sarif")
            SARIFReporter(res).export(sarif_file)

            self.assertTrue(os.path.exists(sarif_file))
            with open(sarif_file, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertIn("SecAudit", content)
                self.assertIn("CWE-319", content)


if __name__ == "__main__":
    unittest.main()
