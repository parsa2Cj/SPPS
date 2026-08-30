import requests
from urllib.parse import urljoin
from typing import List
from ..models import Finding, Severity, Category
from ..config import SENSITIVE_PATHS, DEFAULT_TIMEOUT, DEFAULT_USER_AGENT


class SensitiveFilesScanner:
    """
    Safely probes for exposed configuration files, git metadata, and diagnostic endpoints.
    """

    def __init__(self, target_url: str, timeout: int = DEFAULT_TIMEOUT):
        self.target_url = target_url.rstrip("/") + "/"
        self.timeout = timeout
        self.headers = {"User-Agent": DEFAULT_USER_AGENT}

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        for item in SENSITIVE_PATHS:
            rel_path = item["path"].lstrip("/")
            test_url = urljoin(self.target_url, rel_path)

            try:
                resp = requests.get(
                    test_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                )

                if resp.status_code == 200:
                    content = resp.text

                    # Verify that response is not a generic HTML catch-all/SPA routing response
                    matches_keyword = any(kw.lower() in content.lower() for kw in item["keywords"])
                    content_type = resp.headers.get("Content-Type", "").lower()

                    # Special handling for robots.txt
                    if rel_path == "robots.txt":
                        disallows = [line.strip() for line in content.splitlines() if line.lower().startswith("disallow:")]
                        if disallows:
                            findings.append(
                                Finding(
                                    title="Robots.txt Discloses Hidden Paths",
                                    category=Category.EXPOSED_FILES.value,
                                    severity=Severity.INFO,
                                    description=f"robots.txt reveals {len(disallows)} disallowed paths which may provide directory intelligence to attackers.",
                                    evidence="\n".join(disallows[:10]) + ("\n..." if len(disallows) > 10 else ""),
                                    remediation="Ensure sensitive directories listed in robots.txt have proper authentication and authorization controls.",
                                    location=test_url,
                                    cwe_id="CWE-200",
                                )
                            )
                        continue

                    # For sensitive files (.env, .git, config backups), ensure signature matches
                    if matches_keyword:
                        # Avoid reporting standard HTML error pages as .env leaks
                        if rel_path == ".env" and "<!doctype html" in content.lower():
                            continue

                        snippet = content[:300].strip()
                        findings.append(
                            Finding(
                                title=f"Exposed Sensitive File: {item['name']}",
                                category=Category.EXPOSED_FILES.value,
                                severity=Severity(item["severity"]),
                                description=f"Publicly accessible sensitive file found at {test_url}. This can lead to complete server compromise or data breach.",
                                evidence=f"HTTP 200 OK\nSnippet:\n{snippet}",
                                remediation=f"Immediately delete or restrict web access to '{item['path']}' in your web server configuration (Nginx, Apache, etc.).",
                                location=test_url,
                                cwe_id="CWE-552",
                                reference="https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                            )
                        )

            except requests.exceptions.RequestException:
                # Connection / timeout errors during path probing are safely ignored
                continue

        return findings
