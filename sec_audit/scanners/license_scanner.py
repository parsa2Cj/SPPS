"""
Software License Compliance and Risk Scanner
Audits open-source licenses declared in project dependencies for legal/copyleft risks.
"""

import os
import json
import re
from typing import Dict, List, Tuple
from ..models import Finding, Severity, Category
from ..config import IGNORE_DIRS, RESTRICTIVE_LICENSES


class LicenseScanner:
    """
    Scans project dependency manifests to audit open-source licenses and flag copyleft/restrictive obligations.
    """

    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)

    def scan(self) -> Tuple[List[Finding], Dict[str, int]]:
        findings: List[Finding] = []
        license_counts: Dict[str, int] = {}

        if not os.path.exists(self.target_dir):
            return findings, license_counts

        # Parse package.json
        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

            for file in files:
                fpath = os.path.join(root, file)
                relpath = os.path.relpath(fpath, self.target_dir)

                if file.lower() == "package.json":
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            data = json.load(f)
                            lic = data.get("license")
                            if isinstance(lic, str):
                                lic_clean = lic.strip()
                                license_counts[lic_clean] = license_counts.get(lic_clean, 0) + 1
                                self._check_restrictive_license(lic_clean, relpath, findings)
                            elif isinstance(lic, dict):
                                lic_clean = lic.get("type", "Unknown")
                                license_counts[lic_clean] = license_counts.get(lic_clean, 0) + 1
                                self._check_restrictive_license(lic_clean, relpath, findings)
                    except Exception:
                        pass

                elif file.lower() == "composer.json":
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            data = json.load(f)
                            lic = data.get("license")
                            if isinstance(lic, str):
                                license_counts[lic] = license_counts.get(lic, 0) + 1
                                self._check_restrictive_license(lic, relpath, findings)
                            elif isinstance(lic, list):
                                for l in lic:
                                    license_counts[l] = license_counts.get(l, 0) + 1
                                    self._check_restrictive_license(l, relpath, findings)
                    except Exception:
                        pass

        return findings, license_counts

    def _check_restrictive_license(self, license_name: str, filepath: str, findings: List[Finding]) -> None:
        for r_lic in RESTRICTIVE_LICENSES:
            if r_lic.lower() in license_name.lower():
                findings.append(
                    Finding(
                        title=f"Strong Copyleft / Restrictive License Detected ({license_name})",
                        category=Category.LICENSE.value,
                        severity=Severity.LOW,
                        cvss_score=3.0,
                        description=f"Manifest '{filepath}' specifies license '{license_name}'. Strong copyleft licenses (GPL/AGPL) may require distributing derivative proprietary source code under the same license.",
                        evidence=f"File: {filepath}\nLicense: {license_name}",
                        remediation="Review commercial license compatibility with your organization's legal/compliance guidelines.",
                        location=filepath,
                        cwe_id="CWE-1104",
                    )
                )
                break
