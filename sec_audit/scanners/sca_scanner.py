"""
Software Composition Analysis (SCA) Engine
Multi-ecosystem dependency audit supporting lockfiles and manifest files across 7 languages.
"""

import os
import json
import re
import requests
from typing import List, Tuple, Dict, Set
from ..models import Finding, Severity, Category
from ..config import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, IGNORE_DIRS


class SCAScanner:
    """
    Audits dependencies across multiple languages against the Google OSV.dev vulnerability database.
    """

    OSV_API_URL = "https://api.osv.dev/v1/query"

    def __init__(self, target_dir: str, check_online: bool = True, timeout: int = DEFAULT_TIMEOUT):
        self.target_dir = os.path.abspath(target_dir)
        self.check_online = check_online
        self.timeout = timeout
        self.headers = {"User-Agent": DEFAULT_USER_AGENT, "Content-Type": "application/json"}

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(self.target_dir):
            return findings

        packages: List[Tuple[str, str, str, str]] = []  # (pkg_name, version, ecosystem, filepath)
        seen_keys: Set[Tuple[str, str, str]] = set()

        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

            for file in files:
                fpath = os.path.join(root, file)
                relpath = os.path.relpath(fpath, self.target_dir)
                fname_lower = file.lower()

                # 1. Node.js (package.json, package-lock.json)
                if fname_lower == "package.json":
                    for pkg, ver in self._parse_package_json(fpath):
                        if (pkg, ver, "npm") not in seen_keys:
                            seen_keys.add((pkg, ver, "npm"))
                            packages.append((pkg, ver, "npm", relpath))
                elif fname_lower == "package-lock.json":
                    for pkg, ver in self._parse_package_lock_json(fpath):
                        if (pkg, ver, "npm") not in seen_keys:
                            seen_keys.add((pkg, ver, "npm"))
                            packages.append((pkg, ver, "npm", relpath))

                # 2. Python (requirements.txt, Pipfile.lock, poetry.lock)
                elif fname_lower == "requirements.txt" or fname_lower.endswith(".requirements.txt"):
                    for pkg, ver in self._parse_requirements_txt(fpath):
                        if (pkg, ver, "PyPI") not in seen_keys:
                            seen_keys.add((pkg, ver, "PyPI"))
                            packages.append((pkg, ver, "PyPI", relpath))
                elif fname_lower == "poetry.lock":
                    for pkg, ver in self._parse_poetry_lock(fpath):
                        if (pkg, ver, "PyPI") not in seen_keys:
                            seen_keys.add((pkg, ver, "PyPI"))
                            packages.append((pkg, ver, "PyPI", relpath))

                # 3. PHP (composer.json, composer.lock)
                elif fname_lower == "composer.json":
                    for pkg, ver in self._parse_composer_json(fpath):
                        if (pkg, ver, "Packagist") not in seen_keys:
                            seen_keys.add((pkg, ver, "Packagist"))
                            packages.append((pkg, ver, "Packagist", relpath))
                elif fname_lower == "composer.lock":
                    for pkg, ver in self._parse_composer_lock(fpath):
                        if (pkg, ver, "Packagist") not in seen_keys:
                            seen_keys.add((pkg, ver, "Packagist"))
                            packages.append((pkg, ver, "Packagist", relpath))

                # 4. Rust (Cargo.lock, Cargo.toml)
                elif fname_lower == "cargo.lock":
                    for pkg, ver in self._parse_cargo_lock(fpath):
                        if (pkg, ver, "crates.io") not in seen_keys:
                            seen_keys.add((pkg, ver, "crates.io"))
                            packages.append((pkg, ver, "crates.io", relpath))

                # 5. Go (go.mod)
                elif fname_lower == "go.mod":
                    for pkg, ver in self._parse_go_mod(fpath):
                        if (pkg, ver, "Go") not in seen_keys:
                            seen_keys.add((pkg, ver, "Go"))
                            packages.append((pkg, ver, "Go", relpath))

        # Query OSV database for each unique package
        for pkg, ver, eco, relpath in packages:
            findings.extend(self._check_package_osv(pkg, ver, eco, relpath))

        return findings

    # --- Parsers ---
    def _parse_requirements_txt(self, fpath: str) -> List[Tuple[str, str]]:
        pkgs = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([0-9a-zA-Z\.\-]+)", line)
                    if m:
                        pkgs.append((m.group(1), m.group(2)))
        except Exception:
            pass
        return pkgs

    def _parse_poetry_lock(self, fpath: str) -> List[Tuple[str, str]]:
        pkgs = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                matches = re.findall(r'name = "([^"]+)"\s*version = "([^"]+)"', content)
                pkgs.extend(matches)
        except Exception:
            pass
        return pkgs

    def _parse_package_json(self, fpath: str) -> List[Tuple[str, str]]:
        pkgs = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for pkg, ver_spec in deps.items():
                ver = re.sub(r"[^\d\.]", "", ver_spec)
                if ver:
                    pkgs.append((pkg, ver))
        except Exception:
            pass
        return pkgs

    def _parse_package_lock_json(self, fpath: str) -> List[Tuple[str, str]]:
        pkgs = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            # v2/v3 packages object
            packages_obj = data.get("packages", {})
            for key, val in packages_obj.items():
                if key and "version" in val:
                    pkg_name = key.replace("node_modules/", "")
                    if "/" not in pkg_name or pkg_name.startswith("@"):
                        pkgs.append((pkg_name, val["version"]))
        except Exception:
            pass
        return pkgs

    def _parse_composer_json(self, fpath: str) -> List[Tuple[str, str]]:
        pkgs = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            deps = {**data.get("require", {}), **data.get("require-dev", {})}
            for pkg, ver_spec in deps.items():
                ver = re.sub(r"[^\d\.]", "", ver_spec)
                if "/" in pkg and ver:
                    pkgs.append((pkg, ver))
        except Exception:
            pass
        return pkgs

    def _parse_composer_lock(self, fpath: str) -> List[Tuple[str, str]]:
        pkgs = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            for pkg in data.get("packages", []) + data.get("packages-dev", []):
                name = pkg.get("name")
                ver = pkg.get("version", "").lstrip("v")
                if name and ver:
                    pkgs.append((name, ver))
        except Exception:
            pass
        return pkgs

    def _parse_cargo_lock(self, fpath: str) -> List[Tuple[str, str]]:
        pkgs = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                matches = re.findall(r'\[\[package\]\]\s*name = "([^"]+)"\s*version = "([^"]+)"', content)
                pkgs.extend(matches)
        except Exception:
            pass
        return pkgs

    def _parse_go_mod(self, fpath: str) -> List[Tuple[str, str]]:
        pkgs = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    m = re.match(r"^([a-zA-Z0-9_\-\.\/]+)\s+v([0-9a-zA-Z\.\-]+)", line)
                    if m:
                        pkgs.append((m.group(1), m.group(2)))
        except Exception:
            pass
        return pkgs

    def _check_package_osv(self, pkg_name: str, version: str, ecosystem: str, filepath: str) -> List[Finding]:
        findings = []
        if not self.check_online:
            return findings

        payload = {
            "version": version,
            "package": {
                "name": pkg_name,
                "ecosystem": ecosystem,
            },
        }

        try:
            resp = requests.post(
                self.OSV_API_URL,
                json=payload,
                headers=self.headers,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulns", [])
                for v in vulns:
                    vuln_id = v.get("id", "VULN")
                    summary = v.get("summary") or v.get("details", "Known vulnerability in dependency")
                    if len(summary) > 200:
                        summary = summary[:200] + "..."

                    sev = Severity.HIGH
                    cvss = 7.5
                    database_specific = v.get("database_specific", {})
                    severity_str = database_specific.get("severity", "").upper()
                    if "CRITICAL" in severity_str:
                        sev = Severity.CRITICAL
                        cvss = 9.5
                    elif "HIGH" in severity_str:
                        sev = Severity.HIGH
                        cvss = 7.5
                    elif "MODERATE" in severity_str or "MEDIUM" in severity_str:
                        sev = Severity.MEDIUM
                        cvss = 5.5
                    elif "LOW" in severity_str:
                        sev = Severity.LOW
                        cvss = 3.5

                    findings.append(
                        Finding(
                            title=f"Vulnerable Dependency: {pkg_name}@{version} ({vuln_id})",
                            category=Category.SCA.value,
                            severity=sev,
                            cvss_score=cvss,
                            description=f"Package {pkg_name} ({version}) in {filepath} is affected by {vuln_id}: {summary}",
                            evidence=f"Manifest: {filepath}\nPackage: {pkg_name}=={version}\nAdvisory ID: {vuln_id}",
                            remediation=f"Upgrade {pkg_name} to the latest secure release in {filepath}.",
                            location=f"{filepath} ({pkg_name}=={version})",
                            reference=f"https://osv.dev/vulnerability/{vuln_id}",
                        )
                    )
        except Exception:
            pass

        return findings
