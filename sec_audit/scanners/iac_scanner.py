"""
Infrastructure as Code (IaC) Security Auditor for Docker, Docker Compose, and Kubernetes
"""

import os
import re
from typing import List
from ..models import Finding, Severity, Category
from ..config import IGNORE_DIRS


class IaCScanner:
    """
    Audits Dockerfiles, Docker Compose files, and Kubernetes manifests for security misconfigurations.
    """

    EXPOSED_DB_PORTS = {
        "27017": "MongoDB",
        "3306": "MySQL/MariaDB",
        "5432": "PostgreSQL",
        "6379": "Redis",
        "9200": "Elasticsearch",
        "1521": "Oracle DB",
        "1433": "MS SQL Server",
    }

    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(self.target_dir):
            return findings

        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

            for file in files:
                filepath = os.path.join(root, file)
                relpath = os.path.relpath(filepath, self.target_dir)
                filename_lower = file.lower()

                # 1. Audit Dockerfile
                if filename_lower == "dockerfile" or filename_lower.endswith(".dockerfile"):
                    findings.extend(self._audit_dockerfile(filepath, relpath))

                # 2. Audit Docker Compose
                elif filename_lower in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]:
                    findings.extend(self._audit_docker_compose(filepath, relpath))

        return findings

    def _audit_dockerfile(self, filepath: str, relpath: str) -> List[Finding]:
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return findings

        has_user_directive = False

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            # Check unpinned/latest base image
            if re.match(r"^FROM\s+[a-zA-Z0-9_\-\.\/]+:latest", stripped, re.IGNORECASE) or (
                stripped.startswith("FROM ") and ":" not in stripped and "AS" not in stripped
            ):
                findings.append(
                    Finding(
                        title="Dockerfile Uses Unpinned ':latest' Base Image",
                        category=Category.IAC.value,
                        severity=Severity.LOW,
                        cvss_score=3.5,
                        description="Using the ':latest' tag or omitting image version tags leads to non-reproducible builds and automatic ingestion of breaking/vulnerable upstream changes.",
                        evidence=f"{relpath}:{idx}\n> {stripped}",
                        remediation="Pin the base image to a specific SHA digest or stable semantic version tag (e.g. node:20-alpine or python:3.12-slim).",
                        location=f"{relpath}:{idx}",
                        cwe_id="CWE-1188",
                    )
                )

            # Check hardcoded secrets in ENV
            if re.match(r"^ENV\s+(?:.*(?:PASSWORD|SECRET|API_KEY|TOKEN|AUTH_KEY))\s*=", stripped, re.IGNORECASE):
                findings.append(
                    Finding(
                        title="Hardcoded Secret in Dockerfile ENV Instruction",
                        category=Category.IAC.value,
                        severity=Severity.HIGH,
                        cvss_score=7.8,
                        description="Environment variables defined via ENV in a Dockerfile persist in image layers and can be extracted using 'docker inspect' or 'docker history'.",
                        evidence=f"{relpath}:{idx}\n> {stripped}",
                        remediation="Do not bake secrets into images. Inject secrets at runtime using environment files or secrets managers.",
                        location=f"{relpath}:{idx}",
                        cwe_id="CWE-798",
                    )
                )

            # Check USER directive
            if stripped.startswith("USER "):
                has_user_directive = True

        if not has_user_directive and len(lines) > 2:
            findings.append(
                Finding(
                    title="Dockerfile Missing Non-Root USER Directive",
                    category=Category.IAC.value,
                    severity=Severity.MEDIUM,
                    cvss_score=6.0,
                    description="The container runs as 'root' by default. If the application is compromised, the attacker gains root privileges inside the container.",
                    remediation="Create and switch to a dedicated non-root user (e.g. 'USER appuser' or 'USER node') before CMD/ENTRYPOINT.",
                    location=relpath,
                    cwe_id="CWE-250",
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
                )
            )

        return findings

    def _audit_docker_compose(self, filepath: str, relpath: str) -> List[Finding]:
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return findings

        # Check privileged mode
        if "privileged: true" in content:
            findings.append(
                Finding(
                    title="Container Runs in Privileged Mode (privileged: true)",
                    category=Category.IAC.value,
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    description="Running a container with 'privileged: true' gives it full root capabilities on the host system, allowing easy container breakout.",
                    evidence=f"privileged: true in {relpath}",
                    remediation="Remove 'privileged: true' and grant only specific required Linux capabilities (cap_add).",
                    location=relpath,
                    cwe_id="CWE-250",
                )
            )

        # Check directly exposed database ports
        for port, db_name in self.EXPOSED_DB_PORTS.items():
            pattern = re.compile(rf"""['"]?{port}:{port}['"]?""")
            for idx, line in enumerate(lines, start=1):
                if pattern.search(line) and not "127.0.0.1" in line:
                    findings.append(
                        Finding(
                            title=f"Database Port ({port}/{db_name}) Directly Exposed to 0.0.0.0",
                            category=Category.IAC.value,
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            description=f"{db_name} port {port} is exposed on all network interfaces. Attackers on the local network or internet can reach database endpoints directly.",
                            evidence=f"{relpath}:{idx}\n> {line.strip()}",
                            remediation=f"Bind port to localhost only ('127.0.0.1:{port}:{port}') or use internal Docker network without host port mapping.",
                            location=f"{relpath}:{idx}",
                            cwe_id="CWE-668",
                        )
                    )

        return findings
