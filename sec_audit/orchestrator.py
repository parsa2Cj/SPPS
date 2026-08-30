"""
SecAudit 2.0 Enterprise Orchestrator
Coordinates multithreaded scanning across DAST, Network, SAST, IaC, SCA, and License engines.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List
from .models import ScanResult, Severity, Finding
from .scanners import (
    HeaderScanner,
    SSLScanner,
    DNSScanner,
    TechDetector,
    CORSMethodsScanner,
    SensitiveFilesScanner,
    SASTScanner,
    IaCScanner,
    SCAScanner,
    LicenseScanner,
)


class SecAuditOrchestrator:
    """
    Coordinates and executes multithreaded security audits across web endpoints and codebases.
    """

    SEVERITY_ORDER = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 1,
        Severity.MEDIUM.value: 2,
        Severity.LOW.value: 3,
        Severity.INFO.value: 4,
    }

    def __init__(
        self,
        target_url: Optional[str] = None,
        target_dir: Optional[str] = None,
        check_online_sca: bool = True,
        timeout: int = 10,
        max_workers: int = 6,
    ):
        self.target_url = target_url
        self.target_dir = target_dir
        self.check_online_sca = check_online_sca
        self.timeout = timeout
        self.max_workers = max_workers

    def run(self) -> ScanResult:
        result = ScanResult(
            target_url=self.target_url,
            target_dir=self.target_dir,
        )

        start_time = time.time()
        all_findings: List[Finding] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_tasks = {}

            # 1. Dispatch DAST & Network Scanners
            if self.target_url:
                # Headers & Deep CSP
                header_scanner = HeaderScanner(self.target_url, timeout=self.timeout)
                future_tasks[executor.submit(header_scanner.scan)] = "Headers"

                # SSL / TLS
                ssl_scanner = SSLScanner(self.target_url, timeout=self.timeout)
                future_tasks[executor.submit(ssl_scanner.scan)] = "SSL/TLS"

                # Sensitive files
                files_scanner = SensitiveFilesScanner(self.target_url, timeout=self.timeout)
                future_tasks[executor.submit(files_scanner.scan)] = "Sensitive Files"

                # DNS & Email Security
                dns_scanner = DNSScanner(self.target_url, timeout=self.timeout)
                future_tasks[executor.submit(dns_scanner.scan)] = "DNS Security"

                # HTTP Methods & CORS
                cors_scanner = CORSMethodsScanner(self.target_url, timeout=self.timeout)
                future_tasks[executor.submit(cors_scanner.scan)] = "HTTP Methods & CORS"

                # Tech Detector
                tech_detector = TechDetector(self.target_url, timeout=self.timeout)
                future_tasks[executor.submit(tech_detector.detect)] = "Tech Detector"

            # 2. Dispatch SAST, IaC, SCA & License Scanners
            if self.target_dir:
                # SAST Static Code Analysis
                sast_scanner = SASTScanner(self.target_dir)
                future_tasks[executor.submit(sast_scanner.scan)] = "SAST"

                # IaC (Docker & Kubernetes)
                iac_scanner = IaCScanner(self.target_dir)
                future_tasks[executor.submit(iac_scanner.scan)] = "IaC"

                # SCA Dependency Check
                sca_scanner = SCAScanner(self.target_dir, check_online=self.check_online_sca, timeout=self.timeout)
                future_tasks[executor.submit(sca_scanner.scan)] = "SCA"

                # License Compliance
                lic_scanner = LicenseScanner(self.target_dir)
                future_tasks[executor.submit(lic_scanner.scan)] = "License"

            # 3. Collect Results
            for future in as_completed(future_tasks):
                task_name = future_tasks[future]
                try:
                    res = future.result()
                    if task_name == "Tech Detector":
                        result.detected_tech = res
                    elif task_name == "License":
                        lic_findings, lic_summary = res
                        all_findings.extend(lic_findings)
                        result.license_summary = lic_summary
                    elif isinstance(res, list):
                        all_findings.extend(res)
                except Exception as e:
                    # Non-fatal scanner exception logged
                    pass

        # Sort findings by severity
        all_findings.sort(key=lambda f: self.SEVERITY_ORDER.get(f.severity.value, 99))

        result.findings = all_findings
        result.duration_seconds = time.time() - start_time
        result.calculate_score()
        return result
