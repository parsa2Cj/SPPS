from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    HEADERS = "Security Headers & Cookies"
    CSP = "Content Security Policy (CSP)"
    SSL_TLS = "SSL/TLS & Encryption"
    DNS_EMAIL = "DNS & Email Security (SPF/DMARC/CAA)"
    EXPOSED_FILES = "Sensitive Files & Endpoints"
    HTTP_METHODS_CORS = "HTTP Methods & CORS Security"
    TECH_STACK = "Technology & Server Fingerprint"
    SAST = "Static Source Code Analysis"
    IAC = "Infrastructure as Code (Docker/K8s)"
    SCA = "Dependency Vulnerabilities"
    LICENSE = "License Compliance"


@dataclass
class Finding:
    title: str
    category: str
    severity: Severity
    description: str
    remediation: str
    evidence: Optional[str] = None
    location: Optional[str] = None
    cwe_id: Optional[str] = None
    reference: Optional[str] = None
    cvss_score: Optional[float] = None
    fix_snippet: Optional[Dict[str, str]] = None  # e.g. {"nginx": "...", "apache": "...", "express": "..."}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "location": self.location,
            "cwe_id": self.cwe_id,
            "reference": self.reference,
            "cvss_score": self.cvss_score,
            "fix_snippet": self.fix_snippet,
        }


@dataclass
class ScanResult:
    target_url: Optional[str] = None
    target_dir: Optional[str] = None
    scan_date: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    duration_seconds: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    detected_tech: List[Dict[str, str]] = field(default_factory=list)  # e.g. [{"name": "React", "category": "Frontend"}]
    license_summary: Dict[str, int] = field(default_factory=dict)
    security_score: int = 100
    grade: str = "A+"

    def calculate_score(self) -> None:
        """
        Calculate overall security score (0 to 100) and assign grade.
        """
        counts = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }

        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        self.stats = counts

        score = 100
        score -= counts[Severity.CRITICAL.value] * 25
        score -= counts[Severity.HIGH.value] * 12
        score -= counts[Severity.MEDIUM.value] * 6
        score -= counts[Severity.LOW.value] * 2

        self.security_score = max(0, min(100, score))

        if self.security_score >= 95:
            self.grade = "A+"
        elif self.security_score >= 85:
            self.grade = "A"
        elif self.security_score >= 70:
            self.grade = "B"
        elif self.security_score >= 55:
            self.grade = "C"
        elif self.security_score >= 40:
            self.grade = "D"
        else:
            self.grade = "F"

    def to_dict(self) -> Dict[str, Any]:
        self.calculate_score()
        return {
            "target_url": self.target_url,
            "target_dir": self.target_dir,
            "scan_date": self.scan_date,
            "duration_seconds": round(self.duration_seconds, 2),
            "security_score": self.security_score,
            "grade": self.grade,
            "stats": self.stats,
            "detected_tech": self.detected_tech,
            "license_summary": self.license_summary,
            "findings": [f.to_dict() for f in self.findings],
        }
