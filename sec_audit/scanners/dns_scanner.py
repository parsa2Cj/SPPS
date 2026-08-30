"""
DNS and Email Security Auditor (SPF, DMARC, CAA)
Uses DNS-over-HTTPS (DoH) for 100% portable zero-dependency queries on all OS environments.
"""

import requests
from urllib.parse import urlparse
from typing import List, Dict, Any
from ..models import Finding, Severity, Category
from ..config import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT


class DNSScanner:
    """
    Checks SPF, DMARC, and CAA DNS security records for a target domain.
    """

    DOH_ENDPOINTS = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    ]

    def __init__(self, target_url: str, timeout: int = DEFAULT_TIMEOUT):
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname or ""
        # Strip subdomains for apex domain DMARC/SPF lookups if applicable
        parts = self.hostname.split(".")
        if len(parts) >= 2:
            self.apex_domain = ".".join(parts[-2:])
        else:
            self.apex_domain = self.hostname
        self.timeout = timeout
        self.headers = {
            "Accept": "application/dns-json",
            "User-Agent": DEFAULT_USER_AGENT,
        }

    def _query_doh(self, name: str, rtype: str) -> List[str]:
        results: List[str] = []
        for ep in self.DOH_ENDPOINTS:
            try:
                resp = requests.get(
                    ep,
                    params={"name": name, "type": rtype},
                    headers=self.headers,
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for answer in data.get("Answer", []):
                        data_val = answer.get("data", "").strip('"')
                        if data_val:
                            results.append(data_val)
                    if results:
                        break
            except Exception:
                continue
        return results

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self.apex_domain or self.apex_domain in ["localhost", "127.0.0.1"]:
            return findings

        # 1. Check SPF Record (TXT on apex domain)
        txt_records = self._query_doh(self.apex_domain, "TXT")
        spf_records = [r for r in txt_records if r.startswith("v=spf1")]

        if not spf_records:
            findings.append(
                Finding(
                    title="Missing SPF (Sender Policy Framework) Record",
                    category=Category.DNS_EMAIL.value,
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description=f"Domain '{self.apex_domain}' does not publish an SPF record. Spammers can forge emails pretending to originate from your domain.",
                    remediation=f"Publish a TXT record for '{self.apex_domain}' with: 'v=spf1 mx ~all' (or appropriate mail server IP).",
                    location=f"DNS -> {self.apex_domain} (TXT)",
                    cwe_id="CWE-290",
                    reference="https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/",
                )
            )
        else:
            spf = spf_records[0]
            if "+all" in spf:
                findings.append(
                    Finding(
                        title="Insecure SPF Record (+all Wildcard Allowed)",
                        category=Category.DNS_EMAIL.value,
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        description=f"SPF record contains '+all', explicitly allowing ANY server on the internet to send email on behalf of your domain.",
                        evidence=spf,
                        remediation="Change '+all' to '~all' (SoftFail) or '-all' (HardFail) in your SPF record.",
                        location=f"DNS -> {self.apex_domain} (SPF)",
                        cwe_id="CWE-290",
                    )
                )

        # 2. Check DMARC Record (_dmarc.domain)
        dmarc_name = f"_dmarc.{self.apex_domain}"
        dmarc_txts = self._query_doh(dmarc_name, "TXT")
        dmarc_records = [r for r in dmarc_txts if r.startswith("v=DMARC1")]

        if not dmarc_records:
            findings.append(
                Finding(
                    title="Missing DMARC Record",
                    category=Category.DNS_EMAIL.value,
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description=f"No DMARC policy found for '{self.apex_domain}'. DMARC ensures receiving mail servers reject spoofed phishing emails.",
                    remediation=f"Publish a TXT record at '{dmarc_name}' with: 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{self.apex_domain}'",
                    location=f"DNS -> {dmarc_name}",
                    cwe_id="CWE-290",
                    reference="https://dmarc.org/overview/",
                )
            )
        else:
            dmarc = dmarc_records[0]
            if "p=none" in dmarc.lower():
                findings.append(
                    Finding(
                        title="DMARC Policy Set to 'none' (Monitoring Only)",
                        category=Category.DNS_EMAIL.value,
                        severity=Severity.LOW,
                        cvss_score=3.1,
                        description="DMARC policy is set to 'p=none', which only reports and does not block or quarantine unauthorized spoofed emails.",
                        evidence=dmarc,
                        remediation="Upgrade DMARC policy to 'p=quarantine' or 'p=reject' once verified.",
                        location=f"DNS -> {dmarc_name}",
                        cwe_id="CWE-290",
                    )
                )

        # 3. Check CAA Records (Certificate Authority Authorization)
        caa_records = self._query_doh(self.apex_domain, "CAA")
        if not caa_records:
            findings.append(
                Finding(
                    title="Missing CAA (Certification Authority Authorization) Record",
                    category=Category.DNS_EMAIL.value,
                    severity=Severity.LOW,
                    cvss_score=3.0,
                    description=f"No CAA DNS record found for '{self.apex_domain}'. CAA allows domain owners to restrict which Certificate Authorities (CAs) can issue SSL certificates for the domain.",
                    remediation=f"Add CAA DNS records for your authorized CAs (e.g. '{self.apex_domain} CAA 0 issue \"letsencrypt.org\"').",
                    location=f"DNS -> {self.apex_domain} (CAA)",
                    cwe_id="CWE-295",
                    reference="https://support.dnsimple.com/articles/caa-record/",
                )
            )

        return findings
