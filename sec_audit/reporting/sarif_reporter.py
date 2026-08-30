"""
OASIS SARIF (Static Analysis Results Interchange Format) v2.1.0 Reporter
Enables native integration with GitHub Code Scanning, GitLab Security Dashboards, and CI/CD pipelines.
"""

import json
from typing import Dict, Any
from ..models import ScanResult, Severity


class SARIFReporter:
    """
    Exports scan findings to standard SARIF v2.1.0 format.
    """

    SEVERITY_LEVEL_MAP = {
        Severity.CRITICAL.value: "error",
        Severity.HIGH.value: "error",
        Severity.MEDIUM.value: "warning",
        Severity.LOW.value: "note",
        Severity.INFO.value: "note",
    }

    def __init__(self, result: ScanResult):
        self.result = result

    def export(self, filepath: str) -> None:
        rules = []
        rule_indices = {}
        results = []

        for f in self.result.findings:
            rule_id = f.cwe_id or f.title.replace(" ", "_")
            if rule_id not in rule_indices:
                rule_indices[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "helpUri": f.reference or "https://owasp.org",
                    "help": {
                        "text": f"Remediation:\n{f.remediation}",
                        "markdown": f"**Remediation:**\n{f.remediation}",
                    },
                })

            rule_idx = rule_indices[rule_id]

            # Parse location (filepath:line)
            file_uri = "index.html"
            line_num = 1
            if f.location:
                if ":" in f.location:
                    parts = f.location.split(":")
                    file_uri = parts[0].replace("\\", "/")
                    try:
                        line_num = int(parts[1])
                    except ValueError:
                        line_num = 1
                else:
                    file_uri = f.location.replace("\\", "/")

            result_entry = {
                "ruleId": rule_id,
                "ruleIndex": rule_idx,
                "level": self.SEVERITY_LEVEL_MAP.get(f.severity.value, "warning"),
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": line_num,
                            },
                        }
                    }
                ],
            }
            results.append(result_entry)

        sarif_data: Dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecAudit",
                            "semanticVersion": "2.0.0",
                            "informationUri": "https://github.com/secaudit/secaudit",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        with open(filepath, "w", encoding="utf-8") as out:
            json.dump(sarif_data, out, indent=2, ensure_ascii=False)
