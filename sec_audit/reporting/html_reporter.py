import os
import json
from typing import Optional
from jinja2 import Environment, FileSystemLoader
from ..models import ScanResult


class HTMLReporter:
    """
    Renders an interactive, standalone Enterprise HTML security report.
    """

    def __init__(self, result: ScanResult):
        self.result = result

    def export(self, output_path: str) -> None:
        self.result.calculate_score()
        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
        template = env.get_template("report_template.html")

        rendered = template.render(
            target_url=self.result.target_url,
            target_dir=self.result.target_dir,
            scan_date=self.result.scan_date,
            duration_seconds=round(self.result.duration_seconds, 2),
            security_score=self.result.security_score,
            grade=self.result.grade,
            stats=self.result.stats,
            detected_tech=self.result.detected_tech,
            license_summary=self.result.license_summary,
            findings=[f.to_dict() for f in self.result.findings],
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered)
