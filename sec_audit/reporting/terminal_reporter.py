from typing import Optional
from ..models import ScanResult, Severity

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.box import ROUNDED
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class TerminalReporter:
    """
    Renders formatted, color-coded security audit reports directly to the terminal.
    """

    SEVERITY_COLORS = {
        Severity.CRITICAL.value: "bold red",
        Severity.HIGH.value: "red",
        Severity.MEDIUM.value: "yellow",
        Severity.LOW.value: "blue",
        Severity.INFO.value: "cyan",
    }

    def __init__(self, result: ScanResult):
        self.result = result
        self.result.calculate_score()

    def display(self) -> None:
        if RICH_AVAILABLE:
            try:
                self._display_rich()
            except Exception:
                self._display_plain()
        else:
            self._display_plain()

    def _display_rich(self) -> None:
        console = Console(highlight=False)


        # Header Panel
        target_info = []
        if self.result.target_url:
            target_info.append(f"[bold cyan]Target URL:[/bold cyan] {self.result.target_url}")
        if self.result.target_dir:
            target_info.append(f"[bold cyan]Source Directory:[/bold cyan] {self.result.target_dir}")
        target_info.append(f"[bold]Scan Date:[/bold] {self.result.scan_date}")
        target_info.append(f"[bold]Duration:[/bold] {self.result.duration_seconds:.2f}s")

        if self.result.detected_tech:
            tech_str = ", ".join([t["name"] for t in self.result.detected_tech])
            target_info.append(f"[bold cyan]Tech Stack:[/bold cyan] {tech_str}")

        score_color = "green" if self.result.security_score >= 80 else ("yellow" if self.result.security_score >= 60 else "red")
        target_info.append(
            f"\n[bold]Overall Security Score:[/bold] [{score_color}]{self.result.security_score}/100[/{score_color}] "
            f"([bold {score_color}]Grade {self.result.grade}[/bold {score_color}])"
        )

        console.print(
            Panel(
                "\n".join(target_info),
                title="[bold green]SecAudit 2.0 Enterprise - Security & Compliance Report[/bold green]",
                border_style="green",
                box=ROUNDED,
            )
        )


        # Statistics Summary Table
        summary_table = Table(title="Summary of Findings by Severity", box=ROUNDED)
        summary_table.add_column("Severity", justify="center", style="bold")
        summary_table.add_column("Count", justify="center")

        for sev_name in [Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value, Severity.LOW.value, Severity.INFO.value]:
            cnt = self.result.stats.get(sev_name, 0)
            color = self.SEVERITY_COLORS.get(sev_name, "white")
            summary_table.add_row(f"[{color}]{sev_name}[/{color}]", f"[{color}]{cnt}[/{color}]")

        console.print(summary_table)
        console.print()

        # Detailed Findings Table
        if not self.result.findings:
            console.print("[bold green]No security vulnerabilities or misconfigurations detected![/bold green]\n")
            return

        findings_table = Table(title="Detailed Security Findings", box=ROUNDED, show_lines=True)

        findings_table.add_column("#", justify="center", style="dim", width=4)
        findings_table.add_column("Severity", justify="center", width=12)
        findings_table.add_column("Category", width=20)
        findings_table.add_column("Finding Title & Details", width=45)
        findings_table.add_column("Location & Remediation", width=40)

        for idx, f in enumerate(self.result.findings, start=1):
            sev_color = self.SEVERITY_COLORS.get(f.severity.value, "white")
            sev_badge = f"[{sev_color}]{f.severity.value}[/{sev_color}]"

            details = f"[bold]{f.title}[/bold]\n{f.description}"
            if f.evidence:
                details += f"\n[dim italic]Evidence: {f.evidence[:80]}...[/dim italic]"

            remedy = f"[bold cyan]Fix:[/bold cyan] {f.remediation}"
            if f.location:
                remedy = f"[bold yellow]Loc:[/bold yellow] {f.location}\n" + remedy

            findings_table.add_row(str(idx), sev_badge, f.category, details, remedy)

        console.print(findings_table)
        console.print()

    def _display_plain(self) -> None:
        print("=" * 70)
        print("           SecAudit - Website Security Audit Report           ")
        print("=" * 70)
        if self.result.target_url:
            print(f" Target URL:        {self.result.target_url}")
        if self.result.target_dir:
            print(f" Source Directory:  {self.result.target_dir}")
        print(f" Scan Date:         {self.result.scan_date}")
        print(f" Security Score:    {self.result.security_score}/100 (Grade: {self.result.grade})")
        print("-" * 70)
        print(" SUMMARY:")
        for sev, count in self.result.stats.items():
            print(f"   - {sev:10}: {count}")
        print("-" * 70)
        print(" FINDINGS:")
        for idx, f in enumerate(self.result.findings, start=1):
            print(f" [{idx}] [{f.severity.value}] {f.title} ({f.category})")
            print(f"     Description: {f.description}")
            if f.location:
                print(f"     Location:    {f.location}")
            print(f"     Fix:         {f.remediation}")
            print()
        print("=" * 70)
