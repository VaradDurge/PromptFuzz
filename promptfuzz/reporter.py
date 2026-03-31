"""Reporter — renders FuzzResult to terminal, HTML, and JSON."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from promptfuzz.fuzzer import FuzzResult

_console = Console()

SEVERITY_COLOURS: dict[str, str] = {
    "critical": "red",
    "high": "orange3",
    "medium": "yellow",
    "low": "blue",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PromptFuzz Report — {{ result.timestamp[:10] }}</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e;
    --critical: #f85149; --high: #d29922; --medium: #e3b341; --low: #58a6ff;
    --green: #3fb950; --accent: #58a6ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace; padding: 2rem; }
  h1 { font-size: 1.8rem; margin-bottom: 0.25rem; }
  h2 { font-size: 1.2rem; margin: 1.5rem 0 0.75rem; color: var(--accent); }
  .subtitle { color: var(--muted); margin-bottom: 2rem; font-size: 0.9rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
  .card .val { font-size: 2rem; font-weight: bold; }
  .card .label { font-size: 0.8rem; color: var(--muted); margin-top: 0.25rem; }
  .score-wrap { display: flex; align-items: center; justify-content: center; gap: 2rem; margin-bottom: 2rem; }
  .gauge { width: 120px; height: 120px; border-radius: 50%; background: conic-gradient(
      var(--accent) {{ result.score * 3.6 }}deg, var(--border) 0deg);
    display: flex; align-items: center; justify-content: center; }
  .gauge-inner { width: 90px; height: 90px; border-radius: 50%; background: var(--bg);
    display: flex; align-items: center; justify-content: center; font-size: 1.4rem; font-weight: bold; }
  .filters { margin-bottom: 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap; }
  .btn { padding: 0.3rem 0.8rem; border-radius: 4px; border: 1px solid var(--border);
    background: var(--surface); color: var(--text); cursor: pointer; font-size: 0.85rem; }
  .btn.active { border-color: var(--accent); color: var(--accent); }
  details { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 0.75rem; }
  summary { padding: 0.75rem 1rem; cursor: pointer; display: flex; align-items: center; gap: 0.75rem; font-weight: 500; }
  summary:hover { background: rgba(255,255,255,0.03); }
  .badge { padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }
  .badge-critical { background: rgba(248,81,73,0.2); color: var(--critical); }
  .badge-high { background: rgba(210,153,34,0.2); color: var(--high); }
  .badge-medium { background: rgba(227,179,65,0.2); color: var(--medium); }
  .badge-low { background: rgba(88,166,255,0.2); color: var(--low); }
  .detail-body { padding: 0 1rem 1rem; }
  .field { margin-bottom: 0.75rem; }
  .field-label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem; }
  .field-value { font-size: 0.9rem; }
  pre { background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.75rem; font-size: 0.82rem; white-space: pre-wrap; word-break: break-word; }
  .tag { display: inline-block; padding: 0.1rem 0.4rem; background: rgba(88,166,255,0.1); color: var(--accent); border-radius: 3px; font-size: 0.75rem; margin: 0.1rem; }
  .passed { color: var(--green); }
  .errors { color: var(--muted); }
  footer { margin-top: 3rem; text-align: center; color: var(--muted); font-size: 0.8rem; }
  @media print { body { background: white; color: black; } .card, details { border-color: #ccc; background: #f9f9f9; } }
</style>
</head>
<body>
<h1>PromptFuzz Security Report</h1>
<p class="subtitle">Target: <strong>{{ result.target_description }}</strong> &nbsp;|&nbsp; Context: {{ result.context }} &nbsp;|&nbsp; {{ result.timestamp[:10] }}</p>

<div class="score-wrap">
  <div class="gauge"><div class="gauge-inner">{{ result.score }}</div></div>
  <div>
    <div style="font-size:1.1rem;font-weight:bold;">Security Score</div>
    <div class="subtitle">{{ result.score }}/100 &mdash; {% if result.score >= 80 %}Low Risk{% elif result.score >= 50 %}Medium Risk{% elif result.score >= 20 %}High Risk{% else %}Critical Risk{% endif %}</div>
  </div>
</div>

<div class="grid">
  <div class="card"><div class="val">{{ result.attacks_run }}</div><div class="label">Attacks Run</div></div>
  <div class="card"><div class="val" style="color:var(--critical)">{{ result.vulnerabilities | selectattr('severity','eq','critical') | list | length }}</div><div class="label">Critical</div></div>
  <div class="card"><div class="val" style="color:var(--high)">{{ result.vulnerabilities | selectattr('severity','eq','high') | list | length }}</div><div class="label">High</div></div>
  <div class="card"><div class="val" style="color:var(--medium)">{{ result.vulnerabilities | selectattr('severity','eq','medium') | list | length }}</div><div class="label">Medium</div></div>
  <div class="card"><div class="val" style="color:var(--low)">{{ result.vulnerabilities | selectattr('severity','eq','low') | list | length }}</div><div class="label">Low</div></div>
  <div class="card"><div class="val passed">{{ result.passed | length }}</div><div class="label">Passed</div></div>
</div>

{% if result.vulnerabilities %}
<h2>Vulnerabilities ({{ result.vulnerabilities | length }})</h2>
<div class="filters">
  <button class="btn active" onclick="filterSev('all')">All</button>
  <button class="btn" onclick="filterSev('critical')">Critical</button>
  <button class="btn" onclick="filterSev('high')">High</button>
  <button class="btn" onclick="filterSev('medium')">Medium</button>
  <button class="btn" onclick="filterSev('low')">Low</button>
</div>
<div id="vuln-list">
{% for vuln in result.vulnerabilities %}
<details data-severity="{{ vuln.severity }}">
  <summary>
    <span class="badge badge-{{ vuln.severity }}">{{ vuln.severity }}</span>
    <span>{{ vuln.attack.id }} — {{ vuln.attack.name }}</span>
    <span style="margin-left:auto;color:var(--muted);font-size:0.8rem;">{{ vuln.attack.category }} &nbsp; {{ "%.0f" | format(vuln.result.confidence * 100) }}% confidence</span>
  </summary>
  <div class="detail-body">
    <div class="field"><div class="field-label">Description</div><div class="field-value">{{ vuln.attack.description }}</div></div>
    <div class="field"><div class="field-label">Attack Prompt</div><pre>{{ vuln.attack.prompt }}</pre></div>
    <div class="field"><div class="field-label">Evidence</div><div class="field-value">{{ vuln.result.evidence }}</div></div>
    <div class="field"><div class="field-label">Remediation</div><div class="field-value">{{ vuln.attack.remediation }}</div></div>
    <div class="field"><div class="field-label">Tags</div><div>{% for tag in vuln.attack.tags %}<span class="tag">{{ tag }}</span>{% endfor %}</div></div>
  </div>
</details>
{% endfor %}
</div>
{% else %}
<h2 class="passed">No Vulnerabilities Found</h2>
<p>All {{ result.attacks_run }} attacks were handled correctly.</p>
{% endif %}

<footer>Generated by <strong>PromptFuzz {{ version }}</strong> &mdash; {{ result.timestamp }}</footer>

<script>
function filterSev(sev) {
  document.querySelectorAll('.btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#vuln-list details').forEach(el => {
    el.style.display = (sev === 'all' || el.dataset.severity === sev) ? '' : 'none';
  });
}
</script>
</body>
</html>
"""


_GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (97, "A+"), (93, "A"), (90, "A−"),
    (87, "B+"), (83, "B"), (80, "B−"),
    (77, "C+"), (73, "C"), (70, "C−"),
    (67, "D+"), (63, "D"), (60, "D−"),
    (0,  "F"),
]

_STATUS_FAIL_SEVS = {"critical", "high"}


def _letter_grade(score: int) -> str:
    """Return a letter grade for a security score (0–100).

    Args:
        score: Integer security score.

    Returns:
        Letter grade string, e.g. 'A', 'B+', 'F'.
    """
    for threshold, grade in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def _score_bar(score: int, width: int = 38) -> str:
    """Render an ASCII progress bar for the given score.

    Args:
        score: Integer security score in [0, 100].
        width: Total character width of the bar.

    Returns:
        Bar string using filled (#) and empty (-) characters.
    """
    filled = round(score * width / 100)
    return "#" * filled + "-" * (width - filled)


class Reporter:
    """Renders fuzzing results as terminal output, HTML, or JSON."""

    def print_results(self, result: "FuzzResult") -> None:
        """Print a formatted vulnerability report to the terminal.

        Args:
            result: The FuzzResult to display.
        """
        _console.print()
        _console.rule("[bold]PromptFuzz Security Report[/bold]")
        _console.print()

        # ── Score block ───────────────────────────────────────────────────
        score = result.score
        grade = _letter_grade(score)

        score_colour, risk_label = (
            ("bright_green", "LOW RISK")      if score >= 80 else
            ("yellow",       "MEDIUM RISK")   if score >= 50 else
            ("orange3",      "HIGH RISK")     if score >= 20 else
            ("red",          "CRITICAL RISK")
        )

        n_fail = sum(
            1 for v in result.vulnerabilities if v.severity in _STATUS_FAIL_SEVS
        )
        n_warn = len(result.vulnerabilities) - n_fail
        n_pass = len(result.passed)
        n_err  = len(result.errors)

        bar = _score_bar(score)

        score_body = (
            f"  [{score_colour}]{score:>3}/100[/{score_colour}]"
            f"  [bold {score_colour}]{grade}[/bold {score_colour}]"
            f"  [{score_colour}]{risk_label}[/{score_colour}]\n\n"
            f"  [{score_colour}]{bar}[/{score_colour}]\n\n"
            f"  [bold red]FAIL  {n_fail:>4}[/bold red]"
            f"   [bold yellow]WARN  {n_warn:>4}[/bold yellow]"
            f"   [bold green]PASS  {n_pass:>4}[/bold green]"
            f"   [dim]ERR   {n_err:>4}[/dim]\n"
            f"  [dim]{result.attacks_run} attacks · {result.duration_seconds:.1f}s[/dim]"
        )
        _console.print(Panel(score_body, title="[bold]Security Score[/bold]", expand=False))
        _console.print()

        # ── Category breakdown ────────────────────────────────────────────
        cat_stats: dict[str, dict[str, int]] = {}
        for v in result.vulnerabilities:
            c = v.attack.category
            cat_stats.setdefault(c, {"fail": 0, "warn": 0, "pass": 0})
            if v.severity in _STATUS_FAIL_SEVS:
                cat_stats[c]["fail"] += 1
            else:
                cat_stats[c]["warn"] += 1
        for ar in result.passed:
            c = ar.attack.category
            cat_stats.setdefault(c, {"fail": 0, "warn": 0, "pass": 0})
            cat_stats[c]["pass"] += 1

        if cat_stats:
            cat_table = Table(
                title="Category Breakdown",
                show_header=True,
                header_style="bold dim",
                box=None,
                padding=(0, 2),
            )
            cat_table.add_column("Category", min_width=18)
            cat_table.add_column("FAIL", justify="right", style="bold red")
            cat_table.add_column("WARN", justify="right", style="bold yellow")
            cat_table.add_column("PASS", justify="right", style="bold green")

            for cat in sorted(cat_stats):
                s = cat_stats[cat]
                cat_table.add_row(
                    cat,
                    str(s["fail"]) if s["fail"] else "[dim]0[/dim]",
                    str(s["warn"]) if s["warn"] else "[dim]0[/dim]",
                    str(s["pass"]) if s["pass"] else "[dim]0[/dim]",
                )
            _console.print(cat_table)
            _console.print()

        # ── Vulnerability table ───────────────────────────────────────────
        if result.vulnerabilities:
            vtable = Table(
                title="Findings",
                show_header=True,
                header_style="bold dim",
            )
            vtable.add_column("Status", width=8)
            vtable.add_column("ID", style="dim", width=10)
            vtable.add_column("Name", min_width=28)
            vtable.add_column("Category", width=16)
            vtable.add_column("Severity", width=10)
            vtable.add_column("Confidence", width=10, justify="right")

            for vuln in sorted(
                result.vulnerabilities,
                key=lambda v: list(SEVERITY_COLOURS.keys()).index(v.severity),
            ):
                colour = SEVERITY_COLOURS.get(vuln.severity, "white")
                is_fail = vuln.severity in _STATUS_FAIL_SEVS
                status_text = (
                    Text("FAIL", style="bold red")
                    if is_fail
                    else Text("WARN", style="bold yellow")
                )
                vtable.add_row(
                    status_text,
                    vuln.id,
                    vuln.name,
                    vuln.attack.category,
                    Text(vuln.severity.upper(), style=f"bold {colour}"),
                    f"{vuln.result.confidence * 100:.0f}%",
                )

            _console.print(vtable)
        else:
            _console.print(
                Panel(
                    "[bold green]PASS  All attacks passed — no vulnerabilities detected.[/bold green]",
                    border_style="green",
                    expand=False,
                )
            )

        # ── Multi-turn chain results ──────────────────────────────────────
        if result.chain_results:
            chain_table = Table(
                title="Multi-Turn Chain Results",
                show_header=True,
                header_style="bold dim",
            )
            chain_table.add_column("ID", style="dim", width=12)
            chain_table.add_column("Name", min_width=30)
            chain_table.add_column("Turns", width=6, justify="right")
            chain_table.add_column("Result", width=10)
            chain_table.add_column("Severity", width=10)
            chain_table.add_column("Time", width=9, justify="right")

            for cr in result.chain_results:
                colour = SEVERITY_COLOURS.get(cr.final_severity, "white")
                status = (
                    Text("VULN", style="bold red")
                    if cr.is_vulnerable
                    else Text("SAFE", style="bold green")
                )
                chain_table.add_row(
                    cr.chain.id,
                    cr.chain.name,
                    str(len(cr.turn_results)),
                    status,
                    Text(cr.final_severity.upper(), style=f"bold {colour}"),
                    f"{cr.total_elapsed_ms:.0f}ms",
                )
            _console.print(chain_table)
            _console.print()

        _console.print()
        _console.print(
            f"[dim]Target:[/dim] {result.target_description}  "
            f"[dim]Context:[/dim] {result.context}  "
            f"[dim]Timestamp:[/dim] {result.timestamp[:19]}"
        )
        _console.print()

    def save_html(self, result: "FuzzResult", path: str) -> None:
        """Render and save an HTML vulnerability report.

        Args:
            result: The FuzzResult to render.
            path: Destination file path.
        """
        from promptfuzz import __version__

        env = Environment(autoescape=True)
        template = env.from_string(_HTML_TEMPLATE)
        html = template.render(result=result, version=__version__)
        abs_path = Path(path).resolve()
        abs_path.write_text(html, encoding="utf-8")
        _console.print(f"[green]HTML report saved to:[/green] {abs_path}")

    def save_json(self, result: "FuzzResult", path: str) -> None:
        """Serialise FuzzResult to a JSON file.

        Args:
            result: The FuzzResult to serialise.
            path: Destination file path.
        """
        data = dataclasses.asdict(result)
        abs_path = Path(path).resolve()
        abs_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        _console.print(f"[green]JSON report saved to:[/green] {abs_path}")

    def save_txt(self, result: "FuzzResult", path: str) -> None:
        """Save a plain-text vulnerability report.

        Args:
            result: The FuzzResult to render.
            path: Destination file path.
        """
        from promptfuzz import __version__

        lines: list[str] = []
        sep = "=" * 60

        lines += [
            sep,
            f"PromptFuzz v{__version__} — Security Report",
            sep,
            f"Target    : {result.target_description}",
            f"Context   : {result.context}",
            f"Timestamp : {result.timestamp[:19]}",
            f"Duration  : {result.duration_seconds:.1f}s",
            "",
            f"Score     : {result.score}/100  "
            + (
                "Low Risk" if result.score >= 80
                else "Medium Risk" if result.score >= 50
                else "High Risk" if result.score >= 20
                else "Critical Risk"
            ),
            f"Attacks   : {result.attacks_run}",
            f"Vulnerable: {len(result.vulnerabilities)}",
            f"Passed    : {len(result.passed)}",
            f"Errors    : {len(result.errors)}",
            "",
        ]

        severity_order = ["critical", "high", "medium", "low"]

        # Build a unified list of every attempt: (status, attack, response, extra)
        # "extra" holds vuln-specific fields (confidence, evidence, remediation)
        all_attempts: list[tuple[str, object, str, dict]] = []
        for vuln in result.vulnerabilities:
            all_attempts.append((
                "VULNERABLE",
                vuln.attack,
                vuln.result.response or "(no response)",
                {
                    "confidence": f"{vuln.result.confidence * 100:.0f}%",
                    "evidence": vuln.result.evidence,
                    "remediation": vuln.attack.remediation,
                },
            ))
        for ar in result.passed:
            all_attempts.append(("PASSED", ar.attack, ar.response or "(no response)", {}))
        for ar in result.errors:
            all_attempts.append(("ERROR", ar.attack, ar.response or f"(error: {ar.error})", {}))

        # Sort: vulnerabilities first (by severity), then passed
        def _sort_key(item: tuple) -> tuple:
            status, attack, *_ = item
            sev_idx = severity_order.index(attack.severity) if status == "VULNERABLE" else 99
            order = {"VULNERABLE": 0, "PASSED": 1, "ERROR": 2}
            return (order.get(status, 1), sev_idx)

        all_attempts.sort(key=_sort_key)

        lines += [sep, f"ALL ATTEMPTS ({len(all_attempts)})", sep, ""]
        for i, (status, attack, model_response, extra) in enumerate(all_attempts, 1):
            status_label = (
                "VULNERABLE" if status == "VULNERABLE"
                else "error    " if status == "ERROR"
                else "passed   "
            )
            lines += [
                f"[{i}] [{status_label}] {attack.id} — {attack.name}",
                f"    Severity   : {attack.severity.upper()}",
                f"    Category   : {attack.category}",
            ]
            if extra.get("confidence"):
                lines.append(f"    Confidence : {extra['confidence']}")
            if extra.get("evidence"):
                lines.append(f"    Evidence   : {extra['evidence']}")
            lines.append("    Prompt     :")
            prompt = attack.prompt
            for chunk_start in range(0, min(len(prompt), 500), 72):
                lines.append(f"      {prompt[chunk_start:chunk_start + 72]}")
            if len(prompt) > 500:
                lines.append("      [prompt truncated...]")
            lines.append("    Model Output:")
            for chunk_start in range(0, min(len(model_response), 600), 72):
                lines.append(f"      {model_response[chunk_start:chunk_start + 72]}")
            if len(model_response) > 600:
                lines.append("      [response truncated...]")
            if extra.get("remediation"):
                lines.append(f"    Remediation: {extra['remediation']}")
                lines.append(f"    Tags       : {', '.join(attack.tags)}")
            lines.append("")

        # Chain results section
        if result.chain_results:
            lines += ["", sep, "MULTI-TURN CHAIN RESULTS", sep, ""]
            for cr in result.chain_results:
                status_label = "VULNERABLE" if cr.is_vulnerable else "SAFE"
                lines += [
                    f"[{status_label}] {cr.chain.id} — {cr.chain.name}",
                    f"  Severity : {cr.final_severity.upper()}",
                    f"  Turns    : {len(cr.turn_results)} executed",
                    f"  Time     : {cr.total_elapsed_ms:.0f}ms",
                    "  Path     :",
                ]
                for tr in cr.turn_results:
                    vuln_marker = " [VULN]" if tr.is_vulnerable else ""
                    lines.append(
                        f"    {tr.turn.turn_id:<14} → branch={tr.branch_taken}"
                        f"{vuln_marker}"
                    )
                    if tr.error:
                        lines.append(f"      error: {tr.error}")
                    elif tr.is_vulnerable:
                        lines.append(f"      evidence: {tr.evidence}")
                lines.append("")

        lines += [sep, "End of report", sep]

        abs_path = Path(path).resolve()
        abs_path.write_text("\n".join(lines), encoding="utf-8", errors="replace")
        _console.print(f"[green]TXT report saved to:[/green] {abs_path}")
