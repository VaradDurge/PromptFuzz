"""Interactive wizard — launches when `promptfuzz` is run with no arguments."""

from __future__ import annotations

import os
import sys

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from promptfuzz import __version__
from promptfuzz.attacks.loader import VALID_CATEGORIES

_console = Console()

_CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "jailbreak": "Persona switches, DAN, roleplay bypasses",
    "injection": "Prompt override, delimiter attacks",
    "data_extraction": "System prompt leaking, credential extraction",
    "goal_hijacking": "Purpose redirection attacks",
    "edge_cases": "Unicode, long inputs, encoding attacks",
}

_OUTPUT_CHOICES = [
    questionary.Choice("Terminal only", value="terminal"),
    questionary.Choice("Terminal + TXT file  (report.txt)", value="txt"),
    questionary.Choice("Terminal + HTML report  (report.html)", value="html"),
    questionary.Choice("All formats", value="all"),
]

_SEVERITY_CHOICES = [
    questionary.Choice("low  (show everything)", value="low"),
    questionary.Choice("medium", value="medium"),
    questionary.Choice("high", value="high"),
    questionary.Choice("critical only", value="critical"),
]


def _ask_target() -> str:
    """Ask for target type and then the specific target string.

    Returns:
        A URL string or a 'module:function' import path.
    """
    target_type = questionary.select(
        "What is your target?",
        choices=[
            questionary.Choice("HTTP/HTTPS endpoint (URL)", value="url"),
            questionary.Choice("Python function (module:function)", value="function"),
        ],
    ).ask()

    if target_type is None:
        sys.exit(0)

    if target_type == "url":
        while True:
            url = questionary.text(
                "Enter target URL:",
                validate=lambda t: (
                    True
                    if t.startswith("http://") or t.startswith("https://")
                    else "Must start with http:// or https://"
                ),
            ).ask()
            if url is None:
                sys.exit(0)
            return url
    else:
        while True:
            path = questionary.text(
                "Enter import path (e.g. mymodule:my_function):",
                validate=lambda t: (
                    True
                    if ":" in t and len(t.split(":")) == 2  # noqa: PLR2004
                    else "Format must be module:function"
                ),
            ).ask()
            if path is None:
                sys.exit(0)
            return path


def _ask_categories() -> list[str]:
    """Ask which attack categories to run via multi-select checkboxes.

    Returns:
        List of selected category names (at least one).
    """
    choices = [
        questionary.Choice(
            f"{cat:<20} — {_CATEGORY_DESCRIPTIONS.get(cat, '')}",
            value=cat,
            checked=cat in {"jailbreak", "injection", "data_extraction"},
        )
        for cat in sorted(VALID_CATEGORIES)
    ]

    while True:
        selected = questionary.checkbox(
            "Select attack categories: (space=toggle, enter=confirm)",
            choices=choices,
        ).ask()

        if selected is None:
            sys.exit(0)
        if selected:
            return selected
        _console.print("[yellow]Please select at least one category.[/yellow]")


def _ask_output() -> str:
    """Ask for the desired output format.

    Returns:
        One of 'terminal', 'txt', 'html', 'all'.
    """
    result = questionary.select(
        "Output format:",
        choices=_OUTPUT_CHOICES,
    ).ask()
    if result is None:
        sys.exit(0)
    return result


def _ask_severity() -> str:
    """Ask for the minimum severity to include in the report.

    Returns:
        One of 'low', 'medium', 'high', 'critical'.
    """
    result = questionary.select(
        "Minimum severity to report:",
        choices=_SEVERITY_CHOICES,
    ).ask()
    if result is None:
        sys.exit(0)
    return result


def _ask_ai_attacks() -> bool:
    """Ask whether to use AI-generated attacks (only when API key is present).

    Returns:
        True if the user wants AI-generated attacks, False otherwise.
    """
    if not os.environ.get("OPENAI_API_KEY"):
        return False

    result = questionary.confirm(
        "Use AI-generated attacks? Requires OPENAI_API_KEY",
        default=False,
    ).ask()
    if result is None:
        sys.exit(0)
    return result


def run_wizard() -> None:
    """Run the interactive setup wizard and launch a scan based on answers.

    Asks the user for target, categories, output format, severity threshold,
    and whether to use AI-generated attacks. Prints a summary panel and
    waits for confirmation before starting the scan.
    """
    _console.print()
    _console.print(
        Panel(
            f"[bold cyan]PromptFuzz[/bold cyan] v{__version__} "
            "— LLM Security Testing",
            expand=False,
            border_style="dim",
        )
    )
    _console.print()

    target = _ask_target()
    categories = _ask_categories()
    output_fmt = _ask_output()
    severity = _ask_severity()
    use_ai = _ask_ai_attacks()

    # Load attack count for the chosen categories
    from promptfuzz.attacks.loader import AttackLoader

    loader = AttackLoader()
    attacks = loader.load_categories(categories)
    attack_count = len(attacks)

    # Build summary
    output_label = {
        "terminal": "Terminal only",
        "txt": "Terminal + report.txt",
        "html": "Terminal + report.html",
        "all": "Terminal + report.txt + report.html + report.json",
    }[output_fmt]

    summary = Text()
    summary.append(f"  Target   : ", style="dim")
    summary.append(f"{target}\n", style="cyan")
    summary.append(f"  Attacks  : ", style="dim")
    summary.append(f"{attack_count}  ({' + '.join(categories)})\n", style="green")
    summary.append(f"  Output   : ", style="dim")
    summary.append(f"{output_label}\n")
    summary.append(f"  Severity : ", style="dim")
    summary.append(f"{severity}+\n")
    if use_ai:
        summary.append(f"  AI attacks: ", style="dim")
        summary.append("enabled\n", style="yellow")

    _console.print()
    _console.print(Panel(summary, title="Scan configuration", border_style="cyan"))
    _console.print()

    go = questionary.confirm("Press ENTER to start scan (Ctrl+C to cancel)", default=True).ask()
    if not go:
        _console.print("[dim]Scan cancelled.[/dim]")
        sys.exit(0)

    _console.print()
    _launch_scan(target, categories, output_fmt, severity)


def _launch_scan(
    target: str,
    categories: list[str],
    output_fmt: str,
    severity: str,
) -> None:
    """Execute the scan with the wizard's chosen settings.

    Args:
        target: URL or 'module:function' import path.
        categories: Attack categories to run.
        output_fmt: One of 'terminal', 'txt', 'html', 'all'.
        severity: Minimum severity to display ('low', 'medium', 'high', 'critical').
    """
    import importlib

    from promptfuzz.fuzzer import Fuzzer, SEVERITY_WEIGHTS  # noqa: F401

    # Resolve target
    if target.startswith("http://") or target.startswith("https://"):
        resolved: object = target
    else:
        module_path, func_name = target.rsplit(":", 1)
        try:
            mod = importlib.import_module(module_path)
            resolved = getattr(mod, func_name)
        except (ModuleNotFoundError, AttributeError) as exc:
            _console.print(f"[bold red]Error:[/bold red] Cannot resolve target: {exc}")
            sys.exit(1)

    fuzzer = Fuzzer(
        target=resolved,
        context="LLM application",
        categories=categories,
        verbose=False,
    )

    result = fuzzer.run()

    SEVERITY_ORDER = ["critical", "high", "medium", "low"]
    sev_idx = SEVERITY_ORDER.index(severity)
    result.vulnerabilities = [  # type: ignore[assignment]
        v for v in result.vulnerabilities
        if SEVERITY_ORDER.index(v.severity) <= sev_idx
    ]

    result.report()

    if output_fmt in {"txt", "all"}:
        result.to_txt("report.txt")
        _console.print("[dim]Saved report.txt[/dim]")

    if output_fmt in {"html", "all"}:
        result.save("report.html")
        _console.print("[dim]Saved report.html[/dim]")

    if output_fmt == "all":
        result.to_json("report.json")
        _console.print("[dim]Saved report.json[/dim]")
