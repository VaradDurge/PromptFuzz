"""Command-line interface for PromptFuzz."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any

import rich_click as click
from rich.console import Console
from rich.table import Table

from promptfuzz import __version__
from promptfuzz.attacks.loader import VALID_CATEGORIES, AttackLoader

# ── rich-click global configuration ──────────────────────────────────────────
click.rich_click.USE_RICH_MARKUP = True
click.rich_click.USE_MARKDOWN = False
click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.GROUP_ARGUMENTS_OPTIONS = False
click.rich_click.SHOW_METAVARS_COLUMN = False
click.rich_click.APPEND_METAVARS_HELP = True
click.rich_click.HEADER_TEXT = (
    f"[bold cyan]PromptFuzz[/bold cyan] [dim]v{__version__}[/dim]\n"
    "Adversarial security testing for LLM applications.\n"
    "Find prompt injection, jailbreak, and data extraction vulnerabilities\n"
    "before attackers do — 165+ real attacks, professional reports."
)
click.rich_click.FOOTER_TEXT = (
    "Docs & source: [link=https://github.com/varadk27/promptfuzz]"
    "github.com/varadk27/promptfuzz[/link]"
)
click.rich_click.ERRORS_SUGGESTION = (
    "Try [bold]promptfuzz --help[/bold] or [bold]promptfuzz COMMAND --help[/bold]."
)
click.rich_click.STYLE_ERRORS_SUGGESTION = "yellow italic"
click.rich_click.COMMAND_GROUPS = {
    "promptfuzz": [
        {
            "name": "Quick Start",
            "commands": ["test"],
        },
        {
            "name": "Advanced",
            "commands": ["scan", "validate"],
        },
        {
            "name": "Info",
            "commands": ["list-attacks", "version"],
        },
    ]
}
click.rich_click.OPTION_GROUPS = {
    "promptfuzz test": [
        {
            "name": "Target options",
            "options": ["--context", "--categories"],
        },
        {
            "name": "Output options",
            "options": ["--output", "--json", "--severity"],
        },
        {
            "name": "CI/CD",
            "options": ["--fail-on"],
        },
        {
            "name": "Performance",
            "options": ["--max-workers", "--timeout", "--verbose", "--help"],
        },
    ],
    "promptfuzz scan": [
        {
            "name": "Target (choose one)",
            "options": ["--target", "--config"],
        },
        {
            "name": "Target options",
            "options": ["--context", "--categories"],
        },
        {
            "name": "Output options",
            "options": ["--output", "--json", "--severity"],
        },
        {
            "name": "CI/CD",
            "options": ["--fail-on"],
        },
        {
            "name": "Performance",
            "options": ["--max-workers", "--timeout", "--verbose", "--help"],
        },
    ],
}
# ─────────────────────────────────────────────────────────────────────────────

_console = Console()
_err = Console(stderr=True)

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _run_scan(
    target: str,
    context: str,
    categories: tuple[str, ...],
    output: str | None,
    json_output: str | None,
    severity: str,
    fail_on: str | None,
    max_workers: int,
    timeout: float,
    verbose: bool,
    target_label: str | None = None,
) -> None:
    """Resolve target, run fuzzer, print results, and optionally save reports.

    Args:
        target: URL or 'module:function' import path.
        context: Human-readable target description.
        categories: Attack categories to run.
        output: Path for HTML report, or None.
        json_output: Path for JSON output, or None.
        severity: Minimum severity to display.
        fail_on: Exit code 1 if any vuln at/above this severity.
        max_workers: Concurrent workers.
        timeout: Per-attack timeout in seconds.
        verbose: Enable verbose output.
        target_label: Display label for the target (defaults to target string).
    """
    from promptfuzz.fuzzer import Fuzzer

    try:
        resolved = _resolve_target(target)
    except click.BadParameter as exc:
        _err.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1) from exc

    fuzzer = Fuzzer(
        target=resolved,
        context=context,
        categories=list(categories) if categories else None,
        max_workers=max_workers,
        timeout=timeout,
        verbose=verbose,
    )

    _console.print(f"[bold]PromptFuzz[/bold] v{__version__} — starting scan")
    _console.print(f"Target: [cyan]{target_label or target}[/cyan]")
    _console.print()

    result = fuzzer.run()

    sev_idx = SEVERITY_ORDER.index(severity)
    original_vulns = result.vulnerabilities
    result.vulnerabilities = [  # type: ignore[assignment]
        v for v in result.vulnerabilities
        if SEVERITY_ORDER.index(v.severity) <= sev_idx
    ]
    result.report()
    result.vulnerabilities = original_vulns  # type: ignore[assignment]

    if output:
        result.save(output)

    if json_output:
        result.to_json(json_output)

    if fail_on:
        threshold_idx = SEVERITY_ORDER.index(fail_on)
        failing = [
            v for v in result.vulnerabilities
            if SEVERITY_ORDER.index(v.severity) <= threshold_idx
        ]
        if failing:
            _console.print(
                f"[bold red]FAIL:[/bold red] {len(failing)} vulnerability/ies "
                f"at or above '{fail_on}' severity found."
            )
            raise SystemExit(1)


def _resolve_target(target_str: str) -> Any:
    """Resolve a target string to a URL or a Python callable.

    Strings starting with 'http' are returned as-is.
    Strings of the form 'module:function' are imported and returned as callables.

    Args:
        target_str: Either a URL or a 'module:function' import path.

    Returns:
        The URL string or the resolved callable.

    Raises:
        click.BadParameter: If the import path cannot be resolved.
    """
    if target_str.startswith("http://") or target_str.startswith("https://"):
        return target_str

    if ":" not in target_str:
        raise click.BadParameter(
            f"Target '{target_str}' must be a URL (http/https) "
            "or an import path in 'module:function' format."
        )

    module_path, func_name = target_str.rsplit(":", 1)
    try:
        module = importlib.import_module(module_path)
    except ModuleNotFoundError as exc:
        raise click.BadParameter(
            f"Cannot import module '{module_path}': {exc}"
        ) from exc

    try:
        fn = getattr(module, func_name)
    except AttributeError as exc:
        raise click.BadParameter(
            f"Module '{module_path}' has no attribute '{func_name}'."
        ) from exc

    if not callable(fn):
        raise click.BadParameter(
            f"'{module_path}:{func_name}' is not callable."
        )
    return fn


@click.group(
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(__version__, "-V", "--version", prog_name="promptfuzz")
@click.pass_context
def main(ctx: click.Context) -> None:
    """PromptFuzz — adversarial security testing for LLM applications.

    \b
    Run with no arguments to launch the interactive setup wizard:
      $ promptfuzz

    \b
    Or jump straight in:
      $ promptfuzz test https://api.mychatbot.com/chat
      $ promptfuzz test https://api.mychatbot.com/chat --output report.html
      $ promptfuzz test https://api.mychatbot.com/chat --fail-on high
    """
    if ctx.invoked_subcommand is None:
        from promptfuzz.wizard import run_wizard
        run_wizard()


@main.command("test")
@click.argument("target")
@click.option("--context", default="LLM application", help="Target description.", show_default=True)
@click.option(
    "--categories", "-C", multiple=True,
    type=click.Choice(list(VALID_CATEGORIES), case_sensitive=False),
    help="Attack categories (repeatable). Default: all.",
)
@click.option("--output", "-o", default=None, help="Save HTML report to path.")
@click.option("--json", "json_output", default=None, help="Save JSON report to path.")
@click.option(
    "--severity", "-s", default="low",
    type=click.Choice(SEVERITY_ORDER, case_sensitive=False),
    help="Minimum severity to display.", show_default=True,
)
@click.option(
    "--fail-on", "-f", default=None,
    type=click.Choice(SEVERITY_ORDER, case_sensitive=False),
    help="Exit code 1 if any vulnerability at or above this severity is found.",
)
@click.option("--max-workers", "-w", default=5, show_default=True, help="Concurrent workers.")
@click.option("--timeout", "-T", default=30.0, show_default=True, help="Per-attack timeout (s).")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
def test_cmd(
    target: str,
    context: str,
    categories: tuple[str, ...],
    output: str | None,
    json_output: str | None,
    severity: str,
    fail_on: str | None,
    max_workers: int,
    timeout: float,
    verbose: bool,
) -> None:
    """Quick security test — pass a URL or module:function directly.

    \b
    Examples:
      $ promptfuzz test https://api.mychatbot.com/chat
      $ promptfuzz test https://api.mychatbot.com/chat --output report.html
      $ promptfuzz test myapp:chat_handler --categories jailbreak injection
      $ promptfuzz test https://api.mychatbot.com/chat --fail-on high
    """
    _run_scan(
        target=target,
        context=context,
        categories=categories,
        output=output,
        json_output=json_output,
        severity=severity,
        fail_on=fail_on,
        max_workers=max_workers,
        timeout=timeout,
        verbose=verbose,
    )


@main.command("scan")
@click.option("--target", "-t", default=None, help="URL or module:function path.")
@click.option("--config", "-c", default=None, help="YAML config file path.")
@click.option("--context", default="LLM application", help="Target description.")
@click.option(
    "--categories", "-C", multiple=True,
    type=click.Choice(list(VALID_CATEGORIES), case_sensitive=False),
    help="Attack categories to run (repeatable). Default: all.",
)
@click.option("--output", "-o", default=None, help="Save HTML report to path.")
@click.option("--json", "json_output", default=None, help="Save JSON report to path.")
@click.option(
    "--severity", "-s", default="low",
    type=click.Choice(SEVERITY_ORDER, case_sensitive=False),
    help="Minimum severity to display in output.",
)
@click.option(
    "--fail-on", "-f", default=None,
    type=click.Choice(SEVERITY_ORDER, case_sensitive=False),
    help="Exit with code 1 if any vulnerability at or above this severity is found.",
)
@click.option("--max-workers", "-w", default=5, help="Max concurrent requests.", show_default=True)
@click.option("--timeout", "-T", default=30.0, help="Per-attack timeout in seconds.", show_default=True)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
def scan(
    target: str | None,
    config: str | None,
    context: str,
    categories: tuple[str, ...],
    output: str | None,
    json_output: str | None,
    severity: str,
    fail_on: str | None,
    max_workers: int,
    timeout: float,
    verbose: bool,
) -> None:
    """Full scan with config file support and all advanced options.

    \b
    Examples:
      $ promptfuzz scan --target https://api.mychatbot.com/chat
      $ promptfuzz scan --config promptfuzz.yaml --output report.html
      $ promptfuzz scan --target myapp:chat --categories jailbreak --fail-on high
    """
    from promptfuzz.fuzzer import Fuzzer

    if not target and not config:
        _err.print("[bold red]Error:[/bold red] Provide --target or --config.")
        sys.exit(1)

    if target and config:
        _err.print("[bold red]Error:[/bold red] --target and --config are mutually exclusive.")
        sys.exit(1)

    if config:
        try:
            fuzzer = Fuzzer.from_config(config)
        except (FileNotFoundError, ValueError) as exc:
            _err.print(f"[bold red]Error:[/bold red] {exc}")
            sys.exit(1)

        _console.print(f"[bold]PromptFuzz[/bold] v{__version__} — starting scan")
        _console.print(f"Config: [cyan]{config}[/cyan]")
        _console.print()

        result = fuzzer.run()
        sev_idx = SEVERITY_ORDER.index(severity)
        original_vulns = result.vulnerabilities
        result.vulnerabilities = [  # type: ignore[assignment]
            v for v in result.vulnerabilities if SEVERITY_ORDER.index(v.severity) <= sev_idx
        ]
        result.report()
        result.vulnerabilities = original_vulns  # type: ignore[assignment]

        if output:
            result.save(output)
        if json_output:
            result.to_json(json_output)
        if fail_on:
            threshold_idx = SEVERITY_ORDER.index(fail_on)
            failing = [
                v for v in result.vulnerabilities
                if SEVERITY_ORDER.index(v.severity) <= threshold_idx
            ]
            if failing:
                _console.print(
                    f"[bold red]FAIL:[/bold red] {len(failing)} vulnerability/ies "
                    f"at or above '{fail_on}' severity found."
                )
                sys.exit(1)
    else:
        _run_scan(
            target=target,  # type: ignore[arg-type]
            context=context,
            categories=categories,
            output=output,
            json_output=json_output,
            severity=severity,
            fail_on=fail_on,
            max_workers=max_workers,
            timeout=timeout,
            verbose=verbose,
        )


@main.command("list-attacks")
def list_attacks() -> None:
    """Show all 165+ built-in attacks by category with severity breakdown."""
    loader = AttackLoader()

    table = Table(title="Available Attacks", show_header=True, header_style="bold dim")
    table.add_column("Category", min_width=20)
    table.add_column("Total", justify="right")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("High", justify="right", style="orange3")
    table.add_column("Medium", justify="right", style="yellow")
    table.add_column("Low", justify="right", style="blue")

    grand_total = 0
    for category in sorted(VALID_CATEGORIES):
        attacks = loader.load_category(category)
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for atk in attacks:
            counts[atk.severity] = counts.get(atk.severity, 0) + 1
        total = len(attacks)
        grand_total += total
        table.add_row(
            category,
            str(total),
            str(counts["critical"]),
            str(counts["high"]),
            str(counts["medium"]),
            str(counts["low"]),
        )

    table.add_section()
    table.add_row("[bold]TOTAL[/bold]", f"[bold]{grand_total}[/bold]", "", "", "", "")

    _console.print(table)


@main.command("version")
def version() -> None:
    """Print the installed PromptFuzz version."""
    _console.print(f"PromptFuzz v{__version__}")


@main.command("validate")
@click.option("--config", "-c", required=True, help="YAML config file to validate.")
def validate(config: str) -> None:
    """Validate a YAML configuration file and report any errors."""
    from promptfuzz.fuzzer import Fuzzer

    path = Path(config)
    if not path.exists():
        _err.print(f"[bold red]Error:[/bold red] File not found: {config}")
        sys.exit(1)

    try:
        fuzzer = Fuzzer.from_config(config)
        _console.print("[bold green]Valid[/bold green] — config loaded successfully.")
        _console.print(f"  Target:      {fuzzer.target}")
        _console.print(f"  Context:     {fuzzer.context}")
        _console.print(f"  Categories:  {fuzzer.categories or 'all'}")
        _console.print(f"  Max workers: {fuzzer.max_workers}")
        _console.print(f"  Timeout:     {fuzzer.timeout}s")
    except FileNotFoundError as exc:
        _err.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        _err.print(f"[bold red]Invalid config:[/bold red] {exc}")
        sys.exit(1)
