"""Interactive wizard — launches when `promptfuzz` is run with no arguments."""

from __future__ import annotations

import json
import os
import shlex
import sys
from typing import Any

import click
import questionary
from rich.console import Console
from rich.text import Text

from promptfuzz import __version__
from promptfuzz.attacks.loader import VALID_CATEGORIES

_console = Console()

# Sentinel returned by step functions when the user presses ESC (go back).
_BACK = object()

_LOGO_PROMPT = (
    "   ____   ____    ___   __  __  ____  ______\n"
    "  |  _ \\ |  _ \\  / _ \\ |  \\/  ||  _ \\|_   _|\n"
    "  | |_) || |_) || | | || |\\/| || |_) | | |  \n"
    "  |  __/ |  _ < | |_| || |  | ||  __/  | |  \n"
    "  |_|    |_| \\_\\ \\___/ |_|  |_||_|     |_|  "
)

_LOGO_FUZZ = (
    "   _____  _   _  _____  _____ \n"
    "  |  ___|| | | ||__  / |__  / \n"
    "  | |_   | | | |  / /    / /  \n"
    "  |  _|  | |_| | / /_   / /_  \n"
    "  |_|     \\___/ /_____|/_____|"
)


def _print_header() -> None:
    """Clear the screen and reprint the PromptFuzz logo + tagline."""
    click.clear()
    _console.print()
    _console.print(_LOGO_PROMPT, style="bold white")
    _console.print(_LOGO_FUZZ, style="bold red")
    _console.print()
    _console.print(
        f"  [dim]adversarial LLM security testing"
        f"  ·  v{__version__}"
        f"  ·  165 attacks  ·  5 categories[/dim]"
    )
    _console.rule(style="dim")
    _console.print()

_CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "jailbreak": "Persona switches, DAN, roleplay bypasses",
    "injection": "Prompt override, delimiter attacks",
    "data_extraction": "System prompt leaking, credential extraction",
    "goal_hijacking": "Purpose redirection attacks",
    "edge_cases": "Unicode, long inputs, encoding attacks",
}

_OUTPUT_CHOICES = [
    questionary.Choice("terminal only", value="terminal"),
    questionary.Choice("terminal + report.txt", value="txt"),
    questionary.Choice("terminal + report.html", value="html"),
    questionary.Choice("all formats  (txt + html + json)", value="all"),
]

_SEVERITY_CHOICES = [
    questionary.Choice("low      show everything", value="low"),
    questionary.Choice("medium", value="medium"),
    questionary.Choice("high", value="high"),
    questionary.Choice("critical  only the worst", value="critical"),
]

_SCAN_MODE_CHOICES = [
    questionary.Choice(
        "single-shot  —  165 targeted attacks, one prompt per test",
        value="single",
    ),
    questionary.Choice(
        "multi-turn   —  12 chain attacks, gradual escalation across turns",
        value="chains",
    ),
    questionary.Choice(
        "both         —  full coverage (recommended)",
        value="both",
    ),
]


# ---------------------------------------------------------------------------
# Curl parsing
# ---------------------------------------------------------------------------


def _parse_curl(curl_str: str) -> dict[str, Any]:
    """Parse a curl command string and extract URL, headers, and body fields.

    Args:
        curl_str: Raw curl command, possibly multi-line with backslash continuations.

    Returns:
        Dict with keys 'url' (str|None), 'headers' (dict), 'body_fields' (dict).
    """
    curl_str = curl_str.replace("\\\n", " ").replace("\\\r\n", " ")

    try:
        tokens = shlex.split(curl_str)
    except ValueError:
        tokens = curl_str.split()

    result: dict[str, Any] = {"url": None, "headers": {}, "body_fields": {}}

    # Hop-by-hop and browser-managed headers that must not be forwarded to httpx.
    # Forwarding Transfer-Encoding: chunked alongside a known-size JSON body causes
    # HTTP/1.1 framing conflicts and HTTP 400 errors on many servers.
    _HOP_BY_HOP = {
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "upgrade",
        "accept-encoding",  # httpx negotiates compression itself
        "content-length",   # httpx sets this automatically for JSON payloads
    }

    skip_flags = {
        "-X", "--request", "--compressed", "-s", "--silent", "-v", "--verbose"
    }
    data_flags = {"--data-raw", "--data", "-d", "--data-urlencode"}

    i = 0
    while i < len(tokens):
        tok = tokens[i]

        if tok == "curl":
            i += 1
            continue

        if tok in skip_flags:
            i += 2
            continue

        if tok in {"-H", "--header"}:
            i += 1
            if i < len(tokens):
                header_str = tokens[i]
                if ":" in header_str:
                    key, _, val = header_str.partition(":")
                    if key.strip().lower() not in _HOP_BY_HOP:
                        result["headers"][key.strip()] = val.strip()
            i += 1
            continue

        if tok.startswith("-H"):
            header_str = tok[2:]
            if ":" in header_str:
                key, _, val = header_str.partition(":")
                if key.strip().lower() not in _HOP_BY_HOP:
                    result["headers"][key.strip()] = val.strip()
            i += 1
            continue

        if tok in data_flags:
            i += 1
            if i < len(tokens):
                raw = tokens[i]
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        result["body_fields"] = parsed
                except (json.JSONDecodeError, ValueError):
                    pass
            i += 1
            continue

        if tok.startswith("--data") or tok.startswith("-d"):
            _, _, val = tok.partition("=")
            if val:
                try:
                    parsed = json.loads(val)
                    if isinstance(parsed, dict):
                        result["body_fields"] = parsed
                except (json.JSONDecodeError, ValueError):
                    pass
            i += 1
            continue

        if tok.startswith("http://") or tok.startswith("https://"):
            result["url"] = tok
            i += 1
            continue

        i += 1

    return result


# ---------------------------------------------------------------------------
# HTTP probing
# ---------------------------------------------------------------------------


def _probe_url_with_headers(
    url: str,
    headers: dict[str, str],
    input_field: str,
    output_field: str,
    extra_fields: dict[str, str],
) -> tuple[bool, str, dict[str, Any]]:
    """Send a test POST to the URL and return (success, message, response_body).

    Args:
        url: Target URL.
        headers: HTTP headers to include.
        input_field: JSON key for the prompt.
        output_field: JSON key for the reply.
        extra_fields: Extra fixed fields to include in the payload.

    Returns:
        Tuple of (ok, diagnostic_message, response_json_or_empty_dict).
    """
    import httpx

    payload = {input_field: "hello", **extra_fields}
    try:
        r = httpx.post(url, json=payload, headers=headers, timeout=10.0)
        if r.status_code >= 400:
            try:
                body = r.json()
            except Exception:
                body = r.text[:300]
            return False, (
                f"HTTP {r.status_code} — API rejected the request.\n"
                f"  Response: {body}\n"
                f"  Hint: Check if the API requires extra fields "
                f"(e.g. conversation_id, session_id)."
            ), {}
        try:
            data = r.json()
        except Exception:
            return True, "Connected (non-JSON response). output_field ignored.", {}

        if output_field and output_field not in data:
            available = ", ".join(str(k) for k in data.keys()) or "(empty)"
            return False, (
                f"Connected but response field '{output_field}' not found.\n"
                f"  Available keys: {available}\n"
                f"  Hint: Set the response field to one of the above."
            ), data
        return True, f"OK — received reply via '{output_field}' field.", data

    except httpx.ConnectError:
        return False, (
            f"Cannot connect to {url}.\n"
            f"  Hint: Is the server running? Check the URL."
        ), {}
    except httpx.TimeoutException:
        return False, (
            "Connection timed out (10s). Is the server slow or unreachable?"
        ), {}


def _probe_url(
    url: str,
    input_field: str,
    output_field: str,
    extra_fields: dict[str, str],
) -> tuple[bool, str]:
    """Send a single test request to the URL and return (success, message).

    Args:
        url: Target URL.
        input_field: JSON key for the prompt.
        output_field: JSON key for the reply.
        extra_fields: Extra fixed fields to include in the payload.

    Returns:
        Tuple of (ok, diagnostic_message).
    """
    ok, msg, _ = _probe_url_with_headers(
        url, {}, input_field, output_field, extra_fields
    )
    return ok, msg


# ---------------------------------------------------------------------------
# Individual step functions — return value or _BACK on ESC
# ---------------------------------------------------------------------------


def _step_ask_target() -> Any:
    """Ask target type and URL/path. Returns target string or _BACK."""
    target_type = questionary.select(
        "What is your target?",
        choices=[
            questionary.Choice("HTTP/HTTPS endpoint (URL)", value="url"),
            questionary.Choice("Python function (module:function)", value="function"),
        ],
    ).ask()

    if target_type is None:
        return _BACK

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
                return _BACK
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
                return _BACK
            return path


def _step_ask_headers() -> Any:
    """Ask for auth/custom headers. Returns dict or _BACK."""
    headers_raw = questionary.text(
        "Auth/custom headers? (e.g. Authorization=Bearer xyz,X-Workspace-Id=abc) "
        "Leave blank to skip:",
        default="",
    ).ask()

    if headers_raw is None:
        return _BACK

    headers: dict[str, str] = {}
    if headers_raw.strip():
        for pair in headers_raw.split(","):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                headers[k.strip()] = v.strip()
    return headers


def _step_ask_extra_fields() -> Any:
    """Ask for extra payload fields. Returns dict or _BACK."""
    extra_raw = questionary.text(
        "Extra payload fields? (e.g. conversation_id=abc123,api_key=xyz) "
        "Leave blank to skip:",
        default="",
    ).ask()

    if extra_raw is None:
        return _BACK

    extra_fields: dict[str, str] = {}
    if extra_raw.strip():
        for pair in extra_raw.split(","):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                extra_fields[k.strip()] = v.strip()
    return extra_fields


def _step_probe_and_pick_output(
    url: str,
    headers: dict[str, str],
    extra_fields: dict[str, str],
) -> Any:
    """Probe URL and pick output field from response keys.

    Returns field str or _BACK.
    """
    _console.print(f"[dim]Testing connection to {url}...[/dim]")
    ok, msg, response_data = _probe_url_with_headers(
        url, headers, "message", "", extra_fields
    )

    if ok and response_data:
        _console.print("[green]connected[/green]")
        result = _select_output_field_from_response(response_data)
        if result is None:
            return _BACK
        return result
    elif ok:
        _console.print(f"[green]connected[/green] {msg}")
    else:
        _console.print(f"[yellow]connection failed:[/yellow] {msg}")
        retry = questionary.confirm(
            "Fix the settings and try again?", default=True
        ).ask()
        if retry is None:
            return _BACK
        if retry:
            # Signal caller to go back to extra_fields step
            return _BACK

    field = questionary.text(
        "Response field name (JSON key the API returns the reply in):",
        default="response",
    ).ask()
    if field is None:
        return _BACK
    return (field or "response").strip()


def _step_ask_scan_mode() -> Any:
    """Ask whether to run single-shot, chains-only, or both. Returns str or _BACK."""
    result = questionary.select(
        "Attack mode:",
        choices=_SCAN_MODE_CHOICES,
    ).ask()
    if result is None:
        return _BACK
    return result


def _step_ask_categories() -> Any:
    """Multi-select attack categories. Returns list or _BACK."""
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
            return _BACK
        if selected:
            return selected
        _console.print("[yellow]Please select at least one category.[/yellow]")


def _step_ask_output() -> Any:
    """Ask output format. Returns str or _BACK."""
    result = questionary.select(
        "Output format:",
        choices=_OUTPUT_CHOICES,
    ).ask()
    if result is None:
        return _BACK
    return result


def _step_ask_severity() -> Any:
    """Ask minimum severity. Returns str or _BACK."""
    result = questionary.select(
        "Minimum severity to report:",
        choices=_SEVERITY_CHOICES,
    ).ask()
    if result is None:
        return _BACK
    return result


def _step_confirm_and_launch(
    target: str,
    categories: list[str],
    output_fmt: str,
    severity: str,
    output_field: str,
    extra_fields: dict[str, str],
    headers: dict[str, str],
    scan_mode: str = "single",
) -> Any:
    """Show summary panel and ask to confirm.

    Returns True to launch, _BACK on ESC, False on No.
    """
    from promptfuzz.attacks.chain_loader import ChainLoader
    from promptfuzz.attacks.loader import AttackLoader

    output_label = {
        "terminal": "Terminal only",
        "txt": "Terminal + report.txt",
        "html": "Terminal + report.html",
        "all": "Terminal + report.txt + report.html + report.json",
    }[output_fmt]

    summary = Text()
    summary.append("  target   ", style="dim")
    summary.append(f"{target}\n", style="cyan")

    if scan_mode in {"single", "both"}:
        loader = AttackLoader()
        attacks = loader.load_categories(categories)
        summary.append("  attacks  ", style="dim")
        summary.append(
            f"{len(attacks)}  ({' + '.join(categories)})\n"
        )

    if scan_mode in {"chains", "both"}:
        chain_loader = ChainLoader()
        chains = chain_loader.load_all()
        summary.append("  chains   ", style="dim")
        summary.append(f"{len(chains)} multi-turn\n")

    summary.append("  mode     ", style="dim")
    mode_label = {
        "single": "single-shot",
        "chains": "multi-turn chains",
        "both": "both (full coverage)",
    }[scan_mode]
    summary.append(f"{mode_label}\n")
    summary.append("  output   ", style="dim")
    summary.append(f"{output_label}\n")
    summary.append("  severity ", style="dim")
    summary.append(f"{severity}+\n")
    if extra_fields:
        summary.append("  extra    ", style="dim")
        summary.append(f"{', '.join(f'{k}={v}' for k, v in extra_fields.items())}\n")
    if headers:
        summary.append("  headers  ", style="dim")
        summary.append(f"{', '.join(headers.keys())}\n")

    _console.print()
    _console.rule("[dim]scan configuration[/dim]", style="dim")
    _console.print(summary)
    _console.rule(style="dim")
    _console.print()

    go = questionary.confirm(
        "Press ENTER to start scan (Ctrl+C to cancel)", default=True
    ).ask()

    if go is None:
        return _BACK
    return go


def _select_output_field_from_response(
    response_data: dict[str, Any],
) -> str | None:
    """Present response keys as a select list; fall back to manual entry.

    Args:
        response_data: Parsed JSON response from a probe request.

    Returns:
        The chosen output field name, or None if ESC was pressed.
    """
    str_keys = [k for k, v in response_data.items() if isinstance(v, str)]
    all_keys = list(response_data.keys())
    candidates = str_keys if str_keys else all_keys

    if not candidates:
        fallback = questionary.text(
            "Response field name (JSON key the API returns the reply in):",
            default="response",
        ).ask()
        if fallback is None:
            return None
        return (fallback or "response").strip()

    choices = [questionary.Choice(k, value=k) for k in candidates]
    choices.append(questionary.Choice("(type manually)", value="__manual__"))

    selected = questionary.select(
        "Connected! Which field contains the chatbot's reply?",
        choices=choices,
    ).ask()

    if selected is None:
        return None

    if selected == "__manual__":
        manual = questionary.text(
            "Response field name:",
            default="response",
        ).ask()
        if manual is None:
            return None
        return (manual or "response").strip()

    return selected


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
        return False
    return result


# ---------------------------------------------------------------------------
# Manual wizard — step loop with ESC = go back
# ---------------------------------------------------------------------------


def _run_manual_wizard() -> None:
    """Run the step-by-step guided setup wizard with ESC-to-go-back support."""
    # Mutable state accumulated across steps
    target: str = ""
    headers: dict[str, str] = {}
    extra_fields: dict[str, str] = {}
    output_field: str = "response"
    scan_mode: str = "single"
    categories: list[str] = []
    output_fmt: str = "terminal"
    severity: str = "low"

    # URL targets:      0=target, 1=headers, 2=extra_fields, 3=output_field,
    #                   4=scan_mode, 5=categories*, 6=output, 7=severity, 8=confirm
    # Function targets: 0=target, 1-3=skipped,
    #                   4=scan_mode, 5=categories*, 6=output, 7=severity, 8=confirm
    # *step 5 skipped when scan_mode == "chains"

    step = 0
    while True:

        # ── Step 0: target ──────────────────────────────────────────────────
        if step == 0:
            result = _step_ask_target()
            if result is _BACK:
                _run_landing()
                return
            target = result
            step = 1

        # ── Step 1: headers (URL only) ───────────────────────────────────────
        elif step == 1:
            if target.startswith("http://") or target.startswith("https://"):
                result = _step_ask_headers()
                if result is _BACK:
                    step = 0
                    continue
                headers = result
            step = 2

        # ── Step 2: extra fields (URL only) ─────────────────────────────────
        elif step == 2:
            if target.startswith("http://") or target.startswith("https://"):
                result = _step_ask_extra_fields()
                if result is _BACK:
                    step = 1
                    continue
                extra_fields = result
            step = 3

        # ── Step 3: probe + output field (URL only) ──────────────────────────
        elif step == 3:
            if target.startswith("http://") or target.startswith("https://"):
                result = _step_probe_and_pick_output(target, headers, extra_fields)
                if result is _BACK:
                    step = 2
                    continue
                output_field = result
            step = 4

        # ── Step 4: scan mode ────────────────────────────────────────────────
        elif step == 4:
            result = _step_ask_scan_mode()
            if result is _BACK:
                is_url = target.startswith("http://") or target.startswith("https://")
                step = 3 if is_url else 0
                continue
            scan_mode = result
            step = 5 if scan_mode in {"single", "both"} else 6

        # ── Step 5: categories (skipped for chains-only) ─────────────────────
        elif step == 5:
            result = _step_ask_categories()
            if result is _BACK:
                step = 4
                continue
            categories = result
            step = 6

        # ── Step 6: output format ─────────────────────────────────────────────
        elif step == 6:
            result = _step_ask_output()
            if result is _BACK:
                step = 5 if scan_mode in {"single", "both"} else 4
                continue
            output_fmt = result
            step = 7

        # ── Step 7: severity ──────────────────────────────────────────────────
        elif step == 7:
            result = _step_ask_severity()
            if result is _BACK:
                step = 6
                continue
            severity = result
            step = 8

        # ── Step 8: confirm + launch ──────────────────────────────────────────
        elif step == 8:
            result = _step_confirm_and_launch(
                target, categories, output_fmt, severity,
                output_field, extra_fields, headers,
                scan_mode=scan_mode,
            )
            if result is _BACK:
                step = 7
                continue
            if not result:
                _console.print("[dim]Scan cancelled.[/dim]")
                sys.exit(0)
            _console.print()
            _launch_scan(
                target, categories, output_fmt, severity,
                output_field, extra_fields, headers=headers,
                run_chains=scan_mode in {"chains", "both"},
                run_attacks=scan_mode in {"single", "both"},
            )
            return


# ---------------------------------------------------------------------------
# Curl import wizard — step loop with ESC = go back
# ---------------------------------------------------------------------------


def _run_curl_wizard() -> None:
    """Run the curl-import wizard with ESC-to-go-back support."""
    url: str = ""
    headers: dict[str, str] = {}
    body_fields: dict[str, Any] = {}
    input_field: str = "message"
    extra_fields: dict[str, str] = {}
    output_field: str = "response"
    scan_mode: str = "single"
    categories: list[str] = []
    output_fmt: str = "terminal"
    severity: str = "low"

    step = 0
    while True:

        # ── Step 0: paste curl ───────────────────────────────────────────────
        if step == 0:
            _console.print(
                "[dim]paste your curl command "
                "(single line or with backslash continuations)[/dim]"
            )
            curl_raw = questionary.text("curl:").ask()
            if curl_raw is None:
                _run_landing()
                return

            parsed = _parse_curl(curl_raw.strip())
            url = parsed["url"] or ""
            headers = parsed["headers"]
            body_fields = parsed["body_fields"]

            header_names = ", ".join(headers.keys()) or "(none)"
            field_names = ", ".join(str(k) for k in body_fields.keys()) or "(none)"

            _console.print()
            _console.rule("[dim]parsed[/dim]", style="dim")
            _console.print(
                f"  [dim]url     [/dim] [cyan]{url or '(not found)'}[/cyan]\n"
                f"  [dim]headers [/dim] {header_names}\n"
                f"  [dim]fields  [/dim] {field_names}"
            )
            _console.rule(style="dim")
            _console.print()

            if not url:
                _console.print(
                    "[yellow]Could not detect URL from curl command.[/yellow]"
                )
                switch = questionary.confirm(
                    "Switch to manual setup instead?", default=True
                ).ask()
                if switch or switch is None:
                    _run_manual_wizard()
                return

            step = 1

        # ── Step 1: input field ──────────────────────────────────────────────
        elif step == 1:
            str_fields = [k for k, v in body_fields.items() if isinstance(v, str)]
            if len(str_fields) == 1:
                input_field = str_fields[0]
                _console.print(
                    f"[dim]input field →[/dim] [cyan]{input_field}[/cyan]"
                )
                step = 2
            elif str_fields:
                sel = questionary.select(
                    "Which field contains the user's message?",
                    choices=str_fields,
                ).ask()
                if sel is None:
                    step = 0
                    continue
                input_field = sel
                step = 2
            else:
                field_text = questionary.text(
                    "Input field name (JSON key for the user's message):",
                    default="message",
                ).ask()
                if field_text is None:
                    step = 0
                    continue
                input_field = (field_text or "message").strip()
                step = 2

        # ── Step 2: probe + output field ─────────────────────────────────────
        elif step == 2:
            extra_fields = {
                k: str(v) for k, v in body_fields.items() if k != input_field
            }
            _console.print(f"[dim]probing {url}...[/dim]")
            ok, msg, response_data = _probe_url_with_headers(
                url, headers, input_field, "", extra_fields
            )

            if ok and response_data:
                _console.print("[green]connected[/green]")
                picked = _select_output_field_from_response(response_data)
                if picked is None:
                    step = 1
                    continue
                output_field = picked
            elif ok:
                _console.print(f"[green]connected[/green] {msg}")
                field_text = questionary.text(
                    "Response field name (JSON key the API returns the reply in):",
                    default="response",
                ).ask()
                if field_text is None:
                    step = 1
                    continue
                output_field = (field_text or "response").strip()
            else:
                _console.print(f"[yellow]probe failed:[/yellow] {msg}")
                proceed = questionary.confirm(
                    "Continue anyway (type output field manually)?", default=True
                ).ask()
                if proceed is None or not proceed:
                    step = 1
                    continue
                field_text = questionary.text(
                    "Response field name:", default="response"
                ).ask()
                if field_text is None:
                    step = 1
                    continue
                output_field = (field_text or "response").strip()

            step = 3

        # ── Step 3: scan mode ────────────────────────────────────────────────
        elif step == 3:
            result = _step_ask_scan_mode()
            if result is _BACK:
                step = 2
                continue
            scan_mode = result
            # Chains-only mode skips category selection (chains span all
            # categories); jump straight to output format.
            step = 4 if scan_mode in {"single", "both"} else 5

        # ── Step 4: categories (single-shot or both) ─────────────────────────
        elif step == 4:
            result = _step_ask_categories()
            if result is _BACK:
                step = 3
                continue
            categories = result
            step = 5

        # ── Step 5: output format ─────────────────────────────────────────────
        elif step == 5:
            result = _step_ask_output()
            if result is _BACK:
                step = 4 if scan_mode in {"single", "both"} else 3
                continue
            output_fmt = result
            step = 6

        # ── Step 6: severity ──────────────────────────────────────────────────
        elif step == 6:
            result = _step_ask_severity()
            if result is _BACK:
                step = 5
                continue
            severity = result
            step = 7

        # ── Step 7: confirm + launch ──────────────────────────────────────────
        elif step == 7:
            result = _step_confirm_and_launch(
                url, categories, output_fmt, severity,
                output_field, extra_fields, headers,
                scan_mode=scan_mode,
            )
            if result is _BACK:
                step = 6
                continue
            if not result:
                _console.print("[dim]Scan cancelled.[/dim]")
                sys.exit(0)
            _console.print()
            _launch_scan(
                url, categories, output_fmt, severity,
                output_field, extra_fields, headers=headers,
                run_chains=scan_mode in {"chains", "both"},
                run_attacks=scan_mode in {"single", "both"},
            )
            return


# ---------------------------------------------------------------------------
# Quick scan — step loop with ESC = go back
# ---------------------------------------------------------------------------


def _run_quick_scan() -> None:
    """Ask for URL, optional auth headers, optional extra fields, then fire all attacks.

    ESC goes back to landing.
    """
    url: str = ""
    headers: dict[str, str] = {}
    extra_fields: dict[str, str] = {}
    output_field: str = "response"

    step = 0
    while True:

        # ── Step 0: URL ──────────────────────────────────────────────────────
        if step == 0:
            url_input = questionary.text(
                "Enter target URL:",
                validate=lambda t: (
                    True
                    if t.startswith("http://") or t.startswith("https://")
                    else "Must start with http:// or https://"
                ),
            ).ask()
            if url_input is None:
                _run_landing()
                return
            url = url_input
            step = 1

        # ── Step 1: headers ──────────────────────────────────────────────────
        elif step == 1:
            result = _step_ask_headers()
            if result is _BACK:
                step = 0
                continue
            headers = result
            step = 2

        # ── Step 2: extra body fields ─────────────────────────────────────────
        elif step == 2:
            result = _step_ask_extra_fields()
            if result is _BACK:
                step = 1
                continue
            extra_fields = result
            step = 3

        # ── Step 3: probe + output field ─────────────────────────────────────
        elif step == 3:
            _console.print(f"[dim]probing {url}...[/dim]")
            ok, msg, response_data = _probe_url_with_headers(
                url, headers, "message", "", extra_fields
            )

            if ok and response_data:
                str_keys = [k for k, v in response_data.items() if isinstance(v, str)]
                if len(str_keys) == 1:
                    output_field = str_keys[0]
                    _console.print(
                        f"[green]connected[/green]  [dim]output field →[/dim] "
                        f"[cyan]{output_field}[/cyan]"
                    )
                    step = 4
                elif str_keys:
                    picked = _select_output_field_from_response(response_data)
                    if picked is None:
                        step = 2
                        continue
                    output_field = picked
                    step = 4
                else:
                    _console.print("[green]connected[/green]")
                    step = 4
            elif ok:
                _console.print(f"[green]connected[/green] {msg}")
                step = 4
            else:
                _console.print(f"[yellow]probe failed:[/yellow] {msg}")
                proceed = questionary.confirm(
                    "Continue anyway with default settings?", default=True
                ).ask()
                if proceed is None:
                    step = 2
                    continue
                if not proceed:
                    sys.exit(0)
                step = 4

        # ── Step 4: launch ───────────────────────────────────────────────────
        elif step == 4:
            categories = list(VALID_CATEGORIES)
            _console.print(
                f"[dim]running {len(categories)} categories, low threshold...[/dim]"
            )
            _console.print()
            _launch_scan(
                url, categories, "terminal", "low", output_field,
                extra_fields, headers=headers,
            )
            return


# ---------------------------------------------------------------------------
# Help screen
# ---------------------------------------------------------------------------


def _show_help() -> None:
    """Display the in-app help guide then loop back to the landing screen."""
    help_text = Text()

    help_text.append("getting a curl from devtools\n", style="bold")
    help_text.append("  1. open chrome/edge → F12 → network tab\n", style="dim")
    help_text.append(
        "  2. send a message to your chatbot in the browser\n", style="dim"
    )
    help_text.append(
        "  3. right-click the request → copy → copy as cURL (bash)\n", style="dim"
    )
    help_text.append(
        "     then choose \"import from curl\" in PromptFuzz\n\n", style="dim"
    )

    help_text.append("attack categories\n", style="bold")
    for cat, desc in _CATEGORY_DESCRIPTIONS.items():
        help_text.append(f"  {cat:<20}", style="cyan")
        help_text.append(f" {desc}\n", style="dim")
    help_text.append("\n")

    help_text.append("cli examples\n", style="bold")
    help_text.append(
        "  promptfuzz scan --target http://localhost:8000/chat --verbose\n", style="dim"
    )
    help_text.append(
        "  promptfuzz scan --target mymodule:my_fn"
        " --categories jailbreak\n",
        style="dim",
    )
    help_text.append("  promptfuzz list-attacks\n\n", style="dim")

    help_text.append("python wrapper (for complex APIs)\n", style="bold")
    help_text.append("  from promptfuzz import Fuzzer\n\n", style="dim")
    help_text.append("  def my_bot(prompt: str) -> str:\n", style="dim")
    help_text.append("      # call your API here\n", style="dim")
    help_text.append("      return response_text\n\n", style="dim")
    help_text.append("  result = Fuzzer(target=my_bot).run()\n", style="dim")
    help_text.append("  result.report()\n", style="dim")

    _print_header()
    _console.rule("[dim]help[/dim]", style="dim")
    _console.print(help_text)
    _console.rule(style="dim")
    _console.print()

    _run_landing()


# ---------------------------------------------------------------------------
# Landing screen
# ---------------------------------------------------------------------------


def _run_landing() -> None:
    """Clear screen, reprint header, show landing menu, and route to chosen path.

    ESC on landing screen exits the program.
    """
    _print_header()

    choice = questionary.select(
        "how to set up your scan?",
        choices=[
            questionary.Choice(
                "curl import    ★  paste a curl — auto-detects URL, headers & fields",
                value="curl",
            ),
            questionary.Choice(
                "manual setup      step-by-step guided configuration",
                value="manual",
            ),
            questionary.Choice(
                "quick scan        fire all 165 attacks now, zero config",
                value="quick",
            ),
            questionary.Choice(
                "help              DevTools guide · CLI usage · attack list",
                value="help",
            ),
        ],
    ).ask()

    if choice is None:
        sys.exit(0)

    if choice == "manual":
        _run_manual_wizard()
    elif choice == "curl":
        _run_curl_wizard()
    elif choice == "quick":
        _run_quick_scan()
    elif choice == "help":
        _show_help()


def run_wizard() -> None:
    """Entry point: show the landing screen and route to the chosen setup path.

    Presents four options: manual setup, curl import, quick scan, and help.
    ESC on landing screen exits the program.
    """
    _run_landing()


# ---------------------------------------------------------------------------
# Scan launcher
# ---------------------------------------------------------------------------


def _launch_scan(
    target: str,
    categories: list[str],
    output_fmt: str,
    severity: str,
    output_field: str = "response",
    extra_fields: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    run_chains: bool = False,
    run_attacks: bool = True,
) -> None:
    """Execute the scan with the wizard's chosen settings.

    Args:
        target: URL or 'module:function' import path.
        categories: Attack categories to run.
        output_fmt: One of 'terminal', 'txt', 'html', 'all'.
        severity: Minimum severity to display ('low', 'medium', 'high', 'critical').
        output_field: JSON key containing the model reply in HTTP mode.
        extra_fields: Extra fixed key-value pairs merged into every request payload.
        headers: HTTP headers to include in every request.
        run_chains: Whether to execute multi-turn attack chains.
        run_attacks: Whether to execute single-shot attacks.
    """
    import importlib

    from promptfuzz.fuzzer import SEVERITY_WEIGHTS, Fuzzer  # noqa: F401

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
        output_field=output_field,
        extra_fields=extra_fields or {},
        headers=headers or {},
        verbose=False,
        run_chains=run_chains,
        run_attacks=run_attacks,
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
