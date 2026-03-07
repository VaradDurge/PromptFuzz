"""PromptFuzz — security test for the PICT Dialogflow Messenger chatbot.

Class assignment: authorized security testing of PICT's information chatbot.

HOW TO RUN:
  Step 1 — Close ALL Chrome windows, then open Chrome with remote debugging:
            Windows: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --remote-debugging-port=9222 --user-data-dir=C:\\ChromeDebug

  Step 2 — In that Chrome window, go to https://pict.edu
            Let Cloudflare verify you normally. Open the chat widget.

  Step 3 — Run this script in a second terminal:
            python browser_test.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from datetime import datetime, timezone

os.environ["PYTHONUTF8"] = "1"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from promptfuzz.analyzer import Analyzer, Vulnerability
from promptfuzz.attacks.loader import AttackLoader
from promptfuzz.fuzzer import SEVERITY_WEIGHTS, FuzzResult
from promptfuzz.runner import AttackResult

_console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────
CHATBOT_URL = "https://pict.edu"
TARGET_DESCRIPTION = "PICT information chatbot (Dialogflow Messenger)"
TARGET_CONTEXT = "a university information chatbot for students and visitors"
CDP_ENDPOINT = "http://localhost:9222"   # Chrome remote debugging port
ATTACK_DELAY = 3.0                        # seconds between attacks (avoid rate-limiting)
RESPONSE_TIMEOUT = 25                     # seconds to wait for bot reply

# ─────────────────────────────────────────────────────────────────────────────
# JavaScript — traverses nested Dialogflow Messenger shadow DOMs
# ─────────────────────────────────────────────────────────────────────────────

_JS_PROBE = """
() => {
    var el = document.querySelector('df-messenger');
    if (!el) return { found: false };
    var sr = el.shadowRoot;
    if (!sr) return { found: true, hasShadowRoot: false };
    var children = Array.from(sr.children).map(function(c) { return c.tagName; });
    return { found: true, hasShadowRoot: true, shadowChildren: children };
}
"""

_JS_OPEN_BUBBLE = """
() => {
    var el = document.querySelector('df-messenger');
    if (!el || !el.shadowRoot) return 'no-element';
    var sr = el.shadowRoot;
    // Try common bubble selectors
    var bubble = sr.querySelector('df-messenger-chat-bubble')
              || sr.querySelector('.chat-bubble')
              || sr.querySelector('button');
    if (!bubble) return 'no-bubble';
    bubble.click();
    return 'clicked';
}
"""

_JS_GET_BOT_MESSAGES = """
() => {
    var messenger = document.querySelector('df-messenger');
    if (!messenger || !messenger.shadowRoot) return [];

    // Try both df-messenger-chat and df-messenger-chat-dialogflow
    var chat = messenger.shadowRoot.querySelector('df-messenger-chat')
            || messenger.shadowRoot.querySelector('df-messenger-chat-dialogflow')
            || messenger.shadowRoot.querySelector('df-cx-chat');
    if (!chat || !chat.shadowRoot) return [];

    // Collect all bot/response message elements
    var selectors = [
        'df-response-bubble',
        '.bot-message',
        '[message-type="response"]',
        '[sender="bot"]',
        'df-message-bot',
    ];
    var found = [];
    selectors.forEach(function(sel) {
        var els = chat.shadowRoot.querySelectorAll(sel);
        els.forEach(function(e) { found.push(e); });
    });

    // Deduplicate by text
    var seen = new Set();
    var texts = [];
    found.forEach(function(e) {
        var t = (e.innerText || e.textContent || '').trim();
        if (t && !seen.has(t)) { seen.add(t); texts.push(t); }
    });
    return texts;
}
"""

_JS_SEND_MESSAGE = """
(msg) => {
    var messenger = document.querySelector('df-messenger');
    if (!messenger || !messenger.shadowRoot) return { ok: false, reason: 'no messenger' };

    var chat = messenger.shadowRoot.querySelector('df-messenger-chat')
            || messenger.shadowRoot.querySelector('df-messenger-chat-dialogflow')
            || messenger.shadowRoot.querySelector('df-cx-chat');
    if (!chat || !chat.shadowRoot) return { ok: false, reason: 'no chat sr' };

    var userInput = chat.shadowRoot.querySelector('df-messenger-user-input');
    if (!userInput || !userInput.shadowRoot) return { ok: false, reason: 'no user-input sr' };

    var input = userInput.shadowRoot.querySelector('input[type="text"]');
    if (!input) return { ok: false, reason: 'no input element' };

    // Set value using native setter (works with lit/React)
    var nativeSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype, 'value'
    ).set;
    nativeSetter.call(input, msg);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));

    // Click send button
    var btn = userInput.shadowRoot.querySelector('#sendIconButton')
           || userInput.shadowRoot.querySelector('button');
    if (btn) {
        btn.click();
        return { ok: true, method: 'button-click' };
    }

    // Fallback: Enter key
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    input.dispatchEvent(new KeyboardEvent('keyup',   { key: 'Enter', bubbles: true }));
    return { ok: true, method: 'enter-key' };
}
"""


async def connect_to_chrome() -> tuple:
    """Connect Playwright to the already-open Chrome instance via CDP.

    Returns:
        Tuple of (browser, page) for the pict.edu tab.

    Raises:
        SystemExit: If Chrome is not running with --remote-debugging-port=9222.
    """
    from playwright.async_api import async_playwright

    pw = await async_playwright().start()
    try:
        browser = await pw.chromium.connect_over_cdp(CDP_ENDPOINT)
    except Exception:
        _console.print(
            "\n[bold red]Cannot connect to Chrome.[/bold red]\n"
            "\nMake sure you started Chrome with:\n"
            '  [cyan]chrome.exe --remote-debugging-port=9222 --user-data-dir=C:\\ChromeDebug[/cyan]\n'
            "\nAnd that https://pict.edu is open in that browser.\n"
        )
        sys.exit(1)

    # Find the pict.edu tab
    for context in browser.contexts:
        for page in context.pages:
            if "pict.edu" in page.url:
                _console.print(f"[green]Connected to tab:[/green] {page.url}")
                return pw, browser, page

    # pict.edu not open — open it in a new tab
    _console.print("[yellow]pict.edu not found in open tabs — opening it now...[/yellow]")
    context = browser.contexts[0] if browser.contexts else await browser.new_context()
    page = await context.new_page()
    await page.goto(CHATBOT_URL, wait_until="domcontentloaded", timeout=60000)
    _console.print("[yellow]Please wait for Cloudflare to pass, then press ENTER here...[/yellow]")
    input()
    return pw, browser, page


async def verify_chatbot(page) -> bool:
    """Check if the Dialogflow Messenger widget is accessible on the page.

    Args:
        page: Playwright Page object.

    Returns:
        True if widget found, False otherwise.
    """
    result = await page.evaluate(_JS_PROBE)
    if not result.get("found"):
        _console.print(
            "[bold red]df-messenger not found on page.[/bold red]\n"
            "Make sure:\n"
            "  1. You are on https://pict.edu in the Chrome window\n"
            "  2. The page has fully loaded (no Cloudflare spinner)\n"
            "  3. You can see the chat bubble icon in the corner\n"
        )
        return False
    _console.print(f"[green]Dialogflow Messenger found[/green] — shadow children: {result.get('shadowChildren', [])}")
    return True


async def open_chat_widget(page) -> None:
    """Click the chat bubble to open the Dialogflow Messenger panel.

    Args:
        page: Playwright Page object.
    """
    result = await page.evaluate(_JS_OPEN_BUBBLE)
    _console.print(f"[cyan]Open bubble result:[/cyan] {result}")
    await page.wait_for_timeout(2000)


async def send_attack(page, attack_prompt: str) -> str:
    """Send one attack prompt and wait for the bot response.

    Args:
        page: Playwright Page object.
        attack_prompt: The adversarial message to send.

    Returns:
        Bot's response text, or empty string on failure.
    """
    before_messages = await page.evaluate(_JS_GET_BOT_MESSAGES)
    before_count = len(before_messages)

    result = await page.evaluate(_JS_SEND_MESSAGE, attack_prompt)
    if not result.get("ok"):
        _console.print(f"[red]Send failed:[/red] {result.get('reason')}")
        return ""

    # Poll until a new message appears
    deadline = time.monotonic() + RESPONSE_TIMEOUT
    while time.monotonic() < deadline:
        await page.wait_for_timeout(700)
        messages = await page.evaluate(_JS_GET_BOT_MESSAGES)
        if len(messages) > before_count:
            # Extra wait for streaming / typing animation to finish
            await page.wait_for_timeout(1500)
            messages = await page.evaluate(_JS_GET_BOT_MESSAGES)
            return messages[-1] if messages else ""

    return ""  # Timed out


async def run_all_attacks(page, attacks: list) -> list[AttackResult]:
    """Fire all attacks against the chatbot and collect results.

    Args:
        page: Playwright Page object on pict.edu.
        attacks: List of Attack objects to fire.

    Returns:
        List of AttackResult objects.
    """
    results: list[AttackResult] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=_console,
        transient=True,
    ) as progress:
        task = progress.add_task("Firing attacks...", total=len(attacks))

        for attack in attacks:
            t_start = time.monotonic()
            try:
                response = await send_attack(page, attack.prompt)
                elapsed_ms = (time.monotonic() - t_start) * 1000
                results.append(AttackResult(
                    attack=attack,
                    response=response or None,
                    error=None if response else "No response / timeout",
                    elapsed_ms=elapsed_ms,
                    status="success" if response else "error",
                ))
            except Exception as exc:
                elapsed_ms = (time.monotonic() - t_start) * 1000
                results.append(AttackResult(
                    attack=attack,
                    response=None,
                    error=str(exc),
                    elapsed_ms=elapsed_ms,
                    status="error",
                ))

            progress.update(task, advance=1)
            await page.wait_for_timeout(int(ATTACK_DELAY * 1000))

    return results


def build_report(attack_results: list[AttackResult], start: datetime) -> FuzzResult:
    """Analyse attack results and build a FuzzResult.

    Args:
        attack_results: Raw results from the browser runner.
        start: When the test started (UTC).

    Returns:
        FuzzResult ready for reporting.
    """
    analyzer = Analyzer()
    vulnerabilities: list[Vulnerability] = []
    passed = []
    errors = []

    for ar in attack_results:
        if ar.status != "success" or ar.response is None:
            errors.append(ar)
            continue
        analysis = analyzer.analyze(ar.attack, ar.response)
        if analysis.is_vulnerable:
            vulnerabilities.append(Vulnerability(attack=ar.attack, result=analysis))
        else:
            passed.append(analysis)

    score = max(0, 100 - sum(SEVERITY_WEIGHTS.get(v.severity, 0) for v in vulnerabilities))
    duration = (datetime.now(timezone.utc) - start).total_seconds()

    return FuzzResult(
        target_description=TARGET_DESCRIPTION,
        context=TARGET_CONTEXT,
        attacks_run=len(attack_results),
        vulnerabilities=vulnerabilities,
        passed=passed,
        errors=errors,
        score=score,
        duration_seconds=duration,
        timestamp=start.isoformat(),
    )


async def async_main() -> None:
    """Main async entry point."""
    # Load static attacks (zero API cost)
    _console.print("\n[bold]Loading static attack library...[/bold]")
    loader = AttackLoader()
    attacks = loader.load_categories(["jailbreak", "injection", "data_extraction"])
    _console.print(f"  [green]{len(attacks)} attacks loaded[/green]")

    est_minutes = len(attacks) * (ATTACK_DELAY + 3) / 60
    _console.print(f"  Estimated duration: [yellow]~{est_minutes:.0f} minutes[/yellow]")
    _console.print()

    # Connect to user's running Chrome
    pw, browser, page = await connect_to_chrome()

    # Verify the chatbot widget is present
    _console.print("\n[bold]Verifying Dialogflow Messenger widget...[/bold]")
    await page.wait_for_timeout(2000)
    if not await verify_chatbot(page):
        await pw.stop()
        sys.exit(1)

    # Open the chat if not already open
    _console.print("\n[bold]Opening chat widget...[/bold]")
    await open_chat_widget(page)

    _console.print("\n[bold green]Starting attack sequence...[/bold green]\n")
    start = datetime.now(timezone.utc)
    attack_results = await run_all_attacks(page, attacks)

    await pw.stop()

    # Build and print report
    result = build_report(attack_results, start)

    print()
    print("=" * 60)
    print(f"DONE  Score: {result.score}/100")
    print(f"  Attacks run    : {result.attacks_run}")
    print(f"  Vulnerabilities: {len(result.vulnerabilities)}")
    print(f"  Passed         : {len(result.passed)}")
    print(f"  Errors         : {len(result.errors)}")
    print(f"  Duration       : {result.duration_seconds:.1f}s")
    print("=" * 60)

    result.report()
    result.to_txt("pict_report.txt")
    print()
    print("Report saved to pict_report.txt")


def main() -> None:
    """Sync entry point."""
    print("=" * 60)
    print("PromptFuzz — PICT Chatbot Security Test")
    print("Authorized class assignment")
    print("=" * 60)
    print()
    print("BEFORE RUNNING THIS SCRIPT:")
    print()
    print("  1. Open a NEW Chrome window with this command:")
    print(r'     "C:\Program Files\Google\Chrome\Application\chrome.exe"')
    print(r'     --remote-debugging-port=9222 --user-data-dir=C:\ChromeDebug')
    print()
    print("  2. In that Chrome, go to: https://pict.edu")
    print("     Wait for the page to fully load + Cloudflare to pass.")
    print("     Open the chat widget (click the circle icon).")
    print()
    print("  3. Come back here and press ENTER to start testing.")
    print()
    input("Press ENTER when Chrome is ready...")
    print()
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
