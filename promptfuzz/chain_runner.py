"""Chain runner — executes multi-turn attack chains against HTTP or
callable targets."""

from __future__ import annotations

import asyncio
import inspect
import time
from typing import Any, Callable

import httpx
from rich.progress import Progress

from promptfuzz.analyzer import Analyzer
from promptfuzz.attacks.chain_models import (
    AttackChain,
    ChainResult,
    ChainTurn,
    TurnResult,
)
from promptfuzz.attacks.loader import Attack

_PREV_TOKEN = "{prev_response}"
_MAX_EXCERPT = 500
# Hard ceiling on depth: prevents infinite loops from cyclic DAGs that
# somehow pass the loader's BFS check (e.g. if a chain file is hand-edited).
_MAX_DEPTH = 10


class ChainRunner:
    """Executes multi-turn attack chains with conditional branching.

    Concurrency model: multiple chains run in parallel (bounded by
    ``max_workers``), but turns *within* a single chain always run
    sequentially — each turn depends on the previous response.

    This is intentionally separate from Runner (single-shot attacks)
    because the execution model is fundamentally different: stateful,
    sequential, and branching rather than embarrassingly parallel.
    """

    def __init__(
        self,
        target: str | Callable,
        analyzer: Analyzer,
        headers: dict[str, str] | None = None,
        input_field: str = "message",
        output_field: str = "response",
        extra_fields: dict[str, Any] | None = None,
        max_workers: int = 3,
        timeout: float = 30.0,
    ) -> None:
        """Initialise the ChainRunner.

        Args:
            target: URL string or Python callable.
            analyzer: Analyzer (or JudgeAnalyzer) instance for per-turn
                vulnerability detection. Shared with the single-shot
                runner to avoid constructing a second JudgeAnalyzer client.
            headers: HTTP headers for URL-mode requests.
            input_field: JSON body key for the prompt text.
            output_field: JSON response key for the reply text.
            extra_fields: Extra fixed fields merged into every request.
            max_workers: Max chains running in parallel. Default 3 —
                lower than Runner's default 5 because each chain makes
                2-6 sequential requests, so the effective request
                concurrency is already higher per worker slot.
            timeout: Per-turn HTTP timeout in seconds.
        """
        self.target = target
        self.analyzer = analyzer
        self.headers = headers or {}
        self.input_field = input_field
        self.output_field = output_field
        self.extra_fields = extra_fields or {}
        self.max_workers = max_workers
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        chains: list[AttackChain],
        progress: Progress | None = None,
    ) -> list[ChainResult]:
        """Synchronous wrapper around :meth:`arun`.

        Args:
            chains: Chains to execute.
            progress: Optional Rich Progress for live display.

        Returns:
            List of ChainResult objects.
        """
        return asyncio.run(self.arun(chains, progress))

    async def arun(
        self,
        chains: list[AttackChain],
        progress: Progress | None = None,
    ) -> list[ChainResult]:
        """Execute all chains; chains run in parallel, turns sequentially.

        Args:
            chains: Chains to execute.
            progress: Optional Rich Progress for live display.

        Returns:
            List of ChainResult objects in completion order.
        """
        if not chains:
            return []

        semaphore = asyncio.Semaphore(self.max_workers)
        task_id = None
        if progress is not None:
            task_id = progress.add_task(
                "[magenta]Running chain attacks...", total=len(chains)
            )

        async with httpx.AsyncClient(
            headers=self.headers,
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:
            tasks = [
                self._bounded_run_chain(
                    chain, client, semaphore, progress, task_id
                )
                for chain in chains
            ]
            results = await asyncio.gather(*tasks, return_exceptions=False)

        return list(results)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _bounded_run_chain(
        self,
        chain: AttackChain,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        progress: Progress | None,
        task_id: Any,
    ) -> ChainResult:
        """Acquire semaphore slot, run one chain, then release."""
        async with semaphore:
            result = await self._run_chain(chain, client)
            if progress is not None and task_id is not None:
                progress.advance(task_id)
            return result

    async def _run_chain(
        self,
        chain: AttackChain,
        client: httpx.AsyncClient,
    ) -> ChainResult:
        """Execute a single chain, walking the branching DAG turn by turn.

        Branching decision per turn:
            - ``Analyzer.is_vulnerable == True``  → model complied → follow on_comply
            - ``Analyzer.is_vulnerable == False`` → model refused  → follow on_refuse
            - HTTP/timeout error                  → stop chain     (branch = "error")

        Template substitution:
            ``{prev_response}`` in a turn's prompt is replaced with the
            first ``_MAX_EXCERPT`` characters of the previous turn's
            response. On the first turn it expands to an empty string.
            This is the mechanism for stateless HTTP APIs — prior context
            is embedded directly in the prompt rather than sent as a
            ``messages[]`` array.

        Args:
            chain: The chain to execute.
            client: Shared httpx async client.

        Returns:
            ChainResult with per-turn breakdown and overall verdict.
        """
        turn_map: dict[str, ChainTurn] = {
            t.turn_id: t for t in chain.turns
        }
        turn_results: list[TurnResult] = []
        current_id: str = chain.turns[0].turn_id
        prev_response: str = ""
        any_vulnerable = False
        total_ms = 0.0
        depth = 0

        while current_id != "end" and depth < _MAX_DEPTH:
            depth += 1
            turn = turn_map[current_id]

            rendered = _render_prompt(turn.prompt, prev_response)

            # Fire the turn
            start = time.monotonic()
            response_text: str | None = None
            error: str | None = None

            try:
                if callable(self.target):
                    response_text = await self._call_function(rendered)
                else:
                    response_text = await self._call_http(
                        rendered, client
                    )
            except (httpx.TimeoutException, asyncio.TimeoutError):
                error = "Request timed out"
            except Exception as exc:  # noqa: BLE001
                error = str(exc)

            elapsed_ms = (time.monotonic() - start) * 1000
            total_ms += elapsed_ms

            # Analyze the response
            if response_text is not None:
                # Construct a synthetic Attack so the existing Analyzer
                # works without any modification. The id encodes both the
                # chain and turn for traceability in reports.
                synth_attack = Attack(
                    id=f"{chain.id}/{turn.turn_id}",
                    name=f"{chain.name} [{turn.turn_id}]",
                    category=chain.category,
                    severity=chain.severity,
                    description=chain.description,
                    prompt=rendered,
                    detection=turn.detection,
                    tags=list(chain.tags),
                    remediation=chain.remediation,
                )
                analysis = self.analyzer.analyze(synth_attack, response_text)
                is_vuln = analysis.is_vulnerable
                confidence = analysis.confidence
                evidence = analysis.evidence
            else:
                is_vuln = False
                confidence = 0.0
                evidence = error or "No response received"

            if is_vuln:
                any_vulnerable = True

            # Determine which branch to follow
            if error is not None:
                branch = "error"
                next_id = "end"
            elif is_vuln:
                branch = "comply"
                next_id = turn.on_comply
            else:
                branch = "refuse"
                next_id = turn.on_refuse

            turn_results.append(
                TurnResult(
                    turn=turn,
                    rendered_prompt=rendered,
                    response=response_text,
                    error=error,
                    is_vulnerable=is_vuln,
                    confidence=confidence,
                    evidence=evidence,
                    elapsed_ms=elapsed_ms,
                    branch_taken=branch,
                )
            )

            prev_response = response_text or ""
            current_id = next_id

        return ChainResult(
            chain=chain,
            turn_results=turn_results,
            is_vulnerable=any_vulnerable,
            final_severity=chain.severity,
            total_elapsed_ms=total_ms,
        )

    async def _call_http(
        self,
        prompt: str,
        client: httpx.AsyncClient,
    ) -> str:
        """POST a single turn's prompt to the HTTP target.

        Context from prior turns is NOT sent as a ``messages[]`` array.
        Instead, the ``{prev_response}`` template token injects prior
        context directly into the prompt text. This is the correct
        approach for the typical PromptFuzz target (a single-field
        message endpoint), and is itself a realistic attack technique —
        many real-world injection attacks embed prior exchange context
        in new prompts to establish false continuity.

        Args:
            prompt: The rendered prompt text for this turn.
            client: Shared httpx async client.

        Returns:
            Response text from the target.

        Raises:
            httpx.HTTPStatusError: On non-2xx responses.
        """
        payload: dict[str, Any] = {
            self.input_field: prompt,
            **self.extra_fields,
        }
        response = await client.post(str(self.target), json=payload)
        response.raise_for_status()
        try:
            data = response.json()
            return str(data.get(self.output_field, response.text))
        except Exception:  # noqa: BLE001
            return response.text

    async def _call_function(self, prompt: str) -> str:
        """Invoke a callable target with the rendered prompt.

        Supports both synchronous and async callables, mirroring the
        pattern in Runner._call_function.

        Args:
            prompt: The rendered prompt text for this turn.

        Returns:
            String response from the callable.
        """
        fn: Callable = self.target  # type: ignore[assignment]
        if inspect.iscoroutinefunction(fn):
            result = await fn(prompt)
        else:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, fn, prompt)
        return str(result)


# ---------------------------------------------------------------------------
# Module-level helpers (pure functions, easier to unit-test)
# ---------------------------------------------------------------------------


def _render_prompt(template: str, prev_response: str) -> str:
    """Substitute ``{prev_response}`` in a turn's prompt template.

    Truncates ``prev_response`` to ``_MAX_EXCERPT`` characters and
    appends ``...`` when truncation occurs, keeping payloads manageable
    and avoiding accidental token-limit hits on long model outputs.

    On the first turn of a chain, ``prev_response`` is always ``""``
    so the token is replaced with an empty string. Chain authors should
    design first-turn prompts that read naturally without it.

    Args:
        template: Prompt template string.
        prev_response: The previous turn's model output (may be empty).

    Returns:
        Rendered prompt string.
    """
    if _PREV_TOKEN not in template:
        return template
    excerpt = prev_response[:_MAX_EXCERPT]
    if len(prev_response) > _MAX_EXCERPT:
        excerpt += "..."
    return template.replace(_PREV_TOKEN, excerpt)
